# IR Playbook - ECScape - Cross-Task IAM Credential Hijack in Amazon ECS (EC2 launch type)

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential Access / Privilege Escalation - ECS task-isolation breakout |
| Emulation Tier | Research PoC (multi-resource: full ECS-on-EC2 cluster + co-resident victim tasks) |
| Threat Actor | N/A - technique emulation (naorhaziz/ecscape; Sweet Security research) |
| Platform | aws |
| Severity | High - a zero-permission task walks away with every other task's role and execution-role credentials, plus the secrets those execution roles can read |
| MITRE Tactics | Credential Access, Privilege Escalation |
| MITRE Techniques | T1552.007 (Container API), T1552.005 (Cloud Instance Metadata API), T1134 (agent impersonation) |
| Services in Scope | ECS, EC2, IMDS, IAM, STS, Secrets Manager, SSM Parameter Store, GuardDuty, CloudTrail, VPC Flow Logs |
| Infrastructure Created | ECS cluster (`ecscape`) + t3.small ASG container instance + instance role/profile + 3 task roles + Secrets Manager secret + VPC scaffolding (via `infra/`) |

**What the emulation does:** stands up an ECS-on-EC2 cluster running three tasks in **host network mode** on one t3.small instance - a deny-all attacker task (`ecscape-attacker-role`) and two victims: `s3-control` (task role `ecscape-s3-control-role`, S3 read) and `database` (execution role `ecscape-secret-execution-role`, which resolves the `ecscape-db-secret` Secrets Manager secret). `attack.py` waits for the instance to register and the victims to run, then `RunTask`-launches the attacker task with the ECScape Python payload injected as a base64 command override. Inside the container the payload: (1) reads the **EC2 instance role** from IMDS `169.254.169.254`; (2) reads the ECS **agent introspection API** at `<host>:51678/v1/metadata` for the container-instance identity; (3) calls `ecs:DiscoverPollEndpoint`; (4) opens a **SigV4-signed ACS WebSocket** with `sendCredentials=true`, at which point the control plane streams the IAM credentials of every task on the host. The harvested credentials are recovered from the attacker container's CloudWatch logs.

**Why this is high severity:** the attacker task's *own* role can do nothing (deny-all). Yet by impersonating the ECS agent - the identity the control plane trusts to receive pre-assumed task credentials - it obtains working credentials for `ecscape-s3-control-role` and `ecscape-secret-execution-role`, credentials it could never assume directly via STS (their trust policy names only `ecs-tasks.amazonaws.com`). Task isolation, the security boundary customers assume between co-located tasks, collapses. The execution-role theft is the worse half: that identity is agent-only and can read every secret and SSM parameter wired into any task on the instance.

**The invisible-theft signature.** The credential *delivery* over ACS produces **no CloudTrail event** - the control plane just hands creds to what it believes is the agent. There is no "creds stolen" log line. Every deployable detection keys on the *surrounding* calls (`DiscoverPollEndpoint` rate, `RunTask`) or on the *misuse of the stolen roles* (an execution role acting outside agent bootstrap; a task role appearing off-host). A defender waiting for a single theft event will never see one.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for the rate and correlation queries below
- **GuardDuty enabled in all regions** - the only signal that fires on the *instance*-credential theft, and then only if the stolen instance creds are used off-host (see the caveat in Query 5)
- VPC Flow Logs on all ECS VPCs - the ACS WebSocket to `ecs-a-*.<region>.amazonaws.com` originating from a **task** rather than the agent process is a strong network tell that never reaches CloudTrail
- ECS container-instance and task inventory: for every instance, which tasks (and which task/execution roles) are co-resident. "Which roles were exposed?" must be answerable from the instance ID in minutes
- Know each execution role's legitimate **bootstrap** action set (ECR pull, `logs:CreateLogStream`/`PutLogEvents`, `secretsmanager:GetSecretValue`, `ssm:GetParameters`, `kms:Decrypt`). Anything else from an execution role is the incident

**Alerting (must be pre-configured)**
- Execution-role credentials performing any action **outside** the bootstrap set -> P1 (this is the single highest-fidelity ECScape signal; see `sigma_t1552.007.yml` rule 3)
- `ecs:DiscoverPollEndpoint` called more than once by the same principal in 10 minutes -> P2 (the agent calls it once per boot; see the correlation rule)
- GuardDuty `InstanceCredentialExfiltration.*` -> P0
- A task role observed from a `sourceIPAddress` that is not its task's host -> P1 (correlation, Query 4)
- `ecs:RunTask` from a principal not on the deployment allowlist -> P2 (the attacker launching its task)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, independent of any instance/task/execution role
- `jq` installed
- A map: container instance -> its instance role; each task -> its task role and execution role; each execution role -> the secrets/parameters it can read. This is the blast-radius sheet you fill in during Identification
- The trust and permission policies for every role on the affected instance, on hand

**Known IOC Baselines**
- Baseline which principals legitimately call `ecs:RunTask` (deployment/CI roles, a small set) and `ecs:DiscoverPollEndpoint` (only the ECS agent, via the instance role, once per boot)
- Baseline each task/execution role's normal `sourceIPAddress` (its container instance's private IP / NAT) and, for execution roles, their normal (bootstrap-only) action set
- **Prefer `awsvpc` network mode or Fargate.** ECScape depends on host network mode plus an IMDS hop limit > 1 to let a container reach `169.254.169.254` and `:51678`. `awsvpc` gives each task its own ENI and removes that path; Fargate is not affected at all. A cluster that does not co-locate differing-trust tasks on shared EC2 hosts converts this High-severity technique into a non-event

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*` | GuardDuty | T1552.005 |
| P1 | Task-**execution** role credentials (`assumed-role/*-execution-role`) performing any action outside agent bootstrap (ECR/logs/secrets/ssm/kms at task start) | CloudTrail | T1552.007 |
| P1 | A task role used from a `sourceIPAddress` / task other than the one it was issued to | CloudTrail | T1552.007 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ecs:DiscoverPollEndpoint` called more than once by the same principal within 10 min | CloudTrail | T1552.007 |
| P2 | `ecs:RunTask` from a principal not on the deployment allowlist | CloudTrail | T1552.007 |
| P2 | Outbound TLS to `ecs-a-*.<region>.amazonaws.com` from a task IP rather than the agent process | VPC Flow Logs / host telemetry | T1552.007 |
| P3 | New `ecs:RegisterTaskDefinition` with an unusual/deny-all task role shortly before a `RunTask` | CloudTrail | T1552.007 |

### Detection Rule Quality Notes

The rules in `detections/` are split by technique and are intended to be deployed, but read these caveats first:

| Rule / File | Note |
|-------------|------|
| `sigma_t1552.007.yml` rule 1 (DiscoverPollEndpoint base) | **Do not alert on this directly.** The agent issues exactly this call once per instance boot; the base rule exists only to be referenced by the rate correlation (rule 2). |
| `sigma_t1552.007.yml` rule 2 (rate correlation) | Uses pySigma `correlation: event_count` (not the legacy `condition: ... | count()` pipe form, which no backend compiles). Level medium - a network partition can produce two legitimate agent calls close together, so corroborate. |
| `sigma_t1552.007.yml` rule 3 (execution-role misuse) | The strongest single signal. The `bootstrap_actions` allowlist and the `:assumed-role/ecscape-secret-execution-role/` pattern are emulation-specific - replace with your execution roles and their real bootstrap set. Without tuning it can miss (wrong role suffix) or over-fire (a legitimately reused execution role). |
| `sigma_t1552.007.yml` rule 4 (RunTask) | `deployment_principals` ships as `REPLACE-ME-*` placeholders that match nothing, so until you edit them the rule fires on every deploy. Maintain the allowlist. |
| `sigma_t1552.005.yml` (GuardDuty) | Definitive when it fires, but **may stay silent in a pure ECScape run**: the instance creds are used on the host (to call DiscoverPollEndpoint / open ACS), not off it. GuardDuty is a backstop for the *follow-on* exfiltration, not the primary ECScape detection. |
| `kql_t1552.005.kql`, `kql_t1552.007.kql` | Both depend on environment specifics - a `_GetWatchlist('InstanceRoleIPs')` role->IP map for 005, and the `-execution-role`/`-s3-control-role` suffixes for 007. Bare identifiers do not resolve; maintain the watchlist. |
| ACS delivery | No rule can detect the credential receipt itself - it is not logged. Do not expect one; detect the misuse. |

---

### Key Investigation Queries

> All CloudTrail extraction below uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, which is robust; piping `--output text` into `jq` relies on undocumented tab-delimiting and breaks on fields containing tabs/newlines.

#### Query 1: Find the attacker task launch (`RunTask`) and the task role it used

```bash
# GNU date first, BSD/macOS date second.
START=$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-4H +%Y-%m-%dT%H:%M:%SZ)
REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunTask \
  --start-time "$START" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn, type: .userIdentity.type,
     cluster: .requestParameters.cluster,
     taskDef: .requestParameters.taskDefinition,
     overrides: (.requestParameters.overrides // "none"),
     sourceIP: .sourceIPAddress, error: (.errorCode // "SUCCESS")}'
```

A `RunTask` from an interactive user or an unexpected role, especially with a `containerOverrides.command` that decodes a base64 blob, is the attacker task. Record the `taskArn` from the response and its task role.

#### Query 2: `DiscoverPollEndpoint` rate - the impersonation tell

```bash
START=$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-4H +%Y-%m-%dT%H:%M:%SZ)
REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DiscoverPollEndpoint \
  --start-time "$START" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, principal: .userIdentity.arn, sourceIP: .sourceIPAddress}' | \
  jq -s 'group_by(.principal) | map({principal: .[0].principal, calls: length,
         times: (map(.time) | sort)}) | sort_by(-.calls)'
```

The ECS agent calls this **once** per instance boot. Any principal with `calls > 1` in the window - especially the instance role - is impersonating the agent. Two calls close together can be an agent reconnect; a run of calls is not.

#### Query 3 - The decisive query: what did the execution role do beyond bootstrap?

Execution-role credentials are agent-only. Any action outside the bootstrap set means they left the agent.

```bash
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)
REGION="us-east-1"
EXEC_ROLE="ecscape-secret-execution-role"

aws cloudtrail lookup-events \
  --start-time "$START" --region "$REGION" --output json | \
  jq -r --arg role "$EXEC_ROLE" '
    ["GetAuthorizationToken","BatchGetImage","GetDownloadUrlForLayer","CreateLogStream",
     "PutLogEvents","GetSecretValue","GetParameters","Decrypt"] as $bootstrap |
    .Events[].CloudTrailEvent | fromjson |
    select((.userIdentity.sessionContext.sessionIssuer.userName // "") == $role) |
    select((.eventName as $e | $bootstrap | index($e)) | not) |
    {time: .eventTime, event: .eventName, source: .eventSource,
     ip: .sourceIPAddress, agent: .userAgent, error: (.errorCode // "SUCCESS")}' | \
  jq -s 'sort_by(.time)'
```

Any row here is a high-confidence indicator the execution role was hijacked. An empty result does **not** clear the incident (the attacker may have used only `GetSecretValue`); cross-check the source IP/userAgent of even the bootstrap calls against the legitimate agent in Query 4.

#### Query 4: Cross-task / off-host use of every harvested role (blast radius)

```bash
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)
REGION="us-east-1"
# Every role that was on the compromised instance - from your co-residency map
for ROLE in ecscape-s3-control-role ecscape-secret-execution-role; do
  echo "== $ROLE =="
  aws cloudtrail lookup-events \
    --start-time "$START" --region "$REGION" --output json | \
    jq -r --arg role "$ROLE" '.Events[].CloudTrailEvent | fromjson |
      select((.userIdentity.sessionContext.sessionIssuer.userName // "") == $role) |
      {time: .eventTime, event: .eventName, ip: .sourceIPAddress, error: (.errorCode // "SUCCESS")}' | \
    jq -s 'group_by(.event) | map({event: .[0].event, count: length,
           ips: (map(.ip) | unique)}) | sort_by(-.count)'
done
```

More than one distinct non-`amazonaws.com` `sourceIPAddress` for a role means the credential was used from somewhere other than its owning task - theft. Record every IP; these are IOCs. Flag `iam:*`, `sts:AssumeRole` (pivot), `s3:GetObject` on sensitive buckets, `secretsmanager:GetSecretValue`.

#### Query 5: GuardDuty findings for the instance/roles

```bash
REGION="us-east-1"
DETECTOR_ID=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text)
aws guardduty list-findings --detector-id "$DETECTOR_ID" --region "$REGION" \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS","UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"]}}}' \
  --query 'FindingIds' --output text | \
  xargs -r aws guardduty get-findings --detector-id "$DETECTOR_ID" --region "$REGION" --finding-ids
```

Absence here does not clear the incident - see the caveat in the rule notes.

#### Query 6: Which secrets/parameters the exposed execution roles could read (rotation scope)

```bash
REGION="us-east-1"
EXEC_ROLE="ecscape-secret-execution-role"
# Inline + attached policies -> the Resources the role could GetSecretValue / GetParameters on
aws iam list-role-policies --role-name "$EXEC_ROLE" --query 'PolicyNames' --output text | \
  tr '\t' '\n' | while read -r P; do
    [ -n "$P" ] && aws iam get-role-policy --role-name "$EXEC_ROLE" --policy-name "$P" \
      --query 'PolicyDocument.Statement[?contains(to_string(Action),`secretsmanager`) || contains(to_string(Action),`ssm:GetParameter`)].Resource'
  done
aws iam list-attached-role-policies --role-name "$EXEC_ROLE" --output table
```

Every secret/parameter this role could read must be treated as **exposed** and rotated (§4).

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The **stolen role sessions** are the emergency. ECS task/execution-role tokens keep working from anywhere until they expire (~6h), independent of the tasks or the instance. Revoke them first, before touching the host.

#### Step 1: Revoke active sessions on every harvested role

`aws:TokenIssueTime` invalidates every credential **issued before** the cutoff - which includes the tokens the attacker just harvested - without deleting the roles.

```bash
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Every role co-resident on the compromised instance (from your map), plus the instance role
for ROLE in ecscape-s3-control-role ecscape-secret-execution-role ecscape-instance-role; do
  aws iam put-role-policy --role-name "$ROLE" \
    --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
  echo "[OK] Pre-$CUTOFF sessions revoked for $ROLE"
done
```

**What this does and does not stop.** It kills the tokens that exist right now, including every harvested credential. It does **not** stop fresh theft: if the attacker task is still running and can re-open the ACS WebSocket, the control plane re-issues tokens with a later `TokenIssueTime` that the Deny does not match. This buys time; it is not containment on its own. Stop new theft by killing the attacker task (Step 2) and cordoning the instance (Step 3).

#### Step 2: Stop the attacker task, its task definition, and its principal

```bash
REGION="us-east-1"
CLUSTER="ecscape"
TASK_ARN="<taskArn-from-Query-1>"

# Stop the running attacker task
aws ecs stop-task --cluster "$CLUSTER" --task "$TASK_ARN" --region "$REGION" \
  --reason "IR: ECScape attacker task" --query 'task.lastStatus'

# Deregister its task definition so it cannot be re-run
TASKDEF=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$REGION" \
  --query 'tasks[0].taskDefinitionArn' --output text)
aws ecs deregister-task-definition --task-definition "$TASKDEF" --region "$REGION" \
  --query 'taskDefinition.status'

# Contain the launching principal (Query 1). If an IAM user, disable its keys;
# if a role, revoke its sessions the same way as Step 1.
ATTACKER_ARN="<caller-arn-from-Query-1>"
if echo "$ATTACKER_ARN" | grep -q ':user/'; then
  U=$(echo "$ATTACKER_ARN" | awk -F'/' '{print $NF}')
  for K in $(aws iam list-access-keys --user-name "$U" --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
  done
fi
```

#### Step 3: Cordon the container instance (stop new scheduling), then isolate it

```bash
REGION="us-east-1"
CLUSTER="ecscape"
CI_ARN=$(aws ecs list-container-instances --cluster "$CLUSTER" --status ACTIVE --region "$REGION" \
  --query 'containerInstanceArns[0]' --output text)

# DRAINING stops new tasks landing here and lets the platform move legitimate ones off
aws ecs update-container-instances-state --cluster "$CLUSTER" \
  --container-instances "$CI_ARN" --status DRAINING --region "$REGION" \
  --query 'containerInstances[0].status'

# The instance ran attacker code and holds the instance role. Snapshot, then isolate
# its network (see the EC2-instance-credential playbook Step 4 for the per-ENI
# quarantine-SG procedure). Treat the host as compromised.
```

#### Step 4: Rotate every secret the exposed execution roles could read

The execution-role theft means the attacker could resolve every secret/parameter wired into any task on the host. Rotate them now - revoking sessions does not change a leaked secret **value**.

```bash
REGION="us-east-1"
# From Query 6. In this emulation, the exposed secret is ecscape-db-secret.
aws secretsmanager rotate-secret --secret-id "ecscape-db-secret" --region "$REGION" 2>/dev/null \
  || aws secretsmanager put-secret-value --secret-id "ecscape-db-secret" \
       --secret-string "<new-value>" --region "$REGION"
echo "[OK] Rotate every secret/parameter from Query 6, not just this one"
```

---

## 4. Eradication

### Remove Attacker Access

#### Scope down the roles that made the theft possible

```bash
# The instance role's DEFAULT managed policy (AmazonEC2ContainerServiceforEC2Role)
# grants ecs:Poll + ecs:DiscoverPollEndpoint - the calls ECScape relies on. You
# cannot remove them without breaking the agent, so the fix is network isolation
# (Guardrails), not trimming this policy. Do confirm the instance role carries
# nothing BEYOND the agent + SSM baseline:
aws iam list-attached-role-policies --role-name ecscape-instance-role --output table
aws iam list-role-policies --role-name ecscape-instance-role --output table

# Scope each execution role to only the secrets/parameters its own task needs
# (from Query 6). An over-scoped execution role widens every ECScape on that host.
```

#### Kill the malicious task definition family and any attacker-created tasks

```bash
REGION="us-east-1"
CLUSTER="ecscape"
# Deregister every revision of the attacker family (Step 2 handled one revision)
for TD in $(aws ecs list-task-definitions --family-prefix ecscape-attacker \
    --region "$REGION" --query 'taskDefinitionArns' --output text); do
  aws ecs deregister-task-definition --task-definition "$TD" --region "$REGION" \
    --query 'taskDefinition.status'
done
```

#### Terminate and rebuild the container instance from a known-good AMI

An instance that ran attacker code and served the instance role is untrusted; replace it, do not clean in place.

```bash
REGION="us-east-1"
INSTANCE_ID="<ec2-instance-id-of-the-DRAINING-container-instance>"
# Snapshots from Step 3 preserve evidence. Terminating it lets the ASG launch a
# clean replacement (relaunch templates hardened per Guardrails: awsvpc, hop limit 1).
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'
```

#### Remove persistence created with the stolen roles

```bash
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)
REGION="us-east-1"
aws cloudtrail lookup-events --start-time "$START" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventName | test("^(CreateUser|CreateAccessKey|CreateLoginProfile|CreateRole|PutUserPolicy|AttachRolePolicy|CreateFunction|PutBucketPolicy|RegisterTaskDefinition)$")) |
    {time: .eventTime, actor: .userIdentity.arn, event: .eventName, target: (.requestParameters | tostring)}'
```

Remediate each with the relevant persistence playbook.

#### Remove emergency policies once clean

```bash
for ROLE in ecscape-s3-control-role ecscape-secret-execution-role ecscape-instance-role; do
  aws iam delete-role-policy --role-name "$ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
done
```

---

## 5. Recovery

### Restore Clean State

#### Verify the stolen sessions are dead

```bash
REGION="us-east-1"
CONTAINED_AT="<iso8601-containment-timestamp>"
for ROLE in ecscape-s3-control-role ecscape-secret-execution-role; do
  LEAKS=$(aws cloudtrail lookup-events --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
    jq -r --arg role "$ROLE" '.Events[].CloudTrailEvent | fromjson |
      select((.userIdentity.sessionContext.sessionIssuer.userName // "") == $role) |
      select(.errorCode == null) |
      select(.sourceIPAddress | endswith("amazonaws.com") | not) | .eventTime' | grep -c .)
  [ "$LEAKS" -eq 0 ] && echo "[OK] $ROLE: no successful use since containment" \
                     || echo "[FAIL] $ROLE: $LEAKS calls succeeded after containment"
done
```

#### Verify the replacement runs in `awsvpc` / Fargate with a hardened IMDS

```bash
REGION="us-east-1"
CLUSTER="ecscape"
# New task definitions should be networkMode=awsvpc (or launchType FARGATE)
aws ecs describe-task-definition --task-definition "<new-taskdef>" --region "$REGION" \
  --query 'taskDefinition.networkMode'
# Replacement container instance should enforce IMDS hop limit 1
NEW_INSTANCE="<new-ec2-instance-id>"
aws ec2 describe-instances --instance-ids "$NEW_INSTANCE" --region "$REGION" \
  --query 'Reservations[0].Instances[0].MetadataOptions.{Tokens:HttpTokens,Hop:HttpPutResponseHopLimit}'
```

`networkMode` must be `awsvpc` (or the workload on Fargate); `HttpPutResponseHopLimit` must be `1`.

#### Confirm the secrets were rotated

```bash
REGION="us-east-1"
aws secretsmanager describe-secret --secret-id "ecscape-db-secret" --region "$REGION" \
  --query '{LastChanged:LastChangedDate,LastRotated:LastRotatedDate}'
```

`LastChangedDate` must be after the incident. Repeat for every secret/parameter from Query 6.

#### Confirm the corrected detections fire

```bash
echo "Re-run the emulation on an awsvpc/hop-limit-1 test cluster: expect the payload to FAIL"
echo "at IMDS/introspection (no host path), and NO harvested credentials in the attacker logs."
echo "On the host-mode repro: expect exactly ONE execution-role-misuse alert (rule 3), not one per API call."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A task could reach IMDS and the `:51678` introspection port | Host network mode + IMDS hop limit > 1; `awsvpc`/Fargate not used |
| A task could impersonate the agent to ACS | Instance role carries the default `ecs:Poll`/`ecs:DiscoverPollEndpoint` (unavoidable for the agent) - the real gap is co-locating an untrusted task on that host |
| The theft was invisible | ACS credential delivery is unlogged; no detection on execution-role misuse or cross-task use was deployed |
| Execution-role theft exposed real secrets | Execution role over-scoped / secrets shared across tasks of differing trust on one instance |
| The stolen roles were worth stealing | Task and execution roles broader than the workloads needed |

### Recommended Guardrails

**Architecture (the decisive control)**
- Move workloads to **`awsvpc` network mode** (per-task ENI removes the container's path to host IMDS and `:51678`) or to **Fargate**, which is not affected by ECScape at all
- Do **not** co-locate tasks of differing trust levels on the same EC2 container instance; segregate by cluster/capacity provider
- Enforce IMDS `HttpTokens: required` **and** `HttpPutResponseHopLimit: 1` on all ECS instances and launch templates (hop limit 1 blocks a container one hop from the host)

**Least privilege**
- Scope each task role and execution role to exactly what its task needs; never share one execution role (or its secrets) across tasks that should not trust each other
- A stolen role is only as dangerous as its policy - and an execution role's blast radius is every secret it can resolve

**SCPs (OU level)**

```json
// Deny launching ECS instances / tasks that permit IMDSv1 or a hop limit > 1
{
  "Effect": "Deny",
  "Action": ["ec2:RunInstances", "ec2:ModifyInstanceMetadataOptions"],
  "Resource": "*",
  "Condition": { "StringNotEquals": { "ec2:MetadataHttpTokens": "required" } }
}
```

**Detection**
- Deploy execution-role-misuse (Sigma rule 3) at P1 - the highest-fidelity ECScape signal
- Deploy the `DiscoverPollEndpoint` rate correlation (rule 2) and the cross-task/off-host KQL, with a maintained role->IP watchlist
- Alert `ecs:RunTask` from non-deployment principals (rule 4)
- Alert GuardDuty `InstanceCredentialExfiltration.*` at P0 as the backstop
- Add VPC Flow Log monitoring for task-originated TLS to `ecs-a-*.<region>.amazonaws.com`

### Technique Reference

| Type | Value |
|------|-------|
| MITRE techniques | T1552.007 (Container API), T1552.005 (Cloud Instance Metadata API), T1134 (agent impersonation) |
| MITRE tactics | Credential Access (TA0006), Privilege Escalation (TA0004) |
| Primary path | IMDS instance-role theft -> agent introspection `:51678` -> `ecs:DiscoverPollEndpoint` -> SigV4-signed ACS WebSocket (`sendCredentials=true`) -> harvest co-resident task + execution-role creds |
| Event sources | `ecs.amazonaws.com` (DiscoverPollEndpoint, RunTask); the ACS delivery itself is unlogged |
| Definitive detection | Execution-role credentials used outside agent bootstrap; cross-task/off-host role use |
| Prerequisite for success | EC2 launch type, host network mode (or IMDS hop limit > 1), multiple co-resident tasks. **Not applicable to Fargate or `awsvpc`-isolated tasks** |
| Resources created | ECS cluster + t3.small container instance + instance/attacker/s3-control/execution roles + Secrets Manager secret + VPC scaffolding |
| Follow-on to watch for | `sts:AssumeRole` pivots, `secretsmanager:GetSecretValue`, `s3:GetObject` with the stolen roles, IAM persistence |
| Upstream reference | https://github.com/naorhaziz/ecscape ; https://www.sweet.security/blog/ecscape-understanding-iam-privilege-boundaries-in-amazon-ecs |

### Revert

`pulumi destroy` in `infra/` removes the ECS cluster, container instance/ASG, all
IAM roles, the Secrets Manager secret, and the VPC scaffolding. The attacker task
is `RunTask`-launched (not managed by Pulumi); `attack.py` stops it in a `finally`,
but confirm no `ecscape-attacker` task remains before destroy or the cluster delete
can hang. After a **real** incident (as opposed to an emulation), do not rely on
`pulumi destroy`: the container instance must be treated as compromised and
rebuilt, every harvested role's sessions revoked, and every secret the execution
roles could read rotated, per §3-§4.
