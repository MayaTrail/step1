# IR Playbook - Execute Commands on EC2 Instances via SSM - Fleet-Wide Root Execution via `ssm:SendCommand`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution / Cloud Administration Command (remote command execution across instances) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, `SendCommand` runs arbitrary shell **as root** on every targeted instance with no SSH or network access; a multi-instance send is fleet-wide root RCE (`MANIFEST.py` rates MEDIUM; the IR view is High because of the root-on-many-hosts blast radius) |
| MITRE Tactics | Execution |
| MITRE Techniques | T1651 |
| Services in Scope | SSM, EC2, CloudTrail, IAM, GuardDuty, VPC Flow Logs |
| Infrastructure Created | 3 EC2 instances (SSM-managed) + IAM role (SSM core) + instance profile + VPC (via `infra/`) |

**What the emulation does:** waits for its three EC2 instances to register with SSM, then issues a single `ssm:SendCommand` with the `AWS-RunShellScript` document to **all of them at once**, executing an arbitrary shell command, and reads the results with `ssm:GetCommandInvocation`. The SSM agent runs commands as **root** (Linux) / SYSTEM (Windows), so this is unauthenticated-to-the-host root code execution driven entirely from the AWS control plane.

**Why the fan-out is the signal.** `ssm:SendCommand` is a routine operation, patching, config management, break-fix all use it. What distinguishes an attacker is the *shape*: `AWS-RunShellScript` (arbitrary shell, versus a specific approved document) targeting **many instances at once** or a broad tag `Targets`, from a principal that is not the patch-automation role. The shipped rule (§2) matches every `SendCommand` with no discriminator, so it drowns in benign patch traffic and never keys on the mass-execution pattern.

**The command body is the evidence, and it is often not in CloudTrail.** CloudTrail records the `SendCommand` call, but the `commands` parameter is frequently omitted or truncated. The authoritative record of *what ran* is SSM itself (`ssm list-command-invocations --details`) or SSM Run Command output logging to S3/CloudWatch. Do not conclude "nothing malicious ran" from an empty CloudTrail `commands` field.

**Assume every targeted instance is compromised.** Root code executed on each. Treat them as hosts an attacker had a root shell on: expect on-host persistence, credential theft from IMDS, and lateral movement using each instance's role.

**Relationship to sibling techniques.** The credential-theft and enumeration playbooks use this same `SendCommand` primitive for a *specific* payload (IMDS curl / recon commands). This playbook is the generic case, arbitrary commands, many instances, and its containment (`SendCommand` restriction, instance rebuild) is the common core.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to a log platform. `SendCommand`/`GetCommandInvocation` are management events, so `lookup-events` works for the *calls* (not the command bodies)
- **Enable SSM Run Command output logging to S3 / CloudWatch Logs** account-wide, this is the reliable source of the executed command and its output, because CloudTrail often omits the `commands` payload
- GuardDuty enabled in all regions; VPC Flow Logs on all VPCs, to catch a post-execution C2 callback from a targeted instance
- A current map of instances → their SSM-managed status and instance roles, so blast radius is answerable immediately

**Alerting (must be pre-configured)**
- `ssm:SendCommand` with `AWS-RunShellScript` / `AWS-RunPowerShellScript` from a principal not on the patch-automation allowlist → alert. This is the primary control
- **Fan-out alert: a single `SendCommand` targeting ≥ N instances (start at N=3; tune to your real maintenance-window batch sizes), or using a broad tag `Targets`, from a non-automation principal → page.** Mass execution is the attacker shape
- `ssm:SendCommand` whose recovered command body contains download-and-execute content (`curl`/`wget`/`/dev/tcp`/`base64 -d`), from SSM output logs
- GuardDuty `Backdoor:EC2/C&CActivity.*` / `Trojan:EC2/*` on a targeted instance after the send

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- The patch-automation principal allowlist and the maintenance-window schedule, so a legitimate mass send is distinguishable from an attack
- A rebuild path (golden AMI) for any instance that executed attacker commands

**Known IOC Baselines**
- Baseline which principals call `ssm:SendCommand`, which documents they use, and their normal target counts, attackers deviate on all three
- Baseline maintenance windows; an out-of-window mass send is anomalous on timing alone

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ssm:SendCommand` (`AWS-RunShellScript`/`RunPowerShellScript`) targeting multiple instances from a non-automation principal | CloudTrail | T1651 |
| P0 | Recovered command body contains download-and-execute content (`curl`/`wget`/`/dev/tcp`/`base64 -d`) | SSM output logs | T1651 |
| P1 | `ssm:SendCommand` with a broad tag `Targets` (fleet-wide) from an interactive/non-automation principal | CloudTrail | T1651 |
| P1 | GuardDuty `Backdoor:EC2/C&CActivity.*` on a targeted instance shortly after a send | GuardDuty | T1651 |
| P1 | `SendCommand` from an off-baseline ASN/geography for the principal | CloudTrail | T1651 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ssm:SendCommand` `AWS-RunShellScript` from a principal with no prior SSM history | CloudTrail | T1651 |
| P2 | `ssm:DescribeInstanceInformation` sweep (finding targets) immediately before a `SendCommand` | CloudTrail | T1651 |
| P2 | `SendCommand` outside any maintenance window | CloudTrail | T1651 |
| P2 | `SendCommand` denied at volume (`errorCode = AccessDeniedException` / `InvalidInstanceId`), probing which instances are reachable | CloudTrail | T1651 |
| P3 | Single-instance `SendCommand` of an approved document by the patch-automation role in-window | CloudTrail | T1651 |

### Detection Rule Quality Notes

The rules in `detections/` are unusable as written (identical to the shipped rule for the SSM credential-theft and recon techniques). These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (DescribeInstanceInformation, SendCommand, GetCommandInvocation)` with `condition: selection` | Unusable. `SendCommand`/`GetCommandInvocation` are routine patch operations; `DescribeInstanceInformation` is pure noise. Matching them independently floods the queue | Alert `SendCommand` filtered by document + principal, and add the fan-out and content signals |
| No document / principal / target-count discriminator | Cannot separate patch automation from an attacker, nor a single approved command from fleet-wide arbitrary shell | Filter to `AWS-RunShellScript`/`RunPowerShellScript`, non-automation principals; count target instances |
| No command-body inspection, and no note that CloudTrail often omits it | Misses the strongest signal, and a rule keyed on `requestParameters.parameters.commands` silently matches nothing where SSM omits it | Source command bodies from SSM output logging; treat the CloudTrail-parameter match as best-effort |
| `GetCommandInvocation`/`DescribeInstanceInformation` as triggers | Benign follow-on/enumeration; belong as context, not primary alerts | Demote to correlation |
| Header TODO "verify acronym casing"; `level: medium` | Stale marker; and multi-instance RunShellScript deserves higher severity | Resolve TODO; the filtered rule → `level: high` |

**Recommended detection, `AWS-RunShellScript` from a non-automation principal.**

```yaml
title: SSM SendCommand shell document from non-automation principal
id: 8b1f7c40-2d63-4a90-9e51-3c0b8a7f6d21
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'SendCommand'
    requestParameters.documentName:
      - 'AWS-RunShellScript'
      - 'AWS-RunPowerShellScript'
  automation_principals:
    userIdentity.arn|contains:
      - ':role/patch-automation'
      - ':role/ssm-runner'
      - ':role/BreakGlassAdmin'
  condition: selection and not automation_principals
level: high
```

The **fan-out** (many target instances) and **command-body content** signals are
aggregations/decodes best expressed in the log platform (Query 3), a single-event
Sigma rule cannot count targets or reliably decode the (often-absent) command
body. Where SSM output logging is available, add a content rule matching
download-and-execute tokens in the logged command.

**On error strings:** SSM denials surface as `AccessDeniedException`; an
unreachable/unmanaged target as `InvalidInstanceId`. These are SSM service errors,
**not** `Client.`-prefixed like EC2. Match the SSM forms and confirm against a
sample event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, robust, unlike `--output text | jq`.

#### Query 1: Find the SendCommand(s), the caller, and the fan-out

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime,
     caller: .userIdentity.arn,
     type: .userIdentity.type,
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 5
     document: .requestParameters.documentName,
     command_id: .responseElements.command.commandId,
     # target breadth: explicit instance list and/or tag targets
     target_instances: (.requestParameters.instanceIds // []),
     target_count: ((.requestParameters.instanceIds // []) | length),
     targets: .requestParameters.targets,
     # commands often omitted/truncated by SSM: do not rely on this
     commands: (.requestParameters.parameters.commands // "REDACTED_OR_ABSENT"),
     error: (.errorCode // "SUCCESS"),
     ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

A `RunShellScript` send with a high `target_count` (or a broad `targets` tag)
from a non-automation `caller` is the attack. Note each `command_id` for Query 2.

#### Query 2: Recover what actually ran (authoritative, not CloudTrail)

```bash
REGION="us-east-1"
COMMAND_ID="<command-id-from-Query-1>"

# The executed command and its per-instance output/status: the real evidence
aws ssm list-command-invocations --command-id "$COMMAND_ID" --details \
  --region "$REGION" \
  --query 'CommandInvocations[].{Instance:InstanceId,Status:Status,
           Plugin:CommandPlugins[0].Name,Output:CommandPlugins[0].Output}' \
  --output json | tee ./ir-ssm-command-output.json

echo "=== IOC scan of the executed command / output ==="
# Coarse triage: the dotted-quad pattern also matches version strings etc. - treat
# hits as candidates to confirm, not confirmed IOCs.
grep -Eio 'curl [^"]*|wget [^"]*|https?://[^" ]*|[0-9]{1,3}(\.[0-9]{1,3}){3}|/dev/tcp/[^" ]*' \
  ./ir-ssm-command-output.json | sort -u
```

If `list-command-invocations` no longer has the command (SSM retains invocation
history for 30 days), fall back to the SSM Run Command S3/CloudWatch output
destination configured in §1.

#### Query 3 - Deployable detection (log platform): document + fan-out

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights. Flags RunShellScript sends by non-automation principals and surfaces the target count.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "ssm.amazonaws.com"
| where EventName == "SendCommand"
| extend Req = parse_json(RequestParameters)
| extend Doc = tostring(Req.documentName)
| where Doc in ("AWS-RunShellScript", "AWS-RunPowerShellScript")
| extend TargetCount = array_length(Req.instanceIds)
| extend HasTagTargets = isnotempty(Req.targets)
| where UserIdentityArn !has "role/patch-automation"      // tune to your allowlist
      and UserIdentityArn !has "role/ssm-runner"
| project TimeGenerated, UserIdentityArn, Doc, TargetCount, HasTagTargets,
          SourceIpAddress, CommandId = tostring(parse_json(ResponseElements).command.commandId)
// Threshold is >= 3 (tune to your real maintenance-window batch sizes). A broad
// tag Targets is fleet-wide regardless of the explicit-instance count.
| extend Verdict = case(
    TargetCount >= 3 or HasTagTargets, "FLEET-WIDE SHELL EXECUTION - P0",
    "SHELL EXECUTION BY NON-AUTOMATION PRINCIPAL, review")
| order by TargetCount desc
```

CloudWatch Logs Insights equivalent (target count from the array is not
expandable inline; alert on document + non-automation principal and pivot to
Query 1 for breadth):

```
fields @timestamp, userIdentity.arn, requestParameters.documentName
| filter eventSource = "ssm.amazonaws.com" and eventName = "SendCommand"
| filter requestParameters.documentName in ["AWS-RunShellScript","AWS-RunPowerShellScript"]
| filter userIdentity.arn not like /role\/(patch-automation|ssm-runner)/
```

#### Query 4: Did a targeted instance call out? (C2 confirmation)

```bash
# Query VPC Flow Logs (CloudWatch Logs) for outbound from a targeted instance's
# ENI right after the send. Cross-reference against Query 2 IOCs.
LOG_GROUP="/vpc/flowlogs"
ENI_ID="<eni-of-a-targeted-instance>"
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '2 hours ago' +%s 2>/dev/null \
        || date -u -v-2H +%s)

aws logs filter-log-events --log-group-name "$LOG_GROUP" \
  --start-time "${START}000" --filter-pattern "\"$ENI_ID\"" \
  --query 'events[*].message' --output text 2>/dev/null | \
  awk '$13=="ACCEPT" && $NF=="OK"' | head -50   # v2 flow log: $13=action, $NF=log-status
```

#### Query 5: Full session reconstruction of the SendCommand principal

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 6: Multi-region sweep

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  N=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null | \
    jq -r '[.Events[].CloudTrailEvent | fromjson |
      select(.requestParameters.documentName | test("RunShellScript|RunPowerShellScript"))] | length')
  [ -n "$N" ] && [ "$N" != "0" ] && echo "[!] $REGION, $N RunShellScript sends"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Root code has run on every targeted instance. Contain the principal, stop further
sends, and isolate the affected hosts.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Contain the SendCommand principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')          # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')           # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
  echo "[OK] Revoked sessions for role $R"
fi
```

#### Step 2: Cancel any still-running command and deny further sends

```bash
REGION="us-east-1"
COMMAND_ID="<command-id-from-Query-1>"

# Cancel the command if still in progress
aws ssm cancel-command --command-id "$COMMAND_ID" --region "$REGION" 2>/dev/null && \
  echo "[OK] Cancelled command $COMMAND_ID"

# Deny SendCommand on the suspect principal
SUSPECT_ROLE="<role-name>"
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenySSMSend" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["ssm:SendCommand","ssm:StartSession"],"Resource":"*"}]
  }'
echo "[OK] SendCommand denied for $SUSPECT_ROLE"
```

#### Step 3: Isolate and snapshot each targeted instance

For every instance in Query 1's `target_instances`: network-isolate (sever C2)
and snapshot for forensics. Do not trust the hosts. (Use the per-ENI quarantine-SG
helper from the credential-theft playbook; abbreviated here.)

```bash
REGION="us-east-1"
for IID in $(jq -r '.[].Instance' ./ir-ssm-command-output.json | sort -u); do
  echo "=== Isolating $IID ==="
  for VOL in $(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' --output text); do
    aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
      --description "IR-T1651-$IID-$(date -u +%Y%m%dT%H%M%SZ)" --query 'SnapshotId' --output text
  done
  # Move to a no-egress quarantine SG per ENI (see credential-theft playbook §3 for the full helper)
  echo "  [OK] snapshot(s) started for $IID, apply quarantine SG next"
done
```

#### Step 4: Deny SSM on the instance roles to stop further RunCommand landing

```bash
REGION="us-east-1"
# For each targeted instance's role, deny SSM message channels so a lingering
# attacker cannot re-drive the host.
for IID in $(jq -r '.[].Instance' ./ir-ssm-command-output.json | sort -u); do
  PROFILE=$(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' --output text | awk -F'/' '{print $NF}')
  ROLE=$(aws iam get-instance-profile --instance-profile-name "$PROFILE" \
    --query 'InstanceProfile.Roles[0].RoleName' --output text 2>/dev/null)
  [ -n "$ROLE" ] && aws iam put-role-policy --role-name "$ROLE" \
    --policy-name "EmergencyDenySSMChannel" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ssmmessages:*","ec2messages:*"],"Resource":"*"}]}' && \
    echo "[OK] SSM channel denied for role $ROLE ($IID)"
done
```

---

## 4. Eradication

### Remove Attacker Access: Rebuild the Executed-On Hosts

#### Rebuild every targeted instance

Each targeted instance ran attacker root commands and is untrusted. Snapshots
(Step 3) preserve forensics; rebuild from a golden AMI.

```bash
REGION="us-east-1"
for IID in $(jq -r '.[].Instance' ./ir-ssm-command-output.json | sort -u); do
  aws ec2 terminate-instances --instance-ids "$IID" --region "$REGION" \
    --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'
done
echo "[OK] Targeted instances terminated, relaunch from golden AMI with least-priv roles + IMDSv2"
```

#### Check each instance role for credential abuse

The commands may have harvested each instance's IMDS credentials and used them.
Enumerate each instance role's activity (session name = instance ID, do **not**
key the Username lookup on the role name):

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
for IID in $(jq -r '.[].Instance' ./ir-ssm-command-output.json | sort -u); do
  echo "=== Role activity for session $IID ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue="$IID" \
    --start-time "$START" \
    --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.userIdentity.type == "AssumedRole") |
      {time: .eventTime, event: .eventName, ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
done
```

Off-instance use of any role's credentials → pivot to the credential-theft
playbook. Block the Query 2 C2 IOCs at the edge and hunt for them fleet-wide.

#### Right-size SendCommand permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove ssm:SendCommand from principals that are not patch automation; where it
# is needed, scope by document (ssm:DocumentName) and by target tags.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenySSMSend" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
# Remove the per-instance-role EmergencyDenySSMChannel policies once hosts are rebuilt
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify no further RunShellScript sends since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.documentName | test("RunShellScript|RunPowerShellScript")) |
    select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further shell sends from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further shell sends, containment did not hold"
```

#### Verify the credential is dead

```bash
SUSPECT_ARN="<principal-arn>"
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  ACTIVE=$(aws iam list-access-keys --user-name "$U" \
    --query 'AccessKeyMetadata[?Status==`Active`]' --output text)
  [ -z "$ACTIVE" ] && echo "[OK] No active keys for $U" || echo "[FAIL] $U still has active keys"
fi
```

#### Verify targeted instances are rebuilt (not the compromised originals)

```bash
REGION="us-east-1"
# Confirm the original instance IDs are terminated
FAIL=0
for IID in $(jq -r '.[].Instance' ./ir-ssm-command-output.json | sort -u); do
  STATE=$(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
  [ "$STATE" != "terminated" ] && { echo "[FAIL] $IID is $STATE, expected terminated"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] All executed-on instances terminated/rebuilt"
```

#### Verify C2 IOCs are blocked and absent

```bash
echo "Confirm each Query 2 IOC is blocked at the edge and does not appear in any"
echo "instance's egress after rebuild."
```

#### Confirm the corrected detection fires

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
TEST_PRINCIPAL="<arn-used-for-the-emulation-run>"

# Re-run the emulation and assert a RunShellScript send with a multi-instance
# target set from the test principal is captured
RESULT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$TEST_PRINCIPAL" '[.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.documentName == "AWS-RunShellScript")] |
    {sends: length, max_targets: (map((.requestParameters.instanceIds // []) | length) | max)}')

echo "$RESULT"
echo "Expected: >=1 RunShellScript send with max_targets = 3 (the emulation's fleet),"
echo "classified FLEET-WIDE SHELL EXECUTION, not one alert per instance, and not"
echo "firing on benign GetCommandInvocation/DescribeInstanceInformation."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could run arbitrary shell across the fleet | `ssm:SendCommand` with `AWS-RunShellScript` granted broadly, not scoped to patch automation / approved documents |
| Mass execution undetected | Shipped rule matched all SSM calls with no document/principal/target discriminator and drowned in patch noise |
| What ran was hard to determine | SSM Run Command output logging not enabled, and CloudTrail omitted the command body |
| Instances trusted after root exec | No process to rebuild hosts that executed attacker commands |
| Instance roles harvestable | Root on the host + reachable IMDS + over-permissioned instance roles |

### Recommended Guardrails

**Restrict SendCommand to patch automation and approved documents**

```json
// SCP: only patch-automation principals may SendCommand; and only approved docs
{
  "Effect": "Deny",
  "Action": "ssm:SendCommand",
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/patch-automation", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

```json
// Complementary: even for allowed principals, restrict which documents run
{
  "Effect": "Deny",
  "Action": "ssm:SendCommand",
  "Resource": "arn:aws:ssm:*::document/*",
  "Condition": {
    "StringNotEquals": { "ssm:DocumentName": ["AWS-RunPatchBaseline", "MyOrg-ApprovedMaintenance"] }
  }
}
```

**Operational controls**
- Enable SSM Run Command output logging (S3/CloudWatch) account-wide so every executed command and its output is recorded independently of CloudTrail
- Enforce IMDSv2 and least-privilege instance roles, so root on a host does not immediately become account compromise via harvested role credentials
- Prefer SSM Documents with constrained parameters over `AWS-RunShellScript` for routine automation

**Detection improvements**
- Deploy the document+principal rule and the fan-out rule (Query 3), never the shipped all-SSM match
- Add a command-body content rule against the SSM output-log source
- Alert `DescribeInstanceInformation`→`SendCommand` sequences and out-of-window sends

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1651 - Cloud Administration Command |
| MITRE tactic | Execution (TA0002) |
| Primary API | `ssm:SendCommand` (`AWS-RunShellScript`) → `ssm:GetCommandInvocation` |
| Event source | `ssm.amazonaws.com` |
| Key discriminators | Shell document + non-automation principal + multi-instance/tag `Targets` fan-out |
| Execution context | Runs as **root** (Linux) / SYSTEM (Windows) via the SSM agent |
| Evidence of what ran | `ssm list-command-invocations --details` or SSM output logging - CloudTrail often omits the `commands` payload |
| Error strings (SSM, not `Client.`-prefixed) | `AccessDeniedException`, `InvalidInstanceId` |
| Resources created | 3 SSM-managed EC2 instances + IAM role + instance profile + VPC scaffolding |
| Follow-on to watch for | On-host persistence, IMDS credential theft + off-instance role use, C2 callback, lateral SendCommand to more instances |

### Revert

`pulumi destroy` in `infra/` removes the 3 EC2 instances, IAM role/instance
profile, and VPC. The technique creates nothing beyond the command executions
themselves. After a **real** incident, `pulumi destroy` is irrelevant, every
targeted instance executed attacker root commands and must be rebuilt (§4), the
`SendCommand` permission scoped down, and the C2 IOCs blocked and hunted; tearing
down the stack does not undo on-host persistence or credentials harvested during
execution.
