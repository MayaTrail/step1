# IR Playbook: Enumerate AWS Environment from EC2 Instance — Account Reconnaissance via a Compromised Instance Role

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Discovery / Cloud Infrastructure Reconnaissance |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | Medium — reconnaissance is not damage in itself, but a broad multi-service enumeration run from an instance role is a reliable indicator of an active foothold and precedes lateral movement (`MANIFEST.py` rates LOW; the IR view is Medium because the *context* — recon from a compromised instance — signals a live intrusion) |
| MITRE Tactics | Discovery |
| MITRE Techniques | T1580 |
| Services in Scope | SSM, EC2, S3, IAM, STS, GuardDuty, CloudTrail |
| Infrastructure Created | 1 EC2 instance + IAM role (**`ReadOnlyAccess` + SSM**) + instance profile + VPC scaffolding (via `infra/`) |

**What the emulation does:** drives a target EC2 instance through `ssm:SendCommand` (`AWS-RunShellScript`) to run a series of AWS CLI discovery commands using the instance's attached IAM role: `sts:GetCallerIdentity`, `ec2:DescribeInstances`, `ec2:DescribeVpcs`, `s3:ListBuckets` (`aws s3 ls`), `iam:ListUsers`, `iam:ListRoles`. The output — account topology, running instances, buckets, IAM principals — is the map an attacker uses to plan lateral movement.

**Two separate observability surfaces — the shipped rule watches the wrong one.** This technique appears in CloudTrail in two distinct places:
1. **The delivery**: `ssm:SendCommand` / `ssm:GetCommandInvocation`, recorded under **whoever drove the instance** (the attacker's principal, if they used SSM from outside).
2. **The reconnaissance itself**: `ec2:DescribeInstances`, `s3:ListBuckets`, `iam:ListUsers`, etc., recorded under **the instance role** — `userIdentity.arn = assumed-role/<instance-role>/<instance-id>`, with `sourceIPAddress` the instance's IP. (For instance-profile sessions the session name is the instance ID — see the credential-theft playbook.)

The shipped detection matches only surface (1) — the SSM plumbing — while its own description describes surface (2). An attacker who is *already on the instance* (a shell, not SSM) produces surface (2) with **no SSM events at all**, and the shipped rule sees nothing. The reliable detection is the reconnaissance burst on surface (2), independent of how the commands were delivered.

**The detection model is breadth, not volume.** Unlike the secret-retrieval techniques (count many items of *one* kind), reconnaissance is characterised by **fan-out** — a single principal touching many *different* read/list/describe actions across *multiple services* (`ec2` + `s3` + `iam` + `sts`) in a short window. An application instance role calls a small, fixed set of APIs; a recon burst lights up the whole board. Count distinct `(eventSource, eventName)` pairs per instance-role principal.

**Why this is Medium, not Low.** The commands are read-only and create nothing — but a workload instance role suddenly enumerating IAM users, every VPC, and all buckets is not the workload doing its job; it is an attacker mapping the account from a foothold. Treat it as confirmation of an active intrusion and the immediate precursor to lateral movement.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for the breadth queries below
- **The discovery calls are read events** — a `WriteOnly` trail misses the entire reconnaissance surface. Confirm `ReadWriteType: All`
- GuardDuty enabled in all regions — its `Discovery:*/AnomalousBehavior` and IAM anomaly findings are ML-based corroboration for exactly this pattern (not guaranteed to fire, but valuable when they do)
- An inventory mapping each instance role → the small set of APIs its workload legitimately calls, so "this role just called `iam:ListUsers`" is immediately anomalous
- SSM Run Command output logging to S3/CloudWatch, so the *content* of a `SendCommand`-delivered recon run is recoverable (CloudTrail may omit the command body — see the credential-theft playbook)

**Alerting (must be pre-configured)**
- Breadth alert: a single **instance-role** principal calling more than ~5 distinct read/list/describe actions across **2+ services** within 10 minutes → alert. This is the primary control and it keys on the reconnaissance surface, not SSM
- High-value narrow signal: **`iam:ListUsers` / `iam:ListRoles` / `iam:GetAccountAuthorizationDetails` from an instance role** — application instances essentially never enumerate IAM principals; treat as high confidence on its own
- `ssm:SendCommand` (`AWS-RunShellScript`) from a principal not on the SSM-automation allowlist (the delivery signal, as in the credential-theft playbook)
- GuardDuty `Discovery:*/AnomalousBehavior` → SNS
- If using the Sentinel breadth rule (Query 3): create and maintain an
  `InstanceRoles` watchlist (keyed on the instance-role name) enumerating every
  instance-profile role, so the rule can distinguish instance roles from human/CI
  roles. Keep it current as roles are added

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from the instance role and from any principal under investigation
- `jq` installed
- The instance role's trust and permission policies on hand — the first question is "how much could this role see?", and with `ReadOnlyAccess` attached the answer is "everything"

**Known IOC Baselines**
- Baseline each instance role's normal API set and call rate. Recon shows up as a sharp deviation in *breadth*
- Baseline which principals issue `ssm:SendCommand` — normally a short automation allowlist, never interactive users
- Flag any instance role carrying `ReadOnlyAccess` or other broad managed policies *before* an incident — that is the pre-condition that makes this technique powerful

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | An instance-role principal calls > 5 distinct read/list/describe actions across ≥ 2 services in 10 min | CloudTrail | T1580 |
| P0 | `iam:ListUsers` / `iam:ListRoles` / `iam:GetAccountAuthorizationDetails` from an instance role | CloudTrail | T1580 |
| P1 | Instance-role reconnaissance immediately after `ssm:SendCommand` to that instance from a non-automation principal | CloudTrail | T1580 |
| P1 | Instance-role discovery calls from a `sourceIPAddress` that is not the instance's own IP (stolen instance creds used off-host — see the credential-theft playbook) | CloudTrail | T1580 |
| P1 | GuardDuty `Discovery:IAMUser/AnomalousBehavior` or `Discovery:S3/AnomalousBehavior` attributed to an instance role | GuardDuty | T1580 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ssm:SendCommand` with `AWS-RunShellScript` to an instance from an interactive/non-automation principal | CloudTrail | T1580 |
| P2 | Instance role calling `s3:ListBuckets` / `ec2:DescribeVpcs` / `ec2:DescribeInstances` it never normally calls | CloudTrail | T1580 |
| P2 | `sts:GetCallerIdentity` from an instance role immediately followed by a fan-out of describe/list calls (the "where am I, then map everything" pattern) | CloudTrail | T1580 |
| P3 | A single unfamiliar describe call from an instance role, no fan-out | CloudTrail | T1580 |

### Detection Rule Quality Notes

The rules in `detections/` do not detect this technique. These are correctness defects, not just noise.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `ssm.amazonaws.com` events (`DescribeInstanceInformation`, `SendCommand`, `GetCommandInvocation`) — **the description says the signal is `ec2:Describe*` / `s3:ListBuckets` / `iam:ListUsers`, but the selection watches SSM plumbing instead** | The rule watches the delivery mechanism, not the reconnaissance. An attacker on the instance via a shell (no SSM) is invisible to it; and every legitimate `SendCommand` is a false positive | Rewrite to key on the **reconnaissance surface**: describe/list/get actions from an instance-role principal, counted for breadth |
| No threshold, no per-principal grouping, no breadth logic | Reconnaissance is defined by fan-out across services; a flat event match cannot express it | Count distinct `(eventSource, eventName)` per instance-role principal per window |
| No notion of "instance role" | The whole signal is *an instance role behaving like an operator*. Without identifying instance-role principals the rule cannot target the anomaly | Filter `userIdentity.arn` to `assumed-role/<instance-role-pattern>/` |
| `SendCommand`/`GetCommandInvocation` as primary selectors | These are routine automation events; they belong (if anywhere) to the *delivery* signal, secondary to the recon burst | Demote to a supporting correlation |
| Header TODO "verify acronym casing"; `level: medium` on a rule that mostly matches benign SSM traffic | Stale marker; alert fatigue | Resolve TODO; delivery rule → `level: low`; breadth rule → `level: high` |

**Recommended detection — reconnaissance breadth from an instance role.** This is an aggregation over distinct actions and belongs in a log platform (Query 3). A single-event Sigma rule can only cover the high-value narrow case (IAM enumeration from an instance role):

```yaml
title: IAM principal enumeration from an EC2 instance role
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'ListUsers'
      - 'ListRoles'
      - 'GetAccountAuthorizationDetails'
  instance_role:
    userIdentity.arn|contains: ':assumed-role/'
    userIdentity.sessionContext.sessionIssuer.userName|endswith: '-instance-role'   # match your instance-role naming
  condition: selection and instance_role
level: high
```

The breadth detection (distinct actions across services) cannot be a single-event
Sigma rule — deploy it as the log-platform query in Query 3, or as a Sigma
**correlation** of `type: value_count` counting distinct `eventName` grouped by
`userIdentity.arn`.

**On error strings:** if you extend detection to failed recon (an over-scoped-down role hitting denials), EC2/S3/IAM denials are not uniformly prefixed — EC2 uses `Client.UnauthorizedOperation`; IAM/S3 use `AccessDenied` / `AccessDeniedException`. Match the service-appropriate string and confirm against a sample.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'` — robust, unlike `--output text | jq`.

#### Query 1 — Identify the instance role and the breadth of its reconnaissance

The decisive query: for each instance-role principal, how many distinct actions
across how many services did it touch?

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"    # session name for instance-profile creds

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.type == "AssumedRole") |
    {svc: .eventSource, ev: .eventName, ip: .sourceIPAddress,
     role: (.userIdentity.sessionContext.sessionIssuer.userName // "?")}' | \
  jq -s '{
      role: (.[0].role // "unknown"),
      distinct_actions: ([.[] | "\(.svc):\(.ev)"] | unique | length),
      services: ([.[].svc] | unique),
      actions: ([.[] | "\(.svc):\(.ev)"] | unique | sort),
      source_ips: ([.[].ip] | unique)
    }'
```

A `distinct_actions` count well above the role's baseline, spanning `ec2` + `s3`
+ `iam` + `sts`, is reconnaissance. `iam.amazonaws.com` in `services` for an
application instance role is a standalone red flag.

#### Query 2 — How were the commands delivered? (SSM vs on-host shell)

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

# Was there an SSM SendCommand to this instance, and from whom?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg iid "$INSTANCE_ID" '.Events[].CloudTrailEvent | fromjson |
    select((.requestParameters.instanceIds // []) | index($iid)) |
    {time: .eventTime, caller: .userIdentity.arn, type: .userIdentity.type,
     key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 5
     document: .requestParameters.documentName, sourceIP: .sourceIPAddress}'
```

If this returns the driving principal, contain it too (Step 2). **If it returns
nothing**, the attacker likely ran the commands from an on-host shell — the
instance itself is compromised and the recon happened with no SSM footprint; the
instance role identity in Query 1 is your only control-plane trace.

#### Query 3 — Deployable breadth detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL** — not CloudWatch Logs Insights. Counts distinct actions across services per instance-role principal per 10-minute window. Requires an `InstanceRoles` Sentinel watchlist keyed on the instance-role name (see §1 Preparation).

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where UserIdentityType == "AssumedRole"
// SessionIssuerUserName is the flattened Sentinel column for the role name;
// there is no UserIdentitySessionContext JSON blob to parse in this schema.
| extend RoleName = SessionIssuerUserName
| where RoleName in ((_GetWatchlist('InstanceRoles') | project SearchKey))   // instance roles only
| where EventName startswith "Describe" or EventName startswith "List"
       or EventName startswith "Get" or EventName == "GetCallerIdentity"
| summarize
    DistinctActions = dcount(strcat(EventSource, ":", EventName)),
    Services        = dcount(EventSource),
    ServiceList     = make_set(EventSource, 10),
    IamEnum         = countif(EventSource == "iam.amazonaws.com"),
    Principals      = make_set(UserIdentityArn, 10),   // ARN => instance ID is the last segment
    SourceIPs       = make_set(SourceIpAddress, 10),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated)
    by RoleName, bin(TimeGenerated, 10m)
| where (DistinctActions > 5 and Services >= 2) or IamEnum > 0
| extend Verdict = case(
    IamEnum > 0,                          "IAM ENUMERATION FROM INSTANCE ROLE — P0",
    DistinctActions > 5 and Services >= 2, "MULTI-SERVICE RECON FROM INSTANCE ROLE — P0",
    "REVIEW")
| order by DistinctActions desc
```

CloudWatch Logs Insights equivalent:

```
fields @timestamp, userIdentity.sessionContext.sessionIssuer.userName as role,
       eventSource, eventName, sourceIPAddress
| filter userIdentity.type = "AssumedRole"
| filter eventName like /^(Describe|List|Get)/
| stats count_distinct(concat(eventSource, ":", eventName)) as distinct_actions,
        count_distinct(eventSource) as services by role, bin(10m)
| filter distinct_actions > 5 and services >= 2
```

#### Query 4 — What did the reconnaissance reveal? (scope the exposure)

The attacker now knows whatever these calls returned. Enumerate what was queried
so you know what they mapped.

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.type == "AssumedRole") |
    "\(.eventTime)  \(.eventSource)/\(.eventName)  from \(.sourceIPAddress)"' | sort
```

Assume everything reachable by these read calls (bucket names, VPC/instance
inventory, IAM user/role names) is now known to the attacker — factor that into
what you tighten and rotate.

#### Query 5 — Full session reconstruction of the driving principal

```bash
ACCESS_KEY_ID="<AKIA-or-ASIA-key-from-Query-2>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 6 — Multi-region sweep

**Caveat: this catches only the SSM *delivery* surface, not on-host recon.** An
attacker recon'ing from an on-host shell in another region leaves no
`SendCommand` and is invisible here. For cross-region *reconnaissance* coverage,
run the Query 3 breadth detection in the log platform (which sees all regions'
CloudTrail centrally), or repeat the Query 1 instance-role sweep per region once
you know the instance ID.

```bash
# Delivery-surface sweep (SSM). See caveat above — not a recon sweep.
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  COUNT=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$COUNT" ] && [ "$COUNT" != "0" ] && [ "$COUNT" != "None" ] && \
    echo "[!] $REGION — $COUNT SendCommand events (check for recon runs)"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Reconnaissance means an attacker holds this instance's role credentials and is
planning the next move. Contain the role and the instance before lateral
movement begins. Handle both delivery paths from Query 2: if driven by SSM,
contain the driving principal; if on-host, the instance itself is compromised.

> Run every containment/eradication command under the **break-glass responder
> credentials** from §1, not under the instance role or any principal being contained.

#### Step 1 — Revoke the instance role's active sessions

```bash
INSTANCE_ROLE="<instance-role-name-from-Query-1>"

aws iam put-role-policy \
  --role-name "$INSTANCE_ROLE" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny", "Action": "*", "Resource": "*",
      "Condition": {"DateLessThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}
    }]
  }'
echo "[OK] Pre-existing sessions for $INSTANCE_ROLE revoked"
```

`aws:TokenIssueTime` kills only tokens issued before now. The instance will fetch
fresh credentials from IMDS on its next call — which is why Step 3 (cut the
instance off) matters: while the host is attacker-controlled, it can keep minting
usable tokens.

#### Step 2 — Contain the driving principal (if SSM-delivered)

```bash
DRIVER_ARN="<caller-arn-from-Query-2>"    # empty if the recon was on-host

if echo "$DRIVER_ARN" | grep -q ":user/"; then
  U=$(echo "$DRIVER_ARN" | awk -F'/' '{print $NF}')          # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
elif echo "$DRIVER_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$DRIVER_ARN" | awk -F'/' '{print $2}')           # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
  echo "[OK] Revoked sessions for driving role $R"
fi
```

#### Step 3 — Cut the instance off from SSM and isolate it

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"
INSTANCE_ROLE="<instance-role-name>"

# Deny SSM on the role so no further RunCommand can execute on the host
aws iam put-role-policy --role-name "$INSTANCE_ROLE" \
  --policy-name "EmergencyDenySSM" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ssm:*","ssmmessages:*","ec2messages:*"],"Resource":"*"}]}'
echo "[OK] SSM denied for $INSTANCE_ROLE"

# Snapshot for forensics, then network-isolate (see the credential-theft playbook
# for the full quarantine-SG helper; the instance is compromised and should be
# treated as such)
for VOL in $(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' --output text); do
  aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
    --description "IR-T1580-$INSTANCE_ID-$(date -u +%Y%m%dT%H%M%SZ)" --query 'SnapshotId' --output text
done
echo "[OK] Snapshots started — proceed to network isolation per the quarantine-SG procedure"
```

---

## 4. Eradication

### Remove Attacker Access

Reconnaissance creates nothing to delete — the eradication work is (a) treat the
compromised instance as untrusted, (b) fix the over-privileged role that made the
recon so productive, and (c) act on what the attacker learned.

#### Right-size the instance role — remove `ReadOnlyAccess`

This is the root cause. An instance role should never carry `ReadOnlyAccess`
(account-wide read of every service). Scope it to exactly what the workload
calls.

```bash
INSTANCE_ROLE="<instance-role-name>"

# Show the over-broad attachments — ReadOnlyAccess is the culprit here
aws iam list-attached-role-policies --role-name "$INSTANCE_ROLE" --output table

# Detach ReadOnlyAccess (and any other broad managed policy)
aws iam detach-role-policy --role-name "$INSTANCE_ROLE" \
  --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess" && \
  echo "[OK] Detached ReadOnlyAccess from $INSTANCE_ROLE"

# Replace with a least-privilege inline policy derived from the workload's real
# API usage (from CloudTrail / IAM Access Advisor). Keep SSM core only if needed.
```

#### Rebuild the compromised instance

An instance an attacker ran commands on is untrusted. Snapshot preserved
forensics in §3; terminate and relaunch from the golden AMI with the scoped role
and IMDSv2 enforced (see the credential-theft playbook).

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'
```

#### Act on what the reconnaissance exposed

The attacker now holds a map of the account. From Query 4's action list:
- **IAM enumerated** (`ListUsers`/`ListRoles`): review those principals for weak configs the attacker may now target (users with console access and no MFA, over-permissive roles, long-lived keys)
- **S3 enumerated** (`ListBuckets`): confirm bucket policies and Block Public Access on anything sensitive that was named
- **EC2/VPC enumerated**: no direct exposure, but expect targeting of the instances/subnets revealed

#### Check for follow-on lateral movement

```bash
# The instance role's own subsequent actions, and the driving principal's, for any
# move beyond read-only (AssumeRole, RunInstances, writes)
INSTANCE_ID="<i-xxxxxxxxxxxx>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventName | test("^(Describe|List|Get)") | not) |
    {time: .eventTime, event: .eventName, source: .eventSource, error: (.errorCode // "SUCCESS")}'
```

#### Remove emergency policies once clean

```bash
INSTANCE_ROLE="<instance-role-name>"
aws iam delete-role-policy --role-name "$INSTANCE_ROLE" --policy-name "EmergencyDenySSM" 2>/dev/null
aws iam delete-role-policy --role-name "$INSTANCE_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the instance role no longer carries broad read access

```bash
INSTANCE_ROLE="<instance-role-name>"
BROAD=$(aws iam list-attached-role-policies --role-name "$INSTANCE_ROLE" \
  --query "AttachedPolicies[?PolicyName=='ReadOnlyAccess' || PolicyName=='AdministratorAccess'].PolicyName" \
  --output text)
[ -z "$BROAD" ] && echo "[OK] No broad managed policies on $INSTANCE_ROLE" \
                || echo "[FAIL] $INSTANCE_ROLE still has: $BROAD"
```

#### Verify no further reconnaissance since containment

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"
CONTAINED_AT="<iso8601-containment-timestamp>"

ACTIONS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.type == "AssumedRole") |
    select(.errorCode == null) | "\(.eventSource):\(.eventName)"' | sort -u | grep -c .)

[ "$ACTIONS" -eq 0 ] && echo "[OK] No successful instance-role API activity since containment" \
                     || echo "[FAIL] $ACTIONS distinct actions since containment — role still active"
```

#### Verify the driving principal is contained (if SSM-delivered)

```bash
DRIVER_ARN="<caller-arn-from-Query-2>"
if echo "$DRIVER_ARN" | grep -q ":user/"; then
  U=$(echo "$DRIVER_ARN" | awk -F'/' '{print $NF}')
  ACTIVE=$(aws iam list-access-keys --user-name "$U" \
    --query 'AccessKeyMetadata[?Status==`Active`]' --output text)
  [ -z "$ACTIVE" ] && echo "[OK] No active keys for $U" || echo "[FAIL] $U still has active keys"
fi
```

#### Verify GuardDuty is enabled everywhere

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  D=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text 2>/dev/null)
  { [ -z "$D" ] || [ "$D" = "None" ]; } && echo "[!] GuardDuty NOT enabled in $REGION"
done
echo "[OK] GuardDuty sweep complete"
```

#### Confirm the corrected detection fires

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

# Re-run the emulation, then assert the recon breadth is visible under the instance role
ACTIONS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.type == "AssumedRole") |
    "\(.eventSource):\(.eventName)"' | sort -u)
N=$(echo "$ACTIONS" | grep -c .)
SVCS=$(echo "$ACTIONS" | cut -d: -f1 | sort -u | grep -c .)
echo "Distinct actions: $N across $SVCS services"
{ [ "$N" -gt 5 ] && [ "$SVCS" -ge 2 ]; } && echo "[OK] Breadth signal present — the corrected rule has data to fire on" \
                                          || echo "[FAIL] Expected >5 actions across >=2 services; saw $N/$SVCS"
echo "Confirm the deployed breadth rule produced ONE alert, not one per API call,"
echo "and that it did NOT key on ssm:SendCommand alone."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One compromised instance could enumerate the entire account | Instance role carried `ReadOnlyAccess` — account-wide read of every service — instead of a least-privilege policy |
| Reconnaissance went undetected | The shipped rule watched `ssm:SendCommand` plumbing, not the discovery API burst from the instance role; on-host recon would have been invisible entirely |
| IAM enumeration from an instance role unremarked | No detection for the high-signal "instance role calls `iam:ListUsers`" case |
| Attacker could drive the instance | `ssm:SendCommand` not restricted to automation principals (if SSM-delivered) |
| Instance treated as trustworthy after recon | No process to rebuild an instance that executed attacker commands |

### Recommended Guardrails

**Never attach broad managed policies to instance roles**
- Remove `ReadOnlyAccess` / `AdministratorAccess` / `PowerUserAccess` from all instance roles. Scope each to the specific actions its workload calls (derive from CloudTrail / IAM Access Advisor). This is the single highest-value control — it turns "enumerate everything" into a wall of `AccessDenied`

**Service Control Policy — keep IAM enumeration away from instance roles**

```json
// Deny IAM read/enumeration to instance roles (which never need it)
{
  "Effect": "Deny",
  "Action": [
    "iam:ListUsers", "iam:ListRoles", "iam:GetAccountAuthorizationDetails",
    "iam:ListAccessKeys", "iam:GetLoginProfile"
  ],
  "Resource": "*",
  "Condition": {
    "StringLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/*-instance-role" }
  }
}
```

**Restrict `ssm:SendCommand`** to approved automation principals (see the credential-theft playbook's SCP).

**Detection improvements**
- Deploy the breadth rule (Query 3): distinct `(eventSource, eventName)` per instance-role principal per window — never an `ssm:SendCommand`-only match
- Deploy the narrow high-signal rule: any `iam:List*`/`GetAccountAuthorizationDetails` from an instance role → P0
- Enable and alert GuardDuty `Discovery:*/AnomalousBehavior`
- Alert instance-role credentials used from a non-instance IP (ties to the credential-theft playbook)

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1580 — Cloud Infrastructure Discovery |
| MITRE tactic | Discovery (TA0007) |
| Delivery | `ssm:SendCommand` (`AWS-RunShellScript`) to the instance, or an on-host shell (no SSM footprint) |
| Reconnaissance surface | `sts:GetCallerIdentity`, `ec2:DescribeInstances`, `ec2:DescribeVpcs`, `s3:ListBuckets`, `iam:ListUsers`, `iam:ListRoles` — run as the instance role |
| Key detection insight | Count **breadth** — distinct `(eventSource, eventName)` across ≥2 services from one instance-role principal — not volume of one action. Watch the recon surface, not the SSM plumbing |
| Highest single signal | `iam:List*` / `GetAccountAuthorizationDetails` from an instance role |
| Root-cause control | Instance role carried `ReadOnlyAccess` — the emulation's own infra attaches it |
| Resources created | 1 EC2 instance + IAM role (ReadOnlyAccess + SSM) + instance profile + VPC scaffolding |
| Follow-on to watch for | `sts:AssumeRole` (pivot), off-instance use of the role's creds, writes/`RunInstances` after the read fan-out |

### Revert

`pulumi destroy` in `infra/` removes the EC2 instance, IAM role/instance profile,
and VPC scaffolding. The technique's operations are read-only and create nothing,
so there are no attacker artifacts to clean after an emulation run. After a
**real** incident, `pulumi destroy` is irrelevant — rebuild the compromised
instance and right-size the role per §4; the account map the attacker built
cannot be un-learned, so the lasting remediation is least-privilege plus
tightening whatever the recon exposed.
