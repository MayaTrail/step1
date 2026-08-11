# IR Playbook - Open SSM Sessions to Multiple EC2 Instances - Interactive Fleet Access via `ssm:StartSession`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution / Remote Interactive Access (SSH-less shell to instances) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, an interactive shell on multiple instances with no SSH key, no open port 22, and (absent session logging) no record of what was typed (`MANIFEST.py` rates MEDIUM; the IR view is High because of unlogged interactive access across the fleet) |
| MITRE Tactics | Execution |
| MITRE Techniques | T1021.004 (as mapped by Stratus, imprecise; T1021.008 Direct Cloud VM Connections is the real fit, see §6) |
| Services in Scope | SSM (Session Manager), EC2, CloudTrail, IAM, VPC Flow Logs |
| Infrastructure Created | 3 EC2 instances (SSM-managed) + IAM role (SSM core) + instance profile + VPC (via `infra/`) |

**What the emulation does:** opens an interactive SSM session (`ssm:StartSession`) to each of its three instances in rapid succession, then immediately terminates each (`ssm:TerminateSession`). SSM Session Manager gives a shell on the instance **without SSH, without a key pair, and without any inbound port open**, the connection tunnels over the SSM agent's outbound channel. To network defenses it is invisible; the only control-plane evidence is the `StartSession`/`TerminateSession` CloudTrail events.

**The evidence gap that defines this technique.** `StartSession` opens an *interactive* channel. Unlike `SendCommand`, where the command is a parameter of the API call, **nothing typed inside an SSM session appears in CloudTrail.** The keystrokes and output exist only if **Session Manager logging** (to S3 and/or CloudWatch Logs) is enabled. So CloudTrail answers *"who opened a session to which instance, and when"* but never *"what did they do."* If session logging was off, you cannot reconstruct the activity and must treat every session-accessed instance as fully compromised.

**Why the fan-out matters.** One engineer troubleshooting one box is routine. A single principal opening sessions to **many instances in rapid succession**, especially immediately terminating each, is an access sweep, the interactive analogue of the mass `SendCommand` in the sibling playbook.

**Session as root.** The session runs as `ssm-user`, which is granted passwordless `sudo` on Amazon Linux by default, so interactive access is effectively root on the host.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to a log platform. `StartSession`/`TerminateSession` are management events, so `lookup-events` captures the session *open/close* (never the content)
- **Enable Session Manager logging to S3 and/or CloudWatch Logs, account-wide, ideally with KMS encryption and log-immutability.** This is the single most important control, without it, an SSM session is an unlogged interactive root shell. Enable "Enforce encryption" and prevent users from disabling logging in the Session Manager preferences document
- GuardDuty + VPC Flow Logs, to catch anything the interactive session then did (C2, lateral connections)
- An inventory of which principals legitimately use Session Manager and to which instances, so a sweep is obvious

**Alerting (must be pre-configured)**
- `ssm:StartSession` from a principal not on the Session-Manager operator allowlist → alert. This is the primary control
- **Fan-out alert: one principal opening `StartSession` to ≥ N instances (start at N=3; tune to real operator behaviour) within a short window → page.** The access sweep
- `ssm:StartSession` using the `AWS-StartPortForwardingSession` / `AWS-StartPortForwardingSessionToRemoteHost` document → high severity (tunnelling/pivot, not just a shell)
- Any change to the Session Manager logging preferences that disables or unencrypts logging (`ssm:UpdateDocument`/`CreateDocument` on `SSM-SessionManagerRunShell`) → P0 (an attacker blinding the logs)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- Access to the Session Manager log destination (S3/CloudWatch), the only place session activity lives
- A rebuild path for any instance accessed via an unlogged session

**Known IOC Baselines**
- Baseline which principals open sessions, to which instances, and typical concurrency, a sweep deviates on all three
- Confirm Session Manager logging is currently ON and encrypted; a logging gap is itself a finding

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | One principal opening `ssm:StartSession` to ≥ 3 instances in a short window from a non-operator principal | CloudTrail | T1021.004 |
| P0 | `ssm:StartSession` with a `AWS-StartPortForwardingSession*` document (tunnelling/pivot) | CloudTrail | T1021.004 |
| P0 | Session Manager logging disabled/unencrypted (`UpdateDocument` on `SSM-SessionManagerRunShell`) then sessions opened | CloudTrail | T1021.004 |
| P1 | `ssm:StartSession` from a principal not on the operator allowlist | CloudTrail | T1021.004 |
| P1 | `StartSession`/`TerminateSession` from an off-baseline ASN/geography for the principal | CloudTrail | T1021.004 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Rapid `StartSession`+`TerminateSession` pairs across instances (the emulation's shape) | CloudTrail | T1021.004 |
| P2 | `ssm:DescribeInstanceInformation` sweep immediately before `StartSession` (finding targets) | CloudTrail | T1021.004 |
| P2 | `ssm:StartSession` denied at volume (`errorCode = AccessDeniedException` / `TargetNotConnected`), probing reachable instances | CloudTrail | T1021.004 |
| P3 | A single `StartSession` to one instance by an allowlisted operator | CloudTrail | T1021.004 |

### Detection Rule Quality Notes

The rules in `detections/` are unusable (identical broken pattern to the other SSM techniques). These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (DescribeInstanceInformation, StartSession, TerminateSession)` with `condition: selection` | Noisy and blind. `StartSession` is a normal operator action; `TerminateSession`/`DescribeInstanceInformation` are pure noise. Matching them independently fires on every legitimate session | Alert `StartSession` filtered by principal; add the fan-out and port-forwarding signals |
| No principal allowlist, no fan-out counting | Cannot separate one operator on one box from a sweep across the fleet | Filter to non-operator principals; count distinct target instances per principal per window |
| No awareness that session *content* is not in CloudTrail | A responder may believe CloudTrail shows what was done in the session, it never does | Document the Session Manager logging dependency; alert if logging is disabled |
| `AWS-StartPortForwardingSession` not distinguished | A tunnelling session (pivot) is treated the same as a shell | Add a document-name signal for port-forwarding |
| Header TODO "verify acronym casing"; `level: medium` | Stale marker; and multi-instance interactive access deserves higher severity | Resolve TODO; fan-out / port-forwarding rules → `level: high`/`critical` |

**Recommended detection - StartSession by non-operator + fan-out.**

```yaml
title: SSM StartSession by non-operator principal
id: 9c4f2a71-5e83-4b60-a1d2-7f0c6b9e3a48
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'StartSession'
  operators:
    userIdentity.arn|contains:
      - ':role/ssm-operator'
      - ':role/BreakGlassAdmin'
  condition: selection and not operators
level: high
```

Port-forwarding companion (tunnelling, higher severity):

```yaml
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'StartSession'
    requestParameters.documentName|startswith: 'AWS-StartPortForwardingSession'
  condition: selection
level: critical
```

The **fan-out** (distinct target instances per principal) is an aggregation,
express it as the log-platform query in Query 3, or a Sigma `value_count`
correlation counting distinct `requestParameters.target`.

**On error strings:** SSM denials surface as `AccessDeniedException`; an
unreachable target as `TargetNotConnected`. SSM service errors, **not**
`Client.`-prefixed like EC2. Match the SSM forms and confirm against a sample.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, robust, unlike `--output text | jq`.

#### Query 1: Who opened sessions, to how many instances, with what document?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StartSession \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 5
     target: .requestParameters.target,
     # absent documentName => the default interactive shell; this is an INFERRED
     # default, not an observed field value
     document: (.requestParameters.documentName // "SSM-SessionManagerRunShell"),
     session: .responseElements.sessionId,
     error: (.errorCode // "SUCCESS"),
     ip: .sourceIPAddress}' | \
  jq -s 'group_by(.arn) | map({
      principal: .[0].arn,
      distinct_targets: ([.[] | select(.error=="SUCCESS") | .target] | unique | length),
      targets: ([.[] | select(.error=="SUCCESS") | .target] | unique),
      port_forwarding: ([.[] | select(.document | test("PortForwarding"))] | length > 0),
      denied: ([.[] | select(.error!="SUCCESS")] | length),
      source_ips: ([.[].ip] | unique)
    }) | sort_by(-.distinct_targets)'
```

A principal with `distinct_targets ≥ 3` who is not an allowlisted operator is the
sweep. `port_forwarding: true` escalates it, that is a pivot tunnel, not just a
shell.

#### Query 2: Reconstruct what happened inside the sessions (the hard part)

CloudTrail does **not** contain session activity. Determine whether Session
Manager logging was on, then read it.

```bash
REGION="us-east-1"

# Session metadata (who/when/target/duration): history, not content
aws ssm describe-sessions --state History --region "$REGION" \
  --query 'Sessions[].{Session:SessionId,Owner:Owner,Target:Target,
           Start:StartDate,End:EndDate,Doc:DocumentName}' --output table

# Is Session Manager logging configured? (S3/CloudWatch destinations)
aws ssm get-document --name "SSM-SessionManagerRunShell" --region "$REGION" \
  --query 'Content' --output text 2>/dev/null | \
  jq '{s3Bucket: .inputs.s3BucketName, cwLogGroup: .inputs.cloudWatchLogGroupName,
       cwEncryption: .inputs.cloudWatchEncryptionEnabled, kmsKeyId: .inputs.kmsKeyId}'
```

- If an S3 bucket / CloudWatch log group is configured: retrieve those logs (keyed
  by `SessionId` from Query 1 / `describe-sessions`), they contain the full
  keystroke transcript. **That is the authoritative record of what the attacker
  did.**
- If logging is **not** configured (empty destinations): the interactive activity
  is unrecoverable. Treat every session-accessed instance as fully compromised and
  proceed to rebuild; there is no way to scope the damage more narrowly.

#### Query 3: Deployable fan-out detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights. Counts distinct session targets per principal per short window; flags port-forwarding.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "ssm.amazonaws.com"
| where EventName == "StartSession"
| where isempty(ErrorCode)
| extend Req = parse_json(RequestParameters)
| extend Target = tostring(Req.target)
| extend Doc = tostring(Req.documentName)
| summarize
    DistinctTargets = dcount(Target),
    TargetSet       = make_set(Target, 20),
    PortForwarding  = countif(Doc startswith "AWS-StartPortForwardingSession"),
    SourceIPs       = make_set(SourceIpAddress, 10),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated)
    by UserIdentityArn, bin(TimeGenerated, 15m)
| where DistinctTargets >= 3 or PortForwarding > 0
       or UserIdentityArn !has "role/ssm-operator"      // tune to your allowlist
| extend Verdict = case(
    PortForwarding > 0,     "SSM PORT-FORWARDING / PIVOT - P0",
    DistinctTargets >= 3,   "SSM INTERACTIVE ACCESS SWEEP - P0",
    "SSM SESSION BY NON-OPERATOR, review")
| order by DistinctTargets desc
```

CloudWatch Logs Insights equivalent:

```
fields @timestamp, userIdentity.arn, requestParameters.target, requestParameters.documentName
| filter eventSource = "ssm.amazonaws.com" and eventName = "StartSession"
| filter not ispresent(errorCode)
| stats count_distinct(requestParameters.target) as distinct_targets by userIdentity.arn, bin(15m)
| filter distinct_targets >= 3
```

#### Query 4: Did an accessed instance call out? (post-session C2)

```bash
LOG_GROUP="/vpc/flowlogs"
ENI_ID="<eni-of-an-accessed-instance>"
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '2 hours ago' +%s 2>/dev/null \
        || date -u -v-2H +%s)

aws logs filter-log-events --log-group-name "$LOG_GROUP" \
  --start-time "${START}000" --filter-pattern "\"$ENI_ID\"" \
  --query 'events[*].message' --output text 2>/dev/null | \
  awk '$13=="ACCEPT" && $NF=="OK"' | head -50   # v2 flow log: $13=action, $NF=log-status
```

#### Query 5: Full session reconstruction of the principal

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
    --lookup-attributes AttributeKey=EventName,AttributeValue=StartSession \
    --start-time "$START" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$N" ] && [ "$N" != "0" ] && [ "$N" != "None" ] && \
    echo "[!] $REGION, $N StartSession events"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Interactive root-equivalent access happened on multiple instances. Contain the
principal, kill any live sessions, deny further sessions, and isolate the accessed
hosts.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Terminate any active sessions and contain the principal

```bash
REGION="us-east-1"

# Kill any still-active sessions (the emulation self-terminates, but a real
# attacker's session may be live)
for SID in $(aws ssm describe-sessions --state Active --region "$REGION" \
    --query 'Sessions[].SessionId' --output text); do
  aws ssm terminate-session --session-id "$SID" --region "$REGION" && \
    echo "[OK] Terminated active session $SID"
done

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

#### Step 2: Deny StartSession by the principal

Role principals only, an IAM-user principal was already fully contained by key
deactivation in Step 1, so this step does not apply to it.

```bash
SUSPECT_ROLE="<role-name>"
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenySSMSession" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["ssm:StartSession","ssm:ResumeSession","ssm:SendCommand"],"Resource":"*"}]
  }'
echo "[OK] StartSession denied for $SUSPECT_ROLE"
```

#### Step 3: Isolate and snapshot each accessed instance

For every instance in Query 1's `targets`: network-isolate (sever any lingering
tunnel/C2) and snapshot for forensics. Because session content may be unlogged,
treat each as compromised. (Use the per-ENI quarantine-SG helper from the
credential-theft playbook.)

```bash
REGION="us-east-1"
TARGET_IDS="<space-separated-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
  for VOL in $(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' --output text); do
    aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
      --description "IR-T1021.004-$IID-$(date -u +%Y%m%dT%H%M%SZ)" --query 'SnapshotId' --output text
  done
  echo "[OK] snapshot(s) started for $IID, apply quarantine SG next"
done
```

#### Step 4: Confirm/repair Session Manager logging

If logging was disabled (Query 2), an attacker may have disabled it deliberately.
Restore it so any continued or future session is recorded.

```bash
REGION="us-east-1"
# Re-point Session Manager logging to your S3/CloudWatch destination with encryption.
# (Update the SSM-SessionManagerRunShell document / preferences to your standard.)
echo "Restore Session Manager logging (S3 + CloudWatch, KMS-encrypted) and lock the"
echo "preferences document so non-admins cannot disable it."
```

---

## 4. Eradication

### Remove Attacker Access: Rebuild the Session-Accessed Hosts

#### Rebuild every accessed instance

An instance an attacker had an interactive (root-capable) session on is
untrusted, doubly so if the session was unlogged. Snapshots (Step 3) preserve
forensics; rebuild from a golden AMI.

```bash
REGION="us-east-1"
TARGET_IDS="<space-separated-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
  aws ec2 terminate-instances --instance-ids "$IID" --region "$REGION" \
    --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'
done
echo "[OK] Accessed instances terminated, relaunch from golden AMI, least-priv roles + IMDSv2"
```

#### If logging existed, scope the damage from the transcripts

```bash
# For each SessionId (Query 1 / describe-sessions), pull the S3/CloudWatch
# transcript and review the commands run. Extract IOCs (downloaded URLs, created
# users, credential access) and hunt for them fleet-wide. If logging did NOT
# exist, skip: there is nothing to scope, and full rebuild already applies.
echo "Review Session Manager transcripts per SessionId; extract and block IOCs."
```

#### Check each accessed instance's role for credential abuse

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
TARGET_IDS="<space-separated-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
  echo "=== Role activity for session $IID (session name = instance ID) ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue="$IID" \
    --start-time "$START" \
    --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.userIdentity.type == "AssumedRole") |
      {time: .eventTime, event: .eventName, ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
done
```

Off-instance use of any instance role → pivot to the credential-theft playbook.

#### Right-size StartSession permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove ssm:StartSession from principals that are not designated operators;
# where needed, scope by target tags and forbid the port-forwarding documents.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenySSMSession" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify no further sessions since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StartSession \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further StartSession from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further sessions, containment did not hold"
```

#### Verify Session Manager logging is on and encrypted

```bash
REGION="us-east-1"
CFG=$(aws ssm get-document --name "SSM-SessionManagerRunShell" --region "$REGION" \
  --query 'Content' --output text 2>/dev/null | \
  jq '{s3: .inputs.s3BucketName, cw: .inputs.cloudWatchLogGroupName, kms: .inputs.kmsKeyId}')
echo "$CFG"
echo "$CFG" | jq -e '(.s3 != "" or .cw != "") and .kms != ""' >/dev/null \
  && echo "[OK] Session Manager logging is configured and KMS-encrypted" \
  || echo "[FAIL] Session Manager logging missing or unencrypted, sessions are not auditable"
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

#### Verify accessed instances were rebuilt

```bash
REGION="us-east-1"
FAIL=0
TARGET_IDS="<space-separated-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
  STATE=$(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
  [ "$STATE" != "terminated" ] && { echo "[FAIL] $IID is $STATE, expected terminated"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] All session-accessed instances terminated/rebuilt"
```

#### Confirm the corrected detection fires

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
TEST_PRINCIPAL="<arn-used-for-the-emulation-run>"

TARGETS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StartSession \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$TEST_PRINCIPAL" '[.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .requestParameters.target] | unique | length')

echo "Distinct session targets by the test principal: $TARGETS"
[ "$TARGETS" -ge 3 ] && echo "[OK] Fan-out present (>=3 targets), classifies as INTERACTIVE ACCESS SWEEP" \
                     || echo "[FAIL] Expected >=3 distinct targets; saw $TARGETS"
echo "Confirm the rule produced ONE sweep alert, not one per session, and did NOT"
echo "fire on TerminateSession/DescribeInstanceInformation."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal opened interactive sessions to many instances | `ssm:StartSession` granted broadly, not restricted to designated operators or scoped by target tags |
| What happened in the sessions is unknown | Session Manager logging was off (or unencrypted / disable-able), interactive activity was never recorded |
| Access sweep undetected | Shipped rule matched all SSM session events with no principal/fan-out discriminator |
| Root-equivalent on the host | `ssm-user` has passwordless sudo by default; interactive access = root |
| No tunnelling control | `AWS-StartPortForwardingSession` was available, allowing pivots through the session |

### Recommended Guardrails

**Mandatory, tamper-resistant session logging**
- Enable Session Manager logging to S3 **and** CloudWatch, KMS-encrypted, with "Enforce encryption" on. Lock the `SSM-SessionManagerRunShell` preferences document so non-admins cannot disable it. Without this, SSM sessions are unlogged root shells

**Restrict who can open sessions, and to what**

```json
// SCP: only designated operators may StartSession
{
  "Effect": "Deny",
  "Action": "ssm:StartSession",
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/ssm-operator", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

```json
// Block the port-forwarding documents outright unless a role genuinely needs them
{
  "Effect": "Deny",
  "Action": "ssm:StartSession",
  "Resource": "arn:aws:ssm:*::document/AWS-StartPortForwardingSession*"
}
```

- Scope operator `StartSession` to instances by tag (`ssm:resourceTag/...`) so an operator can only reach their own fleet
- Enforce IMDSv2 and least-privilege instance roles so a session shell cannot pivot via harvested role credentials

**Detection improvements**
- Deploy the non-operator rule, the fan-out rule (Query 3), and the port-forwarding rule, never the shipped all-session match
- Alert any change that disables/unencrypts Session Manager logging at P0
- Alert `DescribeInstanceInformation`→`StartSession` sequences

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1021.004 (as mapped by Stratus), see caveat below |
| MITRE tactic | Execution (TA0002), also Lateral Movement in character |
| Primary API | `ssm:StartSession` (+ `TerminateSession`); `AWS-StartPortForwardingSession*` for tunnelling |
| Event source | `ssm.amazonaws.com` |
| Key discriminators | Non-operator principal; fan-out (≥3 distinct targets/window); port-forwarding document |
| Evidence of activity | **Session Manager logging only** (S3/CloudWatch), session content is NEVER in CloudTrail; no logging = unrecoverable = assume full compromise |
| Execution context | `ssm-user` with passwordless sudo → effectively root |
| Error strings (SSM, not `Client.`-prefixed) | `AccessDeniedException`, `TargetNotConnected` |
| Resources created | 3 SSM-managed EC2 instances + IAM role + instance profile + VPC scaffolding |
| Follow-on to watch for | On-host persistence, IMDS credential theft + off-instance role use, port-forward pivots, C2 |

**MITRE mapping caveat:** the MANIFEST maps this to **T1021.004**, whose canonical
MITRE name is *Remote Services: SSH*, but SSM Session Manager explicitly does
**not** use SSH (no key pair, no port 22; it tunnels over the SSM agent). The
purpose-built sub-technique is **T1021.008 - Remote Services: Direct Cloud VM
Connections**, which covers Session Manager, EC2 Instance Connect, and serial
console. The mapping is inherited from Stratus Red Team; treat the behaviour
(SSH-less interactive access to cloud VMs) as authoritative and the sub-technique
ID as approximate. Recorded for the end-of-run MITRE-mapping finding.

### Revert

`pulumi destroy` in `infra/` removes the 3 EC2 instances, IAM role/instance
profile, and VPC. The emulation opens and immediately terminates each session, so
a normal run leaves no active sessions. After a **real** incident, `pulumi
destroy` is irrelevant, each session-accessed instance must be rebuilt (§4),
`StartSession` scoped down, Session Manager logging restored, and (if logging
existed) the transcripts reviewed for what to hunt and rotate. Tearing down the
stack does not undo what an interactive root session may have done.
