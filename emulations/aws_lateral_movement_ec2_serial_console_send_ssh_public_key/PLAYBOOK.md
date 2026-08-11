# IR Playbook - Usage of EC2 Serial Console to Push an SSH Public Key - Out-of-Band Access via `ec2-instance-connect:SendSerialConsoleSSHPublicKey`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Lateral Movement / Out-of-Band Interactive Access (network-control bypass) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, grants interactive serial-console access to the instance while **bypassing all network controls** (security groups, NACLs, closed port 22); gated only by the account-level serial-console setting (`MANIFEST.py` rates MEDIUM; the IR view is High because it yields console access no firewall can stop) |
| MITRE Tactics | Lateral Movement |
| MITRE Techniques | T1021.004 (see mapping note in §6 - T1021.008 is the more precise fit) |
| Services in Scope | EC2 Instance Connect (serial console), EC2 (account serial-console setting), CloudTrail, IAM |
| Infrastructure Created | 1 EC2 instance + IAM role/instance profile + VPC, **no SSH ingress** (serial console does not need it) |

**What the emulation does:** generates a temporary RSA-2048 key pair and calls `ec2-instance-connect:SendSerialConsoleSSHPublicKey` to push the public key to the instance's **serial console**. AWS accepts the key for a 60-second window during which the attacker connects to the serial console (a virtual terminal on the instance) as an OS user, no SSH port, no network path to the instance required. The key then expires. The technique's precondition is that **serial console access is enabled at the account level** (`ec2:EnableSerialConsoleAccess`); it is **disabled by default**, and the call fails with `SerialConsoleAccessDisabled` if it is off.

**Why this is worse than ordinary Instance Connect, it bypasses the network entirely.** The serial console is out-of-band: it connects to an AWS-hosted serial-console endpoint, not the instance's ENI. So **closing port 22, tightening security groups, or NACLs does nothing to stop it**, and, the critical detection consequence, **the serial-console session does NOT appear in VPC Flow Logs** (unlike the network SSH of standard Instance Connect). There is no inbound-22 connection to correlate against. The *only* control-plane evidence is the `SendSerialConsoleSSHPublicKey` CloudTrail event; the on-console activity is visible only if serial-console output is being captured on the host.

**The account-level setting is both the gate and the lead control.** Because the technique requires account serial-console access to be **on**, two facts follow: (a) an attacker who finds it off may call `ec2:EnableSerialConsoleAccess` first, a P0 precursor and an account-wide security downgrade; and (b) the single highest-value guardrail/containment is to **disable serial console access account-wide**, which neutralises the technique everywhere at once.

**Rarity is the detector.** `SendSerialConsoleSSHPublicKey` is essentially never used in normal operations (serial console is a deep break-glass debugging tool). A **single** call by a non-operator principal is a P0, no volume threshold needed.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`. `SendSerialConsoleSSHPublicKey` (`ec2-instance-connect.amazonaws.com`) and `EnableSerialConsoleAccess` / `DisableSerialConsoleAccess` / `GetSerialConsoleAccessStatus` (`ec2.amazonaws.com`) are all management events, `lookup-events` captures them
- **Serial-console output is NOT logged by default and does not traverse VPC Flow Logs.** If serial console is deliberately enabled for ops, capture console output on the host (a getty/console logger) so on-console activity is auditable, otherwise the session content is unrecoverable
- GuardDuty enabled, corroborating anomalous-access findings on the instance/principal

**Alerting (must be pre-configured)**
- **`ec2-instance-connect:SendSerialConsoleSSHPublicKey` from any non-operator principal → P0** (single call; the API is essentially never legitimate)
- **`ec2:EnableSerialConsoleAccess` (account-level enable) from any non-provisioning principal → P0**, an account-wide security downgrade that makes the technique possible
- Fan-out: one principal pushing serial-console keys to ≥ 2 distinct instances → the lateral-movement sweep
- `SendSerialConsoleSSHPublicKey` with `serialPort`/OS user targeting `root`/admin

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- The account serial-console setting per region (should be **disabled** unless there is a documented ops need), and a map of instances → roles
- A rebuild path for any instance that was serial-console-accessed
- Note: placeholders like `TARGET_IDS="<space-separated-...>"` must be replaced with real space-separated values before running, a literal `<...>` string loops once over itself rather than erroring

**Known IOC Baselines**
- Serial console access should be **disabled** account-wide by default; if it is on, know exactly why and which operators use it
- Baseline the (tiny) set of principals with `ec2-instance-connect:SendSerialConsoleSSHPublicKey`, ideally none outside break-glass

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ec2-instance-connect:SendSerialConsoleSSHPublicKey` from a non-operator principal (even a single call) | CloudTrail | T1021.008 (/.004) |
| P0 | `ec2:EnableSerialConsoleAccess` (account-level enable) from a non-provisioning principal | CloudTrail | T1021.008 (/.004) |
| P0 | `SendSerialConsoleSSHPublicKey` to ≥ 2 distinct instances by one principal (sweep) | CloudTrail | T1021.008 (/.004) |
| P1 | `GetSerialConsoleAccessStatus` (checking if it's on) then `EnableSerialConsoleAccess` then `SendSerialConsoleSSHPublicKey`, the full enable-and-use chain | CloudTrail | T1021.008 (/.004) |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `SendSerialConsoleSSHPublicKey` from an off-baseline ASN/geography for the principal | CloudTrail | T1021.004 |
| P2 | `SendSerialConsoleSSHPublicKey` denied (`errorCode = SerialConsoleAccessDisabled` / `AccessDeniedException`), attacker probing (still investigate; they wanted console access) | CloudTrail | T1021.004 |
| P2 | `DescribeInstances` sweep immediately before the serial-console push (target discovery) | CloudTrail | T1021.004 |
| P3 | Single `SendSerialConsoleSSHPublicKey` by an allowlisted break-glass operator during a known incident | CloudTrail | T1021.004 |

### Detection Rule Quality Notes

The shipped rule is close (the API is rare enough that a bare match is a reasonable start), but it under-scopes and misses the account-enable precursor.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName == "SendSerialConsoleSSHPublicKey"` with **no `eventSource`** | Imprecise, scope to `ec2-instance-connect.amazonaws.com`. (The API is rare, so this rule is *usable* as-is, unlike most in this catalogue, but scoping is still correct) | Add `eventSource` |
| No principal allowlist | Cannot distinguish a break-glass operator from an attacker | Compare against the (tiny) operator allowlist; treat non-operator as P0 |
| The `EnableSerialConsoleAccess` precursor is not detected | An attacker who first enables account serial console goes undetected on the account-wide downgrade | Add a P0 rule on `ec2:EnableSerialConsoleAccess` |
| No fan-out logic | Misses the multi-instance sweep | Count distinct `instanceId` per principal (though a single call is already P0 here) |
| Header TODO "verify acronym casing"; `level: medium` | Stale; a network-bypassing console foothold is higher | Resolve TODO; non-operator rule → `level: high`; enable-access rule → `critical` |

**Recommended detections:**

```yaml
# Rule A: serial-console key push by a non-operator (single call = P0)
title: EC2 serial console SSH key push by non-operator
id: 5c2d8a13-7f40-4e91-b3d2-6a0c9b7e4f81
name: serial_console_push_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2-instance-connect.amazonaws.com'
    eventName: 'SendSerialConsoleSSHPublicKey'
  operators:
    userIdentity.arn|contains:
      - ':role/break-glass'
      - ':role/BreakGlassAdmin'
  condition: selection and not operators
level: high
---
# Rule B: account-level serial console ENABLED (the precursor / downgrade)
title: EC2 serial console access enabled at account level
id: 9a4f1c76-2b83-4d05-8e12-7c3a0b6f9d24
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'EnableSerialConsoleAccess'
  condition: selection
level: critical
```

Add a fan-out correlation (`value_count` of distinct `requestParameters.instanceId`
grouped by `userIdentity.arn`, `gte: 2`) as a `critical` sweep signal, mirroring
the Instance Connect playbook.

**On error strings:** `ec2-instance-connect` errors are service-specific,
`AccessDeniedException`, `SerialConsoleAccessDisabled`, `SerialConsoleSessionLimitExceeded`,
`ThrottlingException`. **Not** `Client.`-prefixed. A `SerialConsoleAccessDisabled`
error means the account gate blocked the attempt, still investigate the principal.

---

### Key Investigation Queries

> `SendSerialConsoleSSHPublicKey` is a CloudTrail management event. **Unlike standard Instance Connect, the serial-console session is out-of-band, it is NOT in VPC Flow Logs** (there is no inbound-22 to correlate). The control-plane event is your primary evidence. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

#### Query 1 - Find the serial-console key pushes: who, which instances

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendSerialConsoleSSHPublicKey \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ec2-instance-connect.amazonaws.com") |
    {arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     instance: .requestParameters.instanceId,
     error: (.errorCode // "SUCCESS"),
     ip: .sourceIPAddress, time: .eventTime}' | \
  jq -s 'group_by(.arn) | map({
      principal: .[0].arn,
      access_keys: ([.[].access_key] | unique),                 # feeds ACCESS_KEY_ID in Query 4
      distinct_instances: ([.[] | select(.error=="SUCCESS") | .instance] | unique),
      instance_count: ([.[] | select(.error=="SUCCESS") | .instance] | unique | length),
      source_ips: ([.[].ip] | unique),                          # all attempts, incl. denied
      denied: ([.[] | select(.error!="SUCCESS")] | length)
    }) | sort_by(-.instance_count)'
```

Any non-operator principal here is a P0. A `SerialConsoleAccessDisabled` denial
still means the actor *tried* to get out-of-band console access, investigate them.

#### Query 2: Did someone enable account serial console? (the precursor)

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

# Account-level enable: an account-wide security downgrade
for EV in EnableSerialConsoleAccess GetSerialConsoleAccessStatus; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ec2.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn, ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'

# Current account serial-console state (should be disabled)
aws ec2 get-serial-console-access-status --region "$REGION" \
  --query 'SerialConsoleAccessEnabled' --output text
```

A `GetSerialConsoleAccessStatus` → `EnableSerialConsoleAccess` →
`SendSerialConsoleSSHPublicKey` chain by one principal is the full attack path.

#### Query 3: What did the session do? (on-host + instance-role)

There is **no Flow Log correlation** here (serial console bypasses networking).
Evidence of what happened in the session comes from on-host console logging (if
enabled) and from the instance role's own CloudTrail activity.

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
INSTANCE_ID="<pushed-to-instance>"

# Instance-role activity: session name = instance ID (NOT the role name)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.type == "AssumedRole") |
    {time: .eventTime, event: .eventName, source: .eventSource, ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'

echo "Also review the instance's serial-console / system logs on the host (if console"
echo "output is being captured) for the login and any commands run."
```

#### Query 4: Full session reconstruction of the pushing principal

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

#### Query 5: Multi-region sweep

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  N=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=SendSerialConsoleSSHPublicKey \
    --start-time "$START" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$N" ] && [ "$N" != "0" ] && [ "$N" != "None" ] && \
    echo "[!] $REGION, $N SendSerialConsoleSSHPublicKey events"
  # Also check the account serial-console state per region
  ST=$(aws ec2 get-serial-console-access-status --region "$REGION" \
    --query 'SerialConsoleAccessEnabled' --output text 2>/dev/null)
  [ "$ST" = "True" ] && echo "[!] $REGION, account serial console is ENABLED"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The pushed key has already expired (60s), but a serial-console session established
in the window persists. Contain the principal, **disable account serial console
(kills the technique account-wide)**, and isolate/rebuild the accessed instance.
Note: closing security groups does **not** help, serial console bypasses the
network.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Disable serial console access at the account level (highest-value action)

This neutralises the technique for every instance in the region at once.

```bash
REGION="us-east-1"
aws ec2 disable-serial-console-access --region "$REGION" && \
  echo "[OK] Account serial console DISABLED in $REGION"
aws ec2 get-serial-console-access-status --region "$REGION" \
  --query 'SerialConsoleAccessEnabled' --output text   # expect False

# Repeat for every region where Query 5 showed it enabled
```

#### Step 2: Contain the pushing principal

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

#### Step 3: Deny serial-console and serial-console-enable actions by the principal

```bash
SUSPECT_ROLE="<role-name>"    # role principals; for an IAM user use put-user-policy
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenySerialConsole" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["ec2-instance-connect:SendSerialConsoleSSHPublicKey","ec2:EnableSerialConsoleAccess"],"Resource":"*"}]
  }'
echo "[OK] Serial console actions denied for $SUSPECT_ROLE"
```

#### Step 4: Isolate and snapshot each accessed instance

Isolating into a quarantine SG preserves state for forensics. (Serial console
access itself is unaffected by SGs, but Step 1 already cut off new serial sessions
account-wide; the quarantine also severs any network foothold established during
the console session.)

```bash
REGION="us-east-1"
TARGET_IDS="<space-separated-pushed-to-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
  for VOL in $(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' --output text); do
    aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
      --description "IR-SerialConsole-$IID-$(date -u +%Y%m%dT%H%M%SZ)" --query 'SnapshotId' --output text
  done
  echo "[OK] snapshot(s) started for $IID, apply quarantine SG"
done
```

---

## 4. Eradication

### Remove Attacker Access: Rebuild the Accessed Hosts

#### Rebuild every serial-console-accessed instance

An instance an attacker had an interactive console session on is untrusted, and
the ephemeral key leaves no artifact to verify against. Rebuild from a golden AMI;
snapshots (Step 4) preserve forensics.

```bash
REGION="us-east-1"
TARGET_IDS="<space-separated-pushed-to-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
  aws ec2 terminate-instances --instance-ids "$IID" --region "$REGION" \
    --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'
done
echo "[OK] Accessed instances terminated, relaunch from golden AMI with IMDSv2"
```

#### Check each instance role for credential abuse

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
TARGET_IDS="<space-separated-pushed-to-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
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

Off-instance use of any instance role → pivot to the credential-theft playbook.

#### Right-size serial-console permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove ec2-instance-connect:SendSerialConsoleSSHPublicKey and
# ec2:EnableSerialConsoleAccess from all but a tiny break-glass set. Keep account
# serial console DISABLED (Step 1) as the standing control.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenySerialConsole" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify account serial console is disabled in every region

```bash
FAIL=0
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  ST=$(aws ec2 get-serial-console-access-status --region "$REGION" \
    --query 'SerialConsoleAccessEnabled' --output text 2>/dev/null)
  [ "$ST" = "True" ] && { echo "[FAIL] $REGION serial console still ENABLED"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] Serial console access disabled in all regions"
```

#### Verify no further serial-console pushes since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendSerialConsoleSSHPublicKey \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further serial-console pushes from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further pushes, containment did not hold"
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
TARGET_IDS="<space-separated-pushed-to-instance-ids-from-Query-1>"
FAIL=0
for IID in $TARGET_IDS; do
  STATE=$(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
  [ "$STATE" != "terminated" ] && { echo "[FAIL] $IID is $STATE, expected terminated"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] All accessed instances terminated/rebuilt"
```

#### Confirm the corrected detection fires

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
TEST_PRINCIPAL="<arn-used-for-the-emulation-run>"

# Re-run against a test instance (with account serial console temporarily enabled)
HIT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendSerialConsoleSSHPublicKey \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$TEST_PRINCIPAL" '[.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ec2-instance-connect.amazonaws.com") |
    select(.userIdentity.arn == $arn)] | length')

[ -n "$HIT" ] && [ "$HIT" -gt 0 ] && echo "[OK] SendSerialConsoleSSHPublicKey captured - Rule A has data to fire on" \
                                  || echo "[FAIL] Not captured, check trail / eventSource"
echo "Confirm Rule A fired P0 for the non-operator push, and (if you enabled serial"
echo "console for the test) that Rule B fired critical on EnableSerialConsoleAccess."
echo "Re-disable account serial console after the test."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could push a key to the serial console | `ec2-instance-connect:SendSerialConsoleSSHPublicKey` granted to a non-break-glass principal |
| The technique was possible at all | Account serial console access was **enabled** (it is off by default), either left on, or turned on by the attacker |
| Network controls did not help | Serial console is out-of-band; SGs/NACLs/closed 22 provide no protection against it |
| Session activity unrecoverable | No serial-console output capture on the host, and it is not in Flow Logs |
| Instance trusted after console access | No process to rebuild a host that was interactively accessed |

### Recommended Guardrails

**Keep serial console access DISABLED (the primary control)**
- Serial console is off by default, keep it that way account-wide. With it disabled, `SendSerialConsoleSSHPublicKey` fails with `SerialConsoleAccessDisabled` regardless of IAM. Enable it only transiently for a specific break-glass incident, then disable again

**Restrict the enabling and using actions**

```json
// SCP: only break-glass may enable serial console or push serial-console keys
{
  "Effect": "Deny",
  "Action": ["ec2:EnableSerialConsoleAccess", "ec2-instance-connect:SendSerialConsoleSSHPublicKey"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/break-glass", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Prefer logged, in-band alternatives**
- Use **SSM Session Manager** (logged, no network exposure, no serial console) for routine shell access, so serial console is never needed and any `SendSerialConsoleSSHPublicKey` is unambiguously malicious
- If serial console is genuinely needed for break-glass, capture console output on the host so the session is auditable

**Detection improvements**
- Deploy Rule A (non-operator serial-console push, single call = P0) + Rule B (account `EnableSerialConsoleAccess` = critical) + the fan-out correlation, never the shipped unscoped match
- Alert the `GetSerialConsoleAccessStatus`→`EnableSerialConsoleAccess`→`SendSerialConsoleSSHPublicKey` chain

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1021.004 (as mapped by Stratus), see caveat below |
| MITRE tactic | Lateral Movement (TA0008) |
| Primary API | `ec2-instance-connect:SendSerialConsoleSSHPublicKey`; precursor `ec2:EnableSerialConsoleAccess` |
| Event source | `ec2-instance-connect.amazonaws.com` (push) and `ec2.amazonaws.com` (account enable/status) |
| Key property | **Bypasses all network controls** (SG/NACL/closed 22), out-of-band; **not in VPC Flow Logs**. Gated only by the account-level serial-console setting (off by default) |
| Precondition | Account serial console access **enabled**, the lead guardrail is to keep it disabled |
| Detector | The API is essentially never legitimate, a single non-operator call is P0; no volume threshold needed |
| Not in CloudTrail / Flow Logs | The serial-console session content, only on-host console output (if captured) |
| Error strings (service-specific) | `SerialConsoleAccessDisabled`, `AccessDeniedException`, `SerialConsoleSessionLimitExceeded`, `ThrottlingException` |
| Resources created | 1 EC2 instance + IAM role/instance profile + VPC (no SSH ingress) |
| Sibling technique | Standard EC2 Instance Connect (the network-SSH variant), same `ec2-instance-connect` service, but that one traverses port 22 and *is* visible in Flow Logs |

**MITRE mapping note:** as with standard EC2 Instance Connect, the MANIFEST maps
this to **T1021.004 (Remote Services: SSH)**, partly apt (it is an SSH session
over the serial console) but the purpose-built sub-technique is **T1021.008
(Remote Services: Direct Cloud VM Connections)**, which explicitly covers EC2
serial console alongside Instance Connect and Session Manager. Inherited from
Stratus; T1021.008 is the more precise mapping. Recorded for the end-of-run
MITRE-mapping finding.

### Revert

`pulumi destroy` in `infra/` removes the EC2 instance, IAM role/instance profile,
and VPC. The pushed key auto-expires after 60s, leaving no instance-side artifact.
**Note:** if the emulation (or an operator) enabled account serial console access
to run this, `pulumi destroy` does **not** turn it back off, explicitly run
`aws ec2 disable-serial-console-access` afterward. After a **real** incident,
`pulumi destroy` is irrelevant, disable account serial console (§3), rebuild any
accessed instance (§4), and scope down the serial-console actions.
