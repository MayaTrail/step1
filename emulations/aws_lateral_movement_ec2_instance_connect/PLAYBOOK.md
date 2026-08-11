# IR Playbook - Usage of EC2 Instance Connect - SSH Access via `ec2-instance-connect:SendSSHPublicKey`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Lateral Movement / Remote Interactive Access (ephemeral SSH key push) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, grants an interactive SSH session on the instance as an OS user (typically sudo-capable); at fan-out across many instances it is a lateral-movement sweep (`MANIFEST.py` rates MEDIUM; the IR view is High because it yields a real shell) |
| MITRE Tactics | Lateral Movement |
| MITRE Techniques | T1021.004 (see mapping note in §6 - T1021.008 is the more precise fit) |
| Services in Scope | EC2 Instance Connect, EC2, CloudTrail, VPC Flow Logs, IAM |
| Infrastructure Created | 1 EC2 instance + SG (SSH open) + IAM role/instance profile + VPC (via `infra/`) |

**What the emulation does:** generates a temporary RSA-2048 key pair and calls `ec2-instance-connect:SendSSHPublicKey` to push the public key to the target instance for a specific OS user. AWS installs the key on the instance for **60 seconds**, during which the attacker can SSH in as that user; the key is then automatically removed. No key is persisted on the instance, the only durable evidence is the `SendSSHPublicKey` CloudTrail event and whatever the SSH session did on the host.

**Why this is stealthy, and what that means for the response.** The key is ephemeral, so **there is nothing to find on the instance afterward** (no rogue entry in `authorized_keys`). You cannot detect this by auditing keys on the box. Detection must key on the control-plane event (`SendSSHPublicKey`) and correlate it with the **inbound SSH connection**, the actual login and everything done in the session are **not in CloudTrail**; they live in VPC Flow Logs (inbound port 22 ACCEPT within ~60s of the push) and the instance's own SSH auth logs.

**Why the "multiple instances" framing matters.** The technique's name is about pushing keys to *many* instances, a lateral-movement fan-out. This emulation pushes to one, so the primary detection must fire on a **single** non-operator `SendSSHPublicKey` (don't set a fan-out threshold so high it misses the one-instance case); the fan-out (many distinct instances by one principal) is a *second*, higher-severity signal layered on top.

**Two delivery variants.** Classic EC2 Instance Connect requires the instance reachable on port 22 (public IP + open SG, which this emulation's infra provides). The newer **EC2 Instance Connect Endpoint (EIC Endpoint)** tunnels SSH privately with **no public IP and no open SG**, and is stealthier; it adds its own CloudTrail events (`ec2-instance-connect:OpenTunnel`). Cover both.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`. `ec2-instance-connect:SendSSHPublicKey` (and EIC-Endpoint `OpenTunnel`) are management events, `lookup-events` captures them, with `userIdentity.arn`, `requestParameters.instanceId`, `requestParameters.instanceOSUser`, and source IP
- **VPC Flow Logs on all VPCs**, the only way to see the SSH connection that follows the key push (the SSH login itself is not in CloudTrail). Deliver to CloudWatch Logs/S3 for correlation
- Centralised **on-host SSH auth logs** (`/var/log/auth.log` / `secure`) so the interactive session is auditable, the key is ephemeral but the login and its commands are logged on the host
- GuardDuty enabled, corroborating anomalous-access findings

**Alerting (must be pre-configured)**
- **`ec2-instance-connect:SendSSHPublicKey` from a principal not on the operator/break-glass allowlist → alert** (the API is rare; a non-operator use is high-signal even for a single instance)
- **Fan-out: one principal pushing keys to ≥ 2 distinct instances in a short window → page** (the lateral-movement sweep)
- `SendSSHPublicKey` with `instanceOSUser` = `root` or an admin user → higher severity
- `ec2-instance-connect:OpenTunnel` (EIC Endpoint) from a non-operator principal
- Correlation: `SendSSHPublicKey` followed within ~60s by an inbound port-22 ACCEPT (Flow Logs) from the caller's IP → confirmed SSH access

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- A map of instances → their SG ingress and whether they are reachable on 22 (and via which EIC Endpoints), plus each instance's role
- A rebuild path for any instance that was SSH'd into

**Known IOC Baselines**
- Baseline which principals use Instance Connect and to which instances, normally a short operator/break-glass set
- Baseline expected source IPs for those operators; an off-baseline IP pushing a key is the signal
- Prefer SSM Session Manager over SSH/Instance Connect so a `SendSSHPublicKey` is unambiguously an incident

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ec2-instance-connect:SendSSHPublicKey` to ≥ 2 distinct instances by one principal in a short window (lateral-movement sweep) | CloudTrail | T1021.008 (/.004) |
| P0 | `SendSSHPublicKey` followed within ~60s by an inbound port-22 ACCEPT from the caller's source IP | CloudTrail + VPC Flow Logs | T1021.008 (/.004) |
| P1 | `SendSSHPublicKey` from a principal not on the operator/break-glass allowlist (even a single instance) | CloudTrail | T1021.004 |
| P1 | `SendSSHPublicKey` with `instanceOSUser = root`/admin | CloudTrail | T1021.004 |
| P1 | `ec2-instance-connect:OpenTunnel` (EIC Endpoint) from a non-operator principal | CloudTrail | T1021.004 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DescribeInstances` sweep immediately before `SendSSHPublicKey` (target discovery) | CloudTrail | T1021.004 |
| P2 | `SendSSHPublicKey` from an off-baseline ASN/geography for the principal | CloudTrail | T1021.004 |
| P2 | `SendSSHPublicKey` denied at volume (`errorCode = AccessDeniedException` / `EC2InstanceNotFoundException`), target probing | CloudTrail | T1021.004 |
| P3 | Single `SendSSHPublicKey` by an allowlisted operator to an expected instance | CloudTrail | T1021.004 |

### Detection Rule Quality Notes

The shipped rules under-scope and miss the technique's signals. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName == "SendSSHPublicKey"` with `condition: selection` and **no `eventSource`** | Imprecise, matches a bare event name across all sources. `SendSSHPublicKey` is an `ec2-instance-connect.amazonaws.com` event; scope to it | Add `eventSource: ec2-instance-connect.amazonaws.com` |
| No principal allowlist | Cannot separate an operator's legitimate break-glass use from an attacker; the whole signal is "who pushed a key" | Compare against the operator/break-glass allowlist |
| No fan-out / multi-instance logic despite the technique's name | Misses the lateral-movement sweep (many instances) that defines the technique | Count distinct `instanceId` per principal per window |
| No use of `instanceOSUser` or `OpenTunnel` | Misses the root-user escalation and the EIC-Endpoint variant | Add `instanceOSUser` severity weighting and an `OpenTunnel` rule |
| No correlation to the actual SSH | The push is permission; the SSH is the access. Alone, `SendSSHPublicKey` doesn't prove a login happened | Correlate with Flow Logs inbound 22 within ~60s |
| Header TODO "verify acronym casing"; `level: medium` | Stale marker; a real SSH foothold is higher | Resolve TODO; non-operator rule → `level: high`; fan-out → `critical` |

**Recommended detection, non-operator SendSSHPublicKey (fires on the single-instance case), plus a fan-out correlation.**

```yaml
# Rule A: SendSSHPublicKey by a non-operator (fires even for ONE instance)
title: EC2 Instance Connect key push by non-operator principal
id: 4b7d2e91-6a03-45c8-9f12-8e0a3c7b6d54
name: eic_sendsshkey_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2-instance-connect.amazonaws.com'
    eventName: 'SendSSHPublicKey'
  operators:
    userIdentity.arn|contains:
      - ':role/ssm-operator'
      - ':role/break-glass'
      - ':role/BreakGlassAdmin'
  condition: selection and not operators
level: high
---
# Rule B - fan-out: key pushed to many instances by one principal (the sweep)
title: EC2 Instance Connect fan-out across instances
id: 6c1a8f42-3b70-4e95-a2d1-9f0c7b6e5a83
status: experimental
correlation:
  type: value_count
  rules:
    - eic_sendsshkey_base
  group-by:
    - userIdentity.arn
  timespan: 15m
  condition:
    gte: 2
    field: requestParameters.instanceId    # distinct target instances
level: critical
```

Add a companion rule on `eventName: OpenTunnel` (same `eventSource`) for the EIC
Endpoint variant, and, where the log platform can join CloudTrail with Flow Logs
- the `SendSSHPublicKey` → inbound-22 correlation as the highest-confidence
signal.

**On error strings:** `ec2-instance-connect` errors are service-specific,
`AccessDeniedException`, `EC2InstanceNotFoundException`,
`EC2InstanceStateInvalidException`, `ThrottlingException`. They are **not**
`Client.`-prefixed like core EC2. Match the service forms and confirm against a
sample event.

---

### Key Investigation Queries

> `SendSSHPublicKey` is a CloudTrail management event. The SSH session it enables is **not** in CloudTrail, correlate with VPC Flow Logs (Query 3) and on-host auth logs. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

#### Query 1 - Find the key pushes: who, which instances, which OS user

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendSSHPublicKey \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ec2-instance-connect.amazonaws.com") |
    {arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 5
     instance: .requestParameters.instanceId,
     osuser: .requestParameters.instanceOSUser,
     error: (.errorCode // "SUCCESS"),
     ip: .sourceIPAddress, time: .eventTime}' | \
  jq -s 'group_by(.arn) | map({
      principal: .[0].arn,
      access_keys: ([.[].access_key] | unique),                 # feeds ACCESS_KEY_ID in Query 5
      distinct_instances: ([.[] | select(.error=="SUCCESS") | .instance] | unique),
      instance_count: ([.[] | select(.error=="SUCCESS") | .instance] | unique | length),
      os_users_reached: ([.[] | select(.error=="SUCCESS") | .osuser] | unique),   # SUCCESS only
      source_ips: ([.[].ip] | unique),                          # all attempts, incl. denied
      denied: ([.[] | select(.error!="SUCCESS")] | length)
    }) | sort_by(-.instance_count)'
```

A non-operator principal here is the suspect. `instance_count ≥ 2` is a
lateral-movement sweep; `os_users_reached` including `root`/admin escalates it.
(`os_users_reached` counts only successful pushes; `source_ips` includes denied
attempts so the attacker's IP is still surfaced even if the push failed.)

#### Query 2: EIC Endpoint tunnels (the private/stealthy variant)

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=OpenTunnel \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ec2-instance-connect.amazonaws.com") |
    {time: .eventTime, caller: .userIdentity.arn,
     endpoint: .requestParameters.instanceConnectEndpointId,
     instance: .requestParameters.instanceId, ip: .sourceIPAddress}'
```

#### Query 3: Confirm the SSH actually happened (Flow Logs correlation)

The push grants a 60s window; confirm an inbound SSH connection followed.

```bash
# For each pushed-to instance, look for inbound port-22 ACCEPT around the push time
LOG_GROUP="/vpc/flowlogs"
ENI_ID="<eni-of-the-pushed-to-instance>"

# The SendSSHPublicKey eventTime from Query 1, in CloudTrail's own format.
PUSH_TIME="2026-01-01T00:00:00Z"          # REPLACE with the real eventTime
# GNU date first, BSD/macOS date second. BSD parses an absolute timestamp with
# -j -f rather than -d, so it needs the input format spelled out.
PUSH_EPOCH=$(date -u -d "$PUSH_TIME" +%s 2>/dev/null \
        || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$PUSH_TIME" +%s)

aws logs filter-log-events --log-group-name "$LOG_GROUP" \
  --start-time "$(( (PUSH_EPOCH - 30) * 1000 ))" \
  --end-time "$(( (PUSH_EPOCH + 180) * 1000 ))" \
  --filter-pattern "\"$ENI_ID\"" \
  --query 'events[*].message' --output text 2>/dev/null | \
  awk '$7=="22" && $13=="ACCEPT" && $NF=="OK" {print $4" -> "$5":"$7}' | sort | uniq -c
  # Default v2 flow log fields: $4=srcaddr $5=dstaddr $7=dstport $13=action $NF=log-status.
  # If your flow logs use a CUSTOM format, these indices shift: adjust to your fields.
```

An inbound 22 ACCEPT from the `SendSSHPublicKey` caller's IP within the window
confirms an interactive session opened, treat the instance as accessed.

#### Query 4: What did the session do? (on-host + instance-role)

The SSH activity is on the host; also check whether the session used the
instance's IMDS role credentials off-box.

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

echo "Also review the instance's SSH auth logs (/var/log/auth.log or secure) for the"
echo "login as $(printf '%s' "<osuser-from-Query-1>") and any sudo/command activity."
```

#### Query 5: Full session reconstruction of the pushing principal

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
    --lookup-attributes AttributeKey=EventName,AttributeValue=SendSSHPublicKey \
    --start-time "$START" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$N" ] && [ "$N" != "0" ] && [ "$N" != "None" ] && \
    echo "[!] $REGION, $N SendSSHPublicKey events"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The pushed key has already expired (60s), so there is no key to revoke, but an
SSH session established during the window **persists** beyond it. Contain the
principal, sever any live session by isolating the instance, and restrict SSH
ingress.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Contain the pushing principal

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

#### Step 2: Deny further key pushes by the principal

```bash
SUSPECT_ROLE="<role-name>"    # role principals; for an IAM user use put-user-policy
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyInstanceConnect" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["ec2-instance-connect:SendSSHPublicKey","ec2-instance-connect:SendSerialConsoleSSHPublicKey","ec2-instance-connect:OpenTunnel"],"Resource":"*"}]
  }'
echo "[OK] EC2 Instance Connect denied for $SUSPECT_ROLE"
```

#### Step 3: Isolate each pushed-to instance (severs any live SSH session) and snapshot

Isolating into a no-egress/no-ingress quarantine SG drops the established SSH
connection and preserves state for forensics. (Use the per-ENI quarantine-SG
helper from the credential-theft playbook.)

```bash
REGION="us-east-1"
TARGET_IDS="<space-separated-pushed-to-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
  for VOL in $(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' --output text); do
    aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
      --description "IR-EIC-$IID-$(date -u +%Y%m%dT%H%M%SZ)" --query 'SnapshotId' --output text
  done
  echo "[OK] snapshot(s) started for $IID, apply quarantine SG to drop any live SSH"
done
```

#### Step 4: Close the SSH exposure that made this reachable

```bash
REGION="us-east-1"
SG_ID="<sg-allowing-22-from-Query/instance>"
# Revoke world/broad SSH ingress so a future key push has no network path
aws ec2 revoke-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
  --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]' 2>/dev/null && \
  echo "[OK] Removed world SSH ingress on $SG_ID"
```

---

## 4. Eradication

### Remove Attacker Access: Rebuild the Accessed Hosts

#### Rebuild every instance that was SSH'd into

An instance an attacker had an interactive (likely sudo) SSH session on is
untrusted. The ephemeral key leaves no artifact to clean, so you cannot verify
the host is clean, rebuild from a golden AMI. Snapshots (Step 3) preserve
forensics.

```bash
REGION="us-east-1"
TARGET_IDS="<space-separated-pushed-to-instance-ids-from-Query-1>"
for IID in $TARGET_IDS; do
  aws ec2 terminate-instances --instance-ids "$IID" --region "$REGION" \
    --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'
done
echo "[OK] Accessed instances terminated, relaunch from golden AMI, IMDSv2, no open 22"
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

#### Right-size Instance Connect permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove ec2-instance-connect:SendSSHPublicKey from non-operator principals. Where
# needed, scope by instance tag and OS user via the ec2:osuser / aws:ResourceTag
# condition keys, and prefer SSM Session Manager over SSH entirely.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyInstanceConnect" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify no further key pushes since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendSSHPublicKey \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further SendSSHPublicKey from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further key pushes, containment did not hold"
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

#### Verify accessed instances were rebuilt and SSH is closed

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

# Confirm no SG still allows world SSH
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  HITS=$(aws ec2 describe-security-groups --region "$REGION" \
    --query 'SecurityGroups[?IpPermissions[?FromPort<=`22` && ToPort>=`22` && IpRanges[?CidrIp==`0.0.0.0/0`]]].GroupId' \
    --output text 2>/dev/null)
  [ -n "$HITS" ] && echo "[!] $REGION world SSH still open: $HITS"
done
```

#### Confirm the corrected detection fires

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
TEST_PRINCIPAL="<arn-used-for-the-emulation-run>"

HIT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendSSHPublicKey \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$TEST_PRINCIPAL" '[.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ec2-instance-connect.amazonaws.com") |
    select(.userIdentity.arn == $arn)] | length')

[ -n "$HIT" ] && [ "$HIT" -gt 0 ] && echo "[OK] SendSSHPublicKey captured - Rule A has data to fire on" \
                                  || echo "[FAIL] Not captured, check trail / eventSource"
echo "Confirm Rule A fired for the SINGLE-instance emulation run (non-operator), and"
echo "that a 2+-instance run additionally triggers the fan-out (Rule B)."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could push an SSH key to the instance | `ec2-instance-connect:SendSSHPublicKey` granted to a non-operator; no allowlist / alerting on key pushes |
| The instance was SSH-reachable | SG allowed inbound 22 (broadly); SSH used instead of SSM Session Manager |
| Interactive access left no host artifact | The Instance Connect key is ephemeral, detection had to be control-plane + Flow Logs, which weren't correlated |
| Access undetected | Shipped rule matched `SendSSHPublicKey` with no eventSource/principal/fan-out logic; no Flow Log correlation |
| Instance trusted after SSH | No process to rebuild a host that was interactively accessed |

### Recommended Guardrails

**Restrict and scope Instance Connect**

```json
// SCP: only operators may push Instance Connect keys
{
  "Effect": "Deny",
  "Action": ["ec2-instance-connect:SendSSHPublicKey", "ec2-instance-connect:SendSerialConsoleSSHPublicKey", "ec2-instance-connect:OpenTunnel"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/ssm-operator", "arn:aws:iam::*:role/break-glass", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- Where operators do need it, scope `SendSSHPublicKey` by instance tag (`aws:ResourceTag`) and restrict the OS user with the `ec2:osuser` condition key (e.g. forbid `root`)

**Remove the need for SSH**
- Prefer **SSM Session Manager** (logged, no open port, no key) for shell access, so no SG needs port 22 and a `SendSSHPublicKey` is unambiguously malicious (ties to the SSM-session playbook)
- If Instance Connect is required, use **EIC Endpoints** (no public IP, no open SG) with their `OpenTunnel` events alarmed, and keep SGs closed to `0.0.0.0/0:22`

**Detection improvements**
- Deploy Rule A (non-operator `SendSSHPublicKey`, fires on one instance) + Rule B (fan-out ≥2 instances) + an `OpenTunnel` rule, never the shipped unscoped match
- Add the `SendSSHPublicKey` → inbound-22 Flow Log correlation as the highest-confidence signal
- Weight `instanceOSUser = root`/admin higher

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1021.004 (as mapped by Stratus), see caveat below |
| MITRE tactic | Lateral Movement (TA0008) |
| Primary API | `ec2-instance-connect:SendSSHPublicKey` (and `OpenTunnel` for EIC Endpoints; `SendSerialConsoleSSHPublicKey` for serial console) |
| Event source | `ec2-instance-connect.amazonaws.com` |
| Key fields | `requestParameters.instanceId`, `requestParameters.instanceOSUser`, source IP |
| Key property | The pushed key is **ephemeral (60s)** and leaves **no artifact on the instance**, detect on the control-plane event + Flow Log inbound-22 correlation, not by auditing host keys |
| Not in CloudTrail | The SSH session itself and its on-host activity, only in VPC Flow Logs (inbound 22) and the host's SSH auth logs |
| Error strings (service-specific, not `Client.`-prefixed) | `AccessDeniedException`, `EC2InstanceNotFoundException`, `EC2InstanceStateInvalidException`, `ThrottlingException` |
| Resources created | 1 EC2 instance + SG (SSH open) + IAM role/instance profile + VPC |
| Follow-on to watch for | On-host activity, IMDS credential theft + off-instance role use, fan-out to more instances |

**MITRE mapping note:** the MANIFEST maps this to **T1021.004 (Remote Services:
SSH)**, which is *partly* apt - EC2 Instance Connect does result in an SSH session
(unlike SSM Session Manager). But the purpose-built sub-technique is **T1021.008
(Remote Services: Direct Cloud VM Connections)**, which explicitly names EC2
Instance Connect alongside Session Manager and serial console. The mapping is
inherited from Stratus Red Team; T1021.004 is defensible here, T1021.008 is more
precise. Recorded for the end-of-run MITRE-mapping finding. (Also note: the
emulation pushes to **one** instance despite the "Multiple Instances" name, the
fan-out is the technique's intent, not what this run performs.)

### Revert

`pulumi destroy` in `infra/` removes the EC2 instance, SG, IAM role/instance
profile, and VPC. The pushed key auto-expires after 60s, so the emulation leaves
no instance-side artifact and nothing to revert. After a **real** incident,
`pulumi destroy` is irrelevant, rebuild any instance that was SSH'd into (§4),
scope down `SendSSHPublicKey`, and close SSH ingress; the ephemeral key is already
gone, but what the interactive session did on the host is not undone by tearing
down the stack.
