# IR Playbook - Execute Malicious Code via EC2 User Data - Root Code Execution via `ec2:ModifyInstanceAttribute`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution / Command & Scripting Interpreter (root code execution on an instance) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, successful execution runs attacker-controlled code **as root** on the instance at boot; the host must be treated as compromised (`MANIFEST.py` rates MEDIUM; the IR view is High because this is arbitrary root code execution, not just a control-plane change) |
| MITRE Tactics | Execution |
| MITRE Techniques | T1059 |
| Services in Scope | EC2, CloudTrail, IAM, GuardDuty, VPC Flow Logs |
| Infrastructure Created | 1 EC2 instance + IAM role (SSM core) + instance profile + VPC (via `infra/`) |

**What the emulation does:** performs the three-step sequence, `ec2:StopInstances`, then `ec2:ModifyInstanceAttribute` replacing the instance's user-data with a malicious shell script (a C2 callback), then `ec2:StartInstances`. The intent is code execution **as root** via cloud-init, without ever needing SSH, SSM, or a session on the host.

**Important caveat on whether it actually runs.** By default, cloud-init executes a user-data *script* **once per instance**, keyed on the instance-id, and a stop/start does **not** change the instance-id. So on a stock Amazon Linux AMI, the emulation's plain stop→start does **not**, by itself, re-run the freshly-injected script. The technique becomes real execution when any of these holds: the injected user-data uses a **`#cloud-boothook`** shebang (the `cc_boothook` module runs on every boot, not once), or cloud-init's script-module frequency is overridden to `always` in `/etc/cloud/cloud.cfg`; the attacker resets cloud-init state (`cloud-init clean`) before the start so the once-per-instance guard is cleared; or the injected user-data is later consumed by a **fresh** instance (a rebuild, an autoscaling launch, or an AMI baked from this instance). Treat the injected user-data as a latent root-code-execution payload regardless of whether it fired on this particular boot, the IR response is the same, and the detection fires on the *write* either way.

**Why the SEQUENCE is the signal, not any single call.** `StopInstances` and `StartInstances` are routine operations (patching, cost management, maintenance). `ModifyInstanceAttribute` is called for many attributes. None is alarming alone. The attack fingerprint is the *ordered correlation* on one instance by one principal: **Stop → Modify(userData) → Start** in a short window. The shipped rule matches each event independently with no correlation (§2), so it both floods on benign stop/start and never keys on the pattern that matters.

**Why `ModifyInstanceAttribute(userData)` is inherently suspicious.** User-data is normally set **once at launch** via `RunInstances`. Modifying the user-data of an *existing* instance afterward is rare in most environments, so `ModifyInstanceAttribute` carrying a `userData` change is a high-signal event on its own, and the pre-requisite `StopInstances` (user-data can only be modified while stopped, the same constraint the user-data *read* playbook documents) narrows it further.

**The malicious script is recoverable even though CloudTrail doesn't log it.** CloudTrail records that user-data was modified but not the (base64) value. The injected script is still sitting in the instance's current user-data, retrieve and decode it (§2 Query 2) to obtain the C2 IOCs.

**Assume host compromise.** If the script executed, an attacker ran code as root: treat the instance as fully compromised (C2, on-host persistence, credential theft from IMDS, lateral movement via the instance role), not merely as an instance with a bad config. A cloud-init caveat matters for *whether it ran this boot* (see §2), but the user-data is attacker-controlled regardless and will execute on any future boot/rebuild that runs it.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for the sequence correlation. `Stop`/`Modify`/`Start` are all management events, so `lookup-events` works
- CloudTrail logs the `ModifyInstanceAttribute` call and that user-data was the modified attribute; it does **not** log the user-data value. Confirm the exact request-parameter shape (`userData` present) against a sample event in your account
- GuardDuty enabled in all regions, and VPC Flow Logs on all VPCs, to catch the C2 callback the injected script makes
- Instance boot/console logs (or CloudWatch Logs agent) so on-host script execution is visible independent of the control plane

**Alerting (must be pre-configured)**
- **`ec2:ModifyInstanceAttribute` modifying `userData` on an existing instance → alert.** This is the primary control, the write is rare and high-signal. Weight higher if the caller is not the provisioning pipeline
- **Sequence alert: `StopInstances` → `ModifyInstanceAttribute(userData)` → `StartInstances` on the same `instanceId` by the same principal within ~15 min → page.** This is the attack fingerprint
- `ec2:ModifyInstanceAttribute(userData)` from any principal not on the provisioning/IaC allowlist
- GuardDuty backdoor/C2 findings (`Backdoor:EC2/C&CActivity.B`, `Trojan:EC2/*`) on the instance after a start

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` and `base64` for decoding the injected user-data
- A golden-AMI / rebuild path for the affected workload, the remediation is rebuild, not clean-in-place
- The instance role's policies on hand, to scope blast radius if the root code used the role's IMDS credentials
- A maintained known-good user-data per instance/launch-template, saved for the responder (e.g. `known-good-userdata.txt`), §4 restores from it when scrubbing

**Known IOC Baselines**
- Baseline which principals modify user-data at all, in most environments this is only the provisioning pipeline, or no one after launch
- Baseline the expected user-data per instance/launch-template, so an injected script is a diff, not a mystery

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Sequence `StopInstances` → `ModifyInstanceAttribute(userData)` → `StartInstances` on one instance by one principal within ~15 min | CloudTrail | T1059 |
| P0 | `ec2:ModifyInstanceAttribute` modifying `userData` from a principal not on the provisioning allowlist | CloudTrail | T1059 |
| P1 | GuardDuty `Backdoor:EC2/C&CActivity.B` / `Trojan:EC2/*` on an instance shortly after a start | GuardDuty | T1059 |
| P1 | Outbound connection from the instance to an unrecognised host/port right after boot (C2 callback) | VPC Flow Logs | T1059 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ec2:ModifyInstanceAttribute(userData)` on any running/stopped production instance (rare outside provisioning) | CloudTrail | T1059 |
| P2 | `StopInstances` immediately followed by `ModifyInstanceAttribute` on the same instance, even if the attribute isn't clearly userData in the log | CloudTrail | T1059 |
| P2 | `ec2:ModifyInstanceAttribute(userData)` denied at volume (`errorCode = Client.UnauthorizedOperation`), permission probing | CloudTrail | T1059 |
| P3 | Provisioning-pipeline principal setting user-data during a known deployment window | CloudTrail | T1059 |

### Detection Rule Quality Notes

The rules in `detections/` do not detect this technique. These are correctness defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (StopInstances, ModifyInstanceAttribute, StartInstances)` with `condition: selection`, no correlation, no `userData` filter | Both noisy and blind to the technique. `Stop`/`Start` fire on every routine maintenance; matching them independently floods the queue and never expresses the ordered sequence that defines the attack | Alert `ModifyInstanceAttribute(userData)` directly, and add a **temporal correlation** for the Stop→Modify→Start sequence |
| No `userData` discriminator on `ModifyInstanceAttribute` | The attribute being modified is the whole point; a bare `ModifyInstanceAttribute` match catches security-group/termination-protection changes too | Filter to the `userData` modification (confirm the request-parameter field name against a sample event) |
| `Stop`/`Start` as standalone triggers | Pure noise on their own | Use them only as the bracketing events in the sequence correlation, never as independent alerts |
| No principal allowlist | Cannot separate the provisioning pipeline (which legitimately sets user-data at launch) from an attacker modifying it later | Add a provisioning/IaC allowlist |
| Header TODO "verify acronym casing"; `level: medium` on a rule matching all stop/start | Stale marker; alert fatigue | Resolve TODO; the `ModifyInstanceAttribute(userData)` rule → `level: high`; sequence correlation → `level: high` |

**Recommended detection, the write, plus the sequence.** The single-event rule catches the user-data write; a temporal correlation catches the full fingerprint.

```yaml
# Rule A: user-data modification of an existing instance (single-event, high value)
title: EC2 ModifyInstanceAttribute changing user-data
id: 3f8c2d51-7a90-4e62-b1c4-9d6f0a2e5b83
name: ec2_modify_userdata
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'ModifyInstanceAttribute'
  userdata:
    # Confirm the exact field against a sample event: userData present in the
    # request is the modified-attribute signal.
    requestParameters.userData|exists: true
  allowlisted:
    userIdentity.arn|contains:
      - ':role/provisioning'
      - ':role/ci-'
      - ':role/BreakGlassAdmin'
  condition: selection and userdata and not allowlisted
level: high
```

```yaml
# Rule B: the Stop -> Modify(userData) -> Start sequence (temporal correlation)
title: EC2 user-data injection sequence
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - ec2_stop_instances        # base rule: eventName StopInstances
    - ec2_modify_userdata       # Rule A above
    - ec2_start_instances       # base rule: eventName StartInstances
  group-by:
    - requestParameters.instanceId
  timespan: 15m
level: high
```

(Define the two trivial base rules `ec2_stop_instances` / `ec2_start_instances`
as single-event selections on their event names. `temporal_ordered` is the modern
Sigma correlation type for an ordered sequence; if a backend lacks it, implement
Rule B as the log-platform query in Query 3.)

**On error strings:** EC2 CloudTrail errors carry a `Client.` prefix,
`Client.UnauthorizedOperation`, `Client.IncorrectInstanceState` (a userData modify
attempted on a running instance). Match the prefixed form and confirm against a
sample event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, robust, unlike `--output text | jq`.

#### Query 1: Find the user-data modification and the surrounding sequence

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters | has("userData")) |     # userData modifications only
    {time: .eventTime,
     caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,             # feeds ACCESS_KEY_ID in Query 5
     instance: .requestParameters.instanceId,
     error: (.errorCode // "SUCCESS"),
     ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

For each suspect `instance`, confirm the bracketing Stop/Start by the same caller:

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
INSTANCE_ID="<i-from-above>"

for EV in StopInstances StartInstances; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json
done | \
  jq -r --arg iid "$INSTANCE_ID" '.Events[].CloudTrailEvent | fromjson |
    select((.requestParameters.instancesSet.items[]?.instanceId) == $iid) |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn}' | \
  jq -s 'sort_by(.time)'
```

A Stop → Modify(userData) → Start ordering on one instance by one principal is the
confirmed attack.

#### Query 2: Retrieve and decode the injected user-data (get the C2 IOCs)

The malicious script is not in CloudTrail, but it is in the instance's current
user-data.

```bash
# GNU base64 decodes with -d, older BSD/macOS with -D. Probe, then decode.
b64d() { if base64 -d </dev/null >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }

REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

aws ec2 describe-instance-attribute --instance-id "$INSTANCE_ID" --attribute userData \
  --region "$REGION" --query 'UserData.Value' --output text | b64d | tee ./ir-injected-userdata.txt

echo "=== IOC scan of the injected script ==="
grep -Ein 'curl|wget|nc |/dev/tcp|bash -i|http[s]?://|[0-9]{1,3}(\.[0-9]{1,3}){3}|AKIA[0-9A-Z]{16}' \
  ./ir-injected-userdata.txt
```

Extract every URL, IP, and domain, these are the C2 IOCs to block and hunt for
across the environment. **Handle this file as attacker-controlled content.**

#### Query 3: Deployable sequence detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights. Finds the Stop→Modify(userData)→Start ordering per instance within 15 minutes.

```kql
let window = 15m;
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "ec2.amazonaws.com"
| where EventName in ("StopInstances", "ModifyInstanceAttribute", "StartInstances")
| extend Req = parse_json(RequestParameters)
// instanceId is on ModifyInstanceAttribute directly; on Stop/Start it is in instancesSet
| extend InstanceId = tostring(coalesce(Req.instanceId, Req.instancesSet.items[0].instanceId))
| extend IsUserDataModify = (EventName == "ModifyInstanceAttribute" and isnotempty(Req.userData))
| where EventName in ("StopInstances","StartInstances") or IsUserDataModify
| sort by InstanceId asc, TimeGenerated asc
| summarize
    Events   = make_list(EventName),
    ModUD    = countif(IsUserDataModify),
    Stops    = countif(EventName == "StopInstances"),
    Starts   = countif(EventName == "StartInstances"),
    Callers  = make_set(UserIdentityArn, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen  = max(TimeGenerated)
    by InstanceId, bin(TimeGenerated, window)
| where ModUD > 0 and Stops > 0 and Starts > 0
| extend Verdict = "EC2 USER-DATA INJECTION SEQUENCE - P0"
| order by LastSeen desc
```

The `ModUD > 0 and Stops > 0 and Starts > 0` within one 15-minute bin approximates
the ordered sequence; for strict ordering, use the Sigma `temporal_ordered`
correlation (Rule B) where the backend supports it.

#### Query 4: Did the instance call out? (C2 confirmation)

```bash
# Query VPC Flow Logs (CloudWatch Logs) for outbound from the instance's ENI
# right after the StartInstances timestamp. Adjust log group + ENI.
LOG_GROUP="/vpc/flowlogs"
ENI_ID="<eni-of-the-instance>"
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '2 hours ago' +%s 2>/dev/null \
        || date -u -v-2H +%s)

aws logs filter-log-events --log-group-name "$LOG_GROUP" \
  --start-time "${START}000" \
  --filter-pattern "\"$ENI_ID\"" \
  --query 'events[*].message' --output text 2>/dev/null | \
  awk '$13=="ACCEPT" && $NF=="OK"' | head -50   # v2 flow log: $13=action, $14/$NF=log-status
```

Cross-reference destination IPs against the IOCs from Query 2.

#### Query 5: Full session reconstruction of the injecting principal

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

#### Query 6: Multi-region sweep for user-data modifications

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  N=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null | \
    jq -r '[.Events[].CloudTrailEvent | fromjson | select(.requestParameters | has("userData"))] | length')
  [ -n "$N" ] && [ "$N" != "0" ] && echo "[!] $REGION, $N user-data modifications"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The instance has (or may have) executed attacker code as root. Contain the
principal, then isolate the instance, do not reboot it into the malicious
user-data again.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Contain the injecting principal

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

#### Step 2: Isolate the instance (do NOT stop/start it through the bad user-data)

Network-isolate to sever C2 while preserving the running state for forensics.
**Do not reboot**, a reboot may re-run the malicious user-data.

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

# Record original SGs, then move to a no-egress quarantine SG (per-ENI).
aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[*].{ENI:NetworkInterfaceId,SGs:Groups[*].GroupId}' \
  --output json | tee "./ir-original-sgs-$INSTANCE_ID.json"

VPC_ID=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].VpcId' --output text)
QSG=$(aws ec2 create-security-group --group-name "ir-quarantine-$INSTANCE_ID" \
  --description "IR isolation" --vpc-id "$VPC_ID" --region "$REGION" --query 'GroupId' --output text) \
  || { echo "[FAIL] SG create"; exit 1; }
if aws ec2 revoke-security-group-egress --group-id "$QSG" --region "$REGION" \
     --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'; then
  echo "[OK] Egress stripped from $QSG"
else
  echo "[FAIL] Egress not stripped"; exit 1
fi
for ENI in $(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[*].NetworkInterfaceId' --output text); do
  aws ec2 modify-network-interface-attribute --network-interface-id "$ENI" \
    --groups "$QSG" --region "$REGION" && echo "[OK] $ENI quarantined"
done
```

#### Step 3: Snapshot for forensics

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"
for VOL in $(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' --output text); do
  aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
    --description "IR-T1059-$INSTANCE_ID-$(date -u +%Y%m%dT%H%M%SZ)" --query 'SnapshotId' --output text
  echo "[OK] Snapshot started for $VOL"
done
```

#### Step 4: Strip user-data modification from the principal pending investigation

```bash
SUSPECT_ROLE="<role-name>"
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyModifyInstance" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["ec2:ModifyInstanceAttribute","ec2:StartInstances"],"Resource":"*"}]
  }'
echo "[OK] ModifyInstanceAttribute/StartInstances denied for $SUSPECT_ROLE"
```

---

## 4. Eradication

### Remove Attacker Access: Rebuild, Don't Clean

The instance ran attacker code as root. Cleaning in place cannot be trusted;
the durable fix is to scrub the user-data, capture forensics, and rebuild.

#### Scrub the malicious user-data (so no future boot re-runs it)

Modifying user-data requires the instance stopped. To be safe against any
per-boot cloud-init configuration (which *would* re-run the payload), scrub the
user-data **while stopped** and only start once it is clean, or skip straight to
rebuild.

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"

# Replace with the known-good user-data (or empty it). --value is file:// base64
# for CLI v2 (cli_binary_format=base64 passes it through unmodified).
base64 < ./known-good-userdata.txt | tr -d '\n' > ./clean-userdata.b64
aws ec2 modify-instance-attribute --instance-id "$INSTANCE_ID" --region "$REGION" \
  --attribute userData --value "file://./clean-userdata.b64"
echo "[OK] User-data scrubbed on $INSTANCE_ID"
```

#### Terminate and rebuild from a golden AMI

```bash
REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

# Snapshots (Step 3) preserve forensics; the host is untrusted after root code exec
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'TerminatingInstances[0].{Id:InstanceId,State:CurrentState.Name}'
# Relaunch from the pipeline/golden AMI with the correct user-data and IMDSv2 enforced
```

#### Check for on-host persistence and role abuse

The root script may have established persistence and used the instance role's
IMDS credentials. Enumerate the role's activity (session name = instance ID):

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$INSTANCE_ID" \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     ip: .sourceIPAddress, error: (.errorCode // "SUCCESS")}' | \
  jq -s 'sort_by(.time)'
```

Off-instance use of the role's credentials, or any IAM/persistence primitive,
means the incident extends beyond the host, pivot to the credential-theft and
persistence playbooks. Block the Query 2 C2 IOCs at the network edge and hunt for
them across other instances.

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyModifyInstance" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the user-data is clean on any surviving instance

```bash
# GNU base64 decodes with -d, older BSD/macOS with -D. Probe, then decode.
b64d() { if base64 -d </dev/null >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }

REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

BODY=$(aws ec2 describe-instance-attribute --instance-id "$INSTANCE_ID" --attribute userData \
  --region "$REGION" --query 'UserData.Value' --output text 2>/dev/null | b64d 2>/dev/null)
if echo "$BODY" | grep -qEi 'curl|wget|/dev/tcp|bash -i|http[s]?://|AKIA[0-9A-Z]{16}'; then
  echo "[FAIL] $INSTANCE_ID user-data still contains suspicious content"
else
  echo "[OK] $INSTANCE_ID user-data is clean (or rebuilt)"
fi
```

#### Verify no further user-data modification since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | select(.requestParameters | has("userData")) |
    select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further user-data modifications from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further user-data modifications, containment did not hold"
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

#### Verify the C2 IOCs are blocked and absent elsewhere

```bash
# Confirm the Query 2 IOC IPs/domains are blocked at the edge (SG/NACL/firewall)
# and hunt for them in Flow Logs across the environment.
echo "Confirm each Query 2 IOC is blocked and does not appear in any other instance's egress."
```

#### Confirm the corrected detection fires

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
INSTANCE_ID="<i-xxxxxxxxxxxx>"

# Re-run the emulation and assert the user-data modification event is captured
N=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg iid "$INSTANCE_ID" '[.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters.instanceId == $iid) |
    select(.requestParameters | has("userData"))] | length')

[ -n "$N" ] && [ "$N" -gt 0 ] && echo "[OK] userData modification captured - Rule A has data to fire on" \
                              || echo "[FAIL] No userData modification captured, check trail / request-param field name"
echo "Confirm the sequence rule (Rule B / Query 3) fired ONE alert for the Stop->Modify->Start ordering."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could modify an instance's user-data | `ec2:ModifyInstanceAttribute` granted to a principal with no provisioning role; no restriction or alerting on user-data writes |
| Root code executed on boot | User-data runs as root by design; no control preventing post-launch user-data changes on production instances |
| Attack undetected | Shipped rule matched stop/start/modify independently with no sequence correlation and no userData filter |
| C2 callback unremarked | No egress alerting / GuardDuty C2 detection wired to page |
| Instance trusted after the event | No process to rebuild an instance that executed attacker root code |

### Recommended Guardrails

**Restrict user-data modification to provisioning principals**

```json
// SCP: only the provisioning/CI roles may modify instance attributes
{
  "Effect": "Deny",
  "Action": "ec2:ModifyInstanceAttribute",
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": ["arn:aws:iam::*:role/provisioning", "arn:aws:iam::*:role/ci-*", "arn:aws:iam::*:role/BreakGlassAdmin"]
    }
  }
}
```

Note: `ec2:ModifyInstanceAttribute` cannot be scoped by *which attribute* is
modified (no supported IAM condition key for the attribute), so this gates the
action wholesale for non-provisioning principals.

**Prefer immutable infrastructure**
- Manage user-data through launch templates / IaC and forbid ad-hoc modification of running fleets; a user-data change then only happens via a reviewed pipeline, and any out-of-band `ModifyInstanceAttribute(userData)` is unambiguously an incident
- Enforce IMDSv2 (limits what root code can do with the instance role) and keep instance roles least-privilege

**Detection improvements**
- Deploy Rule A (user-data modification) and Rule B (Stop→Modify→Start temporal correlation), never the shipped independent stop/start match
- Alert GuardDuty `Backdoor:EC2/C&CActivity.*` and egress anomalies at P0
- Baseline expected user-data per launch template so an injected script is a diff

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1059 - Command and Scripting Interpreter |
| MITRE tactic | Execution (TA0002) |
| Attack sequence | `ec2:StopInstances` → `ec2:ModifyInstanceAttribute(userData=malicious)` → `ec2:StartInstances` |
| Event source | `ec2.amazonaws.com` |
| Key discriminator | `ModifyInstanceAttribute` carrying a `userData` change (rare post-launch), and the ordered Stop→Modify→Start sequence on one instance |
| Recover the payload | Decode the instance's current user-data (`describe-instance-attribute … --attribute userData | base64 -d`), not in CloudTrail |
| Execution context | Runs as **root** via cloud-init on boot. User-data runs once per instance-id by default; re-executes only via a `#cloud-boothook` payload, a module-frequency `always` override, `cloud-init clean`, or a fresh instance |
| Error strings (`Client.`-prefixed) | `Client.UnauthorizedOperation`, `Client.IncorrectInstanceState` (modify attempted while running) |
| Resources created | 1 EC2 instance + IAM role + instance profile + VPC scaffolding |
| Follow-on to watch for | C2 callback (Flow Logs / GuardDuty), on-host persistence, instance-role credential abuse |

### Revert

`pulumi destroy` in `infra/` removes the EC2 instance, IAM role/instance profile,
and VPC. The emulation leaves the instance running with modified user-data;
`pulumi destroy` tears it down cleanly for an emulation run. After a **real**
incident, `pulumi destroy` is irrelevant, the host executed attacker root code
and must be rebuilt (§4), the user-data scrubbed, and the C2 IOCs blocked and
hunted; tearing down the stack does not undo on-host persistence or
credentials the attacker exfiltrated during the boot.
