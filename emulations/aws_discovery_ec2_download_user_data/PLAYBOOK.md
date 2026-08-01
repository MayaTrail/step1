# IR Playbook: Download EC2 Instance User Data — Credential Harvesting via `ec2:DescribeInstanceAttribute`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Discovery / Credential Access (credential harvesting from instance metadata) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | Medium — High if any harvested user-data contains live secrets; Low if none do (`MANIFEST.py` rates LOW; the IR view is Medium because user-data very often contains bootstrap credentials, and the technique reads *every* instance's) |
| MITRE Tactics | Credential Access (MANIFEST tags Discovery — see mapping note in §6) |
| MITRE Techniques | T1552.001 |
| Services in Scope | EC2, CloudTrail, IAM, plus every system whose credentials appear in a harvested user-data script |
| Infrastructure Created | None — the emulation reads existing instances; it creates nothing |

**What the emulation does:** enumerates every running instance with `ec2:DescribeInstances`, then calls `ec2:DescribeInstanceAttribute` with `Attribute=userData` on each one to download its user-data script. User-data is base64-encoded launch-time configuration — and it very frequently contains hardcoded secrets: API keys, database passwords, bootstrap tokens, registry credentials. The attacker harvests all of it from the control plane, without ever touching an instance.

**Why `Attribute=userData` is the whole signal.** `DescribeInstanceAttribute` is a routine call made for many attribute types — `instanceType`, `groupSet`, `disableApiTermination`, `blockDeviceMapping`, and others — almost all benign. Only `Attribute=userData` reads the script that may hold credentials. The single most important field for detecting this technique is `requestParameters.attribute`, and the shipped rules ignore it entirely (§2).

**Why the eradication shape differs from the secrets techniques.** In the Secrets Manager / SSM Parameter Store techniques, every item retrieved *is* a live credential, so every one is rotated. Here, user-data is a *script* that may or may not contain secrets. The blast radius is not "N instances read" — it is "which of those user-data scripts contain live credentials." Eradication is therefore **scan every harvested script, then rotate only the credentials actually found** — and permanently remove secrets from user-data so the next harvest yields nothing.

**Why there is nothing to `pulumi destroy`.** This emulation provisions no infrastructure; it only reads. That also means the *attacker* leaves no created resources — the damage is entirely in what was read and what those scripts exposed.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for rate queries
- **`DescribeInstanceAttribute` is a management read event, captured by default.** Confirm `ReadWriteType: All`; a `WriteOnly` trail drops it and blinds this detection
- CloudTrail logs `requestParameters.attribute` and `requestParameters.instanceId` on `DescribeInstanceAttribute` — so *which attribute* and *which instance* are both recoverable. The user-data **content** is not logged (only that it was requested)
- An inventory of which instances have user-data and whether any is known to contain secrets — so triage can prioritise the instances that actually matter

**Alerting (must be pre-configured)**
- Threshold alert on **distinct instances whose `userData` was read per principal per window**: count distinct `instanceId` on `DescribeInstanceAttribute` where `attribute=userData`. More than ~5 in 10 minutes from one principal → alert. This is the primary control; it must filter on the `userData` attribute and count instances, not raw events
- Any `DescribeInstanceAttribute(userData)` from a principal not on the small allowlist of operations/patch tooling that legitimately reads user-data
- `DescribeInstances` (account-wide enumeration) immediately followed by a sweep of `DescribeInstanceAttribute(userData)` from the same session — the enumerate-then-harvest pattern

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` and a secret-scanning tool (e.g. a regex/entropy scanner) to triage harvested user-data for embedded credentials
- A user-data → owning-application map, so a found secret can be traced to what it authenticates and rotated fast

**Known IOC Baselines**
- Baseline which principals read `userData` at all — normally a very short list (launch templates tooling, some config-management), often none interactively
- Baseline: production accounts should ideally have **no secrets in user-data at all**. If that invariant holds, this technique yields nothing; the alert then exists mainly to catch the recon itself

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | > 5 distinct instances' `userData` read (`DescribeInstanceAttribute`, `attribute=userData`) by one principal in 10 min | CloudTrail | T1552.001 |
| P0 | `DescribeInstanceAttribute(userData)` from a principal not on the user-data-reader allowlist | CloudTrail | T1552.001 |
| P1 | `DescribeInstances` account-wide sweep followed by `DescribeInstanceAttribute(userData)` across most/all returned instances, same session | CloudTrail | T1552.001 |
| P1 | `DescribeInstanceAttribute(userData)` from an off-baseline ASN/geography for the principal | CloudTrail | T1552.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DescribeInstanceAttribute(userData)` on a handful of instances by a principal with no baseline history of reading user-data | CloudTrail | T1552.001 |
| P2 | `DescribeInstanceAttribute(userData)` spanning instances across multiple unrelated applications/VPCs by one principal | CloudTrail | T1552.001 |
| P2 | `DescribeInstanceAttribute` denied at volume (`errorCode = Client.UnauthorizedOperation`) — permission probing | CloudTrail | T1552.001 |
| P3 | Single `DescribeInstanceAttribute(userData)` by an allowlisted operations principal | CloudTrail | T1552.001 |

### Detection Rule Quality Notes

The rules in `detections/` are too coarse to deploy. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (DescribeInstances, DescribeInstanceAttribute)` with `condition: selection`, no threshold and **no `attribute=userData` filter** | Unusable, and misses the point. `DescribeInstances` is one of the highest-volume calls in AWS (every console load, every inventory tool). `DescribeInstanceAttribute` is called for many benign attribute types. Without the `userData` filter the rule fires constantly on activity unrelated to credential harvesting | Drop `DescribeInstances` as a trigger; filter `DescribeInstanceAttribute` to `requestParameters.attribute = userData` |
| No counting of **instances**, no per-principal grouping | The technique is defined by *breadth* — reading many instances' user-data. A rule with no aggregation cannot express it | Threshold on distinct `instanceId` per principal per window |
| `DescribeInstances` treated as a trigger | Enumeration is context, not an incident on its own | Use the `DescribeInstances`→`DescribeInstanceAttribute(userData)` *sequence* as a signal; never alert `DescribeInstances` alone |
| No principal allowlist | Cannot separate patch/config tooling that legitimately reads user-data from an attacker | Add an allowlist of expected user-data readers |
| Header TODO "verify acronym casing" unresolved; `level: medium` on a rule dominated by benign enumeration | Stale marker; guaranteed alert fatigue | Resolve TODO; a raw `DescribeInstanceAttribute(userData)` rule → `level: low`; the volume rule → `level: high` |

**Recommended detection — userData-only, count instances.** This is an aggregation and belongs in a log platform (Query 3) or a Sigma **correlation**:

```yaml
# Document 1 — base rule: successful userData reads only
title: EC2 DescribeInstanceAttribute userData read
id: 6f2b0a17-9c84-4e1d-b3a2-7e5c9d0a1f42
name: ec2_describe_userdata_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'DescribeInstanceAttribute'
    requestParameters.attribute: 'userData'
  success:
    errorCode: null          # Sigma: matches when errorCode is ABSENT (the read succeeded)
  condition: selection and success
level: low
---
# Document 2 — correlation: many DISTINCT instances read by one principal
title: EC2 user-data harvesting across many instances
status: experimental
correlation:
  type: value_count
  rules:
    - ec2_describe_userdata_base
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 5
    field: requestParameters.instanceId    # count DISTINCT instances, not events
level: high
```

**On error strings (learned from the EC2 techniques):** EC2 CloudTrail errors carry a `Client.` prefix — a permission denial is `Client.UnauthorizedOperation`, not `UnauthorizedOperation`. Match the prefixed form (or use a `contains` match) and confirm against a sample event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'` — robust, unlike `--output text | jq`.

#### Query 1 — Who harvested user-data, and how many instances?

```bash
REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstanceAttribute \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters.attribute == "userData") |
    {arn: .userIdentity.arn, instance: .requestParameters.instanceId,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.arn) | map({
      principal: .[0].arn,
      distinct_instances: ([.[] | select(.error=="SUCCESS") | .instance] | unique | length),
      denied: ([.[] | select(.error!="SUCCESS")] | length),
      source_ips: ([.[].ip] | unique)
    }) | sort_by(-.distinct_instances)'
```

The principal with an anomalously high `distinct_instances` is the suspect. A high
`denied` count is permission-probing (`Client.UnauthorizedOperation`).

#### Query 2 — The triage work-list: which instances' user-data was read?

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstanceAttribute \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.attribute == "userData") |
    select(.errorCode == null) |
    .requestParameters.instanceId // empty' | \
  grep . | sort -u | tee ./ir-harvested-instances.txt

echo "Instances whose user-data was harvested: $(grep -c . ./ir-harvested-instances.txt)"
```

`./ir-harvested-instances.txt` is the triage list — each instance's user-data
must now be scanned for secrets (§4). It is not yet a rotation list; only the
instances whose scripts contain live credentials become one.

#### Query 3 — Deployable harvesting detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL** — not CloudWatch Logs Insights. Counts distinct instances' user-data read per principal per 10-minute window.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "ec2.amazonaws.com"
| where EventName == "DescribeInstanceAttribute"
| extend Req = parse_json(RequestParameters)
| where tostring(Req.attribute) == "userData"
| where isempty(ErrorCode)
| extend InstanceId = tostring(Req.instanceId)
| summarize
    InstancesRead = dcount(InstanceId),
    Calls         = count(),
    SourceIPs     = make_set(SourceIpAddress, 10),
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated)
    by UserIdentityArn, bin(TimeGenerated, 10m)
| where InstancesRead > 5
| extend Verdict = "EC2 USER-DATA HARVESTING — P0"
| order by InstancesRead desc
```

CloudWatch Logs Insights equivalent:

```
fields @timestamp, userIdentity.arn, requestParameters.attribute, requestParameters.instanceId, errorCode
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "DescribeInstanceAttribute"
| filter requestParameters.attribute = "userData"
| filter not ispresent(errorCode)
| stats count_distinct(requestParameters.instanceId) as instances_read
    by userIdentity.arn, bin(10m)
| filter instances_read > 5
```

#### Query 4 — Enumeration and sweep rate

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"

# The DescribeInstances enumeration that preceded the harvest
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstances \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | {time: .eventTime, ip: .sourceIPAddress}'

# Harvest rate — CloudTrail eventTime is whole-second resolution, so measure
# reads-per-second (many in one second = scripted, not human)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstanceAttribute \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.attribute == "userData") | .eventTime' | \
  sort | uniq -c | sort -rn | head -30
```

#### Query 5 — Full session reconstruction

```bash
ACCESS_KEY_ID="<AKIA-or-ASIA-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Watch for the actor *using* a credential found in user-data (a leaked IAM key,
a DB login) later in the same session — that is the pivot from harvesting to
active compromise.

#### Query 6 — Multi-region sweep

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  COUNT=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstanceAttribute \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null | \
    jq -r '[.Events[].CloudTrailEvent | fromjson |
      select(.requestParameters.attribute == "userData")] | length')
  [ -n "$COUNT" ] && [ "$COUNT" != "0" ] && \
    echo "[!] $REGION — $COUNT userData reads"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The harvested scripts are already read — containment stops *further* harvesting
and buys time to find and rotate whatever secrets were exposed. The real work is
in §4 (scan and rotate). Contain the principal now.

> Run every containment/eradication command under the **break-glass responder
> credentials** from §1, not under any principal being contained.

#### Step 1 — Disable the offending credential

```bash
SUSPECT_ARN="<principal-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  VICTIM_USER=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')   # user ARN: name is last segment
  aws iam list-access-keys --user-name "$VICTIM_USER" \
    --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status}' --output table
  COMPROMISED_KEY_ID="<key-id>"
  aws iam update-access-key --user-name "$VICTIM_USER" \
    --access-key-id "$COMPROMISED_KEY_ID" --status Inactive
  echo "[OK] Disabled key $COMPROMISED_KEY_ID for $VICTIM_USER"
fi
```

#### Step 2 — Revoke live STS sessions (assumed-role principals)

```bash
# assumed-role ARN: arn:aws:sts::<acct>:assumed-role/<RoleName>/<SessionName>
# The role name is the SECOND path segment, NOT $NF (that is the session name).
SUSPECT_ROLE=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')

aws iam put-role-policy \
  --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny", "Action": "*", "Resource": "*",
      "Condition": {"DateLessThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}
    }]
  }'
echo "[OK] Pre-existing sessions for $SUSPECT_ROLE revoked"
```

`aws:TokenIssueTime` kills only tokens issued before now; a principal able to
mint fresh credentials (e.g. an instance role on a compromised host) needs that
path cut too.

#### Step 3 — Strip user-data read (and broad EC2 describe) from the principal

```bash
SUSPECT_ROLE="<role-name>"

aws iam put-role-policy \
  --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyUserDataRead" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "ec2:DescribeInstanceAttribute",
      "Resource": "*"
    }]
  }'
echo "[OK] DescribeInstanceAttribute denied for $SUSPECT_ROLE"
```

Note: there is no supported IAM condition key to scope
`ec2:DescribeInstanceAttribute` by the *attribute value* — you cannot allow
non-userData attributes while denying `userData` (widely reported; not an
AWS-documented condition key). So this denies the action wholesale during
containment. Restore a scoped grant in recovery if the principal legitimately
needs other attributes.

---

## 4. Eradication

### Remove Attacker Access — Find and Rotate the Exposed Secrets

The core work. For every instance in `./ir-harvested-instances.txt`, retrieve its
user-data, scan it for secrets, and rotate whatever is found. Then remove secrets
from user-data permanently so a future harvest is worthless.

#### Retrieve and scan each harvested script

```bash
REGION="us-east-1"
mkdir -p ./ir-userdata && chmod 700 ./ir-userdata

while read -r IID; do
  [ -z "$IID" ] && continue
  aws ec2 describe-instance-attribute --instance-id "$IID" --attribute userData \
    --region "$REGION" --query 'UserData.Value' --output text 2>/dev/null | \
    base64 -d > "./ir-userdata/$IID.txt" 2>/dev/null
  echo "[*] Retrieved user-data for $IID -> ./ir-userdata/$IID.txt"
done < ./ir-harvested-instances.txt

# Scan for embedded secrets. Use a real scanner (trufflehog/gitleaks-style) in
# production; this grep is a first pass for obvious patterns.
grep -rEin 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|secret|password|passwd|token|api[_-]?key|BEGIN [A-Z ]*PRIVATE KEY' \
  ./ir-userdata/ | tee ./ir-userdata-hits.txt
echo "[*] Review ./ir-userdata-hits.txt — each hit is a candidate live credential to rotate"
```

**Handle these files as sensitive:** they contain the same plaintext the attacker
now has. Store under restrictive permissions and delete when the investigation
closes.

#### Rotate every credential found

For each secret identified, rotate it at its source system (IAM key, DB password,
third-party API key), exactly as in the secrets-exfiltration playbooks. **A found
IAM access key** must be disabled and reissued via IAM:

```bash
LEAKED_KEY="<AKIA-found-in-user-data>"
LEAKED_KEY_USER=$(aws iam get-access-key-last-used --access-key-id "$LEAKED_KEY" \
  --query 'UserName' --output text 2>/dev/null)
[ -n "$LEAKED_KEY_USER" ] && [ "$LEAKED_KEY_USER" != "None" ] && \
  aws iam update-access-key --user-name "$LEAKED_KEY_USER" \
    --access-key-id "$LEAKED_KEY" --status Inactive && \
  echo "[OK] Disabled leaked key $LEAKED_KEY (user $LEAKED_KEY_USER) — reissue via IAM"
```

#### Remove secrets from user-data so re-harvest yields nothing

Scrub the credential out of each instance's user-data and move it to a proper
secret store. Changing user-data requires the instance to be **stopped** (you
cannot modify user-data on a running instance):

```bash
REGION="us-east-1"
IID="<i-xxxxxxxxxxxx>"

# 1. Edit the decoded script to remove the secret and make it fetch the
#    credential from Secrets Manager / SSM at boot instead of embedding it.
cp "./ir-userdata/$IID.txt" "./ir-userdata/$IID.scrubbed.txt"
${EDITOR:-vi} "./ir-userdata/$IID.scrubbed.txt"

# 2. Re-encode to base64 (single line). AWS CLI v2 with the default
#    cli_binary_format=base64 treats file:// content as already-base64, so this
#    is passed through as-is (no double-encoding).
base64 -w0 "./ir-userdata/$IID.scrubbed.txt" > "./ir-userdata/$IID.scrubbed.b64"

# 3. Apply — requires the instance to be STOPPED (user-data cannot be modified
#    on a running instance; AWS returns IncorrectInstanceState otherwise).
aws ec2 stop-instances --instance-ids "$IID" --region "$REGION"
aws ec2 wait instance-stopped --instance-ids "$IID" --region "$REGION"
aws ec2 modify-instance-attribute --instance-id "$IID" --region "$REGION" \
  --attribute userData --value "file://./ir-userdata/$IID.scrubbed.b64"

aws ec2 start-instances --instance-ids "$IID" --region "$REGION"
echo "[OK] Scrubbed user-data on $IID"
```

#### Check whether the attacker used any harvested credential

```bash
# For each leaked IAM key found in user-data, enumerate its activity
LEAKED_KEY="<AKIA...>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$LEAKED_KEY" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, ip: .sourceIPAddress}'
```

Remediate any persistence found with the relevant playbook.

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyUserDataRead" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify no user-data still contains secrets

```bash
REGION="us-east-1"

# Re-pull user-data for the harvested instances and confirm the scan is now clean
FAIL=0
while read -r IID; do
  [ -z "$IID" ] && continue
  BODY=$(aws ec2 describe-instance-attribute --instance-id "$IID" --attribute userData \
    --region "$REGION" --query 'UserData.Value' --output text 2>/dev/null | base64 -d 2>/dev/null)
  if echo "$BODY" | grep -qEi 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|password|token|api[_-]?key|PRIVATE KEY'; then
    echo "[FAIL] $IID user-data still contains a secret pattern"; FAIL=1
  else
    echo "[OK] $IID user-data clean"
  fi
done < ./ir-harvested-instances.txt
[ "$FAIL" -eq 0 ] && echo "[OK] All harvested instances' user-data is secret-free" \
                  || echo "[FAIL] Some user-data still holds secrets — scrub before closing"
```

#### Verify every leaked credential was rotated

```bash
# For each IAM key found in user-data, confirm it is gone/inactive
LEAKED_KEY="<AKIA...>"
STATUS=$(aws iam list-access-keys --user-name "<user>" \
  --query "AccessKeyMetadata[?AccessKeyId=='$LEAKED_KEY'].Status" --output text 2>/dev/null)
{ [ -z "$STATUS" ] || [ "$STATUS" = "Inactive" ]; } && echo "[OK] Leaked key neutralised" \
  || echo "[FAIL] Leaked key $LEAKED_KEY still Active"
# Non-AWS credentials: confirm the OLD value is rejected by its downstream system.
```

#### Verify no further user-data harvesting since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstanceAttribute \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.attribute == "userData") |
    select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further userData reads from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further userData reads — containment did not hold"
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

#### Confirm the corrected detection fires

Re-run the emulation in a controlled window, then assert the telemetry the
corrected rule keys on actually materialised (run against CloudTrail-in-log-platform,
or the CLI check below against raw CloudTrail):

```bash
REGION="us-east-1"
TEST_PRINCIPAL="<arn-used-for-the-emulation-run>"

READS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstanceAttribute \
  --start-time "$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$TEST_PRINCIPAL" '[.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.attribute == "userData")] |
    (map(.requestParameters.instanceId) | unique | length)')

echo "Distinct instances whose userData was read by the test principal: $READS"
[ "$READS" -gt 5 ] && echo "[OK] userData-attribute events present at volume — the corrected rule has data to fire on" \
                   || echo "[FAIL] Expected >5 distinct userData reads; saw $READS — trail may be WriteOnly/delayed, or the rule filter is wrong"
echo "Confirm the deployed rule produced ONE volume alert (not one per instance,"
echo "and not firing on DescribeInstances or non-userData attribute reads)."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| Secrets were present in EC2 user-data at all | Credentials embedded in launch-time config instead of fetched from Secrets Manager / SSM at boot |
| One principal read many instances' user-data uninterrupted | No userData-attribute detection and no per-principal volume threshold; shipped rule ignored the attribute |
| Principal could read user-data account-wide | Broad `ec2:DescribeInstanceAttribute` with no scoping and no reader allowlist |
| Harvesting undetected until secrets were used | `DescribeInstances`→`DescribeInstanceAttribute(userData)` sequence not correlated |

### Recommended Guardrails

**Eliminate the target — no secrets in user-data**
- Never place credentials in user-data. Fetch them at boot from Secrets Manager or SSM Parameter Store using the instance role, so a user-data harvest yields only non-sensitive bootstrap logic
- Scan launch templates and existing user-data for secrets in CI and on a schedule; treat any hit as a finding

**Restrict who can read instance attributes**

```json
// Restrict DescribeInstanceAttribute to operations tooling via an SCP.
// Note: the action is not attribute-scopable, so this gates the whole action.
{
  "Effect": "Deny",
  "Action": "ec2:DescribeInstanceAttribute",
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/ops-tooling",
        "arn:aws:iam::*:role/BreakGlassAdmin"
      ]
    }
  }
}
```

**Detection improvements**
- Deploy the userData-only volume rule (Query 3): `attribute=userData`, distinct `instanceId`, per principal per window — never a raw `DescribeInstanceAttribute` or `DescribeInstances` match
- Correlate `DescribeInstances`→`DescribeInstanceAttribute(userData)` sequences
- Alert any `DescribeInstanceAttribute(userData)` from a principal off the reader allowlist

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1552.001 — Unsecured Credentials: Credentials In Files |
| MITRE tactic | Credential Access (TA0006). MANIFEST tags Discovery; the technique is genuinely dual — discovery of the scripts, credential access to their contents |
| Primary API | `ec2:DescribeInstanceAttribute` with `Attribute=userData`; `DescribeInstances` for enumeration |
| Event source | `ec2.amazonaws.com` |
| Key discriminator | `requestParameters.attribute == "userData"` — without it the call is a benign attribute read |
| Key counting insight | Count distinct `instanceId` whose userData was read; blast radius is "which scripts held secrets", determined by scanning (§4), not by the read count alone |
| Error strings (`Client.`-prefixed for EC2) | `Client.UnauthorizedOperation` (permission denied), `Client.InvalidInstanceID.NotFound` |
| Resources created | None — the emulation and the attack only read |
| Follow-on to watch for | Use of credentials found in user-data (leaked IAM keys, DB logins, third-party tokens) |

### Revert

The emulation creates no infrastructure — `pulumi destroy` is effectively a
no-op and there is nothing to tear down. After a **real** incident, the "revert"
is the §4 work: scrub secrets out of user-data and rotate every exposed
credential. The harvested plaintext cannot be un-read, so rotation is the only
true remediation.
