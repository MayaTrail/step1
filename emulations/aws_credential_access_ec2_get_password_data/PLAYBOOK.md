# IR Playbook: Retrieve EC2 Windows Password Data — Credential Harvesting via `ec2:GetPasswordData`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential Access / Unsecured Credentials |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | Medium (High if the principal is non-human or the calls resolve to real Windows instances) |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1552.005 |
| Services in Scope | EC2, CloudTrail, IAM, SSM (Parameter Store, for key-pair private material) |
| Infrastructure Created | None — this technique provisions no resources |

**What the emulation does:** issues 30 sequential `ec2:GetPasswordData` calls (~0.3 s apart, ~9 s total) against randomly generated, nonexistent instance IDs of the form `i-<17 hex chars>`. Every call fails with `Client.InvalidInstanceID.NotFound`, but each one is recorded in CloudTrail as a management event. The emulation therefore reproduces the *telemetry signature* of Windows credential hunting without ever retrieving a real password.

**Why the failures matter:** a defender must be able to detect this technique when it fails, because a real attacker enumerating instance IDs blindly produces exactly this pattern — and an attacker who has *already* enumerated valid instance IDs produces the same API call with `errorCode` absent. Detections keyed only on success will miss the reconnaissance phase entirely.

**Why retrieval is terminal evidence:** `GetPasswordData` returns the administrator password encrypted with the **public half of the instance's EC2 key pair**. Decryption happens entirely **client-side**, using the PEM private key the operator downloaded at key-pair creation. AWS KMS is not in that path, and no AWS API call is made to decrypt. There is therefore **no follow-on telemetry to wait for** — the `GetPasswordData` call is the last thing you will ever see. Do not build detections that require a confirming downstream event, and never downgrade a retrieval because no such event appeared.

**Why an absent `errorCode` is not proof of disclosure:** the API returns HTTP 200 with an **empty** `PasswordData` field for a Linux instance, for a Windows instance less than ~4 minutes old, and for an instance whose password data is no longer retained. CloudTrail records no `errorCode` in any of those cases and does **not** record whether the response body was populated. A "successful" call is a *candidate* disclosure, to be confirmed against instance facts (Query 3) — not a confirmed one.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail enabled and delivering to S3 with object versioning and MFA delete
- CloudTrail log file validation enabled
- `ec2:GetPasswordData` is a **management event** — it is captured by a default management-events trail with no data-event configuration required. Confirm management events are set to `ReadWriteType: All`; a trail scoped to `WriteOnly` will silently drop this technique entirely
- CloudTrail delivered to CloudWatch Logs (or an equivalent log analytics platform) so that count-over-time queries are possible — point-in-time `lookup-events` alone cannot express the threshold logic this technique requires
- GuardDuty enabled in all regions
- A standing answer to “which principals hold `ec2:GetPasswordData`?” — from IAM Access Advisor, or the policy-scan loop in §4. (IAM **Access Analyzer** does not answer this; it surfaces external/unused access and validates policies)

**Alerting (must be pre-configured)**
- Threshold alert: **more than 3 `ec2:GetPasswordData` calls from a single `userIdentity.arn` within 10 minutes**. This threshold is the single most important control for this technique — see §2 for why an unthresholded rule is unusable
- High-severity alert: any `ec2:GetPasswordData` where `errorCode = Client.InvalidInstanceID.NotFound` occurs **more than 5 times in 10 minutes** from one principal. Legitimate operators query instances that exist; sustained NotFound is enumeration
- Alert on `ec2:GetPasswordData` invoked by any principal in the non-human/service-account inventory. Automation that manages Windows hosts should be an explicit, short allowlist
- Alert on retrieval of key-pair **private** material: `ssm:GetParameter` where `requestParameters.name` begins `/ec2/keypair/` (where the key pair was created via `ec2:CreateKeyPair`, AWS stores the private key there as a SecureString). This is the one genuinely correlated signal — an actor holding both the ciphertext and the private key has the plaintext password
- Do **not** build an alert on `kms:Decrypt` for this technique. EC2 password decryption is client-side and produces no KMS event; such a rule can never fire

**Response Tooling**
- AWS CLI v2 configured with break-glass responder credentials, separate from any principal under investigation
- `jq` installed for JSON parsing
- A current inventory of Windows EC2 instances per account and region — needed to answer "did any of these instance IDs actually exist?" in minutes rather than hours
- A documented allowlist of principals expected to call `ec2:GetPasswordData` (typically: the Windows provisioning pipeline role, and named platform engineers)

**Known IOC Baselines**
- Baseline the normal daily call volume of `ec2:GetPasswordData` per principal. In most accounts this is **zero or near-zero**; where it is not, it is a single automation role with a predictable rate
- Baseline which regions host Windows instances. A `GetPasswordData` call in a region with no Windows footprint is anomalous regardless of volume

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ec2:GetPasswordData` **succeeding** for a principal absent from the Windows-operations allowlist | CloudTrail | T1552.005 |
| P0 | `ec2:GetPasswordData` ≥ 10 calls in 10 min from one `userIdentity.arn` with ≥ 80% `errorCode = Client.InvalidInstanceID.NotFound` | CloudTrail | T1552.005 |
| P1 | `ec2:GetPasswordData` from a principal whose credentials were used from a new ASN/geography in the same session | CloudTrail | T1552.005 |
| P1 | `ec2:GetPasswordData` preceded by `ec2:DescribeInstances` filtered on `platform=windows`, and followed by `ssm:GetParameter` on `/ec2/keypair/*` or `ec2:DescribeKeyPairs`, from the same session | CloudTrail | T1552.005 |
| P1 | `ec2:GetPasswordData` called against instance IDs spanning multiple accounts' ID space, or against IDs never present in any Describe response | CloudTrail | T1552.005 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | > 3 `ec2:GetPasswordData` calls from one `userIdentity.arn` in 10 min (the baseline threshold) | CloudTrail | T1552.005 |
| P2 | `ec2:GetPasswordData` in a region with no Windows instances | CloudTrail | T1552.005 |
| P2 | `ec2:GetPasswordData` with `errorCode = Client.UnauthorizedOperation` — permission probing; the actor lacks the right but is testing for it | CloudTrail | T1552.005 |
| P2 | `ec2:GetPasswordData` from a long-lived IAM user access key rather than an assumed role | CloudTrail | T1552.005 |
| P3 | Single `ec2:GetPasswordData` call, allowlisted principal, successful, business hours | CloudTrail | T1552.005 |

### Detection Rule Quality Notes

The rules in `detections/` require the following corrections before production deployment. **These are noise defects, not cosmetic ones.**

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma `sigma_t1552_005.yml` matches *every* `GetPasswordData` event with `condition: selection` and no aggregation | Unusable in any account that runs Windows. Retrieving an administrator password is a normal, documented operation; a 1:1 rule generates an alert per legitimate provisioning event and will be muted within a week | Add a count aggregation over `userIdentity.arn`. The technique's signal is *rate*, not *occurrence* |
| Neither rule inspects `errorCode` | Loses the strongest discriminator available. `Client.InvalidInstanceID.NotFound` at volume is enumeration; absent `errorCode` at volume is mass credential retrieval. These are different incidents with different severities and the rules cannot distinguish them | Project and pivot on `errorCode` |
| KQL projects no `errorCode`, `RequestParameters`, or `UserAgent` | An analyst opening the alert cannot triage without re-querying. The instance ID being probed is the primary pivot and it is discarded | Project `ErrorCode`, `RequestParameters`, `UserAgent`, `UserIdentityType` |
| Sigma `level: medium` on an unthresholded rule | Medium severity on a high-frequency benign event is the definition of alert fatigue | `level: low` for the raw event; `level: high` for the thresholded + NotFound variant |
| Header comment "verify acronym casing" left unresolved | `GetPasswordData` casing is correct as written; the stale TODO implies the rule is unvalidated | Resolve or remove |

**Recommended thresholded Sigma logic** (replaces `condition: selection`).

Note the pipe-aggregation form — `condition: selection | count() by userIdentity.arn > 3`, and `timeframe:` inside `detection:` — is **legacy Sigma v1 and was removed from the specification**. pySigma rejects it and no current backend will compile it. Rate logic now lives in a separate *correlation* document:

```yaml
# Document 1 — base rule. Low severity: this fires on every call by design.
title: EC2 GetPasswordData invoked
id: 62d0ec7a-4fb4-527d-ac80-deeddb5616e9
name: ec2_getpassworddata_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'GetPasswordData'
  condition: selection
level: low
---
# Document 2 — correlation. This is the deployable detection.
title: EC2 GetPasswordData burst from a single principal
status: experimental
correlation:
  type: event_count
  rules:
    - ec2_getpassworddata_base
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gt: 3
level: high
```

For the enumeration variant, add a third document: a base rule that also matches
`errorCode|contains: 'InvalidInstanceID.NotFound'`, wrapped in its own
`event_count` correlation with `condition: {gt: 5}` at `level: high`.

**On the error string:** EC2 writes CloudTrail `errorCode` with a `Client.`
prefix — `Client.InvalidInstanceID.NotFound`. The unprefixed form is the *boto3*
`Error.Code` (visible in `attack.py`), and a CloudTrail rule keyed on it matches
nothing. Use `errorCode|contains: 'InvalidInstanceID.NotFound'` so the rule is
tolerant of the prefix, and confirm the exact string against a sample event in
the target account before deploying.

---

### Key Investigation Queries

#### Query 1 — Confirm the technique fired and scope the burst

```bash
# All GetPasswordData events in the last 4 hours, with the pivot fields an
# analyst actually needs: who, which instance, did it succeed
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetPasswordData \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson' | jq -r '{time: .eventTime,
          caller: .userIdentity.arn,
          type: .userIdentity.type,
          instance: .requestParameters.instanceId,
          error: (.errorCode // "SUCCESS"),
          sourceIP: .sourceIPAddress,
          agent: .userAgent}'
```

#### Query 2 — Count calls per principal and compute the NotFound ratio

This is the query that separates the technique from benign use. A principal with
a high call count *and* a high NotFound ratio is enumerating.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetPasswordData \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson' | \
  jq -s -r '
    group_by(.userIdentity.arn)[] |
    {
      principal:   .[0].userIdentity.arn,
      total:       length,
      not_found:   ([.[] | select(.errorCode == "Client.InvalidInstanceID.NotFound")] | length),
      unauthorized:([.[] | select(.errorCode == "Client.UnauthorizedOperation")] | length),
      succeeded:   ([.[] | select(.errorCode == null)] | length),
      first_seen:  ([.[].eventTime] | min),
      last_seen:   ([.[].eventTime] | max),
      source_ips:  ([.[].sourceIPAddress] | unique)
    } |
    . + {not_found_ratio: (if .total > 0 then (.not_found / .total) else 0 end)}
  '
```

Interpretation:
- `not_found_ratio` > 0.8 with `total` > 10 → **enumeration; treat as P0**
- `succeeded` > 0 for a non-allowlisted principal → the ciphertext **may** have been returned. CloudTrail cannot distinguish a populated response from an empty one, so this is not yet proof. Cross-reference each probed instance ID via Query 3 and treat as credential-exposed only those that resolve to a **Windows** instance, **older than ~5 minutes**, **launched with a key pair**. Those, escalate and rotate
- `unauthorized` > 0 → the actor lacked the permission; check what else that session probed

#### Query 3 — Did any probed instance ID ever exist?

The emulation uses fabricated IDs. A real intrusion may not. Confirm which
probed IDs correspond to real instances — those are the hosts to treat as
credential-compromised.

```bash
REGION="us-east-1"

# Extract the probed instance IDs from CloudTrail
PROBED=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetPasswordData \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r '.requestParameters.instanceId' | sort -u)

echo "=== Probed instance IDs: $(echo "$PROBED" | grep -c . ) unique ==="

for IID in $PROBED; do
  RESULT=$(aws ec2 describe-instances --instance-ids "$IID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].{Id:InstanceId,Platform:Platform,State:State.Name,Name:Tags[?Key==`Name`]|[0].Value}' \
    --output json 2>/dev/null)
  if [ -n "$RESULT" ] && [ "$RESULT" != "null" ]; then
    echo "[!] REAL INSTANCE PROBED: $IID"
    echo "$RESULT" | jq -r '.'
  else
    echo "[OK] $IID — does not exist (consistent with blind enumeration)"
  fi
done
```

#### Query 4 — Reconstruct the full session around the burst

`GetPasswordData` rarely appears alone. Pull every action taken by the same
access key to establish whether this was reconnaissance inside a broader
intrusion.

```bash
ACCESS_KEY_ID="<AKIA-or-ASIA-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson' | jq -r '{time: .eventTime, event: .eventName, source: .eventSource,
          error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look specifically for, in order: `ec2:DescribeInstances`, `ssm:DescribeInstanceInformation`,
`ec2:GetPasswordData`, `ssm:GetParameter` on `/ec2/keypair/*`, then any lateral-movement primitive
(`ec2:GetConsoleScreenshot`, `ssm:SendCommand`, `ec2-instance-connect:SendSSHPublicKey`).

#### Query 5 — Did the actor also obtain the private key?

Retrieval of the ciphertext alone does not equal plaintext compromise — the
actor also needs the key pair's private key. **Decryption itself is invisible:**
it happens client-side with the PEM file and generates no AWS event. So there is
no "was it decrypted?" query to run. What you *can* determine is whether the
actor had the means.

Key pairs created through `ec2:CreateKeyPair` have their private key stored in
SSM Parameter Store as a SecureString under `/ec2/keypair/<key-pair-id>`.
Retrieval of that parameter is the observable event.

```bash
SUSPECT_ARN="<principal-arn-from-Query-2>"

# Private key material pulled from Parameter Store
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetParameter \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '
    .Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.name | tostring | startswith("/ec2/keypair/")) |
    {time: .eventTime, parameter: .requestParameters.name,
     decrypted: .requestParameters.withDecryption, ip: .sourceIPAddress}'

# Key-pair enumeration — reconnaissance for which keys are worth stealing
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeKeyPairs \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '
    .Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    {time: .eventTime, ip: .sourceIPAddress}'
```

If the key pair was created outside AWS and imported (`ec2:ImportKeyPair`), AWS
never held the private key and this query returns nothing — which tells you
nothing about the actor's access. In that case, fall back to evidence of *use*:
VPC Flow Logs showing inbound 3389/RDP to the probed instance from an
unrecognised source after the retrieval timestamp.

**Treat the absence of all of the above as inconclusive, never as exoneration.**

#### Query 6 — Multi-region sweep

The emulation targets one region, but a real actor enumerates broadly and
CloudTrail management events are per-region.

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
  COUNT=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetPasswordData \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" \
    --query 'length(Events)' --output text 2>/dev/null)

  if [ -n "$COUNT" ] && [ "$COUNT" != "0" ] && [ "$COUNT" != "None" ]; then
    echo "[!] $REGION — $COUNT GetPasswordData events"

    # Flag regions with no Windows footprint: any call here is anomalous
    WIN=$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=platform,Values=windows" \
                "Name=instance-state-name,Values=running,stopped" \
      --query 'length(Reservations[].Instances[])' --output text 2>/dev/null)
    [ "$WIN" = "0" ] && echo "    [!!] No Windows instances in $REGION — calls are unexplained"
  fi
done
```

#### Query 7 — Log-analytics threshold query (deployable detection)

Point-in-time CLI lookups cannot express the rate condition, so the standing
detection has to live in a log platform.

**Dialect warning:** the query below is **Sentinel / Azure Log Analytics KQL**.
It is *not* runnable in CloudWatch Logs Insights, which uses a different query
language entirely — `summarize`, `make_set`, `case()`, `bin()` and the
`AWSCloudTrail` table do not exist there. Run it on the matching engine, or use
the CloudWatch Logs Insights equivalent that follows.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "ec2.amazonaws.com"
| where EventName == "GetPasswordData"
| extend ProbedInstance = tostring(parse_json(column_ifexists("RequestParameters", "{}")).instanceId)
| summarize
    Calls          = count(),
    NotFound       = countif(ErrorCode == "Client.InvalidInstanceID.NotFound"),
    Unauthorized   = countif(ErrorCode == "Client.UnauthorizedOperation"),
    Succeeded      = countif(isempty(ErrorCode)),
    UniqueTargets  = dcount(ProbedInstance),
    SourceIPs      = make_set(SourceIpAddress, 10),
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated)
    by UserIdentityArn, bin(TimeGenerated, 10m)
| extend NotFoundRatio = round(todouble(NotFound) / todouble(Calls), 2)
| where Calls > 3
// Succeeded > 0 must be the SOLE first predicate. An actor who enumerates 40
// IDs and lands on 3 real Windows hosts has Succeeded=3 AND NotFoundRatio=0.92;
// any conjunction here misfiles a real disclosure as enumeration.
| extend Verdict = case(
    Succeeded > 0,                         "POSSIBLE RETRIEVAL — confirm via Query 3, then escalate",
    NotFoundRatio >= 0.8 and Calls >= 10,  "ENUMERATION — P0",
    Unauthorized > 0,                      "PERMISSION PROBING",
    "REVIEW")
| project TimeGenerated, UserIdentityArn, Calls, Succeeded, NotFound,
          NotFoundRatio, UniqueTargets, SourceIPs, Verdict
| order by Calls desc
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Containment scope depends on what Query 2 returned. **If `succeeded = 0` and all
errors are `Client.InvalidInstanceID.NotFound`, no password was disclosed** — contain the
principal, but do not trigger a Windows-wide password rotation.

If `succeeded > 0`, do **not** jump straight to isolation and rotation. A 200
response with an empty body looks identical in CloudTrail to a real disclosure.
First run Query 3 and keep only the probed instance IDs that resolve to a
**Windows** instance **older than ~5 minutes** that was **launched with a key
pair** — those are genuinely credential-exposed. Steps 4 and 5 apply to that
filtered set only. Isolating and snapshotting a host on an empty-response false
positive costs an outage for nothing.

**Sequencing warning:** Step 4's quarantine security group removes all egress,
which severs the SSM Agent's outbound 443. The password rotation in §4 depends
on SSM. Either perform the §4 rotation **before** Step 4, or use the
SSM-permitting variant of the quarantine SG given in Step 4.

#### Step 1 — Identify and disable the offending credential

```bash
SUSPECT_ARN="<principal-arn-from-Query-2>"
REGION="us-east-1"

# Determine whether this is an IAM user key or an assumed-role session
echo "$SUSPECT_ARN" | grep -q ":assumed-role/" && SESSION_TYPE="role" || SESSION_TYPE="user"
echo "Principal type: $SESSION_TYPE"

if [ "$SESSION_TYPE" == "user" ]; then
  VICTIM_USER=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')

  aws iam list-access-keys --user-name "$VICTIM_USER" \
    --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}' \
    --output table

  # Disable, do NOT delete — the key is forensic evidence
  COMPROMISED_KEY_ID="<key-id-from-above>"
  aws iam update-access-key \
    --user-name "$VICTIM_USER" \
    --access-key-id "$COMPROMISED_KEY_ID" \
    --status Inactive

  echo "[OK] Key $COMPROMISED_KEY_ID disabled for $VICTIM_USER"
fi
```

#### Step 2 — Revoke live STS sessions

Disabling an access key does **not** invalidate STS tokens already minted from
it. Those remain valid for their full TTL (up to 12 hours) and will continue to
work. Revoke by token issue time.

```bash
VICTIM_USER="<victim-iam-username>"

aws iam put-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
      }
    }]
  }'

echo "[OK] Session revocation policy applied to $VICTIM_USER"
```

For an assumed-role principal, apply the equivalent at the role:

```bash
SUSPECT_ROLE="<role-name>"

aws iam put-role-policy \
  --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
      }
    }]
  }'
```

#### Step 3 — Strip `ec2:GetPasswordData` from the principal pending investigation

A narrower alternative to full session revocation when the principal is a
production automation role that must keep running.

```bash
SUSPECT_ROLE="<role-name>"

aws iam put-role-policy \
  --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyPasswordData" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": [
        "ec2:GetPasswordData",
        "ec2:GetConsoleOutput",
        "ec2:GetConsoleScreenshot"
      ],
      "Resource": "*"
    }]
  }'

echo "[OK] GetPasswordData denied for $SUSPECT_ROLE"
```

#### Step 4 — Isolate any Windows instance confirmed credential-exposed

Only for instances that survived the Query 3 filter above — Windows, older than
~5 minutes, launched with a key pair. Move each to a quarantine security group,
preserving it for forensics.

**Choose the quarantine profile deliberately:**

| Profile | Egress | Trade-off |
|---------|--------|-----------|
| `strict` | none | Maximum containment. **Forfeits SSM-based remediation** — the §4 password rotation will hang in `Pending` and time out. Use only when rotating out of band |
| `ssm-permitting` | 443 to SSM endpoints only | Retains remote remediation. The instance can still reach the AWS control plane, which is a residual risk if the host itself is attacker-controlled |

The script below builds `ssm-permitting`, because the documented remediation
path in §4 depends on it. Switch `ALLOW_SSM=false` for `strict`.

```bash
REGION="us-east-1"
COMPROMISED_INSTANCE="<i-xxxxxxxxxxxx>"
ALLOW_SSM=true   # false => strict, zero-egress quarantine

VPC_ID=$(aws ec2 describe-instances --instance-ids "$COMPROMISED_INSTANCE" \
  --region "$REGION" --query 'Reservations[0].Instances[0].VpcId' --output text)

# RECORD the original security groups BEFORE overwriting them — §5's restore
# step has nothing to restore to otherwise
aws ec2 describe-instances --instance-ids "$COMPROMISED_INSTANCE" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[*].{ENI:NetworkInterfaceId,SGs:Groups[*].GroupId}' \
  --output json | tee "./ir-original-sgs-$COMPROMISED_INSTANCE.json"
echo "[OK] Original SG mapping saved to ./ir-original-sgs-$COMPROMISED_INSTANCE.json"

QUARANTINE_SG=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=ir-quarantine" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)

if [ "$QUARANTINE_SG" = "None" ] || [ -z "$QUARANTINE_SG" ]; then
  QUARANTINE_SG=$(aws ec2 create-security-group \
    --group-name "ir-quarantine" \
    --description "IR isolation" \
    --vpc-id "$VPC_ID" --region "$REGION" \
    --query 'GroupId' --output text) || { echo "[FAIL] Could not create SG"; exit 1; }

  # Strip the implicit allow-all egress. Check the exit status — a silent
  # failure here leaves a "quarantine" SG with full internet egress.
  if aws ec2 revoke-security-group-egress --group-id "$QUARANTINE_SG" \
       --region "$REGION" \
       --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'; then
    echo "[OK] Default egress removed from $QUARANTINE_SG"
  else
    echo "[FAIL] Default egress NOT removed — $QUARANTINE_SG is not a quarantine SG"
    exit 1
  fi

  if [ "$ALLOW_SSM" = "true" ]; then
    # SSM Agent needs 443 to ssm./ec2messages./ssmmessages. endpoints.
    # Scope to the VPC CIDR if you have SSM interface endpoints; otherwise the
    # regional prefix list for the service.
    VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --region "$REGION" \
      --query 'Vpcs[0].CidrBlock' --output text)
    aws ec2 authorize-security-group-egress --group-id "$QUARANTINE_SG" \
      --region "$REGION" \
      --ip-permissions "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=$VPC_CIDR,Description=SSM-endpoints}]" && \
      echo "[OK] 443 egress to $VPC_CIDR permitted for SSM"
  fi
  echo "[OK] Created quarantine SG $QUARANTINE_SG"
fi

# modify-instance-attribute --groups REJECTS instances with multiple ENIs.
# Apply per-interface when there is more than one.
ENI_COUNT=$(aws ec2 describe-instances --instance-ids "$COMPROMISED_INSTANCE" \
  --region "$REGION" \
  --query 'length(Reservations[0].Instances[0].NetworkInterfaces)' --output text)

if [ "$ENI_COUNT" -gt 1 ]; then
  for ENI in $(aws ec2 describe-instances --instance-ids "$COMPROMISED_INSTANCE" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].NetworkInterfaces[*].NetworkInterfaceId' \
    --output text); do
    aws ec2 modify-network-interface-attribute --network-interface-id "$ENI" \
      --groups "$QUARANTINE_SG" --region "$REGION" && \
      echo "[OK] ENI $ENI quarantined"
  done
else
  aws ec2 modify-instance-attribute \
    --instance-id "$COMPROMISED_INSTANCE" \
    --groups "$QUARANTINE_SG" --region "$REGION" && \
    echo "[OK] $COMPROMISED_INSTANCE isolated into $QUARANTINE_SG"
fi
```

#### Step 5 — Snapshot before any further change

```bash
REGION="us-east-1"
COMPROMISED_INSTANCE="<i-xxxxxxxxxxxx>"

for VOL in $(aws ec2 describe-instances --instance-ids "$COMPROMISED_INSTANCE" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' \
  --output text); do
  aws ec2 create-snapshot --volume-id "$VOL" --region "$REGION" \
    --description "IR-T1552.005-$COMPROMISED_INSTANCE-$(date -u +%Y%m%dT%H%M%SZ)" \
    --query 'SnapshotId' --output text
  echo "[OK] Snapshot initiated for $VOL"
done
```

---

## 4. Eradication

### Remove Attacker Access

#### Rotate the local Windows administrator password on affected instances

`GetPasswordData` returns the password generated at first boot. That value is
static for the life of the instance unless rotated — so a successful retrieval
means the credential remains valid indefinitely. This step is mandatory for
every instance where `succeeded > 0`.

```bash
REGION="us-east-1"
COMPROMISED_INSTANCE="<i-xxxxxxxxxxxx>"

# 1. Pre-create the new password in Secrets Manager. Generate it HERE, not on
#    the host — a password generated in-guest and not written anywhere locks you
#    out of the very account you are trying to recover.
SECRET_NAME="ir/t1552-005/$COMPROMISED_INSTANCE/administrator"

NEW_PASSWORD=$(aws secretsmanager get-random-password \
  --password-length 32 --require-each-included-type \
  --exclude-characters '"@/\' \
  --query 'RandomPassword' --output text)

aws secretsmanager create-secret \
  --name "$SECRET_NAME" \
  --description "IR T1552.005 rotated Administrator password" \
  --secret-string "$NEW_PASSWORD" \
  --region "$REGION" \
  --query 'ARN' --output text

# 2. Have the instance READ the secret and apply it. The instance profile needs
#    secretsmanager:GetSecretValue on this secret ARN.
#    NOTE: --parameters must use JSON form. The shorthand `commands=[...]`
#    parser cannot survive a payload containing commas and brackets.
aws ssm send-command \
  --instance-ids "$COMPROMISED_INSTANCE" \
  --document-name "AWS-RunPowerShellScript" \
  --region "$REGION" \
  --comment "IR T1552.005 - rotate local administrator password" \
  --parameters "$(jq -n --arg secret "$SECRET_NAME" --arg region "$REGION" '{
    commands: [
      "$ErrorActionPreference = \"Stop\"",
      ("$Secret = (Get-SECSecretValue -SecretId \"" + $secret + "\" -Region " + $region + ").SecretString"),
      "$SecurePassword = ConvertTo-SecureString $Secret -AsPlainText -Force",
      "$Admin = Get-LocalUser | Where-Object { $_.SID.Value -like \"*-500\" }",
      "if (-not $Admin) { throw \"No built-in Administrator (RID 500) found\" }",
      "Set-LocalUser -InputObject $Admin -Password $SecurePassword",
      "Write-Output \"Rotated: $($Admin.Name)\""
    ]
  }')" \
  --query 'Command.CommandId' --output text
```

Two details that matter:

- The password is **never generated in-guest and discarded**. It is created in
  Secrets Manager first, so the operator retains access after rotation.
- The account is targeted **by RID 500**, not by the name `Administrator`.
  Renaming the built-in administrator account is a standard hardening step, and
  `Set-LocalUser -Name Administrator` fails outright on any host where it was
  applied.

**If SSM is unavailable**, rotate out of band: stop the instance, detach the
root volume, attach it to a recovery host, and clear the credential offline. Do
not use `ec2:GetPasswordData` itself as part of remediation.

#### Invalidate the EC2 key pair used to encrypt the password

```bash
REGION="us-east-1"
KEY_NAME="<key-pair-name-from-describe-instances>"

# Confirm which instances depend on this key pair before deleting
aws ec2 describe-instances --region "$REGION" \
  --filters "Name=key-name,Values=$KEY_NAME" \
  --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name}' \
  --output table

# Delete only after the dependency list is understood and passwords are rotated
aws ec2 delete-key-pair --key-name "$KEY_NAME" --region "$REGION" && \
  echo "[OK] Key pair $KEY_NAME deleted"
```

**Be precise about what this achieves — it is less than it appears.**
`ec2:delete-key-pair` removes only AWS's stored record of the **public** key. It
does not touch any copy of the private key the attacker holds, and any password
ciphertext already retrieved remains decryptable offline **forever**. Deleting
the key pair prevents exactly one thing: future launches referencing that key
name.

Password rotation (above) is the only control that actually revokes the
attacker's access. Do not close the incident on the strength of this step.

#### Remove the compromised access key

```bash
VICTIM_USER="<victim-iam-username>"
COMPROMISED_KEY_ID="<key-id>"

# Safe to delete now: the key has been Inactive since containment and CloudTrail
# has preserved its full activity history
aws iam delete-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID"

aws iam create-access-key --user-name "$VICTIM_USER" \
  --query 'AccessKey.{AccessKeyId:AccessKeyId,SecretAccessKey:SecretAccessKey}'

# Remove the emergency revocation policy once the new key is distributed
aws iam delete-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "EmergencyRevokeSessions"
```

#### Right-size the permission that allowed this

```bash
SUSPECT_ROLE="<role-name>"

# Which policies grant ec2:GetPasswordData to this principal
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" \
  --query 'AttachedPolicies[*].PolicyArn' --output text | \
  while read -r ARN; do
    VERSION=$(aws iam get-policy --policy-arn "$ARN" \
      --query 'Policy.DefaultVersionId' --output text)
    aws iam get-policy-version --policy-arn "$ARN" --version-id "$VERSION" \
      --query 'PolicyVersion.Document' --output json | \
      jq -e '.Statement[] | select(
        (.Action | if type == "array" then . else [.] end) |
        any(. == "ec2:*" or . == "*" or . == "ec2:GetPasswordData"))' >/dev/null && \
      echo "[!] $ARN grants GetPasswordData (directly or via wildcard)"
  done

# Remove the emergency deny once the underlying policy is corrected
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyPasswordData" 2>/dev/null
```

---

## 5. Recovery

### Restore Clean State

#### Verify the offending credential is dead

```bash
SUSPECT_ARN="<principal-arn>"

# Containment Step 1 branched on user vs assumed-role; this verification must
# branch the same way. Checking list-access-keys is meaningless for a role session.
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  SUSPECT_ROLE=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')

  # a) The emergency deny is still attached
  if aws iam get-role-policy --role-name "$SUSPECT_ROLE" \
       --policy-name "EmergencyDenyPasswordData" >/dev/null 2>&1; then
    echo "[OK] EmergencyDenyPasswordData still attached to $SUSPECT_ROLE"
  else
    echo "[FAIL] Deny policy missing from $SUSPECT_ROLE — role is unconstrained"
  fi

  # b) No successful AssumeRole for this role since containment
  CONTAINED_AT="<iso8601-containment-timestamp>"
  NEW_SESSIONS=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time "$CONTAINED_AT" --region us-east-1 --output json | \
    jq -r --arg role "$SUSPECT_ROLE" '
      .Events[].CloudTrailEvent | fromjson |
      select(.errorCode == null) |
      select((.requestParameters.roleArn // "") | contains($role)) | .eventTime' | wc -l)

  if [ "$NEW_SESSIONS" -eq 0 ]; then
    echo "[OK] No successful AssumeRole for $SUSPECT_ROLE since containment"
  else
    echo "[FAIL] $NEW_SESSIONS new sessions minted for $SUSPECT_ROLE after containment"
  fi
else
  VICTIM_USER=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  COMPROMISED_KEY_ID="<key-id>"

  RESULT=$(aws iam list-access-keys --user-name "$VICTIM_USER" \
    --query "AccessKeyMetadata[?AccessKeyId=='$COMPROMISED_KEY_ID']" --output text)

  if [ -z "$RESULT" ]; then
    echo "[OK] Compromised key $COMPROMISED_KEY_ID confirmed removed"
  else
    echo "[FAIL] Key $COMPROMISED_KEY_ID still present: $RESULT"
  fi
fi
```

#### Verify no further `GetPasswordData` from the suspect principal

```bash
SUSPECT_ARN="<principal-arn>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetPasswordData \
  --start-time "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '
    .Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)

if [ "$COUNT" -eq 0 ]; then
  echo "[OK] No GetPasswordData activity from $SUSPECT_ARN in the last hour"
else
  echo "[FAIL] $COUNT further calls from $SUSPECT_ARN — containment did not hold"
fi
```

#### Verify Windows password rotation completed

```bash
REGION="us-east-1"
COMMAND_ID="<command-id-from-eradication>"
COMPROMISED_INSTANCE="<i-xxxxxxxxxxxx>"

STATUS=$(aws ssm get-command-invocation \
  --command-id "$COMMAND_ID" \
  --instance-id "$COMPROMISED_INSTANCE" \
  --region "$REGION" \
  --query 'Status' --output text 2>/dev/null)

if [ "$STATUS" == "Success" ]; then
  echo "[OK] Administrator password rotated on $COMPROMISED_INSTANCE"
else
  echo "[FAIL] Rotation status: $STATUS — rotate out of band before restoring the host"
fi
```

#### Verify CloudTrail captured the full window

If management-event logging was misconfigured, the investigation above is
incomplete and the scope conclusion cannot be trusted.

```bash
for TRAIL in $(aws cloudtrail describe-trails \
  --query 'trailList[*].Name' --output text); do
  echo "=== $TRAIL ==="
  aws cloudtrail get-trail-status --name "$TRAIL" \
    --query '{IsLogging:IsLogging,LatestDeliveryError:LatestDeliveryError}'

  # Confirm read events are captured — WriteOnly trails miss this technique
  # entirely. Trails using ADVANCED event selectors return an EMPTY
  # EventSelectors list, so both shapes must be queried or this check silently
  # passes on the exact misconfiguration it exists to catch.
  aws cloudtrail get-event-selectors --trail-name "$TRAIL" \
    --query 'EventSelectors[*].{ReadWriteType:ReadWriteType,Management:IncludeManagementEvents}' \
    --output table

  aws cloudtrail get-event-selectors --trail-name "$TRAIL" \
    --query 'AdvancedEventSelectors[*].{Name:Name,ReadOnly:FieldSelectors[?Field==`readOnly`].Equals|[0]}' \
    --output table
done
```

Any trail reporting `ReadWriteType: WriteOnly` **cannot detect this technique**.
Treat that as a P1 gap and remediate before closing the incident.

#### Restore the isolated instance

```bash
REGION="us-east-1"
COMPROMISED_INSTANCE="<i-xxxxxxxxxxxx>"
SG_BACKUP="./ir-original-sgs-$COMPROMISED_INSTANCE.json"   # written by Containment Step 4

# Only after: password rotated, key pair replaced, host forensics complete
if [ ! -f "$SG_BACKUP" ]; then
  echo "[FAIL] No SG backup at $SG_BACKUP — original groups unknown; restore manually"
  exit 1
fi

jq -c '.[]' "$SG_BACKUP" | while read -r ROW; do
  ENI=$(echo "$ROW" | jq -r '.ENI')
  SGS=$(echo "$ROW" | jq -r '.SGs | join(" ")')
  aws ec2 modify-network-interface-attribute \
    --network-interface-id "$ENI" \
    --groups $SGS --region "$REGION" && \
    echo "[OK] $ENI restored to: $SGS"
done"
```

#### Confirm the corrected detections are live

```bash
# Re-run the emulation in a controlled window, then ASSERT the telemetry it
# should have produced. A detection never tested against its own technique is
# unproven, and an echo of expectations proves nothing.
TEST_PRINCIPAL="<arn-used-for-the-emulation-run>"
REGION="us-east-1"

RESULT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetPasswordData \
  --start-time "$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$TEST_PRINCIPAL" '
    [ .Events[].CloudTrailEvent | fromjson | select(.userIdentity.arn == $arn) ] |
    {
      total:     length,
      not_found: ([.[] | select((.errorCode // "") | test("InvalidInstanceID.NotFound"))] | length),
      unique:    ([.[].requestParameters.instanceId] | unique | length)
    }')

TOTAL=$(echo "$RESULT"     | jq -r '.total')
NOTFOUND=$(echo "$RESULT"  | jq -r '.not_found')
UNIQUE=$(echo "$RESULT"    | jq -r '.unique')

echo "Observed: total=$TOTAL not_found=$NOTFOUND unique_targets=$UNIQUE"

[ "$TOTAL" -eq 30 ]    && echo "[OK] 30 events captured" \
                       || echo "[FAIL] Expected 30 events, saw $TOTAL — trail may be WriteOnly or delayed"
[ "$NOTFOUND" -eq 30 ] && echo "[OK] errorCode matching works (30/30 NotFound)" \
                       || echo "[FAIL] Only $NOTFOUND/30 matched — verify the Client. prefix in your rules"
[ "$UNIQUE" -eq 30 ]   && echo "[OK] 30 distinct instance IDs probed" \
                       || echo "[FAIL] Expected 30 unique targets, saw $UNIQUE"

echo "Now confirm the deployed rule produced exactly ONE alert, not 30."
echo "One alert => the correlation threshold works. 30 => still unthresholded."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal was able to call `ec2:GetPasswordData` 30 times without interruption | No rate-based detection on the API; the shipped rule was unthresholded and had been muted as noise |
| Enumeration against nonexistent instance IDs went unremarked | `errorCode` was not part of any detection or dashboard, so failed reconnaissance was invisible |
| The principal held `ec2:GetPasswordData` at all | Permission granted via `ec2:*` or a broad managed policy rather than scoped to the Windows provisioning role |
| Windows administrator passwords are static from first boot | No rotation policy for local administrator credentials after instance launch; retrieval once equals access forever |
| Retrieval was treated as needing downstream confirmation | Decryption of the returned blob is client-side and emits no AWS telemetry, so no confirming event exists. Any detection design that waits for one will never escalate a real retrieval |

### Recommended Guardrails

**Service Control Policies (SCPs) — apply at OU level**

```json
// SCP 1: Restrict GetPasswordData to the Windows provisioning role
{
  "Effect": "Deny",
  "Action": "ec2:GetPasswordData",
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/WindowsProvisioningRole",
        "arn:aws:iam::*:role/BreakGlassAdmin"
      ]
    }
  }
}
```

```json
// SCP 2: Deny GetPasswordData outside regions with a Windows footprint
{
  "Effect": "Deny",
  "Action": "ec2:GetPasswordData",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": ["us-east-1", "eu-west-1"]
    }
  }
}
```

**Eliminate the credential's value**
- Join Windows instances to a directory service (AWS Managed Microsoft AD) so authentication does not depend on a local administrator password recoverable through the EC2 API
- Where a local administrator account is unavoidable, rotate it on first boot via user data or SSM State Manager, so the value returned by `GetPasswordData` is stale by the time any attacker can retrieve it
- Manage the rotated credential in Secrets Manager with automatic rotation; access it via `secretsmanager:GetSecretValue`, which is separately auditable and alertable

**Least-privilege IAM baseline**
- No principal should hold `ec2:*`. `ec2:GetPasswordData`, `ec2:GetConsoleOutput`, and `ec2:GetConsoleScreenshot` are credential-adjacent reads and belong in a separately reviewed permission set
- Audit for wildcard grants quarterly using the policy-scan loop in §4

**Detection improvements**
- Deploy the thresholded rule (> 3 calls / 10 min / principal) and the enumeration rule (> 5 `Client.InvalidInstanceID.NotFound` / 10 min / principal) as **separate** detections at different severities
- Add `errorCode` to every EC2 credential-access detection — failed reconnaissance is the earliest available signal
- Add a correlation rule: `ec2:GetPasswordData` (no `errorCode`) followed within 15 minutes by `ssm:GetParameter` on `/ec2/keypair/*` from the same principal → P0. Do **not** write the equivalent rule against `kms:Decrypt` — that event does not occur for this technique
- Alert on any `ec2:GetPasswordData` in a region with zero Windows instances, at any volume
- Dashboard the per-principal daily call count so that a baseline exists to threshold against

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| MITRE tactic | Credential Access (TA0006) |
| API call | `ec2:GetPasswordData` |
| Event source | `ec2.amazonaws.com` |
| Emulation signature | 30 calls, ~0.3 s apart, instance IDs matching `i-[0-9a-f]{17}` |
| Expected error | `Client.InvalidInstanceID.NotFound` — effectively all emulated calls (a collision with a live instance ID is negligible but not impossible) |
| Alternate error | `Client.UnauthorizedOperation` (principal lacks the permission) |
| Resources created | None — no infrastructure, no cost, nothing to destroy |
| Recommended threshold | > 3 calls per principal per 10 minutes |
| Follow-on to watch for | `ssm:GetParameter` on `/ec2/keypair/*`, `ec2:DescribeKeyPairs`, `ec2:GetConsoleScreenshot`, `ssm:SendCommand`, `ec2-instance-connect:SendSSHPublicKey` |
| No-telemetry gap | Decryption of the password blob is client-side — it produces **no** AWS event. Retrieval is the last observable signal |

### Revert

This emulation creates no AWS resources. `pulumi destroy` is a no-op beyond
tearing down the empty stack. No cleanup of attacker artifacts is required after
an emulation run — the only residue is the CloudTrail events themselves, which
should be **retained** as detection-validation evidence.
