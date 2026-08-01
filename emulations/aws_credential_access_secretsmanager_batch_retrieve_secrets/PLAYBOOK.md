# IR Playbook: Retrieve a High Number of Secrets Manager Secrets via Batch — Bulk Secret Exfiltration through `secretsmanager:BatchGetSecretValue`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential Access / Credentials from Password Stores |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High — every secret returned is disclosed plaintext and must be treated as compromised (`MANIFEST.py` rates MEDIUM; the IR view is High because this exfiltrates live secret material, not just a log signal) |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1555 |
| Services in Scope | Secrets Manager, CloudTrail, IAM, KMS, plus every downstream system whose credentials live in the retrieved secrets |
| Infrastructure Created | 20 Secrets Manager secrets (via `infra/`) |

**What the emulation does:** enumerates secrets with `secretsmanager:ListSecrets` (filtered by a tag), then calls `secretsmanager:BatchGetSecretValue` in batches of 10 to retrieve their plaintext values in bulk. Against the emulation's 20 test secrets that is two batch calls; the pattern is deliberately efficient — one API call pulls up to 20 secret values at once.

**Why the batch API changes triage.** `BatchGetSecretValue` (released late 2023) lets an attacker retrieve many secrets per call instead of one `GetSecretValue` per secret. Two subtleties both matter, and they pull in opposite directions:
- A naive rule that alerts once per `BatchGetSecretValue` **event** undercounts the blast radius — two events can be twenty secrets.
- But Secrets Manager *also* emits a separate `GetSecretValue` CloudTrail entry for **each** secret in the batch. So a rule that sums the batch event's `secretIdList` size *plus* those per-secret `GetSecretValue` events **double-counts** by ~2×.

The correct measure is neither: **count distinct `secretId` from `GetSecretValue` events, from that one source.** It is complete (the batch API emits it per secret) and self-deduplicating. Every query and threshold in this playbook uses that single-source distinct count.

**Why this is High, not Medium.** Unlike an enumeration technique that only probes, this one *succeeds*: at the end of a run the attacker holds the plaintext of every secret returned. Those secrets are database passwords, API keys, and tokens for other systems. Rotation of all disclosed secrets is mandatory — the incident does not end when the AWS access is contained, because the leaked credentials remain valid on their downstream systems.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for rate queries
- **`GetSecretValue` and `BatchGetSecretValue` are management events and are captured by default** — no data-event configuration is required (unlike S3/Lambda data events). Confirm `ReadWriteType: All`; a `WriteOnly` trail drops both, since secret *reads* are read events
- CloudTrail records `requestParameters.secretIdList` for `BatchGetSecretValue` and `requestParameters.secretId` for `GetSecretValue`, so the specific secrets touched are recoverable. Importantly, Secrets Manager also emits a **per-secret `GetSecretValue` entry for every secret in a batch call** — so a batch request for N secrets produces one `BatchGetSecretValue` event plus N `GetSecretValue` events. Those per-secret entries are the authoritative record of *which* secrets were accessed, and (per AWS behaviour, confirm in your account) a failed secret carries an `errorCode` on its spawned entry, so disclosed-vs-denied is at least partially recoverable. Count secrets from the per-secret `GetSecretValue` entries, not by summing across both event types
- Secrets Manager resource policies and KMS key grants inventoried, so "who could read this secret" is answerable

**Alerting (must be pre-configured)**
- Threshold alert on **distinct secrets retrieved per principal per window** — count distinct `secretId` from `GetSecretValue` events (a batch call emits one per secret, so this single source is complete): more than ~15 distinct secrets in 10 minutes from one principal → page. This is the primary control and it must count distinct secrets, not events, and must not sum the batch event against its per-secret entries
- Any use of `BatchGetSecretValue` by a principal not on the small allowlist of applications/roles known to use the batch API — most workloads call `GetSecretValue` for the one secret they need; bulk retrieval is characteristic of exfiltration tooling
- `ListSecrets` (broad enumeration) immediately followed by `BatchGetSecretValue` from the same session — the enumerate-then-sweep pattern
- Retrieval of secrets spanning multiple unrelated applications by a single principal in one window (a web app reading the DB and payments secrets is normal; one principal reading 20 secrets across every app is not)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- A secret → downstream-system map: for each secret, what it authenticates to and how to rotate it. Bulk secret theft is only containable as fast as you can rotate the leaked credentials
- Rotation Lambdas configured and tested for high-value secrets, so mass rotation is a command, not a project

**Known IOC Baselines**
- Baseline which principals call `BatchGetSecretValue` at all — normally a very short list, often empty
- Baseline the normal per-principal secret-read volume. Most principals read a small, stable set of secrets; a sudden broad sweep is the signal
- Tag secrets by owning application so cross-application retrieval is detectable

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | > 15 distinct secrets retrieved (distinct `secretId` on `GetSecretValue` events — the per-secret entries a batch call also emits) by one principal in 10 min | CloudTrail | T1555 |
| P0 | `BatchGetSecretValue` from a principal not on the batch-API allowlist | CloudTrail | T1555 |
| P1 | `ListSecrets` (or `ListSecrets` with broad/no filter) followed within minutes by `BatchGetSecretValue` from the same session | CloudTrail | T1555 |
| P1 | Secrets spanning multiple unrelated applications retrieved by one principal in one window | CloudTrail | T1555 |
| P1 | `BatchGetSecretValue`/`GetSecretValue` from an off-baseline ASN/geography for the principal | CloudTrail | T1555 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Any single `BatchGetSecretValue` with a large `secretIdList` (≥ 10) | CloudTrail | T1555 |
| P2 | `GetSecretValue` in a tight loop over many distinct `secretId`s (the pre-batch-API version of the same attack) | CloudTrail | T1555 |
| P2 | `secretsmanager:GetSecretValue` denied at volume (`errorCode = AccessDenied` or `AccessDeniedException`) — permission probing across secrets | CloudTrail | T1555 |
| P3 | Single `BatchGetSecretValue` with a small list from an allowlisted application principal | CloudTrail | T1555 |

### Detection Rule Quality Notes

The rules in `detections/` are too coarse to deploy. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (ListSecrets, BatchGetSecretValue)` with `condition: selection`, no threshold | Noisy and imprecise. `ListSecrets` is a routine, high-frequency call (consoles, IaC, inventory tooling) — a 1:1 rule on it floods the queue. Bundling it with `BatchGetSecretValue` as an OR means the alert cannot tell enumeration from retrieval | Separate the two. Alert `BatchGetSecretValue` on its own (rarer, higher signal); use `ListSecrets` only as correlation context, never as a standalone trigger |
| No counting of **secrets**, only implicit event matching | The technique's severity scales with secrets retrieved, which raw event-matching ignores | Threshold on **distinct `secretId` from `GetSecretValue` events** per principal per window. A batch call emits one per-secret `GetSecretValue` entry per secret, so this single source is complete — never sum it with an expanded `secretIdList`, which double-counts |
| `GetSecretValue` — the far more common variant of the same attack — is absent | A rule that watches only the batch API misses an attacker who loops `GetSecretValue`, and misses every pre-2023 tool | Include `GetSecretValue` in the volume threshold |
| No principal allowlist or `sourceIPAddress` context | Cannot distinguish the one legitimate batch-consumer app from an attacker | Add allowlist + off-baseline-IP as separate signals |
| Header TODO "verify acronym casing" unresolved; `level: medium` on a rule dominated by benign `ListSecrets` | Stale validation marker; guaranteed alert fatigue | Resolve TODO; `ListSecrets`-inclusive rule → `level: low`; the volume rule → `level: high` |

**Recommended detection — count secrets, not calls.** This is inherently a rate/aggregation rule and belongs in a log platform (Query 5). A single-event Sigma rule can only cover the coarse "batch API used by non-allowlisted principal" case:

```yaml
title: Secrets Manager batch retrieval by non-allowlisted principal
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'BatchGetSecretValue'
  allowlisted:
    userIdentity.arn|contains:
      - ':role/app-secrets-consumer'
      - ':role/secrets-rotation'
  condition: selection and not allowlisted
level: high
```

The volume detection (distinct `secretId` per principal per window) cannot be expressed as a single-event Sigma rule — deploy it as the log-platform query in Query 5, or as a Sigma **correlation** (`type: value_count`, counting distinct `requestParameters.secretId` on `GetSecretValue` events) where the backend supports it. Count `GetSecretValue` only; the batch API emits a per-secret `GetSecretValue`, so adding `BatchGetSecretValue` to the count double-counts.

**On error strings (learned from the EC2 techniques):** Secrets Manager errors are *not* `Client.`-prefixed the way EC2 errors are. Denials show up two different ways depending on where they are evaluated: an IAM-policy denial typically surfaces as `errorCode: AccessDenied` (no suffix), while a service-/resource-policy denial surfaces as `AccessDeniedException`. Match **both**, along with `ResourceNotFoundException` and `DecryptionFailure`, and confirm the exact strings against a real denied-call event in your account.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'` — robust, unlike `--output text | jq`.

#### Query 1 — Find the batch retrieval and its request size

```bash
REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=BatchGetSecretValue \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime,
     caller: .userIdentity.arn,
     type: .userIdentity.type,
     # count of secrets requested in THIS call — the blast-radius number, not "1"
     secrets_requested: ((.requestParameters.secretIdList // []) | length),
     filters: .requestParameters.filters,
     sourceIP: .sourceIPAddress,
     error: (.errorCode // "SUCCESS")}'
```

#### Query 2 — The decisive count: how many distinct secrets did the principal pull?

**Count from one source, deduplicated — do not sum two counts.** Secrets Manager
emits a separate `GetSecretValue` CloudTrail entry for **each** secret in a
`BatchGetSecretValue` call, *in addition to* the single `BatchGetSecretValue`
event. So `GetSecretValue` events already cover both attack styles — the
pre-2023 loop *and* every secret pulled via the batch API. Counting distinct
`secretId` across `GetSecretValue` events alone is therefore the complete,
non-double-counted blast radius. Summing "GetSecretValue count + expanded
secretIdList" (an earlier, wrong approach) inflates the number roughly 2×.

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn-from-Query-1>"

# Distinct secrets accessed = distinct secretId across GetSecretValue events.
# These are emitted per-secret whether the actor looped GetSecretValue or used
# the batch API, so this single source is complete and self-deduplicating.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.errorCode == null) |                       # returned, not denied
    .requestParameters.secretId // empty' | \
  grep . | sort -u | tee ./ir-exposed-secrets.txt

echo "Total distinct secrets exposed: $(grep -c . ./ir-exposed-secrets.txt)"
```

> **Verify this in your account before trusting the count.** The per-secret
> `GetSecretValue`-for-batch behaviour is per AWS documentation; confirm against a
> real `BatchGetSecretValue` event that (a) the spawned `GetSecretValue` entries
> carry `secretId`, and (b) failed secrets carry an `errorCode` (so the
> `errorCode == null` filter correctly separates disclosed from denied). If the
> spawned events do **not** populate `secretId`, fall back to expanding
> `requestParameters.secretIdList` from the `BatchGetSecretValue` events **only**
> (still a single source — never combined with the GetSecretValue count).

`./ir-exposed-secrets.txt` is the eradication work-list — every secret in it must be rotated.

#### Query 3 — What was enumerated before the sweep?

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListSecrets \
  --start-time "$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    {time: .eventTime, filters: .requestParameters.filters,
     maxResults: .requestParameters.maxResults, ip: .sourceIPAddress}'
```

A broad or unfiltered `ListSecrets` means the actor mapped the whole secret store before pulling — treat the full inventory as targeted.

#### Query 4 — Full session reconstruction

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

Watch for use of the stolen secrets *inside* AWS in the same session (e.g. the actor immediately using a retrieved DB credential via RDS Data API, or an IAM key found in a secret), and for exfiltration primitives.

#### Query 5 — Deployable volume detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL** — not CloudWatch Logs Insights.

Count from **one** event type. Because a batch call emits a per-secret
`GetSecretValue` entry for every secret requested, `GetSecretValue` alone is the
complete record — counting distinct `secretId` on it captures both the loop
attack and the batch attack with no double-counting. `BatchGetSecretValue` is
used only to flag that the batch API was involved, never added to the count.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "secretsmanager.amazonaws.com"
| where EventName == "GetSecretValue"
| where isempty(ErrorCode)                              // disclosed, not denied
| extend SecretId = tostring(parse_json(RequestParameters).secretId)
| summarize
    SecretsRetrieved = dcount(SecretId),                // DISTINCT secrets, one source
    Calls            = count(),
    SourceIPs        = make_set(SourceIpAddress, 10),
    FirstSeen        = min(TimeGenerated),
    LastSeen         = max(TimeGenerated)
    by UserIdentityArn, bin(TimeGenerated, 10m)
| where SecretsRetrieved > 15
| join kind=leftouter (
    AWSCloudTrail
    | where TimeGenerated > ago(24h)
    | where EventName == "BatchGetSecretValue"
    | summarize BatchCalls = count() by UserIdentityArn, bin(TimeGenerated, 10m)
  ) on UserIdentityArn, TimeGenerated
| extend Verdict = case(
    BatchCalls > 0, "BULK SECRET EXFILTRATION via batch API — P0",
    "HIGH-VOLUME SECRET READ — review")
| project TimeGenerated, UserIdentityArn, SecretsRetrieved, Calls, BatchCalls, SourceIPs, Verdict
| order by SecretsRetrieved desc
```

CloudWatch Logs Insights equivalent — count distinct secrets from
`GetSecretValue` (single source), flag batch usage separately:

```
fields @timestamp, userIdentity.arn, requestParameters.secretId, errorCode
| filter eventSource = "secretsmanager.amazonaws.com"
| filter eventName = "GetSecretValue"
| filter ispresent(requestParameters.secretId) and not ispresent(errorCode)
| stats count_distinct(requestParameters.secretId) as secrets_retrieved
    by userIdentity.arn, bin(10m)
| filter secrets_retrieved > 15
```

#### Query 6 — Multi-region sweep

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  COUNT=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=BatchGetSecretValue \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$COUNT" ] && [ "$COUNT" != "0" ] && [ "$COUNT" != "None" ] && \
    echo "[!] $REGION — $COUNT BatchGetSecretValue events"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The disclosed secrets are the emergency. The attacker already has their
plaintext — containing the AWS principal stops *further* theft but does nothing
about the credentials already taken. Do both: contain the principal now, and
begin rotation (§4) in parallel rather than after.

#### Step 1 — Disable the offending credential

```bash
SUSPECT_ARN="<principal-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  VICTIM_USER=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
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
SUSPECT_ROLE="<role-name>"     # from the assumed-role ARN

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

As established for instance-profile roles: `aws:TokenIssueTime` kills only tokens
issued before now. If the principal can mint fresh credentials (e.g. it is an
instance role and the host is compromised), also cut that path — but for a
stolen static key or a contained user session this fully stops the principal.

#### Step 3 — Cut the principal off from Secrets Manager immediately

Faster and more targeted than full session revocation when the principal is a
production role that must keep doing its other work.

```bash
SUSPECT_ROLE="<role-name>"

aws iam put-role-policy \
  --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenySecretsRead" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "secretsmanager:ListSecrets"],
      "Resource": "*"
    }]
  }'
echo "[OK] Secrets Manager read denied for $SUSPECT_ROLE"
```

#### Step 4 — Freeze the exposed secrets against tampering (optional, high-value secrets)

For the most sensitive disclosed secrets, attach a resource policy that denies
everyone except the responder and the rotation role while you rotate, preventing
the attacker (or a second stolen principal) from reading the new value the moment
it is created.

```bash
REGION="us-east-1"
SECRET_ID="<high-value-secret-arn>"
RESPONDER_ARN="<break-glass-responder-arn>"
ROTATION_ROLE_ARN="<rotation-role-arn>"

aws secretsmanager put-resource-policy \
  --secret-id "$SECRET_ID" --region "$REGION" \
  --resource-policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": "*",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*",
      "Condition": {"StringNotLike": {"aws:PrincipalArn": ["'"$RESPONDER_ARN"'", "'"$ROTATION_ROLE_ARN"'"]}}
    }]
  }' \
  --block-public-policy
echo "[OK] Read-lock applied to $SECRET_ID during rotation"
```

---

## 4. Eradication

### Remove Attacker Access — Rotate Every Disclosed Secret

This is the core of the incident. Each secret in `./ir-exposed-secrets.txt`
(Query 2) had its plaintext returned to the attacker and is compromised on its
downstream system. Rotation is not optional and is not complete until the
downstream credential is changed, not just the Secrets Manager version.

> Run every command in §4 and §5 under the **break-glass responder
> credentials** from §1, not under any principal still being contained. Step 3's
> deny policy would make a suspect-principal run fail loudly (safe), but a second
> compromised credential would not — use the responder identity explicitly.

#### Rotate secrets that have a rotation Lambda configured

```bash
REGION="us-east-1"

while read -r SECRET; do
  [ -z "$SECRET" ] && continue
  HAS_ROTATION=$(aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" \
    --query 'RotationEnabled' --output text 2>/dev/null)
  if [ "$HAS_ROTATION" = "True" ]; then
    aws secretsmanager rotate-secret --secret-id "$SECRET" --region "$REGION" \
      --rotate-immediately \
      --query 'ARN' --output text && echo "[OK] Rotation triggered: $SECRET"
  else
    echo "[!] MANUAL ROTATION REQUIRED (no rotation Lambda): $SECRET"
  fi
done < ./ir-exposed-secrets.txt
```

#### Manually rotate the rest

For secrets without automatic rotation, change the credential **at the source
system** (database user password, third-party API key, IAM access key), then
store the new value:

```bash
REGION="us-east-1"
SECRET_ID="<secret-arn>"

# After changing the credential on the downstream system:
aws secretsmanager put-secret-value \
  --secret-id "$SECRET_ID" --region "$REGION" \
  --secret-string "file://./new-secret-value.json" \
  --query 'VersionId' --output text && echo "[OK] New value stored for $SECRET_ID"
rm -f ./new-secret-value.json   # do not leave plaintext on disk
```

**Any secret containing an AWS IAM access key** requires that key be deleted and
reissued via IAM as well — storing a new value in Secrets Manager does not
invalidate the leaked key.

#### Remove attacker persistence created with stolen secrets

If any retrieved secret was itself an AWS credential, the attacker may have used
it. Enumerate actions by every access key found in the exposed secrets:

```bash
# For each AWS access key that was stored in an exposed secret:
LEAKED_KEY="<AKIA...>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$LEAKED_KEY" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, ip: .sourceIPAddress}'
```

Remediate any persistence found with the relevant playbook.

#### Remove emergency policies once rotation is complete

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenySecretsRead" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
# Remove the per-secret read-locks from Step 4 once the new values are live
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify every exposed secret was rotated

```bash
REGION="us-east-1"
INCIDENT_START="<iso8601-incident-timestamp>"

FAIL=0
while read -r SECRET; do
  [ -z "$SECRET" ] && continue
  LAST_CHANGED=$(aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" \
    --query 'LastChangedDate' --output text 2>/dev/null)
  # LastChangedDate must be AFTER the incident for rotation to count
  if [ -z "$LAST_CHANGED" ] || [ "$LAST_CHANGED" = "None" ]; then
    echo "[FAIL] $SECRET — cannot read LastChangedDate"; FAIL=1
  else
    echo "[OK] $SECRET last changed $LAST_CHANGED (confirm this is after $INCIDENT_START)"
  fi
done < ./ir-exposed-secrets.txt
[ "$FAIL" -eq 0 ] && echo "[OK] All exposed secrets have a post-incident change" \
                  || echo "[FAIL] Some secrets could not be confirmed rotated"
```

#### Verify no further bulk retrieval since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=BatchGetSecretValue \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further BatchGetSecretValue from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further batch calls — containment did not hold"
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

#### Verify downstream systems reject the old credentials

```bash
# Rotation in Secrets Manager is meaningless if the downstream system still
# accepts the old password. For each rotated secret, confirm the OLD value fails
# and the NEW value works against its target system (DB, API). This is
# system-specific — example for an RDS database credential:
echo "For each rotated DB secret: attempt a login with the OLD password and confirm it is REJECTED."
echo "Automate per system; do not close the incident on Secrets Manager state alone."
```

#### Confirm the corrected detection fires

```bash
# Re-run the emulation against a small test-secret set and assert the volume rule
# reports the SECRET count, not the call count.
echo "Expected: ONE alert reporting 20 DISTINCT secrets (dcount of secretId on"
echo "GetSecretValue events), classified BULK SECRET EXFILTRATION via batch API."
echo "It must read 20, NOT ~40 — a count near 40 means the query is double-counting"
echo "the batch event against its per-secret GetSecretValue entries."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One principal retrieved many secrets uninterrupted | No secret-count threshold alert; the shipped rule counted events, which bulk retrieval defeats |
| `BatchGetSecretValue` usable by this principal | Principal held broad `secretsmanager:GetSecretValue`/`BatchGetSecretValue` on `Resource: *` rather than scoped to its own secrets |
| Secrets readable across unrelated applications by one principal | No per-application resource policies or KMS key separation on secrets |
| Disclosed secrets valid until manually noticed | No automatic rotation configured, so leaked credentials stayed live on downstream systems |
| Blast radius initially undercounted | Triage counted API calls, not secrets returned |

### Recommended Guardrails

**Service Control Policies (SCPs) — apply at OU level**

```json
// SCP 1: Restrict BatchGetSecretValue to approved batch-consumer roles
{
  "Effect": "Deny",
  "Action": "secretsmanager:BatchGetSecretValue",
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/app-secrets-consumer",
        "arn:aws:iam::*:role/BreakGlassAdmin"
      ]
    }
  }
}
```

**Scope secret access to owning workloads**
- Each secret should carry a resource policy allowing only its owning application's role. A web app role should not be able to read the payments or infra secrets. This turns "read 20 secrets" from possible into `AccessDenied`
- Encrypt secrets under per-application KMS CMKs and scope key grants, so cross-application bulk reads fail at the KMS layer even if the Secrets Manager policy is permissive

**Enable rotation everywhere it is feasible**
- Automatic rotation shrinks the value of a stolen secret to the rotation interval. It also makes mass-rotation during an incident a solved problem rather than an emergency project

**Detection improvements**
- Deploy the secret-count volume rule (Query 5) as the primary detection; it must sum `secretIdList` sizes, not count events
- Alert any `BatchGetSecretValue` from a non-allowlisted principal (rare API, high signal)
- Alert cross-application secret retrieval by a single principal
- Keep `ListSecrets` as correlation context only, never a standalone alert

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1555 — Credentials from Password Stores |
| MITRE tactic | Credential Access (TA0006) |
| Primary API | `secretsmanager:BatchGetSecretValue` (up to 20 secrets/call); `ListSecrets` for enumeration |
| Event source | `secretsmanager.amazonaws.com` |
| Key detection insight | Count **secrets returned** (`secretIdList` size), not API calls — 2 calls can disclose 20 secrets |
| Common variant | Loop of `GetSecretValue` (one secret/call) — pre-2023 form of the same attack; include in thresholds |
| Error strings (not `Client.`-prefixed) | `AccessDenied` (IAM-policy denial) / `AccessDeniedException` (service/resource-policy denial) — match both; also `ResourceNotFoundException`, `DecryptionFailure` |
| Resources created | 20 Secrets Manager test secrets |
| Follow-on to watch for | Use of retrieved credentials (DB logins, third-party APIs, leaked IAM keys), data exfiltration |

### Revert

`pulumi destroy` in `infra/` deletes the 20 test secrets. The infra sets
`recovery_window_in_days=0`, so teardown **hard-deletes them immediately** with
no recovery window (equivalent to `--force-delete-without-recovery`) — fine for
disposable emulation secrets. Nothing else is created. After a **real** incident,
`pulumi destroy` is irrelevant — the exposed secrets are your own production
secrets and must be rotated per §4, never deleted.
