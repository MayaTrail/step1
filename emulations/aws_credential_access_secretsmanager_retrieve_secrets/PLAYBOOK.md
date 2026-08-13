# IR Playbook - Retrieve a High Number of Secrets Manager Secrets - Mass Secret Exfiltration through `secretsmanager:GetSecretValue`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential Access / Credentials from Password Stores |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, every secret returned is disclosed plaintext and must be treated as compromised (`MANIFEST.py` rates MEDIUM; the IR view is High because this exfiltrates live secret material, not just a log signal) |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1555 |
| Services in Scope | Secrets Manager, CloudTrail, IAM, KMS, plus every downstream system whose credentials live in the retrieved secrets |
| Infrastructure Created | 20 Secrets Manager secrets (via `infra/`) |

**What the emulation does:** enumerates secrets with `secretsmanager:ListSecrets`, then loops `secretsmanager:GetSecretValue` once per secret to retrieve all 20 plaintext values. This is the classic "walk the vault" pattern, one `GetSecretValue` CloudTrail event per secret, in a tight burst from one principal.

**Relationship to the batch variant.** This is the loop form of the same goal as `BatchGetSecretValue` (its own emulation). The important detection consequence works in your favour here: **Secrets Manager emits a `GetSecretValue` CloudTrail entry per secret regardless of which API was used**, a direct `GetSecretValue` call produces one, and a `BatchGetSecretValue` call produces one *per secret in the batch*. So counting distinct `secretId` on `GetSecretValue` events is the single, complete, non-double-counting measure of secrets exposed by *either* technique. Every threshold and query in this playbook uses that one source.

**Why this is High, not Medium.** The technique succeeds rather than probes: at the end of a run the attacker holds the plaintext of every secret returned, database passwords, API keys, tokens for other systems. Rotation of all disclosed secrets is mandatory. The incident does not end when the AWS principal is contained, because the leaked credentials remain valid on their downstream systems.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for rate queries
- **`GetSecretValue` is a management read event, captured by default**, no data-event configuration required. Confirm `ReadWriteType: All`; a `WriteOnly` trail drops it entirely, blinding this detection
- CloudTrail records `requestParameters.secretId` on every `GetSecretValue` event, so the exact secret read is recoverable; the response value is not logged, so treat any secret read without an `errorCode` as disclosed
- Secrets Manager resource policies and KMS key grants inventoried, so "who could read this secret" is answerable

**Alerting (must be pre-configured)**
- Threshold alert on **distinct secrets retrieved per principal per window**, count distinct `secretId` from `GetSecretValue` events: more than ~15 distinct secrets in 10 minutes from one principal → page. This is the primary control; it must count distinct secrets, not raw events
- `ListSecrets` (broad enumeration) immediately followed by a burst of `GetSecretValue` from the same session, the enumerate-then-sweep pattern
- Retrieval of secrets spanning multiple unrelated applications by a single principal in one window
- `GetSecretValue` from a principal reading secrets it has never read before, especially outside its baseline application set

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- A secret → downstream-system map: for each secret, what it authenticates to and how to rotate it. Bulk secret theft is only containable as fast as you can rotate the leaked credentials
- Rotation Lambdas configured and tested for high-value secrets, so mass rotation is a command, not a project

**Known IOC Baselines**
- Baseline the normal per-principal secret-read volume and *which* secrets each principal reads. Most workloads read a small, stable set; a sudden broad sweep is the signal
- Tag secrets by owning application so cross-application retrieval is detectable

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | > 15 distinct secrets retrieved (distinct `secretId` on `GetSecretValue`) by one principal in 10 min | CloudTrail | T1555 |
| P0 | `ListSecrets` followed within minutes by `GetSecretValue` across most or all enumerated secrets, same session | CloudTrail | T1555 |
| P1 | Secrets spanning multiple unrelated applications retrieved by one principal in one window | CloudTrail | T1555 |
| P1 | `GetSecretValue` burst from an off-baseline ASN/geography for the principal | CloudTrail | T1555 |
| P1 | Principal reads secrets it has no baseline history of reading, in volume | CloudTrail | T1555 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `GetSecretValue` in a tight loop over many distinct `secretId`s, several reads within the same one-second `eventTime` bucket (CloudTrail resolves to whole seconds; multiple events per second indicates scripted, not human, access) | CloudTrail | T1555 |
| P2 | `GetSecretValue` denied at volume (`errorCode = AccessDenied` or `AccessDeniedException`), permission probing across secrets | CloudTrail | T1555 |
| P2 | `ListSecrets` with broad or no filter from an interactive user principal | CloudTrail | T1555 |
| P3 | Modest `GetSecretValue` volume from an allowlisted application reading its own secrets | CloudTrail | T1555 |

### Detection Rule Quality Notes

The rules in `detections/` are too coarse to deploy. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (ListSecrets, GetSecretValue)` with `condition: selection`, no threshold | Unusable. `GetSecretValue` is one of the most frequent calls in any account that uses Secrets Manager, every app fetches its config secret on startup and on cache expiry. A 1:1 rule fires constantly and is muted within days. `ListSecrets` bundled in as an OR only adds noise | Remove the standalone match. Alert on **volume of distinct secrets per principal per window**, not on the occurrence of the event |
| No threshold, no per-principal grouping, no distinct-secret counting | The technique is defined by *volume from one principal*; a rule with no aggregation cannot express it | Threshold on `dcount(secretId)` per `userIdentity.arn` per 10-min window |
| No principal baseline / allowlist | Cannot separate an app reading its own secret (benign, constant) from a principal sweeping the vault | Compare against per-principal baseline; alert on off-baseline secrets and off-baseline volume |
| `ListSecrets` treated as a trigger | Enumeration is context, not an incident on its own, plenty of tooling lists secrets | Use `ListSecrets`→`GetSecretValue` *sequence* as a signal; never alert `ListSecrets` alone |
| Header TODO "verify acronym casing" unresolved; `level: medium` on a rule dominated by benign `GetSecretValue` | Stale validation marker; guaranteed alert fatigue | Resolve TODO; the raw-event rule → `level: low`; the volume rule → `level: high` |

**Recommended detection, threshold on distinct secrets per principal.** This is inherently an aggregation and belongs in a log platform (Query 4) or a Sigma **correlation**:

```yaml
# Document 1: base rule (low; fires on every SUCCESSFUL read by design)
title: Secrets Manager GetSecretValue (successful)
id: 8f3a1e94-2b7c-4d51-9a6e-1c0f5b8e7a20
name: secretsmanager_getsecretvalue_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'secretsmanager.amazonaws.com'
    eventName: 'GetSecretValue'
  # A disclosed secret has no errorCode (in Sigma, `errorCode: null` matches when
  # the field is absent). Keeping only successful reads aligns the correlation's
  # distinct-secret count with the eradication work-list (Query 2): otherwise a
  # principal hitting AccessDenied on 15 secrets fires the same P0 as a real
  # exfiltration.
  success:
    errorCode: null
  condition: selection and success
level: low
---
# Document 2 - correlation: many DISTINCT secrets from one principal
title: Mass Secrets Manager retrieval by a single principal
status: experimental
correlation:
  type: value_count
  rules:
    - secretsmanager_getsecretvalue_base
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 15
    field: requestParameters.secretId     # count DISTINCT secrets, not events
level: high
```

`value_count` over `requestParameters.secretId` counts distinct secrets, which is
the correct measure and also naturally absorbs the batch-API case (whose
per-secret `GetSecretValue` entries land in the same base rule).

**On error strings (learned from the EC2 techniques):** Secrets Manager errors are *not* `Client.`-prefixed. A denial surfaces as `errorCode: AccessDenied` (IAM-policy denial) or `AccessDeniedException` (service/resource-policy denial), match **both**; also `ResourceNotFoundException`, `DecryptionFailure`. Confirm the exact strings against a real denied-call event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, robust, unlike `--output text | jq`.

#### Query 1: Establish who is reading secrets and how many

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {arn: .userIdentity.arn, secret: .requestParameters.secretId,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.arn) | map({
      principal: .[0].arn,
      distinct_secrets: ([.[] | select(.error=="SUCCESS") | .secret] | unique | length),
      denied: ([.[] | select(.error!="SUCCESS")] | length),
      source_ips: ([.[].ip] | unique)
    }) | sort_by(-.distinct_secrets)'
```

The principal with an anomalously high `distinct_secrets` is the suspect. A high
`denied` count alongside it is permission-probing across secrets.

#### Query 2 - The eradication work-list: exactly which secrets did the suspect read?

Single source, deduplicated. This captures secrets read directly *and* any pulled
via the batch API (which emits per-secret `GetSecretValue` entries too).

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SUSPECT_ARN="<principal-arn-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.errorCode == null) |                    # returned, not denied
    .requestParameters.secretId // empty' | \
  grep . | sort -u | tee ./ir-exposed-secrets.txt

echo "Distinct secrets exposed (all require rotation): $(grep -c . ./ir-exposed-secrets.txt)"
```

`./ir-exposed-secrets.txt` is the rotation work-list.

#### Query 3: What was enumerated first, and how fast was the sweep?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"

# Enumeration
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListSecrets \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    {time: .eventTime, filters: .requestParameters.filters, ip: .sourceIPAddress}'

# Rate of the GetSecretValue burst. CloudTrail eventTime resolves to whole
# seconds, so measure reads-per-second: several in one second is scripted, not
# human. This counts events per one-second bucket (highest-rate buckets first).
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | \
  sort | uniq -c | sort -rn | head -30
```

#### Query 4: Deployable volume detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights. Counts distinct secrets per principal per 10-minute window.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "secretsmanager.amazonaws.com"
| where EventName == "GetSecretValue"
| where isempty(ErrorCode)                          // disclosed, not denied
| extend SecretId = tostring(parse_json(RequestParameters).secretId)
| summarize
    SecretsRetrieved = dcount(SecretId),            // DISTINCT secrets
    Calls            = count(),
    SourceIPs        = make_set(SourceIpAddress, 10),
    FirstSeen        = min(TimeGenerated),
    LastSeen         = max(TimeGenerated)
    by UserIdentityArn, bin(TimeGenerated, 10m)
| where SecretsRetrieved > 15
| extend Verdict = "MASS SECRET RETRIEVAL - P0"
| order by SecretsRetrieved desc
```

CloudWatch Logs Insights equivalent:

```
fields @timestamp, userIdentity.arn, requestParameters.secretId, errorCode
| filter eventSource = "secretsmanager.amazonaws.com"
| filter eventName = "GetSecretValue"
| filter ispresent(requestParameters.secretId) and not ispresent(errorCode)
| stats count_distinct(requestParameters.secretId) as secrets_retrieved
    by userIdentity.arn, bin(10m)
| filter secrets_retrieved > 15
```

#### Query 5: Full session reconstruction

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

ACCESS_KEY_ID="<AKIA-or-ASIA-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Watch for use of the retrieved secrets *inside* AWS in the same session (a leaked
IAM key used, a DB credential exercised via RDS Data API) and for exfiltration
primitives.

#### Query 6: Multi-region sweep

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  COUNT=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
    --start-time "$START" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$COUNT" ] && [ "$COUNT" != "0" ] && [ "$COUNT" != "None" ] && \
    echo "[!] $REGION, $COUNT GetSecretValue events"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The disclosed secrets are the emergency. The attacker already has their
plaintext, containing the AWS principal stops *further* theft but does nothing
about the credentials already taken. Contain the principal now, and begin
rotation (§4) in parallel, not after.

> Run every containment/eradication command under the **break-glass responder
> credentials** from §1, not under any principal being contained.

#### Step 1: Disable the offending credential

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

#### Step 2: Revoke live STS sessions (assumed-role principals)

```bash
SUSPECT_ROLE="<role-name>"

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

`aws:TokenIssueTime` kills only tokens issued before now. If the principal can
mint fresh credentials (e.g. an instance role on a compromised host), also cut
that path, but for a stolen static key or a contained role session this stops
the principal.

#### Step 3: Cut the principal off from Secrets Manager immediately

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

#### Step 4: Read-lock high-value disclosed secrets during rotation (optional)

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
      "Effect": "Deny", "Principal": "*",
      "Action": "secretsmanager:GetSecretValue", "Resource": "*",
      "Condition": {"StringNotLike": {"aws:PrincipalArn": ["'"$RESPONDER_ARN"'", "'"$ROTATION_ROLE_ARN"'"]}}
    }]
  }' \
  --block-public-policy
echo "[OK] Read-lock applied to $SECRET_ID during rotation"
```

---

## 4. Eradication

### Remove Attacker Access: Rotate Every Disclosed Secret

Each secret in `./ir-exposed-secrets.txt` (Query 2) had its plaintext returned
to the attacker and is compromised on its downstream system. Rotation is
mandatory and is not complete until the downstream credential is changed, not
just the Secrets Manager version.

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
reissued via IAM, storing a new value in Secrets Manager does not invalidate the
leaked key.

#### Remove attacker persistence created with stolen secrets

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

# For each AWS access key that was stored in an exposed secret:
LEAKED_KEY="<AKIA...>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$LEAKED_KEY" \
  --start-time "$START" \
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
# Remove per-secret read-locks from Step 4 once the new values are live
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
  if [ -z "$LAST_CHANGED" ] || [ "$LAST_CHANGED" = "None" ]; then
    echo "[FAIL] $SECRET, cannot read LastChangedDate"; FAIL=1
  else
    echo "[OK] $SECRET last changed $LAST_CHANGED (confirm after $INCIDENT_START)"
  fi
done < ./ir-exposed-secrets.txt
[ "$FAIL" -eq 0 ] && echo "[OK] All exposed secrets have a post-incident change" \
                  || echo "[FAIL] Some secrets could not be confirmed rotated"
```

#### Verify no further mass retrieval since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | select(.errorCode == null) |
    .requestParameters.secretId' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further successful GetSecretValue from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further reads, containment did not hold"
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
# accepts the old value. For each rotated secret, confirm the OLD credential is
# REJECTED and the NEW one works against its target system. System-specific;
# automate per system. Do not close the incident on Secrets Manager state alone.
echo "For each rotated DB secret: attempt login with the OLD password; confirm REJECTED."
```

#### Confirm the corrected detection fires

```bash
# Re-run the emulation against a small test-secret set and assert the volume rule
# reports DISTINCT secrets read.
echo "Expected: ONE alert reporting 20 distinct secrets (dcount of secretId),"
echo "classified MASS SECRET RETRIEVAL, not 20 separate alerts, and not '1 event'."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One principal read many secrets uninterrupted | No distinct-secret volume threshold; the shipped rule matched raw events with no aggregation |
| Principal could read secrets across the whole store | Broad `secretsmanager:GetSecretValue` on `Resource: *` rather than scoped to the principal's own secrets |
| Secrets readable across unrelated applications by one principal | No per-application resource policies or KMS key separation |
| Disclosed secrets valid until manually noticed | No automatic rotation, so leaked credentials stayed live downstream |
| Enumeration + sweep unremarked | `ListSecrets`→`GetSecretValue` sequence not correlated |

### Recommended Guardrails

**Scope secret access to owning workloads**
- Each secret carries a resource policy allowing only its owning application's role, so one principal reading 20 unrelated secrets becomes `AccessDenied` rather than a successful sweep
- Encrypt secrets under per-application KMS CMKs with scoped grants, so cross-application bulk reads fail at the KMS layer even if the Secrets Manager policy is permissive

**Least-privilege on secret reads**

```json
// Identity policy: scope GetSecretValue to this workload's own secret path
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:*:*:secret:app/web/*"
}
```

**Enable rotation everywhere feasible**, shrinks the value of a stolen secret to the rotation interval and makes mass rotation during an incident a solved problem.

**Detection improvements**
- Deploy the distinct-secret volume rule (Query 4) as the primary detection, `dcount(secretId)` per principal per window, never a raw-event match
- Correlate `ListSecrets`→`GetSecretValue` sequences
- Alert cross-application secret retrieval and off-baseline reads by a single principal
- Never alert `ListSecrets` or single `GetSecretValue` events on their own

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1555 - Credentials from Password Stores |
| MITRE tactic | Credential Access (TA0006) |
| Primary API | `secretsmanager:GetSecretValue` (looped, one secret/call); `ListSecrets` for enumeration |
| Event source | `secretsmanager.amazonaws.com` |
| Key detection insight | Count **distinct `secretId` on `GetSecretValue` events** per principal per window, this one source covers both the loop and the batch API (which also emits per-secret `GetSecretValue`) |
| Batch sibling | `aws.credential-access.secretsmanager-batch-retrieve-secrets`, same goal via `BatchGetSecretValue` |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException`, `ResourceNotFoundException`, `DecryptionFailure` |
| Resources created | 20 Secrets Manager test secrets |
| Follow-on to watch for | Use of retrieved credentials (DB logins, third-party APIs, leaked IAM keys), data exfiltration |

### Revert

`pulumi destroy` in `infra/` deletes the 20 test secrets. The infra sets
`recovery_window_in_days=0`, so teardown **hard-deletes them immediately** with
no recovery window (equivalent to `--force-delete-without-recovery`), there is
nothing to recover once destroyed, which is fine for disposable emulation
secrets. After a **real** incident, `pulumi destroy` is irrelevant, the exposed
secrets are your production secrets and must be rotated per §4, never deleted.
