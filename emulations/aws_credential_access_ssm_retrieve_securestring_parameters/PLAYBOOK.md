# IR Playbook - Retrieve SSM Parameters from the Parameter Store - Mass SecureString Decryption through `ssm:GetParameters`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential Access / Unsecured Credentials |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, every SecureString decrypted is disclosed plaintext and must be treated as compromised (`MANIFEST.py` rates MEDIUM; the IR view is High because this exfiltrates live secret material, not just a log signal) |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1552.007 (see mapping caveat in §6) |
| Services in Scope | SSM Parameter Store, KMS, CloudTrail, IAM, plus every downstream system whose credentials live in the decrypted parameters |
| Infrastructure Created | 42 SSM SecureString parameters (via `infra/`) |

**What the emulation does:** enumerates parameters with `ssm:DescribeParameters`, then calls `ssm:GetParameters` with **`WithDecryption=true`** in batches of 10 to retrieve the plaintext of all 42 SecureString parameters. That is five batch calls, each decrypting up to 10 parameters, a deliberately efficient sweep of the whole parameter store.

**Why `WithDecryption=true` is the whole story.** A SecureString parameter is useless to an attacker unless decrypted. `GetParameters` *without* decryption returns only ciphertext and metadata, routine. `GetParameters` **with** `WithDecryption=true` returns plaintext credentials. The single most important field for detecting this technique is `requestParameters.withDecryption`, and the shipped rules ignore it entirely (see §2).

**Two counting subtleties that differ from the Secrets Manager techniques:**
- `GetParameters` is a **batch** call, one CloudTrail event carries a `names` list of up to 10 parameters. So counting *events* undercounts parameters decrypted.
- Unlike Secrets Manager (which emits a per-secret `GetSecretValue` entry for each item in a batch), **SSM does *not* emit a per-parameter event** for a `GetParameters` call. There is one `GetParameters` event with a `names` array. Therefore the correct count comes from **expanding `requestParameters.names`** across the `GetParameters`/`GetParameter` events, there is no per-item event to count instead.

**KMS is genuinely in the path here.** Decrypting a SecureString calls `kms:Decrypt` on the parameter's KMS key (the account default `alias/aws/ssm` or a customer CMK). So a `kms:Decrypt` correlation is a *real, corroborating* signal for this technique, the opposite of the EC2 password case, where decryption is client-side and KMS is not involved. It also catches an actor who exports the parameter ciphertext and decrypts via KMS directly.

**Why this is High, not Medium.** The technique succeeds rather than probes: the attacker ends with plaintext credentials. Every decrypted SecureString must be rotated; the incident does not end at AWS containment because the leaked values stay valid on their downstream systems.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for rate queries
- **`GetParameters`/`GetParameter` are management read events, captured by default.** Confirm `ReadWriteType: All`; a `WriteOnly` trail drops them and blinds this detection entirely
- CloudTrail logs `requestParameters.names` (or `.name`) and `requestParameters.withDecryption` on these events, so *which* parameters and *whether decryption was requested* are both recoverable. The parameter **values** are never logged
- KMS CloudTrail events (`kms:Decrypt`) available and correlatable to the SSM parameter key(s)
- Inventory of SecureString parameters and which KMS key encrypts each, so blast radius and key scope are known

**Alerting (must be pre-configured)**
- Threshold alert on **distinct SecureString parameters decrypted per principal per window**: count distinct entries in `requestParameters.names` across `GetParameters`/`GetParameter` events where `withDecryption=true`, per principal. More than ~10 in 5 minutes from one principal → page. This is the primary control and it must count parameters, not calls, and only decryption calls
- `ssm:DescribeParameters` (broad enumeration) followed by decrypting `GetParameters` from the same session, enumerate-then-sweep
- Any principal decrypting parameters across multiple unrelated paths/applications in one window
- `kms:Decrypt` volume spike against the SSM parameter KMS key from a non-application principal

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- A parameter → downstream-system map: what each SecureString authenticates to and how to rotate it
- Rotation runbooks/automation for the credentials stored as parameters, so mass rotation is a procedure, not an improvisation

**Known IOC Baselines**
- Baseline which principals decrypt SecureStrings and which parameter paths each touches. Most workloads read a small, fixed set under their own path prefix
- Baseline normal per-principal decryption volume; a broad sweep across the store is the signal
- Organize parameters under per-application path prefixes (`/app/web/…`, `/app/payments/…`) so cross-application access is visible and scopable

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | > 10 distinct SecureString parameters decrypted (`withDecryption=true`, distinct `names`) by one principal in 5 min | CloudTrail | T1552.007 |
| P0 | `ssm:DescribeParameters` sweep followed by decrypting `GetParameters` across most enumerated parameters, same session | CloudTrail | T1552.007 |
| P1 | Parameters decrypted across multiple unrelated path prefixes by one principal in one window | CloudTrail | T1552.007 |
| P1 | Decrypting `GetParameters`/`GetParameter` from an off-baseline ASN/geography for the principal | CloudTrail | T1552.007 |
| P1 | `kms:Decrypt` spike on the SSM parameter KMS key from a principal not in the parameter-consumer baseline | CloudTrail (KMS) | T1552.007 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Any single `GetParameters` with a large `names` list (≥ 10) and `withDecryption=true` | CloudTrail | T1552.007 |
| P2 | `GetParameter`/`GetParameters` decryption of parameters the principal has no baseline history of reading | CloudTrail | T1552.007 |
| P2 | `GetParameters` denied at volume (`errorCode = AccessDeniedException`), permission probing across parameters | CloudTrail | T1552.007 |
| P3 | Modest decryption volume from an allowlisted application reading its own path prefix | CloudTrail | T1552.007 |

### Detection Rule Quality Notes

The rules in `detections/` are too coarse to deploy. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (DescribeParameters, GetParameters)` with `condition: selection`, no threshold and **no `withDecryption` filter** | Unusable, and misses the point. `GetParameters` is extremely high-volume, every app reads its config parameters constantly, mostly SecureStrings *with* decryption legitimately. A rule that fires on every `GetParameters` floods the queue; a rule that ignores `withDecryption` cannot separate metadata reads from credential theft | Filter to `withDecryption=true` and threshold on distinct parameter count per principal |
| No counting of **parameters**, only implicit event matching | `GetParameters` is a batch; one event decrypts up to 10 parameters. Event-matching cannot express "how many parameters were exposed" | Expand `requestParameters.names` and count distinct per principal per window |
| `DescribeParameters` treated as a trigger | Enumeration is context, not an incident; plenty of tooling enumerates | Use `DescribeParameters`→decrypting-`GetParameters` *sequence*; never alert enumeration alone |
| `GetParameter` (singular) absent | An attacker looping `GetParameter` (one name each) evades a `GetParameters`-only rule | Include both `GetParameter` and `GetParameters` in the decryption threshold |
| No KMS correlation | The genuine corroborating signal (`kms:Decrypt` on the SSM key) is unused | Add the KMS-decrypt volume signal |
| Header TODO "verify acronym casing" unresolved; `level: medium` on a rule dominated by benign `GetParameters` | Stale marker; guaranteed alert fatigue | Resolve TODO; raw-event rule → `level: low`; decryption-volume rule → `level: high` |

**Recommended detection, decryption-only, count parameters.** Belongs in a log platform (Query 4) or a Sigma **correlation**. A single-event Sigma rule can cover the coarse "big decrypting batch" case:

```yaml
title: SSM GetParameters bulk SecureString decryption
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'GetParameters'
    requestParameters.withDecryption: true
  condition: selection
level: high
```

**Illustrative only for the batch-size idea, not deployable as written.** There
is **no `count` value-modifier in mainline Sigma** (`|count|gte` does not exist
in the spec and will fail to convert in pySigma / sigma-cli for every backend, so
it is omitted from the rule above). Counting the size of `requestParameters.names`
within a single event is not something the Sigma value-modifier grammar can
express. The deployable form is the base rule above (decrypting `GetParameters`/
`GetParameter`) **plus** an external correlation counting distinct parameter
names, which is exactly the log-platform query in Query 4. Treat Query 4 as the
real detection; treat this Sigma snippet as the "flag any decrypting batch" coarse
signal only.

**On error strings (learned from prior techniques):** SSM errors are *not* `Client.`-prefixed. A denial surfaces as `errorCode: AccessDeniedException` (and IAM-policy denials can surface as `AccessDenied`); a missing parameter as `ParameterNotFound`. Match `AccessDenied`/`AccessDeniedException`, and confirm against a real event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, robust, unlike `--output text | jq`.

#### Query 1: Who is decrypting parameters, and how many?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

# Pull both GetParameters (batch) and GetParameter (singular); keep only decrypting calls
for EV in GetParameters GetParameter; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters.withDecryption == true) |
    { arn: .userIdentity.arn,
      # normalise singular .name and batch .names into one list
      params: ((.requestParameters.names // []) + ([.requestParameters.name] | map(select(. != null)))),
      error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress }' | \
  jq -s 'group_by(.arn) | map({
      principal: .[0].arn,
      distinct_params: ([.[] | select(.error=="SUCCESS") | .params[]] | unique | length),
      denied: ([.[] | select(.error!="SUCCESS")] | length),
      source_ips: ([.[].ip] | unique)
    }) | sort_by(-.distinct_params)'
```

The principal with an anomalously high `distinct_params` is the suspect.

#### Query 2 - The eradication work-list: exactly which SecureStrings were decrypted?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SUSPECT_ARN="<principal-arn-from-Query-1>"

for EV in GetParameters GetParameter; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json
done | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.withDecryption == true) |
    select(.errorCode == null) |
    ((.requestParameters.names // []) + ([.requestParameters.name] | map(select(. != null))))[]' | \
  grep . | sort -u | tee ./ir-exposed-parameters.txt

echo "Distinct SecureStrings decrypted (all require rotation): $(grep -c . ./ir-exposed-parameters.txt)"
```

Note: `names` in CloudTrail may be parameter names or ARNs depending on how the
caller referenced them; normalise to names before matching against your inventory.

#### Query 3: What was enumerated, and how fast was the sweep?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeParameters \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    {time: .eventTime, filters: .requestParameters.parameterFilters, ip: .sourceIPAddress}'
```

#### Query 4: Deployable decryption-volume detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights. Counts distinct decrypted parameters per principal per 5-minute window, decryption calls only.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "ssm.amazonaws.com"
| where EventName in ("GetParameters", "GetParameter")
| extend Req = parse_json(RequestParameters)
| where tostring(Req.withDecryption) == "true"
| where isempty(ErrorCode)
// normalise singular .name and batch .names into one multi-valued column
| extend Names = iff(EventName == "GetParameters", Req.names, pack_array(Req.name))
| mv-expand ParamName = Names to typeof(string)
| summarize
    ParamsDecrypted = dcount(ParamName),
    Calls           = count(),
    SourceIPs       = make_set(SourceIpAddress, 10),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated)
    by UserIdentityArn, bin(TimeGenerated, 5m)
| where ParamsDecrypted > 10
| extend Verdict = "MASS SECURESTRING DECRYPTION - P0"
| order by ParamsDecrypted desc
```

CloudWatch Logs Insights equivalent (note: CWLI cannot expand a JSON array, so it
counts decrypting calls and flags batch usage; pivot to Query 2 for the true
parameter count):

```
fields @timestamp, userIdentity.arn, requestParameters.withDecryption, eventName
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["GetParameters","GetParameter"]
| filter requestParameters.withDecryption = 1
| stats count(*) as decrypt_calls by userIdentity.arn, bin(5m)
| filter decrypt_calls > 3
```

#### Query 5: Corroborate with KMS decryptions

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
SSM_KMS_KEY_ARN="<arn-of-the-SSM-parameter-KMS-key>"   # e.g. the CMK, or resolve alias/aws/ssm

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" --arg key "$SSM_KMS_KEY_ARN" '
    .Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select( any((.resources // [])[]?; .ARN == $key) or (.requestParameters.encryptionContext != null) ) |
    {time: .eventTime, key: (.resources // [])[0].ARN,
     context: .requestParameters.encryptionContext, ip: .sourceIPAddress}'
```

For SSM SecureString decryption, the KMS `Decrypt` call carries an
`encryptionContext` of `{"PARAMETER_ARN": "<param-arn>"}`, which independently
confirms which parameters were decrypted, cross-check against Query 2.

#### Query 6: Full session reconstruction

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

#### Query 7: Multi-region sweep

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  TOTAL=0
  # Union both APIs: an attacker looping singular GetParameter would be invisible
  # to a GetParameters-only sweep (same gap the shipped rule has).
  for EV in GetParameters GetParameter; do
    C=$(aws cloudtrail lookup-events \
      --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
      --start-time "$START" \
      --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
    [ -n "$C" ] && [ "$C" != "None" ] && TOTAL=$((TOTAL + C))
  done
  [ "$TOTAL" != "0" ] && echo "[!] $REGION, $TOTAL GetParameters+GetParameter events"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The decrypted parameters are the emergency. The attacker already has their
plaintext, containing the principal stops *further* theft but does nothing about
the credentials already taken. Contain the principal now; begin rotation (§4) in
parallel.

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
# Extract the ROLE name from an assumed-role ARN
# (arn:aws:sts::<acct>:assumed-role/<RoleName>/<SessionName>). The role name is
# the SECOND path segment: NOT $NF, which would give the session name. This
# differs from the IAM-user parsing in Step 1.
SUSPECT_ROLE=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')   # e.g. from :assumed-role/<RoleName>/<session>

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

`aws:TokenIssueTime` kills only tokens issued before now; a principal that can
mint fresh credentials (e.g. an instance role on a compromised host) needs that
path cut too.

#### Step 3: Cut the principal off from Parameter Store and its KMS key

Denying both the SSM read *and* KMS decrypt is belt-and-braces: even if a broad
SSM grant is missed, no SecureString can be decrypted without the key.

```bash
SUSPECT_ROLE="<role-name>"
SSM_KMS_KEY_ARN="<arn-of-the-SSM-parameter-KMS-key>"

aws iam put-role-policy \
  --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyParamStore" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {"Effect":"Deny","Action":["ssm:GetParameter","ssm:GetParameters","ssm:GetParametersByPath","ssm:DescribeParameters"],"Resource":"*"},
      {"Effect":"Deny","Action":"kms:Decrypt","Resource":"'"$SSM_KMS_KEY_ARN"'"}
    ]
  }'
echo "[OK] Parameter Store + KMS decrypt denied for $SUSPECT_ROLE"
```

---

## 4. Eradication

### Remove Attacker Access: Rotate Every Decrypted Parameter

Each parameter in `./ir-exposed-parameters.txt` (Query 2) had its plaintext
returned to the attacker and is compromised on its downstream system. Rotation is
mandatory and is not complete until the downstream credential changes, not just
the parameter value.

#### Rotate the credential at its source, then overwrite the parameter

SSM Parameter Store has no built-in rotation, every decrypted SecureString is a
manual rotation: change the credential on its downstream system, then overwrite:

```bash
REGION="us-east-1"

while read -r PARAM; do
  [ -z "$PARAM" ] && continue
  echo "[!] ROTATE AT SOURCE then overwrite: $PARAM"
  # After changing the downstream credential, store the new value (kept off the CLI
  # history / argv by reading from a file):
  #   aws ssm put-parameter --name "$PARAM" --type SecureString \
  #     --key-id "$SSM_KMS_KEY_ARN" --overwrite --region "$REGION" \
  #     --value "$(cat ./new-value.txt)" >/dev/null && rm -f ./new-value.txt
done < ./ir-exposed-parameters.txt
```

**Any parameter holding an AWS IAM access key** must have that key deleted and
reissued via IAM, overwriting the parameter does not invalidate the leaked key.

#### Remove attacker persistence created with decrypted credentials

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

# For each AWS access key that was stored in an exposed parameter:
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
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyParamStore" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify every exposed parameter was rotated

```bash
REGION="us-east-1"
INCIDENT_START="<iso8601-incident-timestamp>"

FAIL=0
while read -r PARAM; do
  [ -z "$PARAM" ] && continue
  LAST_MOD=$(aws ssm describe-parameters --region "$REGION" \
    --parameter-filters "Key=Name,Values=$PARAM" \
    --query 'Parameters[0].LastModifiedDate' --output text 2>/dev/null)
  if [ -z "$LAST_MOD" ] || [ "$LAST_MOD" = "None" ]; then
    echo "[FAIL] $PARAM, cannot read LastModifiedDate"; FAIL=1
  else
    echo "[OK] $PARAM last modified $LAST_MOD (confirm after $INCIDENT_START)"
  fi
done < ./ir-exposed-parameters.txt
[ "$FAIL" -eq 0 ] && echo "[OK] All exposed parameters have a post-incident modification" \
                  || echo "[FAIL] Some parameters could not be confirmed rotated"
```

#### Verify no further decryption since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(for EV in GetParameters GetParameter; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$CONTAINED_AT" --region "$REGION" --output json
done | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    select(.requestParameters.withDecryption == true) |
    select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further decrypting reads from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further decrypting reads, containment did not hold"
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
# Overwriting the parameter is meaningless if the downstream system still accepts
# the old value. For each rotated parameter, confirm the OLD credential is
# REJECTED and the NEW one works. System-specific; automate per system.
echo "For each rotated DB parameter: attempt login with the OLD value; confirm REJECTED."
```

#### Confirm the corrected detection fires

```bash
# Re-run the emulation against a small test-parameter set and assert the volume
# rule reports DISTINCT parameters decrypted, decryption-only.
echo "Expected: ONE alert reporting the distinct count of SecureStrings decrypted"
echo "(withDecryption=true), classified MASS SECURESTRING DECRYPTION, not one"
echo "alert per batch call, and not counting non-decrypting reads."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| One principal decrypted many parameters uninterrupted | No decryption-volume threshold; the shipped rule ignored `withDecryption` and had no aggregation |
| Principal could decrypt across the whole store | Broad `ssm:GetParameters` + `kms:Decrypt` on `Resource: *` rather than scoped to the principal's own path prefix and key |
| Parameters readable across unrelated applications | No per-application path-prefix scoping or per-application KMS keys |
| Decrypted values valid until manually noticed | No rotation for credentials stored as parameters (Parameter Store has no built-in rotation) |
| Blast radius initially undercounted | Triage counted `GetParameters` calls, not the `names` decrypted per call |

### Recommended Guardrails

**Scope parameter access by path and key**

```json
// Identity policy: this workload may read+decrypt only its own path prefix
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters"],
     "Resource":"arn:aws:ssm:*:*:parameter/app/web/*"},
    {"Effect":"Allow","Action":"kms:Decrypt",
     "Resource":"arn:aws:kms:*:*:key/<web-app-cmk-id>",
     "Condition":{"StringLike":{"kms:EncryptionContext:PARAMETER_ARN":"arn:aws:ssm:*:*:parameter/app/web/*"}}}
     // NOTE: StringLike, not StringEquals - IAM expands `*` only in Resource and
     // in the *Like operators. StringEquals compares literally and would never
     // match a concrete PARAMETER_ARN, silently denying the app all decryption.
  ]
}
```

- Encrypt each application's SecureStrings under a **per-application CMK** and scope `kms:Decrypt` with a `kms:EncryptionContext:PARAMETER_ARN` condition, so a broad SSM grant still cannot decrypt another app's parameters
- Avoid the account-default `alias/aws/ssm` key for sensitive parameters, a single shared key means one `kms:Decrypt` grant unlocks everything

**Service Control Policy, deny cross-account/unusual decryption**
- Consider an SCP restricting `ssm:GetParameters` with `withDecryption` to expected principals for the most sensitive path prefixes

**Detection improvements**
- Deploy the decryption-volume rule (Query 4): `withDecryption=true`, distinct `names`, per principal per window, never a raw `GetParameters` match
- Correlate `DescribeParameters`→decrypting-`GetParameters` sequences
- Add the `kms:Decrypt`-on-SSM-key volume signal as corroboration
- Alert cross-path and off-baseline decryption by a single principal

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1552.007 (as mapped by Stratus Red Team), see caveat below |
| MITRE tactic | Credential Access (TA0006) |
| Primary API | `ssm:GetParameters` with `WithDecryption=true` (batch, `names` up to 10/call); `DescribeParameters` for enumeration |
| Event source | `ssm.amazonaws.com` (plus `kms.amazonaws.com` for the decrypt) |
| Key discriminator | `requestParameters.withDecryption == true`, without it the call is a metadata read, not credential theft |
| Key counting insight | Count distinct entries in `requestParameters.names` (SSM emits NO per-parameter event for a batch call), count parameters, not calls |
| KMS correlation | Valid here - SecureString decryption calls `kms:Decrypt` with `encryptionContext.PARAMETER_ARN`; contrast with EC2 password data, where KMS is not involved |
| Error strings (not `Client.`-prefixed) | `AccessDeniedException` / `AccessDenied`, `ParameterNotFound` |
| Resources created | 42 SSM SecureString parameters |
| Follow-on to watch for | Use of decrypted credentials (DB logins, third-party APIs, leaked IAM keys), data exfiltration |

**MITRE mapping caveat:** the MANIFEST maps this to **T1552.007**, whose canonical
MITRE name is *Unsecured Credentials: Container API*, which describes reading
credentials from a container orchestration API, not SSM Parameter Store. The
mapping is inherited from Stratus Red Team and is imprecise; the technique is
squarely *Unsecured Credentials* (T1552) but the sub-technique number is a poor
fit. Treat the tactic (Credential Access) as authoritative and the sub-technique
as approximate. Recorded for the end-of-run MITRE-mapping finding.

### Revert

`pulumi destroy` in `infra/` deletes the 42 SecureString parameters. Nothing else
is created. After a **real** incident, `pulumi destroy` is irrelevant, the
decrypted parameters are your production credentials and must be rotated per §4,
never merely deleted.
