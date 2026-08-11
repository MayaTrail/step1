# IR Playbook - Overwrite Lambda Function Code - Code Hijack via `lambda:UpdateFunctionCode`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Software tampering (a function's own code replaced with attacker code) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, the function's deployment package is replaced, so **every invocation runs attacker code under the function's execution role**, unconditionally (unlike an injected layer, this *is* the handler). The role's credentials must be treated as compromised, and the function's business logic (its data handling) is now attacker-controlled, a supply-chain-style integrity compromise. As emulated the target is a hello-world handler with only `AWSLambdaBasicExecutionRole`, so the payoff is small, but the technique in a real account is High. `MANIFEST.py` rates MEDIUM |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1525 |
| Services in Scope | Lambda, CloudTrail (management + Lambda data events), CloudWatch, IAM |
| Infrastructure Created | A target Lambda function (`stratus-red-team-overwrite-lambda`) + its execution role, via `pulumi up`. The code is overwritten and then restored by the attack script |

**What the emulation does:** with a pre-created target function, it (1) `lambda:GetFunction`, downloads the original code ZIP via the presigned `Code.Location` (so the attacker can preserve/mimic it), then (2) `lambda:UpdateFunctionCode` with a malicious ZIP (`index.py` returning `{"pwned": true}` and dumping env vars), replacing the function's `$LATEST` code in place. On cleanup it restores the original ZIP with a second `UpdateFunctionCode`. A normal run leaves only the CloudTrail trail; a real intrusion leaves the malicious code live.

**Why this is potent, and why the usual reflexes miss it.** The function keeps its name, ARN, triggers, resource policy, env vars, and execution role, only the *code behind them* changes. Nothing in the function's wiring looks different. Detection that watches triggers or policies sees nothing; only the **code hash** (`CodeSha256`) changes. And because the code runs under the existing execution role, the attacker inherits every permission that role holds.

**Detection is the code hash and the principal, not the event name.** `UpdateFunctionCode` is exactly what every legitimate deployment does. The signal is **`UpdateFunctionCode` by a principal that is not the deploy pipeline**, and the ground truth is a **`CodeSha256` that no longer matches the known-good build**. The shipped rule matches `GetFunction`/`UpdateFunctionCode` with no principal or hash check (§2), so it fires on every deploy and every console "download function" click.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing Lambda **management** events. `UpdateFunctionCode` carries `requestParameters.functionName` and `responseElements.codeSha256` / `.codeSize` / `.revisionId` / `.version` / `.lastModified` (the **code ZIP itself is not logged**, only its hash). `GetFunction` is a read that returns a presigned download URL
- **Lambda data events** enabled for the functions that matter, so invocations during the code's exposure window are recorded
- A **known-good `CodeSha256` baseline** per function (from your CI/CD build, stored in a CMDB/artifact registry), the authoritative "is this the real code" reference
- **Lambda versioning** (publish a numbered version on each legitimate deploy): published versions are **immutable**, so a rollback target always exists and `UpdateFunctionCode` cannot alter them

**Alerting (must be pre-configured)**
- **`lambda:UpdateFunctionCode` by a principal not on the deploy-pipeline allowlist → P0**
- **A function's live `CodeSha256` diverging from its known-good baseline → P0** (config-drift / periodic hash check)
- **Sequence `GetFunction` → `UpdateFunctionCode` by one principal within minutes → P1** (download-then-overwrite fingerprint)
- CloudWatch alarm on new error patterns / output changes after a code change outside a deploy window

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq`; `unzip`; a sandbox host to download and inspect function code offline
- The known-good `CodeSha256` baseline, the trusted source/artifact to redeploy from, and each function's execution-role ARN

**Known IOC Baselines**
- The emulation's function `stratus-red-team-overwrite-lambda`, tag `StratusRedTeam=true`; the malicious payload returns `{"pwned": true}`
- Baseline which principals deploy code (CI/CD only) and each function's known-good `CodeSha256`

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `lambda:UpdateFunctionCode` by a principal not on the deploy-pipeline allowlist | CloudTrail (management) | T1525 |
| P0 | A function's live `CodeSha256` no longer matches its known-good baseline | Lambda config / drift check | T1525 |
| P1 | Ordered sequence `GetFunction → UpdateFunctionCode` by one principal within minutes | CloudTrail (management) | T1525 |
| P1 | `UpdateFunctionCode` `responseElements.codeSha256` differs from the prior known value for that function | CloudTrail (management) | T1525 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateFunctionCode` outside a deployment window | CloudTrail (management) | T1525 |
| P2 | New error/output patterns in the function's CloudWatch Logs after a code change | CloudWatch Logs | T1525 |
| P2 | `UpdateFunctionCode` denied at volume (`errorCode = AccessDenied`), probing | CloudTrail (management) | T1525 |
| P3 | Deploy pipeline updating code during a known deployment | CloudTrail (management) | T1525 |

### Detection Rule Quality Notes

The shipped rule matches a read and a deploy, and inspects no principal or hash. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (GetFunction, UpdateFunctionCode)` with `condition: selection` | Unusable. `UpdateFunctionCode` fires on every legitimate deploy; `GetFunction` fires on every console view and CI read. The rule never checks *who* or *what changed* | Match `UpdateFunctionCode` filtered to non-deploy principals; add the code-hash drift signal; drop the bare `GetFunction` |
| No principal allowlist | Cannot separate a deploy from a hijack | Exclude the CI/CD deploy roles; alert everyone else |
| No `CodeSha256` check | Misses the ground-truth signal (the code actually changed) and can't catch a hijack by an *allowlisted-but-compromised* pipeline | Compare `responseElements.codeSha256` (and periodic live `CodeSha256`) against the known-good baseline |
| `GetFunction` bundled in | A read is not tampering; it inflates noise | Keep only for the `GetFunction → UpdateFunctionCode` sequence correlation |
| Header TODO "verify acronym casing"; `level: medium` | Stale; arbitrary code exec under a role is higher | Resolve TODO; non-deploy code overwrite → `level: high` |

**Recommended detection, code overwrite by a non-deploy principal, plus the sequence.**

```yaml
# Rule A: UpdateFunctionCode by anyone outside the deploy pipeline
title: Lambda code overwritten by non-deploy principal
id: 6a2d9c41-5e73-4f28-b1d6-8f0c7a3e2b47
name: lambda_updatecode_nondeploy
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName: 'UpdateFunctionCode'
  deploy_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/ci-cd'
      - ':role/BreakGlassAdmin'
  condition: selection and not deploy_pipeline
level: high
---
# Rule B: the download-then-overwrite fingerprint (temporal, ordered)
title: Lambda GetFunction then UpdateFunctionCode sequence
id: 7b3e0d52-6f84-4a39-c2e7-9a1d8b4f3c58
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - lambda_get_function            # base: eventName GetFunction
    - lambda_updatecode_nondeploy    # Rule A
  group-by:
    - userIdentity.arn
  timespan: 10m
level: high
---
# Base rule for the correlation above (deploy this too)
title: Lambda GetFunction
id: 8c4f1e63-7a95-4b40-d3f8-0b2e9c5a4d69
name: lambda_get_function
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName: 'GetFunction'
  condition: selection
level: informational
```

The load-bearing complement to Rule A is the **`CodeSha256` baseline check**, a drift
detector (Config custom rule / scheduled job) comparing each function's live
`CodeSha256` (flat field of `get-function-configuration`; nested under `Configuration`
only if you call `get-function`) against its known-good build hash. That catches a hijack even
when the pipeline role itself is compromised (which Rule A's allowlist would exempt).
**On error strings:** denials surface as `AccessDenied` / `AccessDeniedException`, not
`Client.`-prefixed.

---

### Key Investigation Queries

> Lambda management events are regional, run these in the function's region (default `us-east-1`). Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**, paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 - Reconstruct the overwrite: who changed which function's code, and to what hash

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

for EV in UpdateFunctionCode GetFunction; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "lambda.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 4
     function: .requestParameters.functionName,
     new_sha: .responseElements.codeSha256,          # UpdateFunctionCode: NEW code hash (IOC)
     revision: .responseElements.revisionId,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read per caller: a `GetFunction` then an `UpdateFunctionCode` on the same `function` by
one non-deploy `caller` is the download-then-overwrite. Record the `function`, the
`new_sha` (compare to your known-good baseline, a mismatch confirms the hijack), and
`caller` (IOCs). Multiple `UpdateFunctionCode` events show the overwrite *and* any restore.

#### Query 2: Sweep ALL functions for code drift from the known-good baseline

The definitive account-wide hunt: compare every function's live `CodeSha256` to its
baseline. (Populate `BASELINE` from your CMDB/CI artifact hashes.)

```bash
REGION="us-east-1"
# Map of functionName -> known-good base64 CodeSha256 (fill from your build system):
declare -A BASELINE=(
  ["stratus-red-team-overwrite-lambda"]="<known-good-base64-sha256>"
  # ["my-prod-fn"]="abc123...="
)

for FN in $(aws lambda list-functions --region "$REGION" --query 'Functions[].FunctionName' --output text); do
  LIVE=$(aws lambda get-function-configuration --function-name "$FN" --region "$REGION" \
          --query 'CodeSha256' --output text 2>/dev/null)
  WANT="${BASELINE[$FN]}"
  if [ -n "$WANT" ] && [ "$LIVE" != "$WANT" ]; then
    echo "[!] $FN CodeSha256 DRIFT: live=$LIVE want=$WANT"
  elif [ -z "$WANT" ]; then
    echo "[i] $FN has no baseline on record, add one; live=$LIVE"
  fi
done
echo "[OK] Code-hash drift sweep complete"
```

Any `[!] ... DRIFT` line is a function whose code no longer matches its build, a
confirmed overwrite (or an unrecorded legitimate deploy; reconcile against Query 1).

#### Query 3: Inspect the current (malicious) code (it is NOT in CloudTrail)

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"

# GetFunction returns a presigned S3 Location for the CURRENT deployment package.
LOC=$(aws lambda get-function --function-name "$FUNCTION" --region "$REGION" \
        --query 'Code.Location' --output text)
curl -s "$LOC" -o /tmp/current-code.zip
mkdir -p /tmp/current-code && unzip -o -q /tmp/current-code.zip -d /tmp/current-code

echo "== Current code file tree =="; find /tmp/current-code -type f
echo "== Suspicious patterns =="
grep -rInE 'urllib|requests|socket|/dev/tcp|subprocess|os\.system|exec\(|eval\(|base64|os\.environ|pwned' /tmp/current-code 2>/dev/null
```

Diff against your known-good source. Env-var dumping, network/subprocess calls, or a
changed handler body is the payload, preserve `/tmp/current-code.zip` as evidence.

#### Query 4: Full session reconstruction of the principal that overwrote the code

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look for other persistence/tampering, more code overwrites, layer attaches
(`UpdateFunctionConfiguration`), resource-policy backdoors (`AddPermission`), IAM
backdoors, and remediate each with the relevant playbook.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The malicious code runs on every invocation under the function's execution role. Freeze
invocation, restore known-good code, and treat the role as compromised.

> Run every command under the **break-glass responder credentials** from §1, not under
> any principal being contained.

#### Step 1: Freeze the function (stop the malicious code from running)

```bash
REGION="us-east-1"; FUNCTION="<function-from-Query-1>"
# Stop all invocation without deleting the function or its logs (reverse in Recovery).
aws lambda put-function-concurrency --function-name "$FUNCTION" \
  --reserved-concurrent-executions 0 --region "$REGION" && \
  echo "[OK] Froze $FUNCTION (reserved concurrency 0), malicious code can no longer execute"
```

#### Step 2: Restore known-good code

```bash
REGION="us-east-1"; FUNCTION="<function-from-Query-1>"

# Preferred: redeploy from your trusted source/artifact (IaC pipeline or a known-good ZIP).
aws lambda update-function-code --function-name "$FUNCTION" --region "$REGION" \
  --zip-file fileb:///path/to/known-good.zip --publish && \
  echo "[OK] Restored $FUNCTION from known-good artifact"

# If you publish numbered versions, a published version is IMMUTABLE and safe: point the
# live alias back to the last-good version instead of/until a clean redeploy:
#   aws lambda update-alias --function-name "$FUNCTION" --name live --function-version <N>
```

> `UpdateFunctionCode` only affects `$LATEST`. Any **published numbered version** the
> attacker could not alter is a clean rollback target; aliases pointing at `$LATEST` (or
> at the version the attacker published) are the exposed ones, repoint them to a known-good
> numbered version.

#### Step 3: Treat the function's execution role as compromised

The malicious handler ran under the execution role, so its credentials were exposed.

```bash
EXEC_ROLE=$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
             --query 'Role' --output text | awk -F'/' '{print $NF}')

aws iam put-role-policy --role-name "$EXEC_ROLE" --policy-name "EmergencyRevokeSessions" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
echo "[OK] Revoked pre-existing sessions for execution role $EXEC_ROLE"
aws iam list-attached-role-policies --role-name "$EXEC_ROLE" --output table   # review its reach
```

> `aws:TokenIssueTime` revokes only sessions issued **before** the cutoff; with the
> function frozen (Step 1) no new credentials are being minted. Rotate any secret the role
> could read (Secrets Manager, SSM, DynamoDB rows, S3 objects it could reach).

#### Step 4: Contain the principal that overwrote the code

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
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role, root/federated: contain manually"
fi

# Deny further code changes by the principal:
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["lambda:UpdateFunctionCode","lambda:UpdateFunctionConfiguration","lambda:PublishVersion"],"Resource":"*"}]}'
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  aws iam put-role-policy --role-name "$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')" \
    --policy-name "EmergencyDenyLambdaCode" --policy-document "$DENY_DOC"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  aws iam put-user-policy --user-name "$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')" \
    --policy-name "EmergencyDenyLambdaCode" --policy-document "$DENY_DOC"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every affected function is back to known-good code

For each function Query 2 flagged as drifted, redeploy from trusted source (Step 2) and
re-verify its `CodeSha256` (Recovery). Do not merely "restore" via the attacker's own
downloaded copy, rebuild from your source of truth in case the "original" they captured
was itself tampered.

#### Remove other persistence / tampering by the principal

From Query 4, remediate anything else, layer injection (`UpdateFunctionConfiguration`),
resource-policy backdoors (`AddPermission`), IAM backdoors, using the relevant playbook.

#### Right-size code-deploy permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove lambda:UpdateFunctionCode from principals that are not the CI/CD deploy pipeline.
```

#### Remove emergency policies once clean

```bash
for RN in "<planting-role-name>" "<execution-role-name>"; do
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyRevokeSessions" 2>/dev/null
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyDenyLambdaCode" 2>/dev/null
done
# If the planting principal was an IAM USER (Containment Step 4 used put-user-policy),
# remove the inline deny from the user instead:
aws iam delete-user-policy --user-name "<planting-user-name>" --policy-name "EmergencyDenyLambdaCode" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the function's code matches the known-good baseline

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
BASELINE_SHA="<known-good-base64-sha256>"

LIVE=$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
        --query 'CodeSha256' --output text)
[ "$LIVE" = "$BASELINE_SHA" ] && echo "[OK] $FUNCTION CodeSha256 matches known-good baseline" \
                             || echo "[FAIL] $FUNCTION CodeSha256=$LIVE != baseline $BASELINE_SHA"
```

#### Re-sweep all functions for code drift

```bash
# Re-run Query 2. Expect zero "[!] ... DRIFT" lines.
echo "[i] Re-run the Query-2 drift sweep; any remaining [!] DRIFT is an unremediated overwrite."
```

#### Verify no invocations ran the malicious code since containment

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

# Invoke is DATA-plane: use the CloudWatch metric (management events won't show it).
INVOKED=$(aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations \
  --dimensions Name=FunctionName,Value="$FUNCTION" \
  --start-time "$CONTAINED_AT" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum --region "$REGION" \
  --query 'Datapoints[?Sum>`0`]' --output json | jq 'length')
[ "$INVOKED" -eq 0 ] && echo "[OK] No invocations since containment (function frozen / code restored)" \
                     || echo "[i] $INVOKED invocation window(s) since containment, confirm they post-date the code restore"
```

#### Restore normal concurrency (after code is verified clean)

```bash
REGION="us-east-1"; FUNCTION="<function-from-Query-1>"
aws lambda delete-function-concurrency --function-name "$FUNCTION" --region "$REGION" 2>/dev/null && \
  echo "[OK] Restored default (unreserved) concurrency on $FUNCTION"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm Rule A fires HIGH on the UpdateFunctionCode by a"
echo "non-deploy principal, the CodeSha256 drift check flags the changed hash, and Rule B"
echo "fires on the GetFunction->UpdateFunctionCode sequence, and that none fire on a"
echo "legitimate pipeline deploy or a bare GetFunction read."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could overwrite a function's code | `lambda:UpdateFunctionCode` available outside the CI/CD pipeline; no code-signing enforcement |
| Overwrite undetected | Shipped rule matched deploy/read events with no principal or hash check; no `CodeSha256` baseline to drift-check against |
| Tamper invisible to wiring-based checks | Only the code changed, triggers, policy, env, role all unchanged; detection that watches those sees nothing |
| Execution role compromised | The malicious handler ran under the function's role; roles were over-privileged and their sessions not revoked on suspicion |
| No clean rollback target | Function versioning not used, so no immutable known-good version to roll back to |

### Recommended Guardrails

**Enforce code signing (the strongest structural control)**

```json
// Attach a Lambda code-signing config (Signer profile) to every function with
// UntrustedArtifactOnDeployment=Enforce. Then UpdateFunctionCode with an unsigned or
// untrusted-signer package is REJECTED, an attacker without the signing key cannot
// overwrite the code. (Configured via lambda:CreateCodeSigningConfig +
// PutFunctionCodeSigningConfig, not a single inline JSON, see the Lambda code-signing docs.)
```

**Restrict code deploys to the pipeline**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["lambda:UpdateFunctionCode"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/ci-cd", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Structural controls**
- **Version and alias every function**: deploy to `$LATEST`, publish an immutable numbered version, point a `live` alias at it, so a rollback target always exists and prod traffic runs a pinned version
- **Least-privilege execution roles**, the blast-radius reducer when code does run
- **Track `CodeSha256` in a CMDB** and reconcile on a schedule (Config custom rule), the drift check that catches even a compromised-pipeline overwrite
- Manage all code through reviewed CI/CD; treat any out-of-band `UpdateFunctionCode` as an incident

**Detection improvements**
- Deploy Rule A (non-deploy code overwrite) and Rule B (download→overwrite sequence); never the shipped read+deploy name match
- Run the `CodeSha256` drift detector, the ground-truth signal
- Alarm code changes outside deploy windows

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1525 - Implant Internal Image |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `lambda:GetFunction` (download original) → `lambda:UpdateFunctionCode` (replace `$LATEST` package) |
| Event source | `lambda.amazonaws.com` (regional, query the function's region) |
| Key discriminator | `UpdateFunctionCode` by a non-deploy principal, and a `CodeSha256` that no longer matches the known-good build, not the event names |
| Ground-truth signal | `CodeSha256` (base64 SHA-256 of the package): `responseElements.codeSha256` in the event; live value is the flat `CodeSha256` field of `get-function-configuration` (or nested `Configuration.CodeSha256` via `get-function`), drift from baseline = confirmed overwrite |
| Content inspection | Code ZIP is **not** in CloudTrail, download via `GetFunction` (presigned `Code.Location`) and diff against source |
| "Was it used" pivot | **Data-plane** invocation - NOT in `lookup-events`; use CloudWatch `AWS/Lambda Invocations` + Lambda data events |
| Rollback nuance | `UpdateFunctionCode` alters only `$LATEST`; **published numbered versions are immutable** and make clean rollback targets |
| Blast radius | The function's **execution role**, treat its credentials as compromised (the malicious handler ran under it) |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | The target function persists (created by `pulumi up`); the code is overwritten then restored by the script (a real attack leaves the malicious code) |

**MITRE mapping note:** MANIFEST maps T1525 (Implant Internal Image), Persistence. It is
defensible, but **T1554 (Compromise Host Software Binary)** is arguably the closer fit for
replacing a function's *own* existing code in place (T1525 better describes implanting a
reusable component, like the layer technique). The MANIFEST's technique *name* ("Overwrite
Lambda Function Code") is the upstream Stratus label, not a canonical MITRE name. A
mapping-precision note, not an operational defect.

### Revert

The emulation restores the original code on cleanup, so a normal run leaves the function
as it was; `pulumi destroy` in `infra/` then removes the function and its role. After a
**real** incident, `pulumi destroy` is irrelevant to a code overwrite on a *production*
function, freeze it, redeploy known-good code from your source of truth (not the
attacker's captured copy), verify `CodeSha256`, treat the execution role as compromised,
and enforce code signing; the malicious code runs on every invocation until you restore
it, regardless of any stack teardown.
