# IR Playbook: Persist via Lambda Layer — Code Injection via `lambda:PublishLayerVersion` + `lambda:UpdateFunctionConfiguration`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Implant reusable component (malicious Lambda layer injected into a function) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High — a layer attached to a function ships attacker code that can run **inside the function, under the function's execution role**. If it executes, the execution-role credentials must be treated as compromised and everything that role can reach is in scope — a materially worse outcome than a mere invoke grant. As emulated the target is a hello-world handler with only `AWSLambdaBasicExecutionRole`, and (see below) the layer as shipped would not actually execute — but the technique in a real account is High. `MANIFEST.py` rates MEDIUM |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1525 |
| Services in Scope | Lambda, CloudTrail (management + Lambda data events), CloudWatch, IAM |
| Infrastructure Created | A target Lambda function (`stratus-red-team-layer-lambda`) + its execution role, via `pulumi up`. The malicious **layer** is published, attached, then detached/deleted by the attack script |

**What the emulation does:** with a pre-created target function, it (1) `lambda:PublishLayerVersion` — publishes a layer `stratus-red-team-malicious-layer` containing `python/malicious_layer.py`, then (2) `lambda:UpdateFunctionConfiguration` with `Layers=[<layer-arn>]` — attaches that layer to the function. On cleanup it detaches the layer (`UpdateFunctionConfiguration` with `Layers=[]`) and deletes the layer version. A normal run leaves only the CloudTrail trail; a real intrusion leaves the layer attached, running on every invocation.

**Why this is persistence, and why code-redeploy does not fix it.** The function's own code/ZIP is never modified — so redeploying the function from source (the usual "clean the function" reflex) leaves the layer attached and the injection intact. The malicious code lives in a *separate* versioned artifact (the layer) that the function references. Removing it requires editing the function's **layer list**, not its code.

**Detection is the layer, not the event name.** `UpdateFunctionConfiguration` is one of the most routine Lambda calls (every memory/timeout/env-var/layer change). The signal is **a new, unexpected layer ARN being attached** — especially one published moments earlier by a non-deploy principal, or owned by an account that is not yours/a trusted vendor. The shipped rule matches `PublishLayerVersion`/`UpdateFunctionConfiguration`/`DeleteLayerVersion` with no layer inspection (§2), so it fires on every config change and every layer cleanup.

**Important accuracy note — does the injected code actually run?** A Lambda **layer** unpacks to `/opt`; `python/` is added to `sys.path` *after* the function's own package. So a `python/<module>.py` layer file executes only if the function **imports that module name** — either because the function already imports it, or because the attacker **shadows a third-party dependency** the function imports (the layer's copy on the path wins over site-packages, though not over the function's own top-level modules). Code that must run on *every* invocation regardless of imports belongs in a true **Lambda extension** (`/opt/extensions/<exe>`), which the runtime launches as a separate process automatically. The emulation ships code under `python/` (a code layer, **not** an `/opt/extensions/` extension) and the hello-world handler does not import it, so **as emulated the code would not actually execute** — but detection and response must assume a real attacker chose an executing path (shadowed dependency or a genuine extension). Treat any unexpected attached layer as live until you have inspected its contents.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing Lambda **management** events. `PublishLayerVersion` carries `requestParameters.layerName`, `.compatibleRuntimes`, and `responseElements.layerVersionArn`/`.version` (the layer **content ZIP is not logged**). `UpdateFunctionConfiguration` carries `requestParameters.functionName` and `requestParameters.layers` (the **full new** layer-ARN list — this call *replaces* the list, it does not append)
- **Lambda data events** enabled for the functions that matter, so invocations during the layer's exposure window are recorded
- An **approved-layer allowlist** (the layer ARNs / owner accounts your functions are supposed to use), so an attach outside it is a concrete match

**Alerting (must be pre-configured)**
- **`UpdateFunctionConfiguration` attaching a layer ARN not on the approved-layer allowlist → P0** (especially a layer owned by an account that is not yours/a trusted vendor)
- **Sequence `PublishLayerVersion` → `UpdateFunctionConfiguration` (adding that layer) by one principal within minutes → P0** (the publish-then-attach fingerprint)
- `lambda:PublishLayerVersion` by a principal that is not the IaC/deploy pipeline
- `lambda:AddLayerVersionPermission` sharing a layer to an external account (attacker preparing reuse)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq`; `unzip`; a sandbox host to download and inspect layer contents offline
- The approved-layer allowlist and, per function, its **execution-role ARN** (to scope the blast radius immediately)

**Known IOC Baselines**
- The emulation's layer name `stratus-red-team-malicious-layer`, function `stratus-red-team-layer-lambda`, tag `StratusRedTeam=true`
- Baseline which functions use which layers, and which principals publish layers — a new layer/publisher is the signal
- Baseline each function's execution role, so a compromised one is immediately scoped

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `UpdateFunctionConfiguration` attaching a layer ARN not on the approved-layer allowlist (or owned by an out-of-org account) | CloudTrail (management) | T1525 |
| P0 | Ordered sequence `PublishLayerVersion → UpdateFunctionConfiguration(add that layer)` by one principal within minutes | CloudTrail (management) | T1525 |
| P1 | `lambda:PublishLayerVersion` by a non-IaC principal | CloudTrail (management) | T1525 |
| P1 | `lambda:AddLayerVersionPermission` sharing a layer to an external account | CloudTrail (management) | T1525 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateFunctionConfiguration` layer change outside a deployment window | CloudTrail (management) | T1525 |
| P2 | Invocations of the function during the interval its layer set included an unapproved layer | CloudWatch / data events | T1525 |
| P2 | `PublishLayerVersion`/`UpdateFunctionConfiguration` denied at volume (`errorCode = AccessDenied`) — probing | CloudTrail (management) | T1525 |
| P3 | IaC/deploy pipeline attaching a known, allowlisted layer during a deployment | CloudTrail (management) | T1525 |

### Detection Rule Quality Notes

The shipped rule matches config changes and layer cleanup, and inspects no layer. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (PublishLayerVersion, UpdateFunctionConfiguration, DeleteLayerVersion)` with `condition: selection` | Unusable. `UpdateFunctionConfiguration` fires on every memory/timeout/env/layer change; `DeleteLayerVersion` is teardown (and here the emulation's own cleanup). The rule never inspects *which layer* was attached | Match `UpdateFunctionConfiguration` where `requestParameters.layers` includes an unapproved ARN; add the `Publish → Update` sequence; drop `DeleteLayerVersion` from the alert |
| No layer/allowlist inspection | The entire signal — *which* layer — is exactly what the event-name match ignores | Compare each ARN in `requestParameters.layers` against the approved-layer allowlist / owner-account allowlist |
| `DeleteLayerVersion` bundled in | Deleting a layer is not persistence; it inverts the signal and adds noise | Keep only for the forensic timeline |
| No `PublishLayerVersion → attach` correlation | Misses the publish-then-attach fingerprint | Add a temporal correlation grouped by principal |
| Header TODO "verify acronym casing"; `level: medium` | Stale; code injection under a role is higher | Resolve TODO; unapproved-layer attach → `level: high` |

**Recommended detection — unapproved layer attached, plus the publish-then-attach sequence.**

```yaml
# Rule A — a layer outside the approved set attached to a function
title: Lambda function configured with an unapproved layer
id: 3d9b6f21-7c48-4e15-a2d6-9f0b7c5e1a34
name: lambda_attach_unapproved_layer
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName: 'UpdateFunctionConfiguration'
    requestParameters.layers|contains: 'arn:aws:lambda:'   # a layer set was supplied
  # The approved-layer allowlist is environment-specific and cannot be a static Sigma
  # value. Enforce it at the log platform: for each ARN in requestParameters.layers,
  # alert unless the ARN (or its owner account = the 5th ':'-delimited field) is on the
  # approved-layer / trusted-owner allowlist.
  condition: selection
level: high
---
# Rule B — the publish-then-attach fingerprint (temporal, ordered)
title: Lambda publish-layer then attach sequence
id: 4e0c7a32-8d59-4f26-b3e7-0a1c8d6f2b45
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - lambda_publish_layer            # base: eventName PublishLayerVersion
    - lambda_attach_unapproved_layer  # Rule A
  group-by:
    - userIdentity.arn
  timespan: 15m
level: high
---
# Base rule for the correlation above (deploy this too)
title: Lambda PublishLayerVersion
id: 5f1d8b43-9e60-4a37-c4f8-1b2d9e7a3c56
name: lambda_publish_layer
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName: 'PublishLayerVersion'
  condition: selection
level: informational
```

All three documents deploy together. The **layer-allowlist** decision — the load-bearing
half of Rule A — must run in your rules engine against the live approved-layer list, since
it is a per-environment set, not a static value. **On error strings:** denials surface as
`AccessDenied` / `AccessDeniedException`, not `Client.`-prefixed.

---

### Key Investigation Queries

> Lambda management events are regional — run these in the function's region (default `us-east-1`). Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct the injection: who published a layer and attached it where

```bash
REGION="us-east-1"

for EV in PublishLayerVersion UpdateFunctionConfiguration AddLayerVersionPermission; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "lambda.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,           # feeds ACCESS_KEY_ID in Query 4
     function: .requestParameters.functionName,
     layers: .requestParameters.layers,               # UpdateFunctionConfiguration: full new list
     layer_name: .requestParameters.layerName,        # PublishLayerVersion
     published_arn: .responseElements.layerVersionArn, # PublishLayerVersion result (IOC)
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read per caller: a `PublishLayerVersion` (record `published_arn`) immediately followed
by an `UpdateFunctionConfiguration` whose `layers` includes that ARN is the injection.
Record the `function`, the layer ARN, and `caller` (IOCs). Note the layer's **owner
account** is the 5th `:`-field of the ARN — if it is not yours/a trusted vendor, that
alone is suspicious.

#### Query 2 — Sweep ALL functions for unapproved layers (find every injection)

The attacker may have attached the layer to more than one function, or one you did not
see in Query 1's window. List every function's current layer set and flag any ARN not
on the approved-layer allowlist.

```bash
REGION="us-east-1"
# Approved layer ARNs / trusted owner accounts (fill from your baseline):
APPROVED="arn:aws:lambda:us-east-1:111122223333:layer:approved-shared:4 <owner-accounts-or-arns>"

aws lambda list-functions --region "$REGION" --output json | \
  jq -r '.Functions[] | {fn: .FunctionName, layers: (.Layers // [] | map(.Arn))} |
         select(.layers | length > 0) | "\(.fn)\t\(.layers | join(","))"' | \
while IFS=$'\t' read -r FN LAYERS; do
  for ARN in $(echo "$LAYERS" | tr ',' ' '); do
    case " $APPROVED " in
      *" $ARN "*) : ;;                                  # exact allowlisted ARN — ok
      *) OWNER=$(echo "$ARN" | awk -F: '{print $5}')     # owner account = 5th field
         case " $APPROVED " in
           *" $OWNER "*) : ;;                            # trusted owner account — ok
           *) echo "[!] $FN uses unapproved layer $ARN (owner $OWNER)" ;;
         esac ;;
    esac
  done
done
echo "[OK] Layer sweep complete"
```

Cross-check each flagged function's layer ARN against Query 1 — a layer published by a
non-deploy principal and attached out-of-band is the injection.

#### Query 3 — Inspect the layer's contents (the code is NOT in CloudTrail)

```bash
REGION="us-east-1"
LAYER_ARN="<published_arn-from-Query-1>"

# get-layer-version-by-arn returns a presigned S3 Location to download the ZIP.
LOC=$(aws lambda get-layer-version-by-arn --arn "$LAYER_ARN" --region "$REGION" \
        --query 'Content.Location' --output text)
curl -s "$LOC" -o /tmp/suspect-layer.zip
mkdir -p /tmp/suspect-layer && unzip -o -q /tmp/suspect-layer.zip -d /tmp/suspect-layer

echo "== Layer file tree =="; find /tmp/suspect-layer -type f
echo "== /opt/extensions present? (auto-run extension = executes every invoke) =="
ls /tmp/suspect-layer/extensions 2>/dev/null && echo "[!] EXTENSION present — auto-runs" || echo "[i] no extensions/ dir"
echo "== Suspicious patterns in layer code =="
grep -rInE 'urllib|requests|socket|/dev/tcp|subprocess|os\.system|boto3|exec\(|eval\(|base64' /tmp/suspect-layer 2>/dev/null
```

Determine the execution path: an `extensions/` entry **auto-runs** every invocation; a
`python/<name>.py` runs only if the function imports `<name>` (or the name shadows a
third-party dependency the function imports). Any network/subprocess/credential code is
the payload — preserve `/tmp/suspect-layer.zip` as evidence.

#### Query 4 — Full session reconstruction of the principal that planted the layer

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look for other persistence/tampering by the same principal — more layer attaches,
`UpdateFunctionCode` (code overwrite), `AddPermission` (resource-policy backdoor),
`CreateFunctionUrlConfig`, IAM backdoors — and remediate each with the relevant playbook.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The injection is a layer in the function's config, and its code (if it executed) ran
under the function's execution role. Detach the layer, freeze execution if the role is
privileged, and contain the planting principal and the possibly-compromised role.

> Run every command under the **break-glass responder credentials** from §1, not under
> any principal being contained.

#### Step 1 — Detach the malicious layer (re-specifying the layers to KEEP)

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
BAD_LAYER="<published_arn-from-Query-1>"   # exact ARN incl. version, or a prefix to drop

# UpdateFunctionConfiguration --layers REPLACES the entire list. Compute the layers to
# keep (everything except the malicious one) and set exactly those — do NOT pass an empty
# list unless the bad layer was the only one, or you will strip legitimate layers too.
KEEP=$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
        --query 'Layers[].Arn' --output text | tr '\t' '\n' | grep -vF "$BAD_LAYER" | tr '\n' ' ')

# shellcheck disable=SC2086  (word-splitting is intended to pass each ARN separately)
aws lambda update-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --layers $KEEP && echo "[OK] Detached $BAD_LAYER from $FUNCTION (kept: ${KEEP:-none})"
```

#### Step 2 — Freeze the function if its execution role is privileged

```bash
REGION="us-east-1"; FUNCTION="<function-from-Query-1>"
# If you cannot yet rule out that the layer executed and the role is privileged, stop all
# invocation without deleting the function or its logs (reverse in Recovery):
aws lambda put-function-concurrency --function-name "$FUNCTION" \
  --reserved-concurrent-executions 0 --region "$REGION" && \
  echo "[OK] Froze $FUNCTION (reserved concurrency 0)"
```

#### Step 3 — Treat the function's execution role as compromised

If the layer could have executed (an `extensions/` entry, or a `python/` module the
function imports/shadows — see Query 3), the execution-role credentials were exposed to
attacker code. Revoke its live sessions and review its reach.

```bash
EXEC_ROLE=$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
             --query 'Role' --output text | awk -F'/' '{print $NF}')

# Revoke sessions issued before now (kills currently-leaked role credentials).
aws iam put-role-policy --role-name "$EXEC_ROLE" --policy-name "EmergencyRevokeSessions" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
echo "[OK] Revoked pre-existing sessions for execution role $EXEC_ROLE"
aws iam list-attached-role-policies --role-name "$EXEC_ROLE" --output table   # review its reach
```

> `aws:TokenIssueTime` revokes only sessions issued **before** the cutoff; because the
> function is frozen (Step 2), no new credentials are being minted. Review what the role
> could access (S3, Secrets Manager, DynamoDB, etc.) and rotate any secret it could read.

#### Step 4 — Contain the principal that planted the layer

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
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete the malicious layer version (so it cannot be re-attached)

```bash
REGION="us-east-1"
BAD_LAYER="<published_arn-from-Query-1>"
LNAME=$(echo "$BAD_LAYER" | awk -F: '{print $7}')    # arn:aws:lambda:region:acct:layer:NAME:VERSION
LVER=$(echo "$BAD_LAYER"  | awk -F: '{print $8}')

# If the attacker shared the layer to other accounts for reuse, remove those grants first.
for SID in $(aws lambda get-layer-version-policy --layer-name "$LNAME" --version-number "$LVER" \
              --region "$REGION" --query 'Policy' --output text 2>/dev/null | \
              jq -r 'fromjson | (.Statement // [] | if type=="object" then [.] else . end)[].Sid' 2>/dev/null); do
  aws lambda remove-layer-version-permission --layer-name "$LNAME" --version-number "$LVER" \
    --statement-id "$SID" --region "$REGION" && echo "[OK] Removed layer share $SID"
done

aws lambda delete-layer-version --layer-name "$LNAME" --version-number "$LVER" --region "$REGION" && \
  echo "[OK] Deleted malicious layer $LNAME:$LVER"
```

Repeat detach + delete for every function/layer Query 2 surfaced.

#### Remove other persistence / tampering by the principal

From Query 4, remediate anything else — code overwrite (`UpdateFunctionCode` → redeploy
from a trusted source), a resource-policy backdoor (`AddPermission`), function URLs, IAM
backdoors — using the relevant playbook for each.

#### Right-size layer/config permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove lambda:PublishLayerVersion / UpdateFunctionConfiguration / AddLayerVersionPermission
# from principals that are not the IaC/deploy pipeline.
```

#### Remove emergency policies once clean

```bash
for RN in "<planting-role-name>" "<execution-role-name>"; do
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyRevokeSessions" 2>/dev/null
done
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the malicious layer is detached and deleted

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
BAD_LAYER="<published_arn-from-Query-1>"

aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --query 'Layers[].Arn' --output text | grep -qF "$BAD_LAYER" \
  && echo "[FAIL] $BAD_LAYER still attached to $FUNCTION" \
  || echo "[OK] $BAD_LAYER no longer attached to $FUNCTION"

LNAME=$(echo "$BAD_LAYER" | awk -F: '{print $7}'); LVER=$(echo "$BAD_LAYER" | awk -F: '{print $8}')
aws lambda get-layer-version --layer-name "$LNAME" --version-number "$LVER" --region "$REGION" >/dev/null 2>&1 \
  && echo "[FAIL] layer version $LNAME:$LVER still exists" \
  || echo "[OK] layer version $LNAME:$LVER confirmed deleted"
```

#### Re-sweep all functions for unapproved layers

```bash
# Re-run Query 2. Expect zero "[!] ... unapproved layer" lines.
echo "[i] Re-run the Query-2 sweep; any remaining [!] line is an unremediated injection."
```

#### Verify no invocations ran under the malicious layer since containment

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

# Invoke is DATA-plane — use the CloudWatch metric (management events won't show it).
INVOKED=$(aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations \
  --dimensions Name=FunctionName,Value="$FUNCTION" \
  --start-time "$CONTAINED_AT" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum --region "$REGION" \
  --query 'Datapoints[?Sum>`0`]' --output json | jq 'length')
[ "$INVOKED" -eq 0 ] && echo "[OK] No invocations since containment (layer detached; role revoked)" \
                     || echo "[i] $INVOKED invocation window(s) since containment — confirm they post-date layer removal"
```

#### Restore normal concurrency (if frozen in Step 2)

```bash
REGION="us-east-1"; FUNCTION="<function-from-Query-1>"
aws lambda delete-function-concurrency --function-name "$FUNCTION" --region "$REGION" 2>/dev/null && \
  echo "[OK] Restored default (unreserved) concurrency on $FUNCTION"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm Rule A fires HIGH on the UpdateFunctionConfiguration"
echo "attaching the unapproved layer, and Rule B fires on the PublishLayerVersion->attach"
echo "sequence — and that NEITHER fires on the DeleteLayerVersion / layer-detach cleanup."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could publish a layer and attach it to a function | `lambda:PublishLayerVersion` + `lambda:UpdateFunctionConfiguration` available outside the IaC pipeline; no allowlist of permitted layers |
| Injection undetected | Shipped rule matched config-change and layer-delete events with no layer inspection; no approved-layer allowlist to compare against |
| Persistence survives a function code redeploy | The payload lives in a *layer*, not the function ZIP — redeploying code leaves it attached |
| Execution role possibly compromised | If the layer executed, it ran under the function's role; roles were over-privileged and their sessions not revoked on suspicion |
| Blast radius under-appreciated | Per-function execution roles were not baselined, so the reach of a compromised one was not immediately known |

### Recommended Guardrails

**Restrict who may publish/attach layers to the deploy pipeline**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// deny layer publish/attach/share outside the IaC pipeline.
{
  "Effect": "Deny",
  "Action": ["lambda:PublishLayerVersion", "lambda:UpdateFunctionConfiguration", "lambda:AddLayerVersionPermission"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

(Note this denies *all* `UpdateFunctionConfiguration` for non-pipeline principals, not
only layer changes — Lambda has no request-context condition key for the specific layer
ARN being attached, so the config-change action cannot be narrowed to "layer changes
only" in IAM. If that is too broad, drop `UpdateFunctionConfiguration` from this deny and
rely on the approved-layer detection + code signing below.)

**Structural controls**
- **Code signing for Lambda** (`lambda:CreateCodeSigningConfig` + a Signer profile): with a code-signing config that enforces on deploy, only layers/packages signed by a trusted profile can be attached — the strongest structural control against an unapproved layer
- **Least-privilege execution roles** per function — the blast-radius reducer if a layer does execute
- Maintain an **approved-layer allowlist** and reconcile function layer sets against it on a schedule
- Manage all layers and function config through reviewed IaC; treat any out-of-band publish/attach as an incident

**Detection improvements**
- Deploy Rule A (unapproved-layer attach) and Rule B (publish→attach sequence); never the shipped config-change name match
- Compare every attached layer ARN / owner account against the approved-layer allowlist
- Alarm `AddLayerVersionPermission` to external accounts

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1525 — Implant Internal Image |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `lambda:PublishLayerVersion` → `lambda:UpdateFunctionConfiguration` (`Layers=[...]`) |
| Event source | `lambda.amazonaws.com` (regional — query the function's region) |
| Key discriminator | An **unapproved layer ARN** attached (owner account = 5th ARN field), and the publish→attach sequence — not the event names |
| `UpdateFunctionConfiguration` gotcha | `requestParameters.layers` is the **full replacement** list; detach by re-specifying the layers to KEEP, never blindly `--layers []` |
| Content inspection | Layer ZIP is **not** in CloudTrail — download via `get-layer-version-by-arn` (presigned `Content.Location`) and scan |
| Execution path | `python/<mod>.py` runs only if imported/shadows a dependency; `/opt/extensions/<exe>` auto-runs every invocation. The emulation ships `python/` code the handler never imports → would not execute as-shipped |
| "Was it used" pivot | **Data-plane** invocation — NOT in `lookup-events`; use CloudWatch `AWS/Lambda Invocations` + Lambda data events |
| Blast radius | The function's **execution role** — treat its credentials as compromised if the layer executed |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | The target function persists (created by `pulumi up`); the layer is published/attached/deleted by the script (a real attack leaves it attached) |

**MITRE mapping note:** T1525 (Implant Internal Image), Persistence, is a defensible
mapping — a Lambda layer is a reusable component implanted with malicious code. The
MANIFEST's technique *name* ("Persist via Lambda Layer") is the upstream Stratus label,
not a canonical MITRE technique name; cosmetic, not a mis-mapping.

### Revert

The emulation detaches and deletes its own layer on cleanup, so a normal run leaves the
function with no extra layer; `pulumi destroy` in `infra/` then removes the function and
its role. After a **real** incident, `pulumi destroy` is irrelevant to layers attached to
*other* functions — detach every unapproved layer (re-specifying the keep-list), delete
the layer versions and any cross-account shares, treat every affected execution role as
compromised, and restrict layer publish/attach via SCP + code signing; the layer persists
on each function until you detach it, regardless of any stack teardown.
```
