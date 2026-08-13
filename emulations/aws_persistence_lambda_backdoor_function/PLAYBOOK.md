# IR Playbook - Backdoor Lambda Function via Resource Policy - Persistence via `lambda:AddPermission`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Account Manipulation (cross-account resource-policy backdoor on a Lambda function) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, `lambda:AddPermission` grants an **external AWS account** a standing right to invoke the function, independent of any IAM credential, so it survives rotation and deletion of the compromised principal. The blast radius is the **function's execution role and the data it touches**: invoking a backdoored function runs its code under that role. As emulated the target function is a trivial handler with only `AWSLambdaBasicExecutionRole` (logs only), so an invoke gains little, but in a real account the execution role is the multiplier; treat as High until you have confirmed the function's role is unprivileged. `MANIFEST.py` rates MEDIUM |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1098 |
| Services in Scope | Lambda, CloudTrail (management + Lambda data events), CloudWatch, IAM Access Analyzer, GuardDuty |
| Infrastructure Created | A target Lambda function (`stratus-red-team-backdoor-lambda`) + its execution role, via `pulumi up`. The backdoor **statement** is added and removed by the attack script |

**What the emulation does:** with a pre-created target function, it calls `lambda:AddPermission` to add a statement (`StatementId=stratus-red-team-backdoor-stmt`) to the function's **resource-based policy**, granting `lambda:InvokeFunction` to external account **`193672423079`**. The attacker's account can now invoke the function directly, cross-account. The script removes the statement on cleanup (`RemovePermission`), so a normal run leaves only the CloudTrail trail, a real intrusion leaves the statement (and the standing cross-account grant) in place.

**Why this is persistence, and why it is easy to miss.** The grant lives in the *function's* resource policy, not in IAM. Rotating the attacker's access key, deleting their user/role, and reviewing IAM policies all leave it untouched. Nobody sees it unless they read each function's resource policy (`get-policy`) or run Access Analyzer. It is the Lambda analogue of a backdoored role trust policy.

**Detection is the principal in the statement, not the event name.** `lambda:AddPermission` is used legitimately all the time, to let S3, SNS, EventBridge, API Gateway, or a sibling account invoke a function. The signal is **`AddPermission` whose `principal` is an external/untrusted AWS account or `*`, granting an `Invoke` action**, not the bare event name. The shipped rule matches `AddPermission` *and* `RemovePermission` with no principal inspection (§2), so it fires on every legitimate integration wiring *and* on the attacker's own cleanup.

**One trap that inverts a naïve "was it used" check:** `lambda:InvokeFunction` is a **data-plane** event. It is **not** in CloudTrail management events / `lookup-events`. A `lookup-events` query for `Invoke` always returns zero, never read that as "the backdoor was never used." Use the CloudWatch `AWS/Lambda Invocations` metric and Lambda **data events** (if enabled) instead (Query 3).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing Lambda **management** events. `AddPermission` carries `requestParameters.functionName`, `.statementId`, `.action`, `.principal` (the granted account/service/ARN, **cleartext**, not URL-encoded), and optionally `.sourceArn`/`.sourceAccount`/`.principalOrgID`/`.qualifier`
- **Lambda data events** enabled on the trail for the functions that matter (or at least an account-wide Lambda data-event selector), so a cross-account `Invoke` is actually recorded, otherwise invocation is invisible to CloudTrail and only the CloudWatch metric shows it
- IAM **Access Analyzer** enabled, it analyzes Lambda function resource policies and raises a finding when one grants access to an external principal
- GuardDuty enabled, resource-policy and anomalous-invocation findings corroborate this technique

**Alerting (must be pre-configured)**
- **`lambda:AddPermission` where `principal` is an AWS account ID not in the org / not on an allowlist, or `*`, with an `Invoke` action → P0**
- **Access Analyzer finding: a Lambda function shares invoke access with an external account → P0**
- `lambda:AddPermission` by a principal that is not the IaC/deploy pipeline (weaker alone; strong combined with an external principal)
- CloudWatch alarm on an `Invocations` spike on a function that is normally idle / event-driven only

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` (the resource policy from `get-policy` is a **stringified** JSON that must be `fromjson`-parsed)
- The list of trusted invoking accounts / the org account list (`aws organizations list-accounts`), and the allowlist of service principals that legitimately invoke functions

**Known IOC Baselines**
- The attacker account in this emulation: **`193672423079`**; StatementId `stratus-red-team-backdoor-stmt`; function `stratus-red-team-backdoor-lambda`
- Baseline which functions have resource policies and which principals they grant to, a new external-account statement is the signal
- Baseline the execution role of each function, so you can immediately judge the blast radius of a backdoored one

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `lambda:AddPermission` granting `Invoke` to an **external account** (not in org/allowlist) or to `principal="*"` | CloudTrail (management) | T1098 |
| P0 | Access Analyzer finding: Lambda function invoke-shared with an external account | IAM Access Analyzer | T1098 |
| P1 | `lambda:AddPermission` by a non-IaC principal adding any cross-account/public grant | CloudTrail (management) | T1098 |
| P1 | Cross-account `Invoke` of the function by the granted external account (post-grant) | CloudTrail **data events** / CloudWatch | T1098 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `lambda:AddPermission` to another **in-org** account outside the normal pattern | CloudTrail (management) | T1098 |
| P2 | `lambda:CreateFunctionUrlConfig` with `AuthType=NONE` (public HTTP invoke, a sibling backdoor surface) | CloudTrail (management) | T1098 |
| P2 | `lambda:AddPermission` denied at volume (`errorCode = AccessDenied`), probing | CloudTrail (management) | T1098 |
| P3 | IaC/deploy pipeline wiring a known service principal (`s3`/`sns`/`events`/`apigateway`) to a function | CloudTrail (management) | T1098 |

### Detection Rule Quality Notes

The shipped rule matches the grant *and* its removal, and inspects no principal. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (AddPermission, RemovePermission)` with `condition: selection` | Noisy and signal-blind. `AddPermission` is routine integration wiring; `RemovePermission` is its teardown (and here the emulation's own cleanup). The rule fires on every legit S3/SNS/EventBridge wiring and on removals | Match `AddPermission` only, filtered to a **cross-account/wildcard `principal`** with an `Invoke` action; drop `RemovePermission` from the alerting rule |
| No `principal` inspection | The entire signal, *who* was granted, is exactly what the event-name match ignores | Extract `requestParameters.principal`; alert when it is an account ID not in the org/allowlist, or `*` |
| `RemovePermission` bundled in | A permission *removal* is not persistence; it inverts the signal and adds noise | Keep `RemovePermission` only for the forensic timeline, not the alert |
| No account-scope / allowlist | Cannot separate a sibling-account integration from an attacker account | Compare `principal` against `aws organizations list-accounts` + a service allowlist |
| Header TODO "verify acronym casing"; `level: medium` | Stale; a standing external invoke grant is higher | Resolve TODO; external/wildcard grant → `level: high` |

**Recommended detection, external/wildcard invoke grant.**

```yaml
title: Lambda AddPermission granting external/public invoke
id: 5f2a7c81-4d63-4e90-b1c7-8a0e6b3d5f19
name: lambda_addpermission_external
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName: 'AddPermission'
    requestParameters.action|contains: 'Invoke'   # InvokeFunction / InvokeFunctionUrl
  public:
    requestParameters.principal: '*'
  # 'external' cannot be expressed as a static Sigma value: it is any AWS account
  # not in your org. Enforce it at the log platform: compare requestParameters.principal
  # (a 12-digit account or an account-root ARN) against the org account list, or an
  # allowlist watchlist, and alert when it is neither an in-org account nor a trusted
  # service principal (*.amazonaws.com).
  service_principal:
    requestParameters.principal|endswith: '.amazonaws.com'
  condition: selection and (public or not service_principal)
level: high
```

The `principal` is **cleartext** in the event (a request parameter, not a URL-encoded
policy document), so account digits match directly, no decode step is needed here.
Because "external account" is a set membership your rules engine must evaluate against
the live org list, treat the Sigma above as the static half (public `*` and
non-service grants) and pair it with a log-platform join against
`aws organizations list-accounts` for the "not in my org" half. **On error strings:**
denials surface as `AccessDenied` / `AccessDeniedException`, not `Client.`-prefixed.

---

### Key Investigation Queries

> Lambda management events are regional, the function lives in one region; run these there (default `us-east-1`, adjust to the function's region). Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**, paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 - Reconstruct the grant: who added what to which function's policy

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

for EV in AddPermission RemovePermission CreateFunctionUrlConfig; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "lambda.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,        # feeds ACCESS_KEY_ID in Query 4
     function: .requestParameters.functionName,
     statement_id: .requestParameters.statementId,
     action: .requestParameters.action,
     principal: .requestParameters.principal,       # the granted account/service/*, cleartext IOC
     url_auth: (.requestParameters.authType // .requestParameters.functionUrlAuthType),  # NONE=public URL; CreateFunctionUrlConfig uses authType, AddPermission uses functionUrlAuthType
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

An `AddPermission` whose `principal` is an account ID not in your org (here
`193672423079`) or `*`, with an `Invoke` `action`, is the backdoor. Record the
`function`, `statement_id`, and `principal` (IOCs). A `CreateFunctionUrlConfig`
with `url_auth="NONE"` is a second public-invoke surface, check for it too.

#### Query 2: Sweep ALL functions' resource policies for external principals (find every backdoor)

The attacker may have backdoored more than one function, or one you did not see in
Query 1's window. Read every function's resource policy and flag any statement
granting an out-of-org account or `*`.

```bash
REGION="us-east-1"
# Trusted in-org accounts (add your account IDs / pull from Organizations):
ORG_ACCOUNTS="$(aws organizations list-accounts --query 'Accounts[].Id' --output text 2>/dev/null)"
OWNER_ACCT="$(aws sts get-caller-identity --query Account --output text)"

for FN in $(aws lambda list-functions --region "$REGION" --query 'Functions[].FunctionName' --output text); do
  POL=$(aws lambda get-policy --function-name "$FN" --region "$REGION" --query 'Policy' --output text 2>/dev/null)
  [ -z "$POL" ] && continue    # no resource policy on this function
  echo "$POL" | jq -r --arg org "$ORG_ACCOUNTS $OWNER_ACCT" --arg fn "$FN" '
    fromjson
    | (.Statement // [] | if type=="object" then [.] else . end)   # Statement may be object OR array
    | .[]
    | . as $s
    # Normalise Principal to a list of principal strings, guarding every shape:
    | ( if (.Principal|type)=="string" then [.Principal]            # bare "*"
        elif (.Principal.AWS|type)=="array" then .Principal.AWS
        elif (.Principal.AWS|type)=="string" then [.Principal.AWS]
        else [] end ) as $prins
    | $prins[]
    | . as $p
    # Extract the 12-digit account from a bare id or an account-root ARN:
    | ( ($p | capture("(?<acct>[0-9]{12})").acct) // ($p|select(.=="*")) ) as $acct
    | select($acct != null and ($org | contains($acct) | not))
    | "[!] \($fn): statement Sid=\($s.Sid) grants \($s.Action) to \($p)"'
done
echo "[OK] Lambda resource-policy sweep complete"

# Corroborate with Access Analyzer (it analyzes Lambda resource policies natively):
ANALYZER=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text 2>/dev/null)
[ -n "$ANALYZER" ] && [ "$ANALYZER" != "None" ] && \
  aws accessanalyzer list-findings-v2 --analyzer-arn "$ANALYZER" \
    --filter '{"resourceType":{"eq":["AWS::Lambda::Function"]},"status":{"eq":["ACTIVE"]}}' \
    --query 'findings[].{Resource:resource,Status:status}' --output table 2>/dev/null
```

> The shape guards matter: IAM allows `Statement` as an object or array, and
> `Principal` as `"*"`, `{"AWS":"arn"}`, or `{"AWS":["arn",...]}`. Note `AddPermission`
> with a bare account stores the principal as `arn:aws:iam::193672423079:root`, so the
> 12-digit account is what survives the match. `contains` on a space-joined account
> list is a substring test, fine for fixed-width 12-digit IDs, which cannot be
> substrings of one another.

#### Query 3: Was the backdoored function INVOKED by the external account?

> **`lambda:InvokeFunction` is a data-plane event, it is NOT in `lookup-events`.**
> A management-event query for `Invoke` always returns zero; that is not evidence of
> non-use. Use the two sources below.

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
ATTACKER_ACCT="<principal-from-Query-1>"

# (a) CloudWatch Invocations metric: did the function run at all, and when?
aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations \
  --dimensions Name=FunctionName,Value="$FUNCTION" \
  --start-time "$START" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum --region "$REGION" \
  --query 'Datapoints[?Sum>`0`].[Timestamp,Sum]' --output text | sort

# (b) Lambda DATA events (only if data-event logging was enabled on the trail),
#     these carry the caller, so you can confirm the EXTERNAL account invoked it.
#     NB: match the function on .resources[].ARN, NOT requestParameters - a synchronous
#     (RequestResponse) Invoke records requestParameters=null and the function identity
#     lives only in the resources[] array, so a requestParameters.functionName filter
#     would silently drop the default (sync) invoke an attacker most likely uses.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Invoke \
  --start-time "$START" \
  --region "$REGION" --output json 2>/dev/null | \
  jq -r --arg fn "$FUNCTION" --arg acct "$ATTACKER_ACCT" '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource=="lambda.amazonaws.com"
           and (([.resources[]?.ARN] | map(. // "" | test(":function:" + $fn + "(:|$)")) | any)
                or ((.requestParameters.functionName // "") | contains($fn)))) |
    {time: .eventTime, caller_acct: .userIdentity.accountId, caller: .userIdentity.arn,
     ip: .sourceIPAddress} |
    select(.caller_acct == $acct or .caller_acct == null)' | jq -s 'sort_by(.time)'
```

An `Invocations` datapoint after the grant timestamp means the backdoor was live and
used; a data event whose `caller_acct` is the attacker account is direct confirmation
of cross-account abuse (and every action the function took under its execution role
during that window is in scope). If **(b)** returns nothing because data events were
never enabled, rely on **(a)** and enable Lambda data events now.

#### Query 4: Full session reconstruction of the principal that planted the backdoor

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

Look for *other* persistence and tampering by the same principal, more
`AddPermission` grants, `UpdateFunctionCode` (code overwrite), `PublishLayerVersion` +
`AddLayerVersionPermission` (layer backdoor), `CreateFunctionUrlConfig`, IAM
backdoors, and remediate each with the relevant playbook.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The backdoor is a standing statement in the function's resource policy. Remove it,
determine whether it was invoked, and contain the planting principal.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Remove the backdoor statement(s) from the function policy

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
STMT_ID="<statement_id-from-Query-1>"

# Remove the specific backdoor statement (its existence is already in CloudTrail,
# so no evidence is lost by removing it).
aws lambda remove-permission --function-name "$FUNCTION" --statement-id "$STMT_ID" --region "$REGION" && \
  echo "[OK] Removed statement $STMT_ID from $FUNCTION" || \
  echo "[i] Statement $STMT_ID not present (already removed, or wrong id)"

# Re-read the policy and confirm no other external/public statement remains.
aws lambda get-policy --function-name "$FUNCTION" --region "$REGION" --query 'Policy' --output text 2>/dev/null | \
  jq -r 'fromjson | (.Statement // [] | if type=="object" then [.] else . end)[]
         | {Sid, Principal, Action}'

# If the attacker also created a public function URL, remove it:
aws lambda get-function-url-config --function-name "$FUNCTION" --region "$REGION" >/dev/null 2>&1 && \
  aws lambda delete-function-url-config --function-name "$FUNCTION" --region "$REGION" && \
  echo "[OK] Removed function URL config from $FUNCTION"
```

> If the function's execution role is privileged and you cannot yet rule out abuse,
> consider setting reserved concurrency to 0 (`aws lambda put-function-concurrency
> --function-name "$FUNCTION" --reserved-concurrent-executions 0`) to freeze all
> invocation while you investigate, this stops execution without deleting the
> function or its logs. Reverse it in Recovery.

#### Step 2: Contain the principal that planted the backdoor

The `:user/` and `:assumed-role/` branches cover the common cases. A **root** or
**federated** caller needs manual handling (root credential rotation, or the IdP),
since the script silently no-ops for those principal types.

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
```

Note: `aws:TokenIssueTime` revokes only sessions issued **before** the cutoff; a
credential re-fetched afterward is not caught.

#### Step 3: Deny further resource-policy changes by the principal

```bash
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["lambda:AddPermission","lambda:AddLayerVersionPermission","lambda:CreateFunctionUrlConfig","lambda:UpdateFunctionCode"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyLambdaBackdoor" --policy-document "$DENY_DOC"
  echo "[OK] Lambda resource-policy changes denied for role $R"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyLambdaBackdoor" --policy-document "$DENY_DOC"
  echo "[OK] Lambda resource-policy changes denied for user $U"
else
  echo "[i] Root/federated principal, apply the deny at the SCP level instead"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Strip every external statement from every affected function

```bash
REGION="us-east-1"
OWNER_ACCT="$(aws sts get-caller-identity --query Account --output text)"
ORG_ACCOUNTS="$(aws organizations list-accounts --query 'Accounts[].Id' --output text 2>/dev/null) $OWNER_ACCT"

# For each function Query 2 flagged, remove each external/public statement by its Sid.
for FN in $(aws lambda list-functions --region "$REGION" --query 'Functions[].FunctionName' --output text); do
  POL=$(aws lambda get-policy --function-name "$FN" --region "$REGION" --query 'Policy' --output text 2>/dev/null)
  [ -z "$POL" ] && continue
  for SID in $(echo "$POL" | jq -r --arg org "$ORG_ACCOUNTS" '
      fromjson | (.Statement // [] | if type=="object" then [.] else . end)[]
      | . as $s
      | ( if (.Principal|type)=="string" then [.Principal]
          elif (.Principal.AWS|type)=="array" then .Principal.AWS
          elif (.Principal.AWS|type)=="string" then [.Principal.AWS]
          else [] end )
      | map( (capture("(?<a>[0-9]{12})").a) // (select(.=="*") | "*") )
      | map(select(. != null and ($org | contains(.) | not)))
      | select(length > 0) | $s.Sid'); do
    aws lambda remove-permission --function-name "$FN" --statement-id "$SID" --region "$REGION" && \
      echo "[OK] Removed external statement $SID from $FN"
  done
done
```

> Review each removal before running in production, an in-org account not in
> `list-accounts` (e.g. a partner account you trust) would be flagged; confirm it is
> genuinely unwanted first.

#### Remove other persistence / tampering by the principal

From Query 4, remediate anything else the principal did, code overwrite
(`UpdateFunctionCode` → redeploy from a trusted source, see the overwrite-code
playbook), a backdoor layer (`AddLayerVersionPermission` → the layer-extension
playbook), function URLs, additional grants, IAM backdoors.

#### Right-size `lambda:AddPermission` permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove lambda:AddPermission / AddLayerVersionPermission / CreateFunctionUrlConfig
# from principals that are not the IaC/deploy pipeline.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyLambdaBackdoor" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the backdoor statement is gone

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
STMT_ID="<statement_id-from-Query-1>"

aws lambda get-policy --function-name "$FUNCTION" --region "$REGION" --query 'Policy' --output text 2>/dev/null | \
  jq -e --arg sid "$STMT_ID" 'fromjson | (.Statement // [] | if type=="object" then [.] else . end)
        | any(.[]; .Sid == $sid)' >/dev/null 2>&1 \
  && echo "[FAIL] Statement $STMT_ID still present on $FUNCTION" \
  || echo "[OK] Statement $STMT_ID confirmed removed from $FUNCTION"
```

#### Re-sweep all functions for external principals

```bash
REGION="us-east-1"
OWNER_ACCT="$(aws sts get-caller-identity --query Account --output text)"
ORG_ACCOUNTS="$(aws organizations list-accounts --query 'Accounts[].Id' --output text 2>/dev/null) $OWNER_ACCT"
FAIL=0
for FN in $(aws lambda list-functions --region "$REGION" --query 'Functions[].FunctionName' --output text); do
  POL=$(aws lambda get-policy --function-name "$FN" --region "$REGION" --query 'Policy' --output text 2>/dev/null)
  [ -z "$POL" ] && continue
  HIT=$(echo "$POL" | jq -r --arg org "$ORG_ACCOUNTS" '
    fromjson | (.Statement // [] | if type=="object" then [.] else . end)[]
    | ( if (.Principal|type)=="string" then [.Principal]
        elif (.Principal.AWS|type)=="array" then .Principal.AWS
        elif (.Principal.AWS|type)=="string" then [.Principal.AWS] else [] end )
    | map( (capture("(?<a>[0-9]{12})").a) // (select(.=="*") | "*") )
    | map(select(. != null and ($org | contains(.) | not))) | select(length>0) | "hit"' | head -1)
  [ -n "$HIT" ] && { echo "[FAIL] $FN still grants an external principal"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] No function grants an out-of-org principal"
```

#### Verify no invoke by the attacker account since containment

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

# Data-plane: prefer Lambda data events (caller-aware); fall back to the Invocations metric.
INVOKED=$(aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations \
  --dimensions Name=FunctionName,Value="$FUNCTION" \
  --start-time "$CONTAINED_AT" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum --region "$REGION" \
  --query 'Datapoints[?Sum>`0`]' --output json | jq 'length')
[ "$INVOKED" -eq 0 ] && echo "[OK] No invocations since containment" \
                     || echo "[i] $INVOKED post-containment invocation window(s), confirm they are legitimate (the grant is removed, so any invoke is now from an authorized principal)"
```

#### Restore normal concurrency (if frozen in Step 1)

```bash
REGION="us-east-1"; FUNCTION="<function-from-Query-1>"
aws lambda delete-function-concurrency --function-name "$FUNCTION" --region "$REGION" 2>/dev/null && \
  echo "[OK] Restored default (unreserved) concurrency on $FUNCTION"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm the external-grant rule fires HIGH on the"
echo "AddPermission with principal=193672423079 (an out-of-org account), and that it"
echo "does NOT fire on the RemovePermission cleanup, nor on a legitimate service-principal"
echo "grant (e.g. s3.amazonaws.com)."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could grant an external account invoke access to a function | `lambda:AddPermission` available outside the IaC pipeline; no SCP constraining the `lambda:Principal` to the org |
| Backdoor undetected | Shipped rule matched `AddPermission`/`RemovePermission` with no principal inspection; Access Analyzer not enabled/alarmed on Lambda resource policies |
| Persistence survives credential remediation | The grant lives in the *function* resource policy, not IAM, untouched by key rotation or principal deletion |
| Blast radius under-appreciated | The function's execution role determines what an invoke can do; roles were not baselined per function |
| Possible unnoticed invocation | Lambda **data events** not enabled, so cross-account invocation was invisible to CloudTrail (only the CloudWatch metric showed it) |

### Recommended Guardrails

**Constrain who a function may be shared with (the primary, and genuinely conditionable, control)**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// deny granting Lambda invoke to any principal outside the org.
// lambda:Principal IS a real condition key for AddPermission, so this is enforceable.
{
  "Effect": "Deny",
  "Action": ["lambda:AddPermission", "lambda:AddLayerVersionPermission"],
  "Resource": "*",
  "Condition": {
    "StringNotEqualsIfExists": { "lambda:Principal": ["s3.amazonaws.com", "sns.amazonaws.com", "events.amazonaws.com", "apigateway.amazonaws.com"] },
    "Null": { "lambda:Principal": "false" }
  }
}
```

(Verify the exact behavior of `lambda:Principal` in your account before enforcing,
for cross-account *account* grants combine it with an `aws:PrincipalOrgID` condition
on who may call `AddPermission`, and allowlist your integration service principals.
Test in a non-prod org unit first; a too-broad deny breaks legitimate S3/SNS/EventBridge wiring.)

```json
// SCP fragment: restrict resource-policy and code changes to the deploy pipeline.
{
  "Effect": "Deny",
  "Action": ["lambda:AddPermission", "lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionCode"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Structural controls**
- **Least-privilege execution roles** per function, the single biggest blast-radius reducer; a backdoored function with a scoped role can do little
- Enable **IAM Access Analyzer** and alarm on any Lambda external-access finding
- Enable **Lambda data events** on high-value functions so cross-account invocation is actually logged
- Manage all resource policies through reviewed IaC; treat any out-of-band `AddPermission` as an incident

**Detection improvements**
- Deploy the external/wildcard-grant rule (principal-aware), never the shipped `AddPermission`/`RemovePermission` name match
- Join `requestParameters.principal` against the live org account list + a service-principal allowlist
- Alarm `CreateFunctionUrlConfig` with `AuthType=NONE` and any `Invocations` spike on a normally-idle function

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 - Account Manipulation |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `lambda:AddPermission` (adds a statement to the function resource policy granting `lambda:InvokeFunction` to an external account) |
| Event source | `lambda.amazonaws.com` (regional, query the function's region) |
| Key discriminator | `requestParameters.principal` is an out-of-org account (or `*`) with an `Invoke` action, **cleartext**, not URL-encoded; account digits match directly |
| Sweep tool | `aws lambda get-policy` per function (policy is a **stringified** JSON, `fromjson`) + IAM Access Analyzer (analyzes Lambda resource policies), not the Credential Report |
| "Was it used" pivot | **Data-plane** `Invoke` - NOT in `lookup-events`; use CloudWatch `AWS/Lambda Invocations` + Lambda data events (caller-aware) |
| Related backdoor surfaces | `CreateFunctionUrlConfig` (public URL), `AddLayerVersionPermission` (layer share), `UpdateFunctionCode` (code overwrite) |
| Conditionable guardrail | `lambda:Principal` condition key on `AddPermission`, the grant target *is* constrainable (unlike some network-firewall APIs) |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | The target function persists (created by `pulumi up`); the backdoor statement is added and removed by the script (a real attack leaves the statement) |

**MITRE mapping note:** T1098 (Account Manipulation), Persistence, is a defensible
mapping, modifying a resource policy to grant standing external access is account/
access manipulation. The MANIFEST's technique *name* ("Backdoor Lambda Function via
Resource Policy") is the upstream Stratus label, not a canonical MITRE technique name;
cosmetic, not a mis-mapping.

### Revert

The emulation removes its own backdoor statement on cleanup, so a normal run leaves
the function but no grant; `pulumi destroy` in `infra/` then removes the function and
its role. After a **real** incident, `pulumi destroy` is irrelevant to attacker-added
statements on *other* functions, remove every external statement (§3-§4), delete any
attacker function URLs, redeploy any tampered code, and constrain `AddPermission` via
SCP; the resource-policy grant persists until you remove it, regardless of any stack
teardown.
