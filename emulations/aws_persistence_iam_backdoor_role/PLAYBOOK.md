# IR Playbook: Backdoor IAM Role Trust Policy — Persistence via `iam:UpdateAssumeRolePolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Account Manipulation (cross-account role backdoor) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High — a trust-policy backdoor grants a foreign account standing access to the role that **survives rotation of the original credentials**; it is durable, quiet persistence (`MANIFEST.py` rates MEDIUM; the IR view is High because it is an enduring cross-account foothold) |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1098 |
| Services in Scope | IAM, STS, CloudTrail, IAM Access Analyzer |
| Infrastructure Created | 1 IAM role with a same-account trust policy (via `infra/`) |

**What the emulation does:** calls `iam:UpdateAssumeRolePolicy` to rewrite an existing role's **trust policy** (the `AssumeRolePolicyDocument`), adding an external AWS account — the Stratus marker account **`193672423079`** — as a trusted principal. That external account can then `sts:AssumeRole` into the role at will. The emulation's revert restores the original trust policy.

**Why this is potent persistence.** The backdoor is on the *role's trust relationship*, not on any credential. Rotating the access keys the attacker originally used, deleting their IAM user, or revoking their sessions does **nothing** to the backdoor — the foreign account keeps its standing right to assume the role until the trust policy is fixed. It is also quiet: there is no new user, no new key, just one line changed in a JSON document that few teams monitor.

**The detection is content inspection, not the event name.** `iam:UpdateAssumeRolePolicy` is a legitimate operation (IaC updates trust policies routinely). The signal is *what the new policy contains*: a Principal referencing an **account outside your organization**, or a **wildcard `*`** principal (world-assumable — catastrophic). CloudTrail records the new `policyDocument` (URL-encoded) in `requestParameters`, so the added principal is inspectable in the event. The shipped rule matches the event name and even bundles the benign `GetRole` read (§2) — it never inspects the policy.

**IAM Access Analyzer is the purpose-built control.** Access Analyzer continuously evaluates role trust policies and raises a finding for any that grant access to a principal outside your account/organization. A trust-policy backdoor produces an Access Analyzer finding — the highest-value standing detection for this technique.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail (IAM is global → events land in `us-east-1`). `UpdateAssumeRolePolicy` is a management event with `requestParameters.roleName` and `requestParameters.policyDocument` (URL-encoded new trust policy)
- **IAM Access Analyzer enabled** with an account- or organization-level analyzer — it flags any role trusting an external principal, which is exactly this backdoor. Alarm its findings
- A maintained list of your **organization's account IDs** (and any intentionally-trusted third-party accounts), so "external principal" is a concrete comparison rather than a guess
- CloudTrail delivered to a log platform so trust-policy content can be decoded and matched at scale

**Alerting (must be pre-configured)**
- **`iam:UpdateAssumeRolePolicy` where the new `policyDocument` Principal includes an account not in the org allowlist, or a `*` wildcard → P0**
- **`iam:CreateRole` whose initial trust policy trusts an external/wildcard principal** (the create-new variant of the same backdoor)
- IAM Access Analyzer new finding for external access to a role → P0
- `iam:UpdateAssumeRolePolicy` by a principal not on the IaC/identity-admin allowlist
- **`sts:AssumeRole` where the *assuming* principal belongs to an external account** — the backdoor being *used* (see §2 Query 3)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` and a URL-decoder (`python -c 'import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))'`) for the CloudTrail `policyDocument`
- The known-good trust policy for each sensitive role (from IaC), so restoration is exact
- The org account allowlist on hand

**Known IOC Baselines**
- Baseline which principals modify trust policies — normally only IaC/identity-admin
- The Stratus emulation marker account **`193672423079`** — its appearance in any trust policy is an unambiguous emulation/attack indicator
- Baseline the set of roles that *intentionally* trust external accounts (cross-account integrations), so a *new* external trust stands out

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `iam:UpdateAssumeRolePolicy` whose new trust policy adds a Principal in an **external/non-org account** or a `*` wildcard | CloudTrail | T1098 |
| P0 | Trust policy trusting account **`193672423079`** (the Stratus marker) — or any unknown external account | CloudTrail / Access Analyzer | T1098 |
| P0 | IAM Access Analyzer finding: role trust policy grants access to an external principal | Access Analyzer | T1098 |
| P1 | `iam:CreateRole` with an initial external/wildcard trust policy | CloudTrail | T1098 |
| P1 | `sts:AssumeRole` into the role where the assuming principal is an **external account** (backdoor in use) | CloudTrail | T1098 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `iam:UpdateAssumeRolePolicy` by a principal not on the IaC/identity-admin allowlist | CloudTrail | T1098 |
| P2 | Trust policy adding an external account **without** an `ExternalId`/condition (no confused-deputy protection) | CloudTrail | T1098 |
| P2 | `iam:UpdateAssumeRolePolicy` denied at volume (`errorCode = AccessDenied`) — permission probing | CloudTrail | T1098 |
| P3 | IaC principal updating a trust policy during a known deployment, staying same-account | CloudTrail | T1098 |

### Detection Rule Quality Notes

The shipped rules match the event but not the malicious content. These are correctness defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (GetRole, UpdateAssumeRolePolicy)` with `condition: selection` | Noisy and blind. `GetRole` is a benign read; `UpdateAssumeRolePolicy` fires on every legitimate IaC trust update. The rule never inspects whether an *external* principal was added | Drop `GetRole`; decode `requestParameters.policyDocument` and match an external/wildcard Principal |
| No org-account comparison | Cannot tell a same-account (benign) trust change from a cross-account backdoor | Compare added account IDs against the org allowlist; flag anything outside it, and any `*` |
| `CreateRole` with a backdoored trust policy not covered | An attacker can create a *new* role trusting themselves, evading an Update-only rule | Include `CreateRole` and inspect its `assumeRolePolicyDocument` |
| No Access Analyzer integration | The purpose-built external-access detector is unused | Alarm Access Analyzer findings for role external access |
| No detection of the backdoor being *used* | Catches the plant but not the cross-account `AssumeRole` that follows | Add a rule for external-account `AssumeRole` into the role |
| Header TODO "verify acronym casing"; `level: medium` | Stale; durable cross-account persistence is higher | Resolve TODO; external-principal rule → `level: critical` |

**Recommended detection — decode the trust policy and match an external principal.** The `policyDocument` is **URL-encoded** in the CloudTrail event, which constrains what a static Sigma rule can match: percent-encoding escapes quotes/colons/`*` (`"`→`%22`, `*`→`%2A`), so substring patterns like `"AWS":"*"` **never match the raw event**. Only **12-digit account IDs pass through URL-encoding verbatim**, so a Sigma rule can reliably catch *known-bad account IDs* (the Stratus marker and your own threat-intel accounts) — but the general "wildcard or any non-org account" detection MUST decode the document, which is the log-platform / Query 1 path.

```yaml
# Sigma — catches KNOWN-BAD account IDs in a trust-policy change (digits survive
# URL-encoding). It does NOT catch wildcards or arbitrary external accounts — use
# Query 1 (decode) for those.
title: IAM role trust policy references a known-bad account
id: 7a2c9f41-6b83-4e50-9d17-3c0b8a7e6f92
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'UpdateAssumeRolePolicy'
      - 'CreateRole'
  # Update stores the trust policy in policyDocument; CreateRole in
  # assumeRolePolicyDocument. OR them so both variants are covered.
  update_doc:
    requestParameters.policyDocument|contains:
      - '193672423079'          # Stratus marker account; add your own IOC account IDs
  create_doc:
    requestParameters.assumeRolePolicyDocument|contains:
      - '193672423079'
  condition: selection and (update_doc or create_doc)
level: critical
```

The general "any account not in the org, or a wildcard" case cannot be a static
substring against the encoded event — the authoritative check is the decode +
org-allowlist comparison in Query 1 (and its account-wide equivalent in Query 2).
Deploy those as the standing detection; the Sigma above is a known-IOC-account
catcher only.

**On error strings:** IAM denials surface as `AccessDenied` (IAM-policy denial) or `AccessDeniedException`; a bad policy document as `MalformedPolicyDocument`. Not `Client.`-prefixed. Match both denial forms and confirm against a sample.

---

### Key Investigation Queries

> IAM events are global → query **`us-east-1`**. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. The `policyDocument` in the event is **URL-encoded** — decode it before matching.

#### Query 1 — Find trust-policy changes and decode the added principals

```bash
REGION="us-east-1"
# Your org's account IDs (space-separated). Used by the manual decode step below
# (and wired into Query 2's automated sweep) — NOT filtered inside this Query 1 jq,
# which just surfaces every trust change for you to inspect.
ORG_ACCOUNTS="111111111111 222222222222"

for EV in UpdateAssumeRolePolicy CreateRole; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "iam.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     role: (.requestParameters.roleName // .requestParameters.roleName),
     # policyDocument (Update) or assumeRolePolicyDocument (CreateRole), URL-encoded
     doc: (.requestParameters.policyDocument // .requestParameters.assumeRolePolicyDocument),
     ip: .sourceIPAddress}' | \
  jq -s 'group_by(.caller) | map({
      caller: .[0].caller,
      access_keys: ([.[].access_key] | unique),        # feeds ACCESS_KEY_ID in Query 5
      changes: [.[] | {time, event, role, ip,
        # URL-decode happens below in bash; keep the raw doc here
        doc}]
    })'
```

Decode and inspect each `doc` for external principals:

```bash
# Paste a raw policyDocument value to decode + extract its trusted AWS principals
DOC='<url-encoded-policyDocument-from-above>'
python3 -c 'import urllib.parse,sys,json; d=json.loads(urllib.parse.unquote(sys.argv[1])); \
  print(json.dumps([s.get("Principal",{}).get("AWS") for s in d.get("Statement",[])], indent=2))' "$DOC"
# Any account ID here NOT in ORG_ACCOUNTS, or a "*", is the backdoor.
```

#### Query 2 — Sweep ALL roles for external/wildcard trust (find every backdoor)

The attacker may have backdoored more than the one role. Enumerate every role's
current trust policy and flag external/wildcard principals.

```bash
ORG_ACCOUNTS="111111111111 222222222222"

aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' --output json | \
  jq -r --arg org "$ORG_ACCOUNTS" '
    ($org | split(" ")) as $allow |
    .[] |
    . as $r |
    (.Trust.Statement // [])[] |
    # .Principal may be an object ({"AWS":...} / {"Service":...}) or the bare
    # string "*". Guard against indexing a string, which would crash the sweep.
    ( if (.Principal|type) == "object" then (.Principal.AWS // empty)
      elif .Principal == "*" then "*"
      else empty end ) |
    (if type == "array" then . else [.] end)[] as $p |
    # extract the account id from an ARN or bare id, flag wildcard and non-org
    ($p | if . == "*" then "WILDCARD"
          elif test("[0-9]{12}") then (capture("(?<acct>[0-9]{12})").acct)
          else . end) as $acct |
    select($acct == "WILDCARD" or (($acct | test("^[0-9]{12}$")) and ($allow | index($acct) | not))) |
    "[!] Role \($r.Name) trusts external/wildcard principal: \($p)"'
```

Every line here is a role to remediate. Note `list-roles` returns the trust policy
as decoded JSON (no URL-decoding needed, unlike the CloudTrail event).

#### Query 3 — Was the backdoor USED? (external account assumed the role)

Cross-account `AssumeRole` is logged in your (the role-owner's) account. This tells
you whether the foreign account has already taken the role — which escalates the
incident from "planted" to "active."

```bash
REGION="us-east-1"
ROLE_NAME="<backdoored-role-name>"
EXTERNAL_ACCT="193672423079"    # or the external account from Query 1

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg role "$ROLE_NAME" --arg acct "$EXTERNAL_ACCT" '
    .Events[].CloudTrailEvent | fromjson |
    select((.requestParameters.roleArn // "") | contains($role)) |   # literal, not regex
    select((.userIdentity.accountId // "") == $acct
           or ((.userIdentity.arn // "") | test($acct))) |
    {time: .eventTime, assumedBy: .userIdentity.arn,
     account: .userIdentity.accountId, sourceIP: .sourceIPAddress}'
```

Any result = the backdoor was exercised. Everything the resulting session did (its
`roleSessionName` in subsequent events) is now part of the incident.

#### Query 4 — What did an assumed session do?

```bash
REGION="us-east-1"
ROLE_NAME="<backdoored-role-name>"

# Actions performed under the role (session name from Query 3 / assume events)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="<roleSessionName-from-Query-3>" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 5 — Full session reconstruction of the principal that planted the backdoor

```bash
ACCESS_KEY_ID="<access-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look for *other* persistence the same principal planted — more backdoored roles,
new users/keys, login profiles.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The backdoor grants standing access; close it first, then determine whether it was
used and contain the planting principal.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1 — Restore the role's trust policy (close the backdoor)

```bash
ROLE_NAME="<backdoored-role-name>"

# Restore the known-good (same-account) trust policy from IaC
aws iam update-assume-role-policy --role-name "$ROLE_NAME" \
  --policy-document file://./known-good-trust-policy.json
echo "[OK] Restored trust policy for $ROLE_NAME"

# Verify no external/wildcard principal remains
aws iam get-role --role-name "$ROLE_NAME" \
  --query 'Role.AssumeRolePolicyDocument.Statement[].Principal' --output json
```

#### Step 2 — Revoke any live sessions already obtained via the backdoor

Restoring the trust policy stops *new* assumptions, but STS sessions already
minted from the backdoor remain valid for their TTL. Cut them with a
token-issue-time deny on the role.

```bash
ROLE_NAME="<backdoored-role-name>"
aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
      "Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]
  }'
echo "[OK] Pre-existing sessions for $ROLE_NAME revoked"
```

#### Step 3 — Contain the principal that planted the backdoor

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

#### Step 4 — Deny further trust-policy changes by the principal

```bash
SUSPECT_ROLE="<role-name>"    # role principals; for an IAM user use put-user-policy
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyTrustChanges" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["iam:UpdateAssumeRolePolicy","iam:CreateRole","iam:AttachRolePolicy","iam:PutRolePolicy"],"Resource":"*"}]
  }'
echo "[OK] Trust/role modification denied for $SUSPECT_ROLE"
```

---

## 4. Eradication

### Remove Attacker Access

#### Fix every backdoored role (from Query 2)

Restore the correct same-account trust policy for **each** role Query 2 flagged —
do not assume only the one role from Query 1 was touched.

```bash
# For each flagged role, restore its known-good trust policy:
ROLE_NAME="<flagged-role>"
aws iam update-assume-role-policy --role-name "$ROLE_NAME" \
  --policy-document file://./known-good-trust-policy-$ROLE_NAME.json && \
  echo "[OK] Restored $ROLE_NAME"
```

#### Remove other persistence planted by the principal

From Query 5, remediate anything else the principal created — extra backdoored
roles, new IAM users/access keys, login profiles, attached admin policies — using
the relevant persistence playbook for each.

#### Right-size trust-policy permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove iam:UpdateAssumeRolePolicy from principals that are not IaC/identity-admin.
# Trust-policy changes should flow only through reviewed IaC.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
ROLE_NAME="<backdoored-role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyTrustChanges" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify no role trusts an external/wildcard principal

```bash
ORG_ACCOUNTS="111111111111 222222222222"
HITS=$(aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' --output json | \
  jq -r --arg org "$ORG_ACCOUNTS" '
    ($org | split(" ")) as $allow | .[] | . as $r |
    (.Trust.Statement // [])[] |
    ( if (.Principal|type)=="object" then (.Principal.AWS // empty)
      elif .Principal=="*" then "*" else empty end ) |
    (if type=="array" then . else [.] end)[] as $p |
    ($p | if .=="*" then "WILDCARD" elif test("[0-9]{12}") then capture("(?<a>[0-9]{12})").a else . end) as $acct |
    select($acct=="WILDCARD" or (($acct|test("^[0-9]{12}$")) and ($allow|index($acct)|not))) |
    $r.Name')
[ -z "$HITS" ] && echo "[OK] No role trusts an external/wildcard principal" \
               || echo "[FAIL] Still backdoored: $HITS"
```

#### Verify Access Analyzer reports no external role access

```bash
ANALYZER=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER" \
  --filter '{"resourceType":{"eq":["AWS::IAM::Role"]},"status":{"eq":["ACTIVE"]}}' \
  --query 'findings[].{Resource:resource,External:isPublic,Principal:principal}' --output table 2>/dev/null
echo "Review any ACTIVE role findings above; there should be none unexpected."
```

#### Verify no further trust changes / backdoor use since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateAssumeRolePolicy \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)
[ "$COUNT" -eq 0 ] && echo "[OK] No further trust-policy changes from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further changes — containment did not hold"
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

```bash
echo "Re-run the emulation and confirm the corrected rule fires on the UpdateAssumeRolePolicy"
echo "whose decoded policyDocument trusts account 193672423079 (external), classified"
echo "P0 — and that it does NOT fire on a benign same-account trust update or on GetRole."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could add an external account to a role's trust policy | `iam:UpdateAssumeRolePolicy` granted outside IaC/identity-admin; no guardrail on cross-account trust |
| Backdoor undetected | Shipped rule matched the event but never decoded/inspected the policy for an external principal; IAM Access Analyzer not alarmed |
| Persistence survives credential rotation | Trust-policy backdoors are independent of the attacker's own credentials — rotating keys does not remove them |
| Possibly more than one role backdoored | No account-wide sweep of role trust policies for external principals |
| Cross-account use unnoticed | No alert on external-account `AssumeRole` into internal roles |

### Recommended Guardrails

**Detect external trust continuously**
- Enable **IAM Access Analyzer** (account + org) and alarm every finding of a role trusting an external principal — this is the standing control that catches this exact backdoor
- A scheduled sweep (Query 2 logic) as defence-in-depth

**Restrict who can change trust, and to whom**

```json
// SCP: only IaC/identity-admin may change role trust policies
{
  "Effect": "Deny",
  "Action": ["iam:UpdateAssumeRolePolicy", "iam:CreateRole"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/identity-admin", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- Consider an SCP that denies `sts:AssumeRole` from outside the org for internal roles (via `aws:PrincipalOrgID` conditions on the roles' trust policies), so even a backdoored trust policy can't be used cross-org
- Manage all trust policies through reviewed IaC; treat any out-of-band `UpdateAssumeRolePolicy` as an incident

**Detection improvements**
- Deploy the content-inspection rule (decode `policyDocument`, match external/wildcard principal) — never the shipped event-name match
- Alarm Access Analyzer role findings and external-account `AssumeRole` into internal roles

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 — Account Manipulation |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `iam:UpdateAssumeRolePolicy` (also `iam:CreateRole` for the create-new variant) |
| Event source | `iam.amazonaws.com` (global → events in `us-east-1`) |
| Key discriminator | The new trust policy's Principal references an **external/non-org account** or a `*` wildcard — decode `requestParameters.policyDocument` (URL-encoded); the event name alone is benign |
| Purpose-built control | **IAM Access Analyzer** — flags roles trusting external principals |
| Emulation IOC | External account **`193672423079`** (Stratus marker) added as a trusted principal |
| Persistence property | Independent of the attacker's own credentials — survives key rotation / user deletion until the trust policy is fixed |
| "Was it used?" signal | Cross-account `sts:AssumeRole` is logged in the role-owner's account with the external `userIdentity.accountId` |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException`, `MalformedPolicyDocument` |
| Resources created | 1 IAM role (same-account trust) |

**MITRE mapping note:** T1098 (Account Manipulation), Persistence, is a sound
mapping for backdooring a role's trust relationship — a good fit, unlike the
T1021.004/T1204.003/T1087 stretches elsewhere in this catalogue. (The parent
technique is used here, consistent with the MANIFEST; a case could be made for a
sub-technique, but the parent is accurate and not a stretch.)

### Revert

`pulumi destroy` in `infra/` removes the IAM role; the emulation's own revert
restores the original same-account trust policy, so a normal run self-cleans. After
a **real** incident, `pulumi destroy` is irrelevant — restore the correct trust
policy on every backdoored role (§3–§4), remove any sessions/other persistence, and
tighten who can change trust; deleting a stack does not un-plant a backdoor the
attacker placed on a role you still need.
