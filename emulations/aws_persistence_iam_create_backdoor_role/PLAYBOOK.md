# IR Playbook: Create IAM Backdoor Role with Admin Access — Persistence via `iam:CreateRole` + `iam:AttachRolePolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Account Manipulation (external-trust admin role) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High — a new role trusting a foreign account and holding `AdministratorAccess` is a standing, cross-account admin foothold that survives password/key/MFA changes on the compromised identity (`MANIFEST.py` rates MEDIUM; the IR view is High) |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1098 (see mapping note in §6) |
| Services in Scope | IAM, STS, CloudTrail, IAM Access Analyzer, GuardDuty |
| Infrastructure Created | None — the emulation creates and then deletes its own backdoor role |

**What the emulation does:** the backdoor-admin-role sequence — `iam:CreateRole` with an `AssumeRolePolicyDocument` that trusts an **external AWS account** (the Stratus marker **`193672423079`**), then `iam:AttachRolePolicy` attaching the AWS-managed **`AdministratorAccess`**. The foreign account can now `sts:AssumeRole` into a full-admin role at will. The emulation cleans up (detaches, deletes the role); a real intrusion leaves the role in place.

**Why this is durable, cross-account persistence.** It combines the two backdoor primitives: a **cross-account trust** (an external account is allowed to assume the role) *and* **admin privilege** on that role. It is independent of any of the attacker's own credentials — rotating the compromised user's key, resetting its password, or adding MFA does nothing. And because the trusted principal is a *different account*, the attacker retains access even if their foothold inside your account is fully evicted.

**Detection is content + sequence — the two discriminators from the sibling techniques, together.** `CreateRole` and `AttachRolePolicy` are routine (IaC creates roles constantly). The signals are (1) the new role's **trust policy trusts an external/non-org account or a `*` wildcard** — decode the URL-encoded `assumeRolePolicyDocument`; and (2) **`AdministratorAccess` (or admin-equivalent) attached** to it, ideally as the ordered sequence `CreateRole(external trust) → AttachRolePolicy(admin)` by one principal. The shipped rule matches `CreateRole`/`AttachRolePolicy`/`DetachRolePolicy`/`DeleteRole` with no content or sequence inspection (§2).

**Two purpose-built controls apply.** **IAM Access Analyzer** flags the external-trust half (a role trusting an outside principal); an **SCP blocking `AdministratorAccess` attachment by non-admins** (the AMBERSQUID guardrail) blocks the admin half.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail (IAM is global → events land in `us-east-1`). `CreateRole` → `requestParameters.assumeRolePolicyDocument` (**URL-encoded** trust policy) + `responseElements.role.roleName`/`.arn`; `AttachRolePolicy` → `requestParameters.roleName` + `requestParameters.policyArn`. **`lookup-events` returns ≤50 events/page** — paginate or use the log platform for busy accounts/long windows
- **IAM Access Analyzer** enabled (account + org) — it flags any role trusting an external principal, which is half of this backdoor. Alarm its findings
- GuardDuty enabled — corroborating persistence findings
- The org account-ID allowlist (so "external principal" is a concrete comparison) and the admin-managed-policy ARN list (`AdministratorAccess`, `IAMFullAccess`, `PowerUserAccess`)
- An allowlist of principals that legitimately create roles and attach admin (identity-admin / IaC)

**Alerting (must be pre-configured)**
- **`iam:CreateRole` whose decoded trust policy trusts an external/non-org account or `*` → P0**
- **`iam:AttachRolePolicy` attaching `AdministratorAccess`/admin-equivalent by a non-identity-admin principal → P0**
- **Sequence: `CreateRole(external trust) → AttachRolePolicy(admin)` by one principal within minutes → P0** (the fresh-backdoor-admin-role fingerprint)
- IAM Access Analyzer new finding for external role trust → P0
- **`sts:AssumeRole` where the assuming principal is an external account** — the backdoor being *used* (logged in your account)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` and a URL-decoder for the CloudTrail `assumeRolePolicyDocument`
- The org account allowlist and admin-policy ARN list on hand

**Known IOC Baselines**
- The Stratus marker account **`193672423079`** in any trust policy is an unambiguous emulation/attack indicator
- Baseline who creates roles / attaches admin (identity-admin/IaC only) and which roles *intentionally* trust external accounts

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Sequence `CreateRole(external/wildcard trust) → AttachRolePolicy(AdministratorAccess)` by one principal within minutes | CloudTrail | T1098 |
| P0 | `iam:CreateRole` whose decoded trust policy trusts an external/non-org account (e.g. `193672423079`) or `*` | CloudTrail | T1098 |
| P0 | `iam:AttachRolePolicy` attaching `AdministratorAccess`/admin-equivalent by a non-identity-admin principal | CloudTrail | T1098 |
| P1 | IAM Access Analyzer finding: role trust grants access to an external principal | Access Analyzer | T1098 |
| P1 | `sts:AssumeRole` into the role by an **external account** (backdoor in use) | CloudTrail | T1098 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `iam:CreateRole` by a non-provisioning principal, or trust policy adding an external account **without** an `ExternalId`/condition | CloudTrail | T1098 |
| P2 | `iam:AttachRolePolicy` with `IAMFullAccess`/`PowerUserAccess` (self-escalation-capable) | CloudTrail | T1098 |
| P2 | `iam:CreateRole`/`AttachRolePolicy` denied at volume (`errorCode = AccessDenied`) — probing | CloudTrail | T1098 |
| P3 | IaC creating a role with a same-account trust and a scoped policy during a known deployment | CloudTrail | T1098 |

### Detection Rule Quality Notes

The shipped rule matches every role-lifecycle event and inspects neither the trust policy nor the attached policy. These are correctness defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (CreateRole, AttachRolePolicy, DetachRolePolicy, DeleteRole)` with `condition: selection` | Unusable. Every IaC role create/update fires it; `DetachRolePolicy`/`DeleteRole` are the benign cleanup/revert. It never checks the trust principal or the attached policy | Alert on external-trust `CreateRole` (decode the doc) and admin `AttachRolePolicy`; add the sequence correlation; drop the cleanup events |
| No trust-policy content check | The external-trust half of the signal is exactly what an event-name match ignores | Decode `assumeRolePolicyDocument` (URL-encoded) and match a non-org account / `*` |
| No admin-policy content check | The admin half is likewise ignored | Match `requestParameters.policyArn` = admin ARN(s) |
| No Access Analyzer integration | The purpose-built external-trust detector is unused | Alarm Access Analyzer role findings |
| No detection of the role being *assumed* cross-account | Catches the plant, not the use | Add an external-account `AssumeRole`-into-the-role rule |
| Header TODO "verify acronym casing"; `level: medium` | Stale; a cross-account admin backdoor is higher | Resolve TODO; both content rules → `level: critical` |

**Recommended detection — external-trust create, admin attach, and the sequence.** The trust-policy content needs a decode (Query 1). A Sigma rule can catch the encoding-safe pieces:

```yaml
# Rule A — CreateRole trusting a KNOWN-BAD account (digits survive URL-encoding)
title: IAM CreateRole trust policy references a known-bad account
id: 7b3c1a92-8d64-4e05-9f12-3a0c8b7e6f14
name: iam_createrole_external
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreateRole'
  known_bad_account:
    requestParameters.assumeRolePolicyDocument|contains:
      - '193672423079'          # Stratus marker; add your own IOC account IDs
  condition: selection and known_bad_account
level: critical
---
# Rule B — AdministratorAccess attached to a role by non-identity-admin
title: IAM AdministratorAccess attached to a role by non-identity-admin
id: 8c4f2a83-9d15-4e07-b2d1-6a0c9b7e5f24
name: iam_attach_role_admin
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'AttachRolePolicy'
    requestParameters.policyArn:
      - 'arn:aws:iam::aws:policy/AdministratorAccess'
      - 'arn:aws:iam::aws:policy/IAMFullAccess'
      - 'arn:aws:iam::aws:policy/PowerUserAccess'
  identity_admin:
    userIdentity.arn|contains:
      - ':role/identity-admin'
      - ':role/iac-deploy'
      - ':role/BreakGlassAdmin'
  condition: selection and not identity_admin
level: critical
```

Because the trust policy is **URL-encoded** in the event, a substring like
`"AWS":"*"` never matches (only bare account-ID digits survive encoding). The
general "external/wildcard trust" detection MUST decode the document — deploy
Query 1 (and Access Analyzer) as the standing detection; Rule A is a known-IOC
catcher. Combine A + B (and the base `CreateRole`) into a `temporal_ordered`
correlation grouped by `userIdentity.arn` for the full sequence.

**On error strings:** IAM denials surface as `AccessDenied` / `AccessDeniedException`; a bad trust document as `MalformedPolicyDocument`. Not `Client.`-prefixed. Confirm against a sample.

---

### Key Investigation Queries

> IAM events are global → query **`us-east-1`**. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. The `assumeRolePolicyDocument` in the event is **URL-encoded** (decode it); `responseElements.role.*` is **nested**. `lookup-events` is ≤50/page — paginate or use the log platform for long windows.

#### Query 1 — Find role creations, decode the trust, and pair with admin attaches

```bash
REGION="us-east-1"
ORG_ACCOUNTS="111111111111 222222222222"   # your org account IDs; anything else is external

for EV in CreateRole AttachRolePolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "iam.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,           # feeds ACCESS_KEY_ID in Query 5
     role: (.requestParameters.roleName // .responseElements.role.roleName),
     trust_doc: .requestParameters.assumeRolePolicyDocument,   # URL-encoded (CreateRole)
     policy_arn: .requestParameters.policyArn,                 # (AttachRolePolicy)
     ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Decode the trust doc of each `CreateRole` and extract its trusted principals
(guarding the object-vs-array/string shapes):

```bash
DOC='<url-encoded-assumeRolePolicyDocument-from-above>'
python3 -c '
import urllib.parse,sys,json
d=json.loads(urllib.parse.unquote(sys.argv[1]))
st=d.get("Statement",[])
st=[st] if isinstance(st,dict) else st
out=[]
for s in st:
    p=s.get("Principal",{})
    if isinstance(p,str): out.append(p)              # e.g. "*"
    elif isinstance(p,dict):
        aws=p.get("AWS")
        out += (aws if isinstance(aws,list) else [aws]) if aws else []
print(json.dumps(out,indent=2))' "$DOC"
# Any account ID here NOT in ORG_ACCOUNTS, or a "*", is the backdoor trust.
```

A `CreateRole` with an external trust, followed by an `AttachRolePolicy` with
`policy_arn` = `.../AdministratorAccess` on the same `role` by the same `caller`,
is the backdoor. Record the `role` (IOC).

#### Query 2 — Sweep ALL roles for external-trust AND admin (find every backdoor role)

```bash
ORG_ACCOUNTS="111111111111 222222222222"

# Roles whose trust policy trusts an external/wildcard principal (list-roles returns DECODED trust JSON)
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' --output json | \
  jq -r --arg org "$ORG_ACCOUNTS" '
    ($org | split(" ")) as $allow | .[] | . as $r |
    (.Trust.Statement // [] | if type=="object" then [.] else . end)[] |
    ( if (.Principal|type)=="object" then (.Principal.AWS // empty)
      elif .Principal=="*" then "*" else empty end ) |
    (if type=="array" then . else [.] end)[] as $p |
    ($p | if .=="*" then "WILDCARD" elif test("[0-9]{12}") then capture("(?<a>[0-9]{12})").a else . end) as $acct |
    select($acct=="WILDCARD" or (($acct|test("^[0-9]{12}$")) and ($allow|index($acct)|not))) |
    "[!] Role \($r.Name) trusts external/wildcard principal: \($p)"'

# Of those, which also hold AdministratorAccess (the full backdoor)
for R in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  aws iam list-attached-role-policies --role-name "$R" \
    --query "AttachedPolicies[?PolicyName=='AdministratorAccess'].PolicyName" --output text 2>/dev/null | \
    grep -q . && echo "[!] Role $R holds AdministratorAccess (check its trust above)"
done
echo "[OK] Backdoor-role sweep complete"
```

A role appearing in **both** lists — external trust *and* admin — is a confirmed
backdoor.

#### Query 3 — Was the backdoor role USED? (external account assumed it)

```bash
REGION="us-east-1"
ROLE_NAME="<backdoor-role-name>"
EXTERNAL_ACCT="193672423079"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg role "$ROLE_NAME" --arg acct "$EXTERNAL_ACCT" '
    .Events[].CloudTrailEvent | fromjson |
    select((.requestParameters.roleArn // "") | contains($role)) |
    select((.userIdentity.accountId // "") == $acct or ((.userIdentity.arn // "") | test($acct))) |
    {time: .eventTime, assumedBy: .userIdentity.arn, account: .userIdentity.accountId, ip: .sourceIPAddress}'
```

Any result = the backdoor was exercised. The resulting session's actions
(`roleSessionName`) are part of the incident.

#### Query 4 — What did an assumed session do?

```bash
REGION="us-east-1"
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

Look for *other* persistence — more backdoor roles/users, backdoored existing
trust policies, access keys, login profiles.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The backdoor role grants standing cross-account admin. Neutralise it (strip admin,
then delete), revoke any live sessions, and contain the planting principal.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1 — Strip admin from and revoke sessions on the backdoor role

```bash
ROLE_NAME="<backdoor-role-name>"

# Detach AdministratorAccess so any live session immediately loses admin
aws iam detach-role-policy --role-name "$ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null && \
  echo "[OK] Detached AdministratorAccess from $ROLE_NAME"

# Revoke sessions already assumed via the backdoor (token-issue-time deny)
aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
echo "[OK] Sessions revoked on $ROLE_NAME"
```

#### Step 2 — Contain the principal that planted the backdoor

The `:user/` and `:assumed-role/` branches below cover the common cases. A **root**
or **federated** caller (`SAMLUser`/`WebIdentityUser`) needs manual handling — root
via password rotation + key removal (see the console-login-without-MFA playbook),
federated via the IdP — since the script silently no-ops for those principal types.

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

#### Step 3 — Deny further role/privilege creation by the principal

```bash
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:CreateRole","iam:AttachRolePolicy","iam:PutRolePolicy","iam:UpdateAssumeRolePolicy"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyRoleCreation" --policy-document "$DENY_DOC"
  echo "[OK] Role/privilege-creation denied for role $R"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyRoleCreation" --policy-document "$DENY_DOC"
  echo "[OK] Role/privilege-creation denied for user $U"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete the backdoor role(s)

```bash
ROLE_NAME="<backdoor-role-name>"

# Detach all managed policies, delete inline policies, then delete the role
for PA in $(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
  aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$PA"
done
for PN in $(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames[]' --output text 2>/dev/null); do
  aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$PN"
done
aws iam delete-role --role-name "$ROLE_NAME" && echo "[OK] Deleted backdoor role $ROLE_NAME"
```

Repeat for every backdoor role Query 2 surfaced.

#### Remove other persistence planted by the principal

From Query 5, remediate anything else — more backdoor roles/users, backdoored
existing trust policies, keys, login profiles — via the relevant persistence
playbook for each.

#### Right-size role/privilege-creation permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove iam:CreateRole / AttachRolePolicy from principals that are not
# identity-admin/IaC. No workload principal should be able to attach AdministratorAccess
# or create externally-trusted roles.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyRoleCreation" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the backdoor role is gone

```bash
ROLE_NAME="<backdoor-role-name>"
aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1 \
  && echo "[FAIL] $ROLE_NAME still exists" \
  || echo "[OK] $ROLE_NAME confirmed deleted"
```

#### Verify no role has both external trust and admin (re-sweep)

```bash
ORG_ACCOUNTS="111111111111 222222222222"
EXT=$(aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' --output json | \
  jq -r --arg org "$ORG_ACCOUNTS" '
    ($org | split(" ")) as $allow | .[] | . as $r |
    (.Trust.Statement // [] | if type=="object" then [.] else . end)[] |
    ( if (.Principal|type)=="object" then (.Principal.AWS // empty) elif .Principal=="*" then "*" else empty end ) |
    (if type=="array" then . else [.] end)[] as $p |
    ($p | if .=="*" then "WILDCARD" elif test("[0-9]{12}") then capture("(?<a>[0-9]{12})").a else . end) as $acct |
    select($acct=="WILDCARD" or (($acct|test("^[0-9]{12}$")) and ($allow|index($acct)|not))) | $r.Name')
[ -z "$EXT" ] && echo "[OK] No role trusts an external/wildcard principal" \
              || echo "[i] External-trust roles to review against admin holdings: $EXT"
```

#### Verify Access Analyzer reports no unexpected external role access

```bash
ANALYZER=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)
# list-findings-v2 is the current-generation API; list-findings still works
aws accessanalyzer list-findings-v2 --analyzer-arn "$ANALYZER" \
  --filter '{"resourceType":{"eq":["AWS::IAM::Role"]},"status":{"eq":["ACTIVE"]}}' \
  --query 'findings[].{Resource:resource,Status:status}' --output table 2>/dev/null
echo "There should be no unexpected ACTIVE role findings."
```

#### Verify no further role creation / admin attach since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(for EV in CreateRole AttachRolePolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$CONTAINED_AT" --region "$REGION" --output json 2>/dev/null
done | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)
[ "$COUNT" -eq 0 ] && echo "[OK] No further role creation / admin attach from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further events — containment did not hold"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm: Rule A fires on the CreateRole trusting"
echo "193672423079, Rule B fires CRITICAL on AttachRolePolicy(AdministratorAccess),"
echo "the sequence correlation fires, and NONE of them fire on the DetachRolePolicy/"
echo "DeleteRole cleanup events."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could create an externally-trusted admin role | `iam:CreateRole` + `iam:AttachRolePolicy` (esp. admin) available outside identity-admin/IaC; no SCP on external trust or admin attachment |
| Backdoor undetected | Shipped rule matched all role events and inspected neither the trust nor the attached policy; IAM Access Analyzer not alarmed |
| Persistence survives credential remediation and account eviction | The trusted principal is a *different account* — independent of the attacker's foothold in yours |
| Possibly more than one backdoor role | No account-wide sweep of role trust + admin holdings |

### Recommended Guardrails

**Block admin attachment by non-admins (adapts the AMBERSQUID guardrail — that one denies unconditionally; this adds a break-glass carve-out, and covers roles too)**

```json
{
  "Effect": "Deny",
  "Action": ["iam:AttachRolePolicy", "iam:AttachUserPolicy"],
  "Resource": "*",
  "Condition": {
    "ArnEquals": { "iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess" },
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/identity-admin", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Constrain external trust**
- Enable **IAM Access Analyzer** and alarm every role external-trust finding — the standing control for the cross-account half
- Consider an SCP requiring `aws:PrincipalOrgID` on role trust for internal roles, so a backdoor trust to a foreign account can't be assumed cross-org
- Restrict `iam:CreateRole` to identity-admin/IaC; manage all roles through reviewed IaC

**Detection improvements**
- Deploy Rule A (external-trust create — decode), Rule B (admin attach), and the sequence correlation — never the shipped all-events match
- Alarm Access Analyzer role findings and external-account `AssumeRole` into internal roles

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 — Account Manipulation |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `iam:CreateRole` (external trust) → `iam:AttachRolePolicy` (`AdministratorAccess`) |
| Event source | `iam.amazonaws.com` (global → events in `us-east-1`) |
| Key discriminators | Decoded `assumeRolePolicyDocument` trusts an external/non-org account or `*`; `policyArn` = admin; the create→attach sequence |
| Encoding / nesting | `assumeRolePolicyDocument` is **URL-encoded** in the event (decode); `responseElements.role.*` is **nested**; `list-roles`/`get-role` return the trust **decoded** |
| Purpose-built controls | IAM Access Analyzer (external trust) + admin-attach SCP (admin half) |
| Emulation IOC | External account **`193672423079`** in the trust policy |
| "Was it used?" signal | Cross-account `sts:AssumeRole` into the role, logged in the role-owner's account with the external `userIdentity.accountId` |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException`, `MalformedPolicyDocument` |
| Resources created | None persisted — the emulation deletes its own backdoor role |
| Related | The modify-existing-role-trust backdoor (#19 sibling) and the create-admin-**user** backdoor (#21 sibling) — this technique is their combination |

**MITRE mapping note:** the MANIFEST maps this to **T1098 (Account Manipulation)**,
Persistence — a sound fit for adding a backdoor role. A case could be made for
**T1136.003 (Create Account: Cloud Account)** since it creates a new principal;
either is defensible. The parent T1098 mapping is accurate and not a stretch.
Recorded for the end-of-run MITRE-mapping finding.

### Revert

The emulation creates and then deletes its own role, so a normal run self-cleans;
`pulumi destroy` has nothing to remove (no infra). After a **real** incident,
`pulumi destroy` is irrelevant — delete every backdoor role (§3–§4), revoke any
sessions assumed via it, remove other persistence, and enforce the external-trust
+ admin-attach guardrails; the attacker's cross-account admin role persists until
you delete it.
