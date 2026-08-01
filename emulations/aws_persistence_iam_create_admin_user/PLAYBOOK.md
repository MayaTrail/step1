# IR Playbook: Create an IAM User with Admin Access — Persistence via `iam:CreateUser` + `iam:AttachUserPolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Create Cloud Account (net-new backdoor admin user) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High — a new IAM user with `AdministratorAccess` and its own access key is a fully independent admin foothold that survives remediation of the original credential (`MANIFEST.py` rates MEDIUM; the IR view is High because it plants a standing admin identity) |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1136.003 |
| Services in Scope | IAM, CloudTrail, GuardDuty |
| Infrastructure Created | None — the emulation creates and then deletes its own backdoor user |

**What the emulation does:** runs the backdoor-admin sequence — `iam:CreateUser` (a new user), `iam:AttachUserPolicy` attaching the AWS-managed **`AdministratorAccess`** policy, then `iam:CreateAccessKey` to mint programmatic credentials for it. The attacker now holds an independent admin identity. The emulation cleans up after itself (detaches, deletes the key and user), so a normal run leaves only the CloudTrail trail — but a real intrusion leaves the user in place.

**Why this is potent persistence.** It is a brand-new identity the attacker fully controls, with maximum privilege and its own key. Rotating the credential the attacker originally compromised, or deleting *their* IAM user, does nothing to this new one. It hides in plain sight among legitimate users unless someone reviews *who created which admin users*.

**Detection is content + sequence, not the event names.** `CreateUser`, `AttachUserPolicy`, and `CreateAccessKey` all occur legitimately (onboarding, IaC). The signal is: **`AttachUserPolicy` (or `PutUserPolicy`) granting admin**, and the higher-confidence fingerprint is the **ordered sequence `CreateUser → AttachUserPolicy(admin) → CreateAccessKey` by one principal in a short window**. The shipped rule matches *all seven* IAM user-lifecycle events with no content or sequence filter (§2) — it fires on every routine user operation.

**"Inline" is a misnomer — cover both attachment styles.** The emulation (and this technique's common name) says "inline admin policy," but the code attaches the *managed* `AdministratorAccess` via `AttachUserPolicy`. An attacker could equally use `iam:PutUserPolicy` with an **inline** admin document. Detect both: `AttachUserPolicy` with an admin *policy ARN*, and `PutUserPolicy` with an inline *policy document* granting `"Action":"*"` (the latter is URL-encoded in CloudTrail — decode it).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail (IAM is global → events land in `us-east-1`). The relevant events carry: `CreateUser` → `responseElements.user.userName`/`.arn`; `AttachUserPolicy` → `requestParameters.userName` + `requestParameters.policyArn`; `PutUserPolicy` → `requestParameters.policyName` + `requestParameters.policyDocument` (URL-encoded inline policy); `CreateAccessKey` → `responseElements.accessKey.accessKeyId`
- GuardDuty enabled — **`Persistence:IAMUser/UserPermissions`** and privilege-escalation findings corroborate this technique
- The list of AWS-managed policies that confer admin or near-admin (`AdministratorAccess`, `IAMFullAccess`, `PowerUserAccess`, and any custom admin policy ARNs), so an admin attach is a concrete match
- An allowlist of principals that legitimately create users and attach admin (identity-admin / IaC), so anyone else doing it is anomalous

**Alerting (must be pre-configured)**
- **`iam:AttachUserPolicy` where `policyArn` is `AdministratorAccess` (or an admin-equivalent), by a principal not on the identity-admin allowlist → P0**
- **`iam:PutUserPolicy` whose decoded inline document grants `"Action":"*"` on `"Resource":"*"` → P0** (the inline-admin variant)
- **Sequence: `CreateUser` → `AttachUserPolicy(admin)` → `CreateAccessKey` by one principal within a few minutes → P0** (the fresh-backdoor-admin fingerprint)
- GuardDuty `Persistence:IAMUser/UserPermissions` → SNS
- `iam:CreateUser` by a non-provisioning principal (weaker on its own; strong in the sequence)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` and a URL-decoder for any inline `policyDocument`
- The identity-admin allowlist and a current inventory of users with admin policies

**Known IOC Baselines**
- Baseline who creates users and attaches admin — normally only identity-admin / IaC
- The emulation's backdoor username pattern (the Stratus default) as an emulation indicator
- Baseline the set of users that *should* have `AdministratorAccess`; a *new* admin user outside that set is the signal

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Ordered sequence `CreateUser → AttachUserPolicy(AdministratorAccess) → CreateAccessKey` by one principal within minutes | CloudTrail | T1136.003 |
| P0 | `iam:AttachUserPolicy` attaching `AdministratorAccess`/admin-equivalent to any user, by a non-identity-admin principal | CloudTrail | T1136.003 |
| P0 | `iam:PutUserPolicy` whose decoded inline document grants `"Action":"*"`/`"Resource":"*"` | CloudTrail | T1136.003 |
| P1 | GuardDuty `Persistence:IAMUser/UserPermissions` | GuardDuty | T1136.003 |
| P1 | `iam:CreateAccessKey` for a just-created user (the backdoor getting its credential) | CloudTrail | T1136.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `iam:CreateUser` by a non-provisioning/interactive principal | CloudTrail | T1136.003 |
| P2 | `iam:AttachUserPolicy` with `IAMFullAccess`/`PowerUserAccess` (privilege that enables self-escalation to admin) | CloudTrail | T1136.003 |
| P2 | `iam:CreateUser`/`AttachUserPolicy` denied at volume (`errorCode = AccessDenied`) — probing | CloudTrail | T1136.003 |
| P3 | Identity-admin/IaC creating a user and attaching a scoped policy during a known onboarding | CloudTrail | T1136.003 |

### Detection Rule Quality Notes

The shipped rule matches every IAM user-lifecycle event and inspects nothing. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (CreateUser, AttachUserPolicy, CreateAccessKey, ListAccessKeys, DeleteAccessKey, DetachUserPolicy, DeleteUser)` with `condition: selection` | Unusable. These are the routine IAM user operations; the rule fires on every onboarding, rotation, and offboarding. It never inspects *which policy* was attached or the *sequence* | Alert `AttachUserPolicy` filtered to an admin `policyArn`; add the `CreateUser→Attach→CreateKey` sequence correlation; drop the cleanup/list events |
| No admin-policy content check | The entire signal (admin privilege) is exactly what an event-name match ignores | Match `requestParameters.policyArn` = admin ARN(s); for inline, decode `policyDocument` and match `"Action":"*"` |
| No `PutUserPolicy` (inline) coverage | Misses the inline-admin variant the technique's own name references | Include `PutUserPolicy` with a decoded-document admin match |
| No principal allowlist / sequence | Cannot separate onboarding from a backdoor; misses the multi-step fingerprint | Exclude identity-admin; add a temporal correlation |
| Header TODO "verify acronym casing"; `level: medium` | Stale; a standing admin backdoor is higher | Resolve TODO; admin-attach rule → `level: critical` |

**Recommended detection — admin attach, plus the create-admin sequence.**

```yaml
# Rule A — AdministratorAccess (or admin-equivalent) attached to a user
title: IAM AdministratorAccess attached to a user by non-identity-admin
id: 8c3f1a72-9d64-4e50-b1d2-6a0c9b7e4f83
name: iam_attach_admin_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'AttachUserPolicy'
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
---
# Rule B — the fresh-backdoor-admin sequence (temporal, ordered)
title: IAM create-admin-user backdoor sequence
id: 9d4f2a83-6c15-4e07-b2d1-8a0c9b7e5f94
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - iam_create_user           # base: eventName CreateUser
    - iam_attach_admin_base     # Rule A
    - iam_create_access_key     # base: eventName CreateAccessKey
  group-by:
    - userIdentity.arn
  timespan: 10m
level: critical
```

(Define the two trivial base rules `iam_create_user` / `iam_create_access_key` as
single-event selections on their event names. For the **inline** variant, add a
rule on `PutUserPolicy` whose decoded `requestParameters.policyDocument` contains
`"Action":"*"` — a decode step the log platform must perform, since the document
is URL-encoded in the raw event.)

**On error strings:** IAM denials surface as `AccessDenied` / `AccessDeniedException`. Not `Client.`-prefixed. Confirm against a sample.

---

### Key Investigation Queries

> IAM events are global → query **`us-east-1`**. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. Note the nested response shapes: `CreateUser` → `responseElements.user.*`, `CreateAccessKey` → `responseElements.accessKey.*`. **`lookup-events` returns ≤50 events per page** — for a busy account or a multi-day window, add `--max-items`/paginate on `NextToken`, or run these against your log platform, so IOCs aren't silently truncated.

#### Query 1 — Reconstruct the backdoor: admin attaches, new users, and their keys

```bash
REGION="us-east-1"

for EV in AttachUserPolicy CreateUser CreateAccessKey PutUserPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "iam.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,           # feeds ACCESS_KEY_ID in Query 4
     target_user: (.requestParameters.userName // .responseElements.user.userName),
     policy_arn: .requestParameters.policyArn,
     new_key: .responseElements.accessKey.accessKeyId,   # backdoor key IOC (nested!)
     inline_policy: .requestParameters.policyName,
     ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read this timeline per caller: a `CreateUser` then an `AttachUserPolicy` with
`policy_arn` = `.../AdministratorAccess` then a `CreateAccessKey` on the same
`target_user`, all by one `caller` within minutes, is the backdoor. Record the
`target_user` and `new_key` (IOCs).

#### Query 2 — Sweep ALL users for admin privilege (find every backdoor admin)

The attacker may have created more than one, or attached admin to an existing
user. Enumerate every user with an admin policy (managed or inline).

```bash
for U in $(aws iam list-users --query 'Users[].UserName' --output text); do
  # Managed admin policies
  aws iam list-attached-user-policies --user-name "$U" \
    --query "AttachedPolicies[?PolicyName=='AdministratorAccess' || PolicyName=='IAMFullAccess' || PolicyName=='PowerUserAccess'].PolicyName" \
    --output text 2>/dev/null | grep -q . && echo "[!] $U has an admin MANAGED policy"
  # Inline policies granting Action:* (decode not needed — get-user-policy returns decoded JSON)
  for P in $(aws iam list-user-policies --user-name "$U" --query 'PolicyNames[]' --output text 2>/dev/null); do
    aws iam get-user-policy --user-name "$U" --policy-name "$P" \
      --query 'PolicyDocument' --output json 2>/dev/null | \
      jq -e '(.Statement // [] | if type=="object" then [.] else . end)   # Statement may be a single object OR array
             | any(.[]; (.Effect=="Allow") and ((.Action=="*") or ((.Action|type=="array") and (.Action|index("*")))))' >/dev/null \
      && echo "[!] $U has an inline admin policy: $P (also review Resource scope / NotAction)"
  done
done
echo "[OK] Admin-user sweep complete"
```

Cross-check each flagged user's `CreateUser` caller (Query 1) — a user created by
someone other than identity-admin, holding admin, is a backdoor.

#### Query 3 — Was the backdoor user/key USED?

```bash
REGION="us-east-1"
BACKDOOR_KEY="<new_key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$BACKDOOR_KEY" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Any activity means the backdoor admin was exercised — everything it did is part of
the incident, and its `ip` values are IOCs. Also check for a console login profile
on the backdoor user (`iam:CreateLoginProfile`) and any `ConsoleLogin` by it.

#### Query 4 — Full session reconstruction of the principal that planted the backdoor

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

Look for *other* persistence — more backdoor users, backdoored roles, login
profiles, additional access keys.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The backdoor is a standing admin identity. Neutralise it (disable its key, strip
its admin), determine whether it was used, and contain the planting principal.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1 — Neutralise the backdoor user

```bash
BACKDOOR_USER="<target_user-from-Query-1>"

# Disable its access key(s) (do NOT delete yet — preserve evidence)
for K in $(aws iam list-access-keys --user-name "$BACKDOOR_USER" \
    --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
  aws iam update-access-key --user-name "$BACKDOOR_USER" --access-key-id "$K" --status Inactive
  echo "[OK] Disabled key $K on $BACKDOOR_USER"
done

# Strip admin immediately (detach managed + delete inline)
aws iam detach-user-policy --user-name "$BACKDOOR_USER" \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null && \
  echo "[OK] Detached AdministratorAccess from $BACKDOOR_USER"

# If it has a console login profile, remove it
aws iam delete-login-profile --user-name "$BACKDOOR_USER" 2>/dev/null && \
  echo "[OK] Removed console login profile from $BACKDOOR_USER"
```

#### Step 2 — Contain the principal that created the backdoor

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

#### Step 3 — Deny further user/privilege creation by the principal

```bash
# Same deny document, applied to a role OR an IAM user depending on the principal:
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:CreateUser","iam:AttachUserPolicy","iam:PutUserPolicy","iam:CreateAccessKey","iam:CreateLoginProfile"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyUserCreation" --policy-document "$DENY_DOC"
  echo "[OK] User/privilege-creation denied for role $R"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyUserCreation" --policy-document "$DENY_DOC"
  echo "[OK] User/privilege-creation denied for user $U"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete the backdoor user(s)

```bash
BACKDOOR_USER="<target_user-from-Query-1>"

# Full teardown: delete keys, detach policies, delete inline policies, delete login
# profile, then delete the user.
for K in $(aws iam list-access-keys --user-name "$BACKDOOR_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
  aws iam delete-access-key --user-name "$BACKDOOR_USER" --access-key-id "$K"
done
for PA in $(aws iam list-attached-user-policies --user-name "$BACKDOOR_USER" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
  aws iam detach-user-policy --user-name "$BACKDOOR_USER" --policy-arn "$PA"
done
for PN in $(aws iam list-user-policies --user-name "$BACKDOOR_USER" --query 'PolicyNames[]' --output text 2>/dev/null); do
  aws iam delete-user-policy --user-name "$BACKDOOR_USER" --policy-name "$PN"
done
aws iam delete-login-profile --user-name "$BACKDOOR_USER" 2>/dev/null
aws iam delete-user --user-name "$BACKDOOR_USER" && echo "[OK] Deleted backdoor user $BACKDOOR_USER"
```

Repeat for every backdoor user Query 2 surfaced.

#### Remove other persistence planted by the principal

From Query 4, remediate anything else the principal created — more backdoor users,
backdoored role trust policies, additional keys, login profiles — using the
relevant persistence playbook for each.

#### Right-size user/privilege-creation permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove iam:CreateUser / AttachUserPolicy from principals that are not
# identity-admin/IaC. No workload principal should be able to attach AdministratorAccess.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyUserCreation" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the backdoor user is gone

```bash
BACKDOOR_USER="<target_user-from-Query-1>"
aws iam get-user --user-name "$BACKDOOR_USER" >/dev/null 2>&1 \
  && echo "[FAIL] $BACKDOOR_USER still exists" \
  || echo "[OK] $BACKDOOR_USER confirmed deleted"
```

#### Verify no unexpected user holds admin (re-sweep)

```bash
FAIL=0
for U in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam list-attached-user-policies --user-name "$U" \
    --query "AttachedPolicies[?PolicyName=='AdministratorAccess'].PolicyName" --output text 2>/dev/null | \
    grep -q . && { echo "[i] $U has AdministratorAccess — confirm it is an approved admin"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] No user holds AdministratorAccess" \
                  || echo "[i] Review the admin users above against your approved-admin list"
```

#### Verify no further user creation / admin attach since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(for EV in CreateUser AttachUserPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$CONTAINED_AT" --region "$REGION" --output json 2>/dev/null
done | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)
[ "$COUNT" -eq 0 ] && echo "[OK] No further user creation / admin attach from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further events — containment did not hold"
```

#### Verify the backdoor key never worked after disablement

```bash
REGION="us-east-1"
BACKDOOR_KEY="<new_key-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

USED=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$BACKDOOR_KEY" \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) | .eventTime' | grep -c .)
[ "$USED" -eq 0 ] && echo "[OK] Backdoor key had no successful use after containment" \
                  || echo "[FAIL] Backdoor key succeeded $USED times post-containment"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm: Rule A fires CRITICAL on the AttachUserPolicy"
echo "with policyArn=AdministratorAccess (non-identity-admin caller), and Rule B fires"
echo "on the CreateUser->AttachUserPolicy(admin)->CreateAccessKey sequence — NOT on"
echo "the benign DeleteUser/ListAccessKeys cleanup events."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could create a user and grant it admin | `iam:CreateUser` + `iam:AttachUserPolicy` (esp. with `AdministratorAccess`) available outside identity-admin/IaC; no SCP blocking admin attachment |
| Backdoor undetected | Shipped rule matched all IAM user events and never checked the attached policy or the create sequence; GuardDuty `Persistence:IAMUser/UserPermissions` not alarmed |
| Persistence survives original-credential remediation | The backdoor is an independent identity with its own key |
| Possibly more than one backdoor admin | No account-wide sweep of users for admin privilege |
| Standing admin possible at all | No permissions boundary requiring new users to be created within limits |

### Recommended Guardrails

**Block admin attachment by non-admins (the primary control — mirrors the AMBERSQUID guardrail)**

```json
// SCP: deny attaching AdministratorAccess to any principal except identity-admin
{
  "Effect": "Deny",
  "Action": ["iam:AttachUserPolicy", "iam:AttachRolePolicy"],
  "Resource": "*",
  "Condition": {
    "ArnEquals": { "iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess" },
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/identity-admin", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

```json
// SCP: restrict user creation to identity-admin / IaC
{
  "Effect": "Deny",
  "Action": ["iam:CreateUser", "iam:CreateAccessKey"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/identity-admin", "arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Structural controls**
- **Permissions boundaries**: require every new IAM user/role to be created with a boundary, capping what even an admin attach can grant
- Prefer **IAM Identity Center (SSO)** with no standing IAM users, so creating one is inherently anomalous
- Manage all IAM identities through reviewed IaC; treat any out-of-band `CreateUser`/`AttachUserPolicy(admin)` as an incident

**Detection improvements**
- Deploy Rule A (admin attach by non-identity-admin) and Rule B (the create-admin sequence) — never the shipped all-events match
- Cover the inline variant (`PutUserPolicy` with a decoded `"Action":"*"`)
- Alarm GuardDuty `Persistence:IAMUser/UserPermissions`

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1136.003 — Create Account: Cloud Account |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `iam:CreateUser` → `iam:AttachUserPolicy` (`AdministratorAccess`) → `iam:CreateAccessKey` |
| Event source | `iam.amazonaws.com` (global → events in `us-east-1`) |
| Key discriminator | Admin `policyArn` on `AttachUserPolicy` (or `"Action":"*"` in a decoded `PutUserPolicy` inline doc), and the ordered create→attach→key sequence — not the event names |
| Nested response fields | `CreateUser` → `responseElements.user.userName`; `CreateAccessKey` → `responseElements.accessKey.accessKeyId` (both nested — a flat path yields null) |
| GuardDuty | `Persistence:IAMUser/UserPermissions` (confirm against the current GuardDuty finding-types reference — names are occasionally revised) |
| "Inline" caveat | The name says inline, but the emulation uses the *managed* `AttachUserPolicy`; cover both managed (`policyArn`) and inline (`PutUserPolicy` + decoded doc) |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | None persisted — the emulation deletes its own backdoor user (a real attack leaves it) |

**MITRE mapping note:** T1136.003 (Create Account: Cloud Account), Persistence, is
the correct, precise mapping for creating a new cloud identity for persistence — no
caveat needed.

### Revert

The emulation creates and then deletes its own user, so a normal run self-cleans;
`pulumi destroy` has nothing to remove (no infra). After a **real** incident,
`pulumi destroy` is irrelevant — delete every backdoor user and its key (§3–§4),
remove any other persistence, and block admin attachment via SCP; the attacker's
new admin identity persists until you delete it, regardless of any stack teardown.
