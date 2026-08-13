# IR Playbook - Create an IAM User with Console Access - Persistence via `iam:CreateUser` + `iam:CreateLoginProfile`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Create Cloud Account (net-new console-login backdoor user) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | Medium, a new IAM user with a console password is an independent, human-interactive foothold that survives rotation of the originally-compromised credential. As emulated it holds **no permissions** (the script attaches no policy), so its immediate blast radius is low; it escalates to **High** the moment a privilege grant (`AttachUserPolicy`/`PutUserPolicy`/`AddUserToGroup`) accompanies it, or if it is left standing as an unnoticed, MFA-less console credential. `MANIFEST.py` rates MEDIUM, which matches the as-created capability |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1136.003 |
| Services in Scope | IAM, CloudTrail (incl. console sign-in), GuardDuty |
| Infrastructure Created | None, the emulation creates and then deletes its own backdoor user + login profile |

**What the emulation does:** `iam:CreateUser` (a new user `stratus-red-team-backdoor-user`), then `iam:CreateLoginProfile` to set a **console password** with `PasswordResetRequired=false`. The attacker now holds an independent identity that can sign in to the AWS Management Console. The emulation cleans up after itself (`DeleteLoginProfile`, `DeleteUser`), so a normal run leaves only the CloudTrail trail, a real intrusion leaves the user and its password in place.

**Why this is persistence.** It is a brand-new identity with an interactive console credential the attacker chose. Rotating the key the attacker originally compromised, or deleting *their* user/role, does nothing to this one. It survives incident cleanup that only targets access keys, and, because it is a *password*, not a key, it will not appear in an access-key-focused rotation sweep.

**Detection is content + sequence, not the event names.** `CreateUser` and `CreateLoginProfile` both occur legitimately (human onboarding). The signal is the **ordered pair `CreateUser → CreateLoginProfile` by one principal in a short window**, a net-new identity handed a console credential, especially by a principal that is not the identity-admin/onboarding pipeline. The shipped rule matches `CreateUser`/`CreateLoginProfile`/`DeleteLoginProfile`/`DeleteUser` with no sequence or principal filter (§2), it fires on every onboarding *and* every offboarding.

**As emulated the user is powerless, but never assume that in a real intrusion.** The script attaches no policy, so the created console user can sign in but can do almost nothing. A real attacker typically pairs the login profile with a privilege grant. Treat any `AttachUserPolicy` / `PutUserPolicy` / `AddUserToGroup` on the *same* new user in the *same* window as an escalation of this same incident (see Query 1 and §4), and hunt it even though this emulation does not perform it.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail (IAM is global → management events land in `us-east-1`). Relevant events carry: `CreateUser` → `responseElements.user.userName`/`.arn`; `CreateLoginProfile` → `requestParameters.userName` + `requestParameters.passwordResetRequired` (the **password itself is never logged**), response `responseElements.loginProfile.userName`; a later console sign-in → `ConsoleLogin` from `signin.amazonaws.com` with `userIdentity.userName` = the backdoor user and `additionalEventData.MFAUsed`
- Console sign-in events must be captured, they are global and recorded in `us-east-1`. Confirm the trail includes global service events
- GuardDuty enabled, **`Persistence:IAMUser/UserPermissions`** and anomalous-console-login findings corroborate this technique
- The IAM **Credential Report** (`aws iam generate-credential-report`) as the account-wide inventory of which users have a *password* (`password_enabled`) and whether MFA is on (`mfa_active`)

**Alerting (must be pre-configured)**
- **`iam:CreateLoginProfile` by a principal not on the identity-admin/onboarding allowlist → P0** (handing an identity an interactive console credential is rare and high-signal)
- **Sequence `CreateUser` → `CreateLoginProfile` by one principal within minutes → P0** (the net-new console-backdoor fingerprint)
- **A privilege grant (`AttachUserPolicy`/`PutUserPolicy`/`AddUserToGroup`) on a user that received a login profile in the same window → P0** (the escalated variant)
- GuardDuty `Persistence:IAMUser/UserPermissions` and any anomalous-`ConsoleLogin` finding → SNS
- `iam:CreateUser` by a non-provisioning principal (weaker alone; strong in the sequence)

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq`; the identity-admin/onboarding allowlist
- A current Credential Report and the baseline set of users that *should* have console access

**Known IOC Baselines**
- Baseline who creates users and login profiles, normally only identity-admin / the onboarding pipeline
- The emulation's backdoor username (`stratus-red-team-backdoor-user`, tag `StratusRedTeam=true`) as an emulation indicator
- Baseline the set of IAM users with `password_enabled=true`; a *new* console-enabled user outside that set, especially with `mfa_active=false`, is the signal

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Ordered pair `CreateUser → CreateLoginProfile` by one principal within minutes | CloudTrail | T1136.003 |
| P0 | `iam:CreateLoginProfile` on any user by a principal not on the identity-admin/onboarding allowlist | CloudTrail | T1136.003 |
| P0 | Privilege grant (`AttachUserPolicy`/`PutUserPolicy`/`AddUserToGroup`) on a user that got a login profile in the same window | CloudTrail | T1136.003 |
| P1 | `ConsoleLogin` (Success) by the newly-created user, `MFAUsed=No`, the backdoor being exercised | CloudTrail (`signin.amazonaws.com`) | T1136.003 |
| P1 | GuardDuty `Persistence:IAMUser/UserPermissions` | GuardDuty | T1136.003 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `iam:CreateUser` by a non-provisioning/interactive principal | CloudTrail | T1136.003 |
| P2 | `iam:CreateLoginProfile` with `passwordResetRequired=false` outside the onboarding pipeline (attacker sets a password for immediate use; onboarding usually forces a reset) | CloudTrail | T1136.003 |
| P2 | `iam:CreateUser`/`CreateLoginProfile` denied at volume (`errorCode = AccessDenied`), probing | CloudTrail | T1136.003 |
| P3 | Identity-admin/onboarding pipeline creating a user and login profile during a known onboarding | CloudTrail | T1136.003 |

### Detection Rule Quality Notes

The shipped rule matches four IAM user-lifecycle events and inspects nothing. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (CreateUser, CreateLoginProfile, DeleteLoginProfile, DeleteUser)` with `condition: selection` | Noisy and imprecise. `CreateUser`/`CreateLoginProfile` are routine onboarding; `DeleteLoginProfile`/`DeleteUser` are routine offboarding (and here the emulation's own cleanup). The rule fires on every onboarding *and* every offboarding and never checks the *sequence* or the *principal* | Alert `CreateLoginProfile` by non-allowlisted principals; add the `CreateUser→CreateLoginProfile` sequence correlation; drop the `Delete*` cleanup events from the primary rule |
| `DeleteLoginProfile`/`DeleteUser` bundled in | These are the benign teardown/offboarding half; including them guarantees false positives and inverts the signal (a *deletion* is not persistence) | Remove from the detection selection; keep only for the "was the backdoor cleaned up or not" forensic timeline |
| No principal allowlist / sequence | Cannot separate onboarding from a backdoor; misses the multi-step fingerprint | Exclude identity-admin/onboarding; add the temporal correlation |
| No coverage of the escalated variant | Misses a login profile paired with a privilege grant (the dangerous case) | Add a correlation joining `CreateLoginProfile` with `AttachUserPolicy`/`PutUserPolicy`/`AddUserToGroup` on the same `userName` |
| Header TODO "verify acronym casing"; `level: medium` | Stale | Resolve TODO; the `CreateLoginProfile`-by-non-admin rule → `level: high` |

**Recommended detection, login-profile by non-admin, plus the create-console-user sequence.**

```yaml
# Rule A: a console login profile handed to a user by a non-onboarding principal
title: IAM CreateLoginProfile by non-identity-admin principal
id: 7b1e4c93-2a58-4d61-9c3a-5f0b8d6e2a17
name: iam_create_login_profile_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreateLoginProfile'
  identity_admin:
    userIdentity.arn|contains:
      - ':role/identity-admin'
      - ':role/onboarding'
      - ':role/iac-deploy'
      - ':role/BreakGlassAdmin'
  condition: selection and not identity_admin
level: high
---
# Base rule for the correlation below: a bare CreateUser selection (deploy this too)
title: IAM CreateUser
id: 6a0d3b82-1948-4c50-8b23-4e9a7c5d1f06
name: iam_create_user
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreateUser'
  condition: selection
level: informational
---
# Rule B: the net-new console-backdoor sequence (temporal, ordered)
title: IAM create-console-user backdoor sequence
id: 8c2f5d04-3b69-4e72-a1d4-6a1c9b7e5f28
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - iam_create_user               # base rule above
    - iam_create_login_profile_base # Rule A's base selection (CreateLoginProfile)
  group-by:
    - userIdentity.arn
  timespan: 10m
level: high
```

All three documents above must be deployed together, the correlation references
both base rules by their `name:`. For the **escalated** variant, add a further correlation
joining a `CreateLoginProfile` and an `AttachUserPolicy`/`PutUserPolicy`/`AddUserToGroup`
on the same `requestParameters.userName` within the window, that is the pairing
that turns a powerless console user into a real threat.

**On error strings:** IAM denials surface as `AccessDenied` / `AccessDeniedException`, not `Client.`-prefixed. Confirm against a sample. **On `passwordResetRequired`:** it is a *supporting* discriminator only, some legitimate flows also set it `false`; never gate a containment action on it alone.

---

### Key Investigation Queries

> IAM and console sign-in events are global → query **`us-east-1`**. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. Note the **nested** response shapes: `CreateUser` → `responseElements.user.*`, `CreateLoginProfile` → `responseElements.loginProfile.*`. **`lookup-events` returns ≤50 events per page**, for a busy account or multi-day window, add `--max-items`/paginate on `NextToken`, or run these against your log platform, so IOCs aren't silently truncated.

#### Query 1 - Reconstruct the backdoor: new users, their login profiles, and any privilege grants

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

for EV in CreateUser CreateLoginProfile AttachUserPolicy PutUserPolicy AddUserToGroup; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "iam.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,              # feeds ACCESS_KEY_ID in Query 4
     target_user: (.requestParameters.userName // .responseElements.user.userName),
     reset_required: .requestParameters.passwordResetRequired,   # false = set for immediate use
     policy_arn: .requestParameters.policyArn,           # present on AttachUserPolicy (escalation)
     inline_policy: .requestParameters.policyName,       # present on PutUserPolicy (escalation)
     group: .requestParameters.groupName,               # present on AddUserToGroup (escalation)
     error: (.errorCode // "SUCCESS"),
     ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read this timeline per caller: a `CreateUser` immediately followed by a
`CreateLoginProfile` on the same `target_user` by one `caller` is the console
backdoor. If an `AttachUserPolicy`/`PutUserPolicy`/`AddUserToGroup` on the same
`target_user` also appears, the identity was **armed with privilege**, treat as
High and hunt the granted permissions. Record `target_user`, `caller`, and its
`access_key` (IOCs).

#### Query 2: Sweep ALL users for console access without MFA (find every backdoor)

The attacker may have created more than one, or enabled console access on an
existing user. The Credential Report is the authoritative, account-wide inventory
of who has a password and whether MFA is on.

```bash
# GNU base64 decodes with -d, older BSD/macOS with -D. Probe, then decode.
b64d() { if base64 -d </dev/null >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }

aws iam generate-credential-report >/dev/null 2>&1
sleep 3   # report generation is async; retry if STATE is STARTED
aws iam get-credential-report --query 'Content' --output text | b64d | \
  awk -F',' 'NR==1 || ($4=="true" && $8=="false") {print}'
# CSV columns: 1 user, 4 password_enabled, 5 password_last_used, 8 mfa_active
# Filter above = console-enabled users with NO MFA: the highest-risk set.
echo "[OK] Credential-report console/MFA sweep complete, reconcile every password_enabled=true,mfa_active=false user against approved console users"
```

> Confirm the column positions against your report header (`... | head -1`) before
> relying on `$4`/`$8` - AWS has added columns over time. Any `password_enabled=true`
> user you did not expect, especially `mfa_active=false` and recently created, is a
> candidate backdoor; cross-check its `CreateUser` caller in Query 1.

#### Query 3: Was the backdoor console user USED? (ConsoleLogin hunt)

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
BACKDOOR_USER="<target_user-from-Query-1>"

# For an IAM *user*, userIdentity.userName == the user name, so a Username lookup is
# correct here (unlike assumed-role sessions, where the session name differs).
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$BACKDOOR_USER" \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     console_result: .responseElements.ConsoleLogin,          # Success/Failure on ConsoleLogin
     mfa: .additionalEventData.MFAUsed,                       # "No" = password-only sign-in
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Any `ConsoleLogin` with `console_result="Success"` means the backdoor was
exercised from the console, every subsequent action by that user is part of the
incident, and its `ip` values are IOCs. A `Success` with `mfa="No"` confirms a
password-only sign-in (the emulation sets no MFA). Repeated `Failure` entries mean
someone is trying the password, still contain immediately.

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

Look for *other* persistence, more backdoor users, additional login profiles,
access keys, backdoored role trust policies, and remediate each with the relevant
persistence playbook.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The backdoor is a standing identity with an interactive console credential.
Neutralise it (remove the login profile, the persistence mechanism), determine
whether it signed in, and contain the planting principal.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1: Neutralise the backdoor console credential

```bash
BACKDOOR_USER="<target_user-from-Query-1>"

# A login profile cannot be "disabled": deleting it is the neutralisation.
# Its existence is already recorded in CloudTrail, so no evidence is lost.
aws iam delete-login-profile --user-name "$BACKDOOR_USER" 2>/dev/null && \
  echo "[OK] Removed console login profile from $BACKDOOR_USER (console access revoked)" || \
  echo "[i] No login profile on $BACKDOOR_USER (already removed, or wrong user)"

# If the attacker also armed the user (Query 1 showed a policy/group), strip it now,
# and disable any access key it holds (do NOT delete yet: preserve evidence).
for PA in $(aws iam list-attached-user-policies --user-name "$BACKDOOR_USER" \
    --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
  aws iam detach-user-policy --user-name "$BACKDOOR_USER" --policy-arn "$PA" && \
    echo "[OK] Detached $PA from $BACKDOOR_USER"
done
for K in $(aws iam list-access-keys --user-name "$BACKDOOR_USER" \
    --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
  aws iam update-access-key --user-name "$BACKDOOR_USER" --access-key-id "$K" --status Inactive && \
    echo "[OK] Disabled key $K on $BACKDOOR_USER"
done
```

#### Step 2: Contain the principal that created the backdoor

The `:user/` and `:assumed-role/` branches cover the common cases. A **root** or
**federated** caller (`SAMLUser`/`WebIdentityUser`) needs manual handling, root
via password rotation + key removal, federated via the IdP, since the script
silently no-ops for those principal types.

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
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role, root/federated: contain manually (root credential rotation or IdP)"
fi
```

Note: `aws:TokenIssueTime` revokes only sessions issued **before** the cutoff; a
credential the attacker re-fetches afterward is not caught. It kills currently-active
sessions, not the underlying access.

#### Step 3: Deny further user / console-credential creation by the principal

```bash
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:CreateUser","iam:CreateLoginProfile","iam:UpdateLoginProfile","iam:AttachUserPolicy","iam:PutUserPolicy","iam:AddUserToGroup","iam:CreateAccessKey"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyUserCreation" --policy-document "$DENY_DOC"
  echo "[OK] User/credential-creation denied for role $R"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyUserCreation" --policy-document "$DENY_DOC"
  echo "[OK] User/credential-creation denied for user $U"
else
  echo "[i] Root/federated principal, apply the deny at the SCP/IdP level instead"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete the backdoor user(s)

```bash
BACKDOOR_USER="<target_user-from-Query-1>"

# Full teardown: delete login profile, keys, detach/delete policies, remove from
# groups, then delete the user. Each guarded so a missing sub-resource doesn't abort.
aws iam delete-login-profile --user-name "$BACKDOOR_USER" 2>/dev/null
for K in $(aws iam list-access-keys --user-name "$BACKDOOR_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
  aws iam delete-access-key --user-name "$BACKDOOR_USER" --access-key-id "$K"
done
for PA in $(aws iam list-attached-user-policies --user-name "$BACKDOOR_USER" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
  aws iam detach-user-policy --user-name "$BACKDOOR_USER" --policy-arn "$PA"
done
for PN in $(aws iam list-user-policies --user-name "$BACKDOOR_USER" --query 'PolicyNames[]' --output text 2>/dev/null); do
  aws iam delete-user-policy --user-name "$BACKDOOR_USER" --policy-name "$PN"
done
for G in $(aws iam list-groups-for-user --user-name "$BACKDOOR_USER" --query 'Groups[].GroupName' --output text 2>/dev/null); do
  aws iam remove-user-from-group --user-name "$BACKDOOR_USER" --group-name "$G"
done
aws iam delete-user --user-name "$BACKDOOR_USER" && echo "[OK] Deleted backdoor user $BACKDOOR_USER"
```

Repeat for every backdoor user Query 2 surfaced.

#### Remove other persistence planted by the principal

From Query 4, remediate anything else the principal created, additional users,
login profiles, keys, backdoored role trust policies, using the relevant
persistence playbook for each.

#### Right-size user/credential-creation permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove iam:CreateUser / iam:CreateLoginProfile from principals that are not
# identity-admin/onboarding. No workload principal should be able to mint a console user.
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

#### Verify no unexpected user holds console access without MFA (re-sweep)

```bash
# GNU base64 decodes with -d, older BSD/macOS with -D. Probe, then decode.
b64d() { if base64 -d </dev/null >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }

aws iam generate-credential-report >/dev/null 2>&1
sleep 3
FAIL=$(aws iam get-credential-report --query 'Content' --output text | b64d | \
  awk -F',' 'NR>1 && $4=="true" && $8=="false" {print $1}' | grep -vc '^$')
[ "$FAIL" -eq 0 ] && echo "[OK] No console-enabled user without MFA" \
                  || echo "[i] $FAIL console user(s) without MFA remain, reconcile each against approved console users (some may be legitimate)"
```

> This lists MFA-less console users for human reconciliation; it is not a hard
> pass/fail (you may legitimately have some). Confirm none is attacker-created.

#### Verify the backdoor user never signed in after containment

```bash
REGION="us-east-1"
BACKDOOR_USER="<target_user-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

USED=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$BACKDOOR_USER" \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson
         | select(.eventName == "ConsoleLogin" and .responseElements.ConsoleLogin == "Success")
         | .eventTime' | grep -c .)
[ "$USED" -eq 0 ] && echo "[OK] No successful console sign-in by $BACKDOOR_USER after containment" \
                  || echo "[FAIL] $USED successful sign-in(s) post-containment, the login profile was not fully removed"
```

#### Verify no further user creation / login-profile creation since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(for EV in CreateUser CreateLoginProfile; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$CONTAINED_AT" --region "$REGION" --output json 2>/dev/null
done | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)
[ "$COUNT" -eq 0 ] && echo "[OK] No further user/login-profile creation from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further events, containment did not hold"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm: Rule A fires HIGH on the CreateLoginProfile"
echo "(non-identity-admin caller), and Rule B fires on the CreateUser->CreateLoginProfile"
echo "sequence, and that NEITHER fires on the benign DeleteLoginProfile/DeleteUser"
echo "cleanup events the shipped rule wrongly includes."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could create a user and give it a console password | `iam:CreateUser` + `iam:CreateLoginProfile` available outside identity-admin/onboarding; no SCP restricting who can mint console credentials |
| Backdoor undetected | Shipped rule matched create *and delete* user/profile events with no sequence, principal, or content filter; GuardDuty persistence findings not alarmed |
| Persistence survives original-credential remediation | The backdoor is an independent identity with its own **password**, invisible to an access-key rotation sweep |
| Standing console access without MFA | No account policy requiring MFA on every console-enabled user; no Credential-Report review |
| Could have been armed with privilege unnoticed | No correlation between a login-profile grant and an accompanying policy/group attach |

### Recommended Guardrails

**Restrict console-credential creation to the onboarding pipeline (the primary control)**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// deny minting console users outside identity-admin/onboarding.
{
  "Effect": "Deny",
  "Action": ["iam:CreateUser", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/identity-admin", "arn:aws:iam::*:role/onboarding", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

```json
// SCP fragment: require MFA to exist before a console user can do anything sensitive,
// i.e. deny broad actions when MFA is not present (defence-in-depth for any password-only user).
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" },
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/*"] }
  }
}
```

(The second fragment uses `BoolIfExists`, not plain `Bool`, on purpose: for
plain IAM-user password/access-key auth the `aws:MultiFactorAuthPresent` key is
often **absent** from the request context, and a plain `Bool` deny would silently
never fire against exactly the non-MFA users it targets, `BoolIfExists` treats
an absent key as matching, so the deny still applies. Role sessions and service
principals are excluded here by the `aws:PrincipalArn` `role/*` clause, **not** by
the operator. Scope and test it before enforcing, a too-broad MFA deny can lock
out legitimate flows.)

**Structural controls**
- Prefer **IAM Identity Center (SSO)** with **no standing IAM users**, so creating a console user at all is inherently anomalous
- **Enforce MFA** on every IAM user that retains console access; review the Credential Report on a schedule for `password_enabled=true, mfa_active=false`
- **Permissions boundaries** on all new users, capping what even an armed backdoor could do
- Manage all IAM identities through reviewed IaC; treat any out-of-band `CreateUser`/`CreateLoginProfile` as an incident

**Detection improvements**
- Deploy Rule A (`CreateLoginProfile` by non-identity-admin) and Rule B (the create→login-profile sequence); never the shipped create-and-delete match
- Add the escalation correlation (login profile + policy/group grant on the same user)
- Alarm the `ConsoleLogin` (`MFAUsed=No`, Success) by any newly-created user, and GuardDuty `Persistence:IAMUser/UserPermissions`

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1136.003 - Create Account: Cloud Account |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `iam:CreateUser` → `iam:CreateLoginProfile` (console password) |
| Event source | `iam.amazonaws.com` (global → events in `us-east-1`); sign-in via `signin.amazonaws.com` |
| Key discriminator | `CreateLoginProfile` (a *console password*, not a key) on a net-new user, by a non-onboarding principal, and the ordered `CreateUser → CreateLoginProfile` pair, not the event names |
| Nested response fields | `CreateUser` → `responseElements.user.userName`; `CreateLoginProfile` → `responseElements.loginProfile.userName` (nested, a flat path yields null). The **password is never in CloudTrail** |
| "Was it used" pivot | `ConsoleLogin` (`responseElements.ConsoleLogin == "Success"`, `additionalEventData.MFAUsed == "No"`) by the backdoor user, not an access-key hunt |
| Account-wide sweep | IAM **Credential Report** (`password_enabled` / `mfa_active` columns), not Access Analyzer |
| GuardDuty | `Persistence:IAMUser/UserPermissions` (confirm against the current GuardDuty finding-types reference, names are occasionally revised) |
| Severity note | As emulated the user has **no permissions** → Medium; escalates to High if a policy/group grant accompanies the login profile |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | None persisted, the emulation deletes its own user + login profile (a real attack leaves them) |

**MITRE mapping note:** T1136.003 (Create Account: Cloud Account), Persistence, is
the correct, precise mapping for creating a new cloud identity for persistence.
Note the MANIFEST's technique *name* ("Create IAM User with Console Access") is the
upstream Stratus label, not the canonical MITRE name ("Create Account: Cloud
Account"), a cosmetic naming inconsistency, not a mis-mapping.

### Revert

The emulation creates and then deletes its own user + login profile, so a normal
run self-cleans; `pulumi destroy` has nothing to remove (no infra). After a **real**
incident, `pulumi destroy` is irrelevant, delete every backdoor user, remove its
login profile and any keys/policies (§3-§4), remove any other persistence, and
restrict console-credential creation via SCP; the attacker's console identity
persists until you delete it, regardless of any stack teardown.
