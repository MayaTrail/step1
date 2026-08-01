# IR Playbook: Backdoor IAM User Console Login via `iam:UpdateLoginProfile` — Privilege Escalation by Password Hijack

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Privilege Escalation / Account Manipulation (hijack an existing IAM user's console password) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High — `iam:UpdateLoginProfile` resets **another** IAM user's console password to one the attacker controls, letting them sign in as that user. If the target is more privileged than the attacker's current principal, this is a direct privilege escalation; it also locks the legitimate user out. **Key mitigant:** resetting the password does **not** touch the target's MFA — if the target has MFA enrolled, the attacker's new password alone will not complete a console sign-in. `MANIFEST.py` rates HIGH (the IR view agrees) |
| MITRE Tactics | Privilege Escalation |
| MITRE Techniques | T1098.001 |
| Services in Scope | IAM, CloudTrail (incl. console sign-in) |
| Infrastructure Created | A target IAM user (`stratus-red-team-update-login-profile-user`) with an existing console login profile, via `pulumi up` |

**What the emulation does:** with a pre-created target user that already has a console login profile, it calls `iam:UpdateLoginProfile` with `Password=<attacker-chosen>` and `PasswordResetRequired=False` — silently replacing that user's console password. A single `UpdateLoginProfile` event is the only CloudTrail evidence. The attacker can now sign in to the console as the target user.

**Why this is privilege escalation, and how it differs from creating a user.** `UpdateLoginProfile` acts on an **existing** user — the attacker picks a *more privileged* victim (a human admin, say) and takes over their console identity, inheriting whatever that user can do. (Creating a *new* console user is the persistence sibling — `CreateUser` + `CreateLoginProfile`; this technique hijacks one that already exists.) It is characteristically an **administrative** action: by AWS's own console self-service design, a user changing their *own* password uses `iam:ChangePassword` (which requires the old password), so a legitimate `UpdateLoginProfile` is normally a help-desk/identity-admin resetting *someone else's* password — which makes an unexpected caller high-signal. Note this is a convention, **not** an AWS-enforced restriction: a principal holding `iam:UpdateLoginProfile` on `*`/`${aws:username}` *can* call it against its own account, so a self-targeted `UpdateLoginProfile` is itself suspicious (it signals an over-broad grant) and should not be dismissed as impossible.

**MFA is the deciding control.** A password reset does not remove or reset the target's MFA device. If the victim has MFA, the attacker holds a valid password but still cannot pass the console MFA challenge — the hijack fails at sign-in. The users worth worrying about first are therefore **privileged users without MFA**.

**Detection is the caller and the target, not the event name.** `UpdateLoginProfile` is legitimate for help-desk / identity-admin password resets. The signal is **`UpdateLoginProfile` by a principal not on the password-reset/identity-admin allowlist**, especially targeting a privileged user, with `PasswordResetRequired=false`. The shipped rule pairs it with the read `GetLoginProfile` and inspects neither caller nor target (§2).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail (IAM is global → events land in `us-east-1`). `UpdateLoginProfile` carries `requestParameters.userName` (the **target**) and `requestParameters.passwordResetRequired`; the **password is never logged**. The caller is `userIdentity.arn`. A follow-on console sign-in is a `ConsoleLogin` event (`signin.amazonaws.com`) with `userIdentity.userName` = the target and `additionalEventData.MFAUsed`
- The allowlist of principals that legitimately reset passwords (help-desk / identity-admin / password-reset automation) — so any other caller is anomalous
- An inventory of which IAM users are **privileged** and which have **MFA** — the intersection "privileged + no MFA" is the highest-risk target set

**Alerting (must be pre-configured)**
- **`iam:UpdateLoginProfile` by a principal not on the password-reset allowlist → P0**
- **`iam:UpdateLoginProfile` targeting a privileged user → P0**, doubly so if that user has no MFA
- **A `ConsoleLogin` (Success) by a user whose password was just reset by a non-allowlisted principal → P0** (the hijack being used)
- The legitimate user reporting they can no longer log in (their password stopped working) → treat as a possible hijack

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq`; the password-reset allowlist; the privileged-user and MFA inventories

**Known IOC Baselines**
- The emulation's target `stratus-red-team-update-login-profile-user`, tag `StratusRedTeam=true`, `PasswordResetRequired=false`
- Baseline which principals reset passwords and which users have console access + MFA

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `iam:UpdateLoginProfile` by a principal not on the password-reset/identity-admin allowlist | CloudTrail | T1098.001 |
| P0 | `iam:UpdateLoginProfile` targeting a privileged user (esp. one without MFA) | CloudTrail | T1098.001 |
| P0 | `ConsoleLogin` (Success) by the target user shortly after a non-allowlisted `UpdateLoginProfile`, from an anomalous IP | CloudTrail (`signin.amazonaws.com`) | T1098.001 |
| P1 | `UpdateLoginProfile` with `passwordResetRequired=false` outside the help-desk flow (attacker keeps the password; help-desk usually forces a reset) | CloudTrail | T1098.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | The legitimate user reports a sudden inability to sign in (password no longer works) | Help-desk / user report | T1098.001 |
| P2 | `iam:UpdateLoginProfile` denied at volume (`errorCode = AccessDenied`) — probing | CloudTrail | T1098.001 |
| P3 | Help-desk/identity-admin resetting a password during a known, ticketed request (usually `passwordResetRequired=true`) | CloudTrail | T1098.001 |

### Detection Rule Quality Notes

The shipped rule pairs the action with a read and inspects neither caller nor target.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (GetLoginProfile, UpdateLoginProfile)` with `condition: selection` | Imprecise. `GetLoginProfile` is a routine read (noise); `UpdateLoginProfile` is legitimate for help-desk resets. The rule never checks *who* called it or *whom* it targeted | Match `UpdateLoginProfile` filtered to non-allowlisted callers; drop the bare `GetLoginProfile` |
| No caller allowlist | Cannot separate a help-desk reset from a hijack | Exclude the password-reset/identity-admin roles; alert everyone else |
| No target-privilege / MFA context | Misses the escalation severity (a privileged, MFA-less victim) | Enrich with the privileged-user + MFA inventory; escalate those targets |
| `GetLoginProfile` bundled in | A read is not the attack | Keep only for the forensic timeline |
| `level: medium` | The shipped MANIFEST severity is HIGH and correct | Raise the rule to `high` |

**Recommended detection — password reset by a non-allowlisted principal.**

```yaml
title: IAM UpdateLoginProfile by non-password-reset principal
id: 4a1e7c92-5b63-4d70-9c2a-8f0b6d3e5a14
name: iam_updateloginprofile_nonhelpdesk
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'UpdateLoginProfile'
  password_reset_role:
    userIdentity.arn|contains:
      - ':role/helpdesk-password-reset'
      - ':role/identity-admin'
      - ':role/BreakGlassAdmin'
  condition: selection and not password_reset_role
level: high
```

Enrich at the log platform: raise to *critical* when `requestParameters.userName` is on your
privileged-user list, and correlate with a `ConsoleLogin` by that user within the next hour.
a legitimate `UpdateLoginProfile` is normally an admin resetting *another* user's password
(console self-service uses `iam:ChangePassword`), so a non-allowlisted caller — or a
self-targeted reset — is high-signal. **On error strings:**
denials surface as `AccessDenied` / `AccessDeniedException`, not `Client.`-prefixed.

---

### Key Investigation Queries

> IAM and console sign-in events are global → query **`us-east-1`**. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct the hijack: who reset whose password

```bash
REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateLoginProfile \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 4
     target_user: .requestParameters.userName,       # the victim (IOC)
     reset_required: .requestParameters.passwordResetRequired,   # false = attacker keeps the password
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

A `UpdateLoginProfile` by a caller who is not help-desk/identity-admin, on a `target_user`
who is not the caller, is the hijack. Record the `caller` (the compromised principal) and the
`target_user` (the victim whose console access is now attacker-controlled) — both IOCs.

#### Query 2 — Assess the victim: privilege and MFA (how bad is it?)

```bash
TARGET="<target_user-from-Query-1>"

echo "== Attached managed policies =="
aws iam list-attached-user-policies --user-name "$TARGET" --output table
echo "== Inline policies =="
aws iam list-user-policies --user-name "$TARGET" --output table
echo "== Group memberships (inherited privilege) =="
aws iam list-groups-for-user --user-name "$TARGET" --query 'Groups[].GroupName' --output table
echo "== MFA devices (if ANY, the password hijack alone cannot complete console sign-in) =="
aws iam list-mfa-devices --user-name "$TARGET" --query 'MFADevices[].SerialNumber' --output table
```

The victim's privileges are what the attacker gains. If `list-mfa-devices` is **empty**, the
attacker can sign in with just the password — treat as an active compromise. If MFA is present,
the hijack is blunted at sign-in (but still reset the password and investigate).

#### Query 3 — Was the hijacked console account SIGNED IN TO?

```bash
REGION="us-east-1"
TARGET="<target_user-from-Query-1>"

# For an IAM user, userIdentity.userName == the user name, so a Username lookup is correct here.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$TARGET" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventName == "ConsoleLogin") |
    {time: .eventTime, result: .responseElements.ConsoleLogin,   # Success/Failure
     mfa: .additionalEventData.MFAUsed, ip: .sourceIPAddress} |
    select(.time)' | jq -s 'sort_by(.time)'
```

A `ConsoleLogin` `Success` after the `UpdateLoginProfile` timestamp — especially with
`mfa="No"` and from an IP that is not the legitimate user's — is the hijack being used; every
action by that user session afterward is in scope. A run of `Failure` with `mfa` challenges
means MFA is blocking the attacker (good) — still contain.

#### Query 4 — Full session reconstruction of the principal that reset the password

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

Look for other hijacks (more `UpdateLoginProfile`), new users/keys, and any privileged actions
the compromised principal took — remediate each with the relevant playbook.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The attacker holds a valid console password for the victim. Cut the victim's session and reset
the password through a secure channel, then contain the calling principal.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained.

#### Step 1 — Freeze the victim account and kill any active session

```bash
TARGET="<target_user-from-Query-1>"

# An explicit Deny on the victim applies to any console session already open under it (IAM
# identity policies are evaluated per request), stopping the attacker's actions immediately.
aws iam put-user-policy --user-name "$TARGET" --policy-name "EmergencyFreeze" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
echo "[OK] Froze $TARGET — any active console session is now denied"

# Also disable the victim's access keys (in case the attacker minted/used them):
for K in $(aws iam list-access-keys --user-name "$TARGET" \
    --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text 2>/dev/null); do
  aws iam update-access-key --user-name "$TARGET" --access-key-id "$K" --status Inactive
  echo "[OK] Disabled key $K on $TARGET"
done
```

#### Step 2 — Take back the console password (invalidate the attacker's)

```bash
TARGET="<target_user-from-Query-1>"
NEWPW="$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)Aa1!"   # random, meets IAM complexity

# Reset to a random password the attacker does not know, forcing a change at next login.
aws iam update-login-profile --user-name "$TARGET" --password "$NEWPW" --password-reset-required && \
  echo "[OK] Reset $TARGET console password (attacker's password no longer valid; reset forced)"

# Alternatively, remove console access entirely until the legitimate user re-onboards securely:
#   aws iam delete-login-profile --user-name "$TARGET"
```

> Deliver the new password / re-onboarding **out of band** to the verified legitimate user —
> never through the same channel that may be compromised.

#### Step 3 — Contain the principal that performed the reset

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')          # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyLoginProfile" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:UpdateLoginProfile","iam:CreateLoginProfile"],"Resource":"*"}]}'
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')           # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
  echo "[OK] Revoked sessions for role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> `aws:TokenIssueTime` revokes only sessions issued **before** the cutoff; a credential
> re-fetched afterward is not caught.

---

## 4. Eradication

### Remove Attacker Access

#### Restore the victim securely and require MFA

```bash
TARGET="<target_user-from-Query-1>"
# After the legitimate user re-establishes a password out of band, ENROLL MFA so a future
# password reset cannot by itself grant console access:
echo "[i] Enroll an MFA device for $TARGET (virtual or hardware) before removing the freeze."
# Verify MFA now present:
aws iam list-mfa-devices --user-name "$TARGET" --query 'MFADevices[].SerialNumber' --output table
```

#### Remove other hijacks / persistence by the principal

From Query 4, remediate anything else the principal did — more `UpdateLoginProfile` hijacks,
new backdoor users, access keys, IAM changes — with the relevant playbook.

#### Right-size `iam:UpdateLoginProfile` permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove iam:UpdateLoginProfile from principals that are not help-desk / identity-admin.
```

#### Remove emergency policies once clean

```bash
TARGET="<target_user-from-Query-1>"; SUSPECT="<suspect-name>"
aws iam delete-user-policy --user-name "$TARGET" --policy-name "EmergencyFreeze" 2>/dev/null
aws iam delete-user-policy --user-name "$SUSPECT" --policy-name "EmergencyDenyLoginProfile" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed (only after the account is verified clean and MFA is enrolled)"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the attacker's password no longer works and the account is controlled

```bash
TARGET="<target_user-from-Query-1>"
# Confirm a login profile exists (reset) with reset-required, and MFA is now enrolled.
aws iam get-login-profile --user-name "$TARGET" --query 'LoginProfile.PasswordResetRequired' --output text
MFA=$(aws iam list-mfa-devices --user-name "$TARGET" --query 'length(MFADevices)' --output text)
[ "$MFA" -gt 0 ] && echo "[OK] $TARGET has MFA enrolled" || echo "[FAIL] $TARGET still has NO MFA — enroll before closing"
```

#### Verify no console sign-in by the victim since containment (except the verified user)

```bash
REGION="us-east-1"
TARGET="<target_user-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

HITS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$TARGET" \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson
         | select(.eventName == "ConsoleLogin" and .responseElements.ConsoleLogin == "Success")
         | "\(.eventTime) \(.sourceIPAddress) MFA=\(.additionalEventData.MFAUsed)"')
[ -z "$HITS" ] && echo "[OK] No successful console sign-in by $TARGET since containment" \
               || { echo "[i] Sign-ins since containment — confirm each is the LEGITIMATE user (post-reset, MFA=Yes):"; echo "$HITS"; }
```

#### Verify no further password resets by the principal

```bash
REGION="us-east-1"
SUSPECT_ARN="<caller-arn-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

N=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateLoginProfile \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson | select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)
[ "$N" -eq 0 ] && echo "[OK] No further UpdateLoginProfile by $SUSPECT_ARN since containment" \
              || echo "[FAIL] $N further resets — containment did not hold"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm the rule fires HIGH on the UpdateLoginProfile by a"
echo "non-password-reset principal (escalating to critical when the target is privileged) —"
echo "and that it does NOT fire on the benign GetLoginProfile read or a help-desk reset."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could reset another user's console password | `iam:UpdateLoginProfile` available outside help-desk/identity-admin; no SCP restriction |
| Hijack yielded privilege | The victim was privileged and reachable by password reset; no separation between the compromised principal and high-value identities |
| Attacker could sign in with just a password | The victim had **no MFA** — a password reset was sufficient for console access |
| Undetected | Shipped rule bundled a read event and inspected neither caller nor target |
| Legitimate user lock-out not triaged | No process linking "user can't log in" to a possible password hijack |

### Recommended Guardrails

**Restrict password resets to help-desk / identity-admin (primary control)**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["iam:UpdateLoginProfile", "iam:CreateLoginProfile"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/helpdesk-password-reset", "arn:aws:iam::*:role/identity-admin", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Enforce MFA on every console user (the control that defeats this technique)**

```json
// SCP/identity-policy fragment: deny sensitive actions unless MFA is present in the request
// context, so a password-only console session (post-hijack) can do nothing.
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

(The MFA fragment uses `BoolIfExists` so it also applies when the key is absent — exactly the
password-only console case; role/service principals are excluded by the `aws:PrincipalArn`
clause, not by the operator. Scope and test before enforcing.)

**Structural controls**
- **Require MFA for all human IAM users**, and prefer IAM Identity Center (SSO) so console passwords are not a standing credential at all
- **Least-privilege**: keep highly privileged identities out of reach of routine password-reset roles
- Alert help-desk lock-out reports into the SOC as a possible hijack signal

**Detection improvements**
- Deploy the caller-aware rule (`UpdateLoginProfile` by non-allowlisted principal); never the shipped read+action match
- Enrich with the privileged-user + MFA inventory; escalate privileged/MFA-less targets
- Correlate `UpdateLoginProfile` with a subsequent `ConsoleLogin` by the target

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| MITRE tactic | Privilege Escalation (also Persistence for T1098) |
| Primary API | `iam:UpdateLoginProfile` (reset an existing user's console password) |
| Event source | `iam.amazonaws.com` (global → events in `us-east-1`); sign-in via `signin.amazonaws.com` |
| Key discriminator | Caller not on the password-reset allowlist, target ≠ caller (self-service is `iam:ChangePassword`), `passwordResetRequired=false` — not the event name |
| Decisive mitigant | MFA on the target — a password reset does **not** reset/remove MFA, so an MFA-enrolled victim cannot be signed into with the new password alone |
| Fields | `requestParameters.userName` (target), `requestParameters.passwordResetRequired`; password never logged; `ConsoleLogin` → `responseElements.ConsoleLogin` + `additionalEventData.MFAUsed` |
| "Was it used" pivot | `ConsoleLogin` (Success) by the target user after the reset, anomalous IP / `MFAUsed=No` |
| vs. the persistence sibling | `CreateUser`+`CreateLoginProfile` creates a *new* console user (persistence); this hijacks an *existing* one (privilege escalation) |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | The target user persists (created by `pulumi up`); the emulation only changes its password (a real attack does the same to a real user) |

**MITRE mapping note:** T1098.001 (Account Manipulation: Additional Cloud Credentials) under
the **Privilege Escalation** tactic is a reasonable fit — resetting a credential on an existing
account to take it over is account manipulation, and it escalates when the victim is more
privileged. (T1098's canonical tactics are Persistence and Privilege Escalation; the MANIFEST
picks the escalation framing, which matches the technique's intent.) The MANIFEST's technique
*name* is the upstream Stratus label, not a canonical MITRE name — cosmetic only.

### Revert

`pulumi destroy` in `infra/` removes the target user and its login profile. After a **real**
incident, reset the victim's password out of band, enroll MFA, contain the calling principal,
and restrict `UpdateLoginProfile` to help-desk/identity-admin; the attacker retains console
access as the victim until the password is reset and any active session denied, regardless of
any stack teardown.
```
