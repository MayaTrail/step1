# IR Playbook: Console Login Without MFA - Valid-Account Console Access via a Non-MFA IAM User

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Initial Access / Valid Accounts (console sign-in without MFA) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | Medium, a non-MFA console login is a strong compromise indicator for accounts that should enforce MFA; **High if the identity is root or an admin** |
| MITRE Tactics | Initial Access |
| MITRE Techniques | T1078.004 |
| Services in Scope | IAM, CloudTrail (`signin.amazonaws.com`), GuardDuty |
| Infrastructure Created | 1 IAM user with a console login profile and **no MFA** (via `infra/`) |

**What the emulation does:** provisions an IAM user with a console password (login profile) and no MFA device, then (because a real console login needs a browser) *simulates* the attack by confirming the user has no MFA and documenting the CloudTrail signal it would produce: a `ConsoleLogin` event with `additionalEventData.MFAUsed = "No"` and `responseElements.ConsoleLogin = "Success"`. In a real intrusion, an attacker who has the username and password logs into the AWS Management Console with no second factor, the `MFAUsed=No` console login is the detectable event.

**Why this technique is really about a control gap plus stolen credentials.** The "attack" is just a successful console sign-in; what makes it an incident is (a) MFA was not enforced, so a leaked password alone grants full console access, and (b) the login is from an unexpected identity/location. The response therefore has two halves: treat the specific login as possible credential compromise, and close the MFA-enforcement gap so a password alone is never sufficient again.

**The shipped detection here is good, validate and extend it, don't replace it.** Unlike most techniques in this catalogue, the rules in `detections/` are correctly written: they scope to `signin.amazonaws.com` / `ConsoleLogin`, filter `MFAUsed == "No"` and `ConsoleLogin == "Success"`, and even carry a false-positive note. The work in §2 is to *validate* them and add the important edge cases they don't yet cover, federated/SSO false positives, root logins, and failed-login brute force, not to rewrite a working rule.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail. **`ConsoleLogin` is emitted by the global `signin.amazonaws.com` endpoint and lands in `us-east-1`**, ensure the trail captures global service events and query `us-east-1` for these events regardless of where your workloads run
- The `ConsoleLogin` event carries `additionalEventData.MFAUsed`, `responseElements.ConsoleLogin` (Success/Failure), `userIdentity` (the user/role), and `sourceIPAddress`, everything the detection needs is in the event
- GuardDuty enabled, `UnauthorizedAccess:IAMUser/*` and anomalous-behaviour findings corroborate a suspicious login
- An **MFA-exemption allowlist**: the (ideally empty) set of identities legitimately without MFA, so `MFAUsed=No` for anyone else is unambiguous

**Alerting (must be pre-configured)**
- **`ConsoleLogin`, `MFAUsed=No`, `ConsoleLogin=Success` for any IAM user not on the MFA-exemption allowlist → alert** (the canonical rule, already shipped here in good shape)
- **P0: root `ConsoleLogin` with `MFAUsed=No`**, root must always have MFA; a non-MFA root login is a critical event on its own
- A `ConsoleLogin` from a new/off-baseline source IP or geography for the user, MFA or not, geo/impossible-travel signal
- A burst of `ConsoleLogin` with `ConsoleLogin=Failure` for one user or from one IP, console password brute force preceding a successful login
- AWS Config `iam-user-mfa-enabled` / `mfa-enabled-for-iam-console-access` non-compliant → the standing control gap

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any account under investigation
- `jq` installed
- The account's IAM inventory: which users have console access, which have MFA, and which are (supposedly) exempt

**Known IOC Baselines**
- Baseline each console user's normal source IPs/geographies and login hours
- Baseline which identities are SSO/federated (they sign in differently, see the federated caveat in §2) vs. genuine IAM users with passwords

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Root `ConsoleLogin` with `additionalEventData.MFAUsed = No`, `ConsoleLogin = Success` | CloudTrail (`us-east-1`) | T1078.004 |
| P0 | IAM-user `ConsoleLogin`, `MFAUsed = No`, `Success`, from an unexpected IP/geo for that user | CloudTrail | T1078.004 |
| P1 | IAM-user `ConsoleLogin`, `MFAUsed = No`, `Success`, for a user not on the MFA-exemption allowlist | CloudTrail | T1078.004 |
| P1 | GuardDuty `UnauthorizedAccess:IAMUser/*` on the same user around the login | GuardDuty | T1078.004 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Burst of `ConsoleLogin` `Failure` for one user / from one IP (password brute force) | CloudTrail | T1078.004 |
| P2 | `ConsoleLogin` `MFAUsed = No` `Success` for an *allowlisted* exempt user from an off-baseline IP | CloudTrail | T1078.004 |
| P2 | Impossible travel: two `ConsoleLogin` successes for one user from geographically distant IPs within a short window | CloudTrail | T1078.004 |
| P3 | `ConsoleLogin` `MFAUsed = No` for a genuinely exempt service identity from its normal IP | CloudTrail | T1078.004 |

### Detection Rule Quality Notes

**The shipped rules are largely correct**, a notable exception in this catalogue. The Sigma rule (`sigma_t1078_004.yml`) and KQL (`kql_t1078_004.kql`) both scope to `signin.amazonaws.com` / `ConsoleLogin`, filter `MFAUsed == "No"` and `ConsoleLogin == "Success"`, and the Sigma even documents false positives. They are deployable as-is. The refinements below add coverage they lack; they are extensions, not fixes for brokenness.

| Refinement | Why | How |
|-----------|-----|-----|
| **Exclude / separately handle federated & SSO logins** | For SAML/IAM Identity Center (SSO) console sessions, MFA is enforced at the **IdP**, and AWS may record `MFAUsed=No` even though the user *did* complete MFA. Firing on those is a false positive that erodes trust in the rule | Exclude IAM Identity Center default roles (`:assumed-role/AWSReservedSSO_`), **and** external SAML federation (`userIdentity.type: SAMLUser`, or sessions from `AssumeRoleWithSAML`), **and** any custom-named permission-set roles your org uses (the default prefix does not catch renamed ones, enumerate yours). Route all of these to a separate, lower-severity rule; treat their MFA posture as an IdP-side control |
| **Split out root** | A non-MFA **root** login is categorically worse than an IAM-user one and warrants P0/critical, not the blended `medium` | Add a rule variant keyed on `userIdentity.type == "Root"` at `level: critical` |
| **Add failed-login / brute-force coverage** | The success rule misses the brute force that precedes a successful non-MFA login | A companion rule on `ConsoleLogin == "Failure"` counted per user / per source IP over a window |
| **Allowlist-aware, not blanket** | `level: medium` on every non-MFA login (including known-exempt service accounts) causes fatigue | Suppress allowlisted exempt identities; keep non-allowlisted at `high`, root at `critical` |
| Resolve stale header/TODO if present | Hygiene | The header here already targets the canonical signal, leave as-is |

**Recommended additions (the shipped success rule stays):**

```yaml
# P0 variant: root console login without MFA
title: Root console login without MFA
id: 8e2c1f47-9a05-4b63-8d12-6f3a0c7b9e24
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'signin.amazonaws.com'
    eventName: 'ConsoleLogin'
    userIdentity.type: 'Root'
    additionalEventData.MFAUsed: 'No'
  success:
    responseElements.ConsoleLogin: 'Success'
  condition: selection and success
level: critical
```

To the shipped IAM-user rule, add an SSO/federated exclusion so it does not fire
on compliant IdP-MFA sessions:

```yaml
  # add to the shipped rule's detection block
  federated:
    userIdentity.arn|contains: ':assumed-role/AWSReservedSSO_'
  condition: selection and success and not federated
```

**On the login-result field:** `responseElements.ConsoleLogin` is `Success` or
`Failure`; `additionalEventData.MFAUsed` is `Yes` / `No`. Match these exact
strings. (KQL note: parse `AdditionalEventData`/`ResponseElements` with
`parse_json` and compare with `==`, do **not** use `has`, which is whole-term
and unreliable for these values.)

---

### Key Investigation Queries

> `ConsoleLogin` events are global, query **`us-east-1`**. CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

#### Query 1: Find the non-MFA console login(s) and the identity/source

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"   # ConsoleLogin is a global (signin.amazonaws.com) event

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime,
     identity: .userIdentity.arn,
     type: .userIdentity.type,
     user: (.userIdentity.userName // .userIdentity.arn),
     mfa: .additionalEventData.MFAUsed,
     result: .responseElements.ConsoleLogin,
     # SSO/federated sessions enforce MFA at the IdP: MFAUsed=No there is not the same signal
     federated: ((.userIdentity.arn // "") | test("assumed-role/AWSReservedSSO_")),
     sourceIP: .sourceIPAddress,
     userAgent: .userAgent}' | \
  jq -s 'sort_by(.time)'
```

Prioritise rows where `mfa == "No"`, `result == "Success"`, `federated == false`.
`type == "Root"` is P0. Note the `sourceIP` and `userAgent`, an unfamiliar IP/UA
for the user is the compromise signal.

**If `type == "Root"`, skip Query 2-4 and go to Containment Step 3.** Root
`ConsoleLogin` events have no `userName`, so `SUSPECT_USER` and the
`userName`-filtered Queries 2-4 do not apply, root is handled separately (it
can't be contained by IAM policy). Queries 2-4 and `SUSPECT_USER` are for
**IAM-user** identities only.

#### Query 2: Was this login from an anomalous location, and what came before?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
BASELINE_START=$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30d +%Y-%m-%dT%H:%M:%SZ)
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SUSPECT_USER="<iam-username-from-Query-1>"
SUSPECT_IP="<source-ip-from-Query-1>"

# All console logins for this user: establish their baseline IPs vs the suspect one
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "$BASELINE_START" \
  --region "$REGION" --output json | \
  jq -r --arg u "$SUSPECT_USER" '.Events[].CloudTrailEvent | fromjson |
    select((.userIdentity.userName // "") == $u) |
    {time: .eventTime, ip: .sourceIPAddress, mfa: .additionalEventData.MFAUsed,
     result: .responseElements.ConsoleLogin}' | \
  jq -s 'group_by(.ip) | map({ip: .[0].ip, logins: length,
         first: (min_by(.time).time), last: (max_by(.time).time)}) | sort_by(-.logins)'

# Failed logins from the suspect IP (brute force preceding success?)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r --arg ip "$SUSPECT_IP" '.Events[].CloudTrailEvent | fromjson |
    select(.sourceIPAddress == $ip) |
    {time: .eventTime, user: (.userIdentity.userName // .userIdentity.arn),
     result: .responseElements.ConsoleLogin}' | \
  jq -s 'sort_by(.time)'
```

A `sourceIP` that never appears in the 30-day baseline, or a run of `Failure`
before the `Success`, elevates this to likely credential compromise.

#### Query 3: What did the session do after login?

The login is entry; the damage is what followed. Reconstruct the user's actions.

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SUSPECT_USER="<iam-username-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$SUSPECT_USER" \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

(For an IAM *user* the `Username` lookup attribute is the user name and works
directly, unlike assumed-role sessions, where it is the session name.) Flag
privilege changes, new credentials (`CreateAccessKey`, `CreateLoginProfile`),
persistence, and data access.

#### Query 4: Confirm the user's MFA state (the control gap)

```bash
SUSPECT_USER="<iam-username-from-Query-1>"

aws iam list-mfa-devices --user-name "$SUSPECT_USER" \
  --query 'MFADevices[].{Serial:SerialNumber,Enabled:EnableDate}' --output table
echo "If empty, the user had NO MFA, a password alone granted console access."
```

#### Query 5 - Account-wide: who else can log in without MFA?

The same gap likely exists for other users. Find every console user without MFA.

```bash
# Users with a console login profile but no MFA device
for U in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam get-login-profile --user-name "$U" >/dev/null 2>&1 || continue   # console access?
  MFA=$(aws iam list-mfa-devices --user-name "$U" --query 'length(MFADevices)' --output text)
  [ "$MFA" = "0" ] && echo "[!] $U has console access and NO MFA"
done

# Root MFA status (critical)
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text | \
  awk '{print ($1==1)?"[OK] Root has MFA":"[!!] ROOT HAS NO MFA, remediate immediately"}'
```

#### Query 6: Multi-region note

`ConsoleLogin` is a global event delivered to `us-east-1`; there is no per-region
sweep to do for the login itself. Do sweep the *post-login actions* (Query 3
pattern) across regions if the session touched regional services.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Treat the login as credential compromise until proven otherwise. Cut console
access, then investigate the session and close the MFA gap.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1: Revoke the user's console password and active sessions

```bash
SUSPECT_USER="<iam-username-from-Query-1>"

# Remove the console login profile (kills password-based console access immediately)
aws iam delete-login-profile --user-name "$SUSPECT_USER" 2>/dev/null && \
  echo "[OK] Console login profile removed for $SUSPECT_USER"

# Invalidate any active sessions / derived credentials by attaching a session-cutoff deny
aws iam put-user-policy --user-name "$SUSPECT_USER" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
      "Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]
  }'
echo "[OK] Session-revocation policy applied to $SUSPECT_USER"
```

Note: `aws:TokenIssueTime` only affects **STS/temporary** credentials (assumed
roles, `GetSessionToken`); it does **not** constrain requests signed with the
user's long-lived access keys, which is why Step 2 disables those separately.
Removing the login profile (above) is what kills the browser console session's
ability to keep working.

#### Step 2: Disable the user's access keys (in case the attacker also made/used them)

```bash
SUSPECT_USER="<iam-username-from-Query-1>"
for K in $(aws iam list-access-keys --user-name "$SUSPECT_USER" \
    --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
  aws iam update-access-key --user-name "$SUSPECT_USER" --access-key-id "$K" --status Inactive
  echo "[OK] Disabled key $K for $SUSPECT_USER"
done
```

#### Step 3: If root logged in without MFA, escalate immediately

```bash
# Root cannot be "contained" by IAM policy. If Query 1 showed a root non-MFA login:
echo "[!!] ROOT non-MFA login: rotate the root password NOW, enable root MFA, and"
echo "     review all root activity. Engage AWS Support if account takeover is suspected."
```

#### Step 4: Undo anything the session changed (from Query 3)

If Query 3 showed the session creating access keys, users, login profiles, or
policy changes, reverse them per the relevant persistence playbook (backdoor
user/role, login profile, etc.) before closing containment.

---

## 4. Eradication

### Remove Attacker Access and Close the Gap

#### Rotate the user's credentials and re-issue with MFA required

```bash
SUSPECT_USER="<iam-username-from-Query-1>"

# Delete disabled keys (evidence preserved in CloudTrail) and re-create only if needed
for K in $(aws iam list-access-keys --user-name "$SUSPECT_USER" \
    --query 'AccessKeyMetadata[?Status==`Inactive`].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name "$SUSPECT_USER" --access-key-id "$K"
  echo "[OK] Deleted compromised key $K"
done

# Re-issue a console password with reset-required, to be paired with MFA enrolment
aws iam create-login-profile --user-name "$SUSPECT_USER" \
  --password "$(aws secretsmanager get-random-password --password-length 32 \
    --require-each-included-type --query 'RandomPassword' --output text)" \
  --password-reset-required 2>/dev/null && \
  echo "[OK] New console password set (reset required); enrol MFA before use"
```

#### Enforce MFA so a password is never sufficient again (the root cause)

```bash
# Attach a policy that DENIES all actions unless MFA is present, to the console-user group.
# This is the durable fix: it makes non-MFA sessions useless even with a valid password.
cat <<'JSON'
{
  "Version":"2012-10-17",
  "Statement":[{
    "Sid":"DenyAllExceptSelfManageMFAWithoutMFA",
    "Effect":"Deny",
    "NotAction":["iam:CreateVirtualMFADevice","iam:EnableMFADevice","iam:ListMFADevices",
                 "iam:ListVirtualMFADevices","iam:ResyncMFADevice","iam:DeactivateMFADevice",
                 "iam:DeleteVirtualMFADevice","iam:GetUser","iam:ChangePassword","sts:GetSessionToken"],
    "Resource":"*",
    "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}
  }]
}
JSON
echo "Attach the above to the console-users group so no action works without MFA."
```

#### Remediate every other non-MFA console user (from Query 5)

Enrol MFA (or remove console access) for each user Query 5 flagged, and ensure
root has MFA. Do not close the incident with the same gap open on other users.

#### Remove emergency policy once the account is clean

```bash
SUSPECT_USER="<iam-username-from-Query-1>"
aws iam delete-user-policy --user-name "$SUSPECT_USER" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policy removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the user now requires MFA and has no stale credentials

```bash
SUSPECT_USER="<iam-username-from-Query-1>"

MFA=$(aws iam list-mfa-devices --user-name "$SUSPECT_USER" --query 'length(MFADevices)' --output text)
[ "$MFA" != "0" ] && echo "[OK] $SUSPECT_USER now has an MFA device" \
                  || echo "[FAIL] $SUSPECT_USER still has no MFA, enrol before restoring access"

ACTIVE=$(aws iam list-access-keys --user-name "$SUSPECT_USER" \
  --query 'AccessKeyMetadata[?Status==`Active`]' --output text)
[ -z "$ACTIVE" ] && echo "[OK] No unexpected active keys" || echo "[i] Active keys present, confirm they are the re-issued ones"
```

#### Verify no further non-MFA logins since containment

```bash
REGION="us-east-1"
SUSPECT_USER="<iam-username-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg u "$SUSPECT_USER" '.Events[].CloudTrailEvent | fromjson |
    select((.userIdentity.userName // "") == $u) |
    select(.additionalEventData.MFAUsed == "No" and .responseElements.ConsoleLogin == "Success") |
    .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No non-MFA logins for $SUSPECT_USER since containment" \
                   || echo "[FAIL] $COUNT non-MFA logins after containment, access not fully cut"
```

#### Verify account-wide MFA posture

```bash
# No console user should lack MFA; root must have MFA
REMAINING=$(for U in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam get-login-profile --user-name "$U" >/dev/null 2>&1 || continue
  MFA=$(aws iam list-mfa-devices --user-name "$U" --query 'length(MFADevices)' --output text)
  [ "$MFA" = "0" ] && echo "$U"
done)
[ -z "$REMAINING" ] && echo "[OK] All console users have MFA" || echo "[FAIL] Still without MFA: $REMAINING"

aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text | \
  awk '{print ($1==1)?"[OK] Root MFA enabled":"[FAIL] Root still has no MFA"}'
```

#### Confirm the detection fires

```bash
echo "Re-run/replay a non-MFA ConsoleLogin for a test user and confirm the shipped"
echo "rule fires ONE alert (MFAUsed=No, Success), that the root variant is P0/critical,"
echo "and that a compliant AWSReservedSSO login does NOT false-positive."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A password alone granted full console access | MFA not enforced for the user; no `aws:MultiFactorAuthPresent` deny policy |
| Credential compromise possible | The user's password was obtainable (phishing, reuse, leak) and nothing else was required |
| Account-wide exposure | Other console users / root also lacked MFA (Query 5), a systemic gap, not one user |
| Detection existed but coverage was partial | The shipped rule correctly caught IAM-user non-MFA logins but had no root variant, no SSO false-positive handling, and no brute-force companion |

### Recommended Guardrails

**Enforce MFA everywhere (the primary control)**
- Attach the `aws:MultiFactorAuthPresent = false` deny policy to all console users so a non-MFA session can do nothing but enrol MFA
- Enable MFA on **root** and remove/rotate root access keys; use root only for the few tasks that require it
- Prefer **IAM Identity Center (SSO) with enforced MFA** over long-lived IAM users with passwords, it centralises MFA at the IdP and removes standing console passwords

**Standing compliance**
- AWS Config `iam-user-mfa-enabled`, `mfa-enabled-for-iam-console-access`, and `root-account-mfa-enabled` rules, alarmed on non-compliant
- Periodic Credential Report review for `mfa_active = false` on any console user

**Detection improvements (extend the good shipped rule)**
- Keep the shipped IAM-user `MFAUsed=No` `Success` rule; **add** the root-login P0 variant and the SSO/federated exclusion
- Add a `ConsoleLogin=Failure` brute-force companion (per user / per source IP)
- Add geo/impossible-travel enrichment on successful logins

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1078.004 - Valid Accounts: Cloud Accounts |
| MITRE tactic | Initial Access (TA0001) |
| Signal event | `ConsoleLogin` (`eventSource: signin.amazonaws.com`) with `additionalEventData.MFAUsed = "No"` and `responseElements.ConsoleLogin = "Success"` |
| Event location | Global service → events land in **`us-east-1`** |
| Shipped-rule status | **Good**, correctly scoped and filtered; extend with root variant + SSO exclusion + brute-force companion (do not replace) |
| Key false positive | SAML/SSO (`AWSReservedSSO_`) logins where MFA is enforced at the IdP but `MFAUsed` reads `No` |
| Highest-severity variant | Root `ConsoleLogin` with `MFAUsed=No` → P0/critical |
| Emulation note | The script does not perform a real browser login; it verifies the user has no MFA and documents the `ConsoleLogin` signal |
| Resources created | 1 IAM user with a console login profile and no MFA |
| Follow-on to watch for | Post-login privilege escalation, credential creation, persistence (`CreateAccessKey`/`CreateLoginProfile`), data access |

### Revert

`pulumi destroy` in `infra/` removes the IAM user and its login profile. The
emulation performs no real login and creates no attacker artifacts, so a normal
run self-cleans. After a **real** incident, `pulumi destroy` is irrelevant, the
response is to cut the compromised user's console access (§3), reverse anything
the session did, and, the durable fix, enforce MFA account-wide (§4) so a
stolen password is never again sufficient for console access.
