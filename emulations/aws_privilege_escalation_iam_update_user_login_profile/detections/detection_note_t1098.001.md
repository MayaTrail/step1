# Detection Note: T1098.001 (Backdoor IAM User Console Login via UpdateLoginProfile)

**Signal:** `iam:UpdateLoginProfile`, hijacking an **existing** user's console
password, by a caller outside the help-desk / identity-admin allowlist.

**A single high-signal event.** Unlike its sibling
(`iam_create_user_login_profile`, which creates a *new* console user), this
technique takes over an account that already exists, with whatever privileges
it already has.

## Why the caller is the discriminator

Console **self-service** password change is `iam:ChangePassword`.
`UpdateLoginProfile` is by convention an **administrative** action, someone
resetting *another* user's password. So a non-help-desk caller is high-signal.

One correction to that framing: this is a console **convention**, not an
AWS-enforced invariant. A principal holding broad `iam:UpdateLoginProfile`
*can* target itself, and a self-targeted reset is suspicious in its own right,
it implies an over-broad grant. The queries flag that case separately.

## MFA is the deciding mitigant

**A password reset does not touch the victim's MFA device.** An MFA-enrolled
victim cannot be signed in with the new password alone, so the incident is
contained by a control already in place.

That makes the triage priority unambiguous:

> **Privileged target + no MFA** is the highest-risk intersection. Enrich
> against `iam list-mfa-devices` (or a privileged-user watchlist) and escalate
> that combination first.

## Confirmation

The reset is the alert; the **`ConsoleLogin` by that user within the hour** is
the confirmation of takeover. Both are correlated here, grouped by the **target
user**, not the caller, since the login is performed by the victim identity.

Console sign-in is **global** and recorded in **us-east-1**; a region-filtered
workspace returns nothing for the login half.

`passwordResetRequired: false` is a supporting discriminator only, never gate
containment on it alone.

## Containment

**An explicit Deny on the victim kills an active console session.** Permissions
are evaluated per request rather than cached for the session's lifetime, so the
deny takes effect near-immediately (IAM is eventually consistent, allow a few
seconds). Then reset the password again and enrol MFA. Contain the caller
separately.

**On the MFA guardrail:** an SCP using `BoolIfExists` on
`aws:MultiFactorAuthPresent` treats an **absent** key as **matching**, so the
deny does fire against password-only console users. The clause excluding role
sessions is the `PrincipalArn` condition, not the `IfExists` operator.

**Error strings:** denials surface as `AccessDenied` / `AccessDeniedException`.
Not `Client.`-prefixed like EC2.

**A note on the shipped rule's severity:** its `level` was `medium` while the
manifest severity was **HIGH**, and the manifest was right, which is unusual
in this catalogue. The rule is raised to `high` here, resolving the
inconsistency.

**MITRE:** T1098.001 (*Account Manipulation: Additional Cloud Credentials*) is
a reasonable fit, spanning both Persistence and Privilege Escalation tactics.

**Severity:** manifest HIGH = IR view High.

**GuardDuty:** no finding type specific to this technique.

## Tuning the allowlist

The rule ships `:role/REPLACE-ME-*` placeholders, not defaults. They match
nothing, so an unedited rule has no exclusions at all and alerts on the routine
activity it is supposed to ignore.

Derive the real list from your own trail. The principals that show up
repeatedly, across weeks rather than once, are your automation:

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-90d +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateLoginProfile \
  --start-time "$START" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | .userIdentity.arn' | \
  sort | uniq -c | sort -rn
```

Keep the recurring service and pipeline roles. Leave out anything human unless
it is a documented break-glass path, since a human name on the allowlist is a
standing hole in the rule.

Re-check the list when provisioning changes. A retired pipeline role left in
place is dead weight; a new one missing from it produces the false-positive
wave that gets a rule muted.

**Files here:**
- `sigma_t1098.001.yml`, three documents: the non-help-desk reset (`high`),
  the reset→login correlation (`critical`), and the console-login base rule
  (`low`).
- `kql_t1098.001.kql`, joins resets to subsequent logins with MFA-aware
  verdicts, and flags self-targeted resets.

Full response procedure is in `../PLAYBOOK.md`.
