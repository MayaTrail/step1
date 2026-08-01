# Detection Note — T1136.003 (Create IAM User with Console Access)

**Signal:** `iam:CreateUser` followed by `iam:CreateLoginProfile` — a net-new
console-enabled user created outside the normal provisioning pipeline.

**The discriminator is a console PASSWORD** — not an access key, not an admin
policy. That distinguishes this from its siblings: the backdoor here is
interactive console access, so the "was it used?" pivot is **`ConsoleLogin`**,
not access-key activity.

## The original rule was signal-inverted

It matched `CreateUser`, `CreateLoginProfile`, `DeleteLoginProfile` and
`DeleteUser` with a bare `condition: selection`. Beyond firing on every
onboarding, bundling the `Delete*` events meant a **deletion** — the opposite
of persistence — raised the same alert as a backdoor. Those events are kept
here only for the forensic timeline (was the backdoor cleaned up, and when),
never as alerting conditions.

## Honest severity

**A console user with no policy attached is powerless.** The emulation attaches
nothing, so as-emulated this is genuinely **Medium** — which matches the
manifest, unusually for this set.

It escalates to **High** when a privilege grant accompanies it —
`AttachUserPolicy`, `PutUserPolicy`, or `AddUserToGroup` on the same user. That
pairing is what turns an empty account into a usable identity, and it has its
own `critical` correlation here.

This is why the queries group by **target user** rather than by caller: the
privilege grant may come from a different principal than the one that created
the profile.

## Field details

Nested response paths — the flat forms return `null`:

```
CreateUser         -> responseElements.user.userName
CreateLoginProfile -> responseElements.loginProfile.userName
```

**`passwordResetRequired: false`** is a *supporting* discriminator only. An
attacker sets it so the victim account does not force a password change on
first use — but some legitimate flows also set it false. It colours the triage;
it must never gate a containment action on its own.

**Containment:** you cannot "disable" a login profile — `delete-login-profile`
is the action. There is no intermediate state.

**Account-wide sweep** for profiles created before logging: use the **IAM
credential report** (`password_enabled`, `mfa_active` columns), not Access
Analyzer — Access Analyzer covers resource-policy external access, not console
passwords.

**On the MFA guardrail — a mechanism that is easy to get backwards:** an SCP
using `BoolIfExists` on `aws:MultiFactorAuthPresent` treats an **absent** key as
**matching**, so the deny **does** fire against password-only console users.
The clause that excludes role sessions is the `PrincipalArn` condition, not the
`IfExists` operator.

**Error strings:** IAM denials surface as `AccessDenied` /
`AccessDeniedException`. Not `Client.`-prefixed like EC2.

**Console sign-in is global** and recorded in **us-east-1** — a region-filtered
hunt for the follow-on login returns nothing.

**MITRE:** T1136.003 (*Create Account: Cloud Account*) is precise. The manifest
technique *name* is the upstream label rather than the canonical MITRE name —
cosmetic only.

**Severity:** manifest MEDIUM = IR view Medium as emulated; High with a
privilege grant.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1136_003.yml` — five documents: `CreateLoginProfile` by
  non-identity-admin (`high`), the `CreateUser` base rule (`low`), the
  create-console-user sequence (`high`), the **escalation** correlation pairing
  console access with a privilege grant (`critical`), and its grant base rule
  (`low`). All are inlined here so the correlations are deploy-complete.
- `kql_t1136_003.kql` — target-user-centric query with escalation verdicts and
  the `ConsoleLogin` follow-on pivot.

Full response procedure is in `../PLAYBOOK.md`.
