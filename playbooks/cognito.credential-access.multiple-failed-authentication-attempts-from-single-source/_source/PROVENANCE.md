# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | One alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Threshold | Group-by | Source MITRE label |
|-------|----------|------|-----------|----------|--------------------|
| Multiple Failed Authentication Attempts From Single Source IP | P3 | volume | 15 in 10m | `source_ip` | T1110/TA0006 |

## Merge assessment — **no merge**

The candidate is
`../../cognito.credential-access.multiple-failed-administrative-authentication-attempts/`, and it is
a serious candidate: both rules count failed Cognito authentications, both match the same two
error codes, both group by source IP, both are P3, and the register maps both to `t1110`. The
tempting reading is that they are one observable at two thresholds, separated only by whether the
target account is an administrator.

**That reading is wrong on the facts.** `AdminInitiateAuth` authenticates an ordinary end user on
a server's behalf — nothing about its *target* is administrative. What is administrative is the
*caller*. Both merge tests from `07-TIERS.md` were applied and both fail.

### Test 1 — same observable, same response, differing only in threshold or priority

**The observable is different.** Two APIs with opposite authorization models, documented by AWS in
opposite terms:

- `InitiateAuth`: *"Amazon Cognito doesn't evaluate AWS Identity and Access Management (IAM)
  policies in requests for this API operation. For this operation, you can't use IAM credentials
  to authorize requests, and you can't grant IAM permissions in policies."*
- `AdminInitiateAuth`: *"Amazon Cognito evaluates AWS Identity and Access Management (IAM)
  policies in requests for this API operation. For this operation, you must use IAM credentials
  to authorize requests."*

So there is no calling principal on this side and always one on the other. The `AuthFlow` enums
are disjoint where it matters — AWS states `ADMIN_USER_PASSWORD_AUTH` and `ADMIN_NO_SRP_AUTH`
*"isn't valid for InitiateAuth"*, and `USER_PASSWORD_AUTH` *"isn't valid for AdminInitiateAuth"* —
so a merged rule matching both event names and both flow sets would be matching combinations that
cannot occur. And the group-by keys are not a stylistic difference: the sibling can group by
`userIdentity.arn` because it has one, and this rule cannot.

**The response is different, and that is what decided it.** The two use cases have **no
containment lever in common**:

| | This use case | The IAM-authorized sibling |
|---|---|---|
| Who is contained | Nobody — there is no principal. The address is blocked at AWS WAF and the affected accounts are signed out and reset | An AWS principal — deny the IAM action, revoke sessions, disable access keys |
| Does an IAM deny help | **No.** AWS states IAM is not evaluated for this API. A deny policy is a documented no-op | Yes — it is the entire containment |
| Does AWS WAF help | **Yes.** WAF's documented scope is *"public API operations… that don't use AWS credentials to authorize"*, naming `InitiateAuth`, `RespondToAuthChallenge` and `GetUser`. A block surfaces as `ForbiddenException` | **No.** `AdminInitiateAuth` is IAM-authorized and is excluded from WAF inspection by definition |
| Blast radius | The user pool | The user pool **plus** whatever else the compromised AWS credential reaches |
| Severity | Medium — a public API on the internet is scanned continuously | High — the account boundary was already crossed before the alert fired |

A merged playbook would have to instruct a responder to apply an IAM deny that AWS documents as
having no effect on half its triggers, and a WAF rule that AWS documents as not inspecting the
other half. That is the definition of a different response, and it is the half of the merge test
that carries the most weight.

### Test 2 — a FLOW rule composed of building blocks already shipped

Does not apply. Neither rule is a flow or a correlation over other rules.

**Verdict: two use cases, two playbooks**, cross-referenced in both directions — in each
Classification block, in both detection notes, and in both KQL files — because the same two
structural traps apply to both and are explained once on each side with a pointer to the other.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../cognito.credential-access.multiple-failed-administrative-authentication-attempts/` | **Separate** — see above |
| the risk-configuration use case (not in this set) | **Separate.** Threat protection's automatic responses being set to no-action is a defence-evasion precursor with its own observable (`SetRiskConfiguration`) and its own response (restore the configuration). It is cross-referenced from §4 here as a control to turn back on, not absorbed |
| the non-SRP app-client use case (not in this set) | **Separate.** Enabling `ALLOW_USER_PASSWORD_AUTH` is what puts a plaintext password into the `InitiateAuth` call; that use case is the misconfiguration and this one is its exploitation. Different observable, different response |

## Threshold and window, as inherited — and the arithmetic that makes it a defect

Retained at **15 in 10 minutes**, and the extract records both verbatim. Retaining the number is
not the same as endorsing it, and the finding recorded in `../PLAYBOOK.md` §2 is arithmetic rather
than judgement.

AWS locks a user out after five failed password attempts for `2^(n-5)` seconds, and attempts made
during a lockout return a `Password attempts exceeded` exception the source rule does not match.
Accumulating **fifteen counted failures against one account** therefore requires waiting out
2⁰+2¹+…+2⁹ = 1,023 seconds — over seventeen minutes, outside the rule's own ten-minute window. A
sustained single-account brute force **cannot fire this rule at all**. Fifteen is an implicit
multi-account threshold that the rule never states and never verifies, because it does not count
accounts.

The shipped rules keep the number and fix what makes it unreachable: the base rule OR-s the
lockout form in, so the single-account case counts; a second correlation treats sustained lockouts
as an availability attack in their own right at a threshold of ten; and both use `gte`, never `gt`
(F6). The tuning basis is written into `../detections/sigma_t1110_003.yml` in prose, including the
warning that on a consumer-facing pool behind carrier NAT this threshold is ordinary traffic and
must be paired with an egress allowlist rather than raised.

The group-by is retained as `sourceIPAddress` — it is the only actor identifier that exists on
this API — and its inadequacy is recorded as a defect rather than inherited silently.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction (workflow
step 0) deliberately, for the reason given in the authoring brief: the originals are packaged in a
proprietary format whose scaffolding — payload field lists, entity labels, product-specific field
prefixes, internal enums and packaging metadata — identifies the source on sight while bearing on
nothing about whether the rules are correct. What is retained is the complete detection logic:
name, priority, type, MITRE label, the query verbatim, threshold, window and group-by.

No MITRE substitution was needed: the source's structured label is `T1110/TA0006`, and T1110 is
live. `../PLAYBOOK.md` §6 refines it to a sub-technique and adds a second mapping; the reasoning
is there, not here.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation only
— a deployed rule travels outside the organisation that wrote it, and an internal path is not
resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
