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
| Multiple Failed Administrative Authentication Attempts | P3 | volume | 5 in 10m | `source_ip`, `userIdentity.arn` | T1110/TA0006 |

## Merge assessment — **no merge**, against the obvious candidate

The obvious candidate is
`../../cognito.credential-access.multiple-failed-authentication-attempts-from-single-source/`.
The two look like one rule at two thresholds: both count failed Cognito authentications, both
match the same two error codes, both group by source IP, and the register maps both to `t1110`.
The tempting reading is that they are the same observable distinguished only by whether the
target is an administrator, and that a merged playbook would carry two rows at two priorities.

**That reading is wrong on the facts, and the difference is not the target — it is the caller.**
`AdminInitiateAuth` authenticates an ordinary end user on a server's behalf; nothing about the
*target* is administrative. What is administrative is the *principal making the call*. Both merge
tests were applied and both fail.

### Test 1 — same observable, same response, differing only in threshold or priority

**Fails on the observable.** These are two different APIs with two mutually exclusive
authorization models, documented by AWS in opposite terms:

- `AdminInitiateAuth`: *"Amazon Cognito evaluates AWS Identity and Access Management (IAM)
  policies in requests for this API operation. For this operation, you must use IAM credentials
  to authorize requests."*
- `InitiateAuth`: *"Amazon Cognito doesn't evaluate AWS Identity and Access Management (IAM)
  policies in requests for this API operation. For this operation, you can't use IAM credentials
  to authorize requests, and you can't grant IAM permissions in policies."*

So every event here carries a real `userIdentity.arn` and every event there does not. Their
`AuthFlow` enums are disjoint at exactly the point that matters: AWS states that
`ADMIN_USER_PASSWORD_AUTH` and `ADMIN_NO_SRP_AUTH` *"isn't valid for InitiateAuth"*, and that
`USER_PASSWORD_AUTH` *"isn't valid for AdminInitiateAuth"*. A single rule cannot match both event
names and both flow sets without matching combinations that cannot exist.

**Fails harder on the response, which is what actually decided it.** The two use cases have **no
containment lever in common**:

| | This use case | The unauthenticated sibling |
|---|---|---|
| Who is contained | An AWS principal — deny the IAM action, revoke sessions, disable keys | Nobody. There is no principal. Containment is WAF, per-client flow removal and per-user reset |
| Does AWS WAF help | **No.** WAF's documented scope is *"public API operations… that don't use AWS credentials to authorize"* — `AdminInitiateAuth` is excluded by definition | **Yes.** WAF is the primary rate-limiting control, and a block surfaces as `ForbiddenException` |
| Does an IAM deny help | Yes — it is the whole containment | **No.** IAM is not evaluated for this API at all; a deny policy is a no-op |
| Blast radius | Whatever else the compromised AWS credential can reach | The user pool only |

A merged playbook would have to tell a responder to apply an IAM deny that is documented as
having no effect on half its triggers, or a WAF rule that is documented as not inspecting the
other half. That is the definition of a different response.

### Test 2 — a FLOW rule composed of building blocks already shipped

Does not apply. Neither rule is a flow or a correlation over other rules; both are volume
thresholds over a single event shape.

**Verdict: two use cases, two playbooks.** They are cross-referenced in both directions — in
`../PLAYBOOK.md`'s Classification block, in both detection notes, and in the KQL — because the
same two structural traps (the SRP failure landing on the Respond call, and
`PreventUserExistenceErrors` suppressing the enumeration error code) apply to both and should be
explained once and pointed at twice.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../cognito.credential-access.multiple-failed-authentication-attempts-from-single-source/` | **Separate** — see above |
| the non-SRP app-client use case (not in this set) | **Separate**, and a genuine precondition rather than a variant. Enabling `ALLOW_ADMIN_USER_PASSWORD_AUTH` is what makes a password failure land on `AdminInitiateAuth` at all; that use case is the misconfiguration, this one is its exploitation. Different observable, different response (remove a flow from an app client versus contain a principal), and this playbook's §4 cites it rather than absorbing it |
| the risk-configuration use case (not in this set) | **Separate.** That one covers an actor disabling threat protection's automatic responses; it is a defence-evasion precursor with its own containment. Related enough to cross-reference, not enough to merge |

## Threshold and window, as inherited

Retained at **5 in 10 minutes**, and the extract records both verbatim. The threshold is kept but
its justification is replaced: the source gives none, and the defensible basis is that AWS locks a
user out after exactly **five** failed password attempts and doubles the lockout from there, so
five is the count at which a real account's state has already changed. The shipped correlation
uses `gte: 5`, never `gt`, so a run that stops at exactly five does not fall through the rule
written to catch it (F6). The tuning basis is stated in prose in
`../detections/sigma_t1110_001.yml` so a deployer can adjust it knowingly.

The group-by is retained as `(userIdentity.arn, sourceIPAddress)` and its **gap** is recorded as a
defect rather than inherited: it never counts the target account, so guessing and spraying arrive
as the same alert. The correction lives in `../detections/kql_t1110_001.kql`, which counts
distinct subs, because Sigma has no distinct-value count over a correlation group.

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
live. `../PLAYBOOK.md` §6 refines it to the sub-technique and adds the second mapping the source
omits; the reasoning is there, not here.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation only
— a deployed rule travels outside the organisation that wrote it, and an internal path is not
resolvable to whoever receives it.

**Tier:** 1, on criterion 2 of `07-TIERS.md` — *the response has ordering that can go wrong*.
