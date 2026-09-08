# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels; sequence alerts expressed as multi-stage flows referencing component alerts by internal ID |
| Scope captured | One flow alert and the two component alerts its stages reference |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| User Pool Deletion Protection Disabled Followed by User Pool Deletion | P1 | flow, 2 stages, 30-minute second stage, grouped by `requestParameters.userPoolId` | T1485/TA0040 |
| User Pool Deletion Protection Disabled | P3 | per-event (threshold 0 in 10m) | T1485/TA0040 |
| User Pool Deletion Detected | P3 | per-event (threshold 0 in 10m) | T1485/TA0040 |

## Why three alerts appear in the extract for one use case

**This directory is one use case: the flow alert.** The other two are its **stage
components**, and they are reproduced because the flow alert is otherwise unauditable — in
the source format its stages reference component alerts by bare internal ID (`12` then `5`)
and carry no query of their own. Without the components, the `Detection Rule Quality Notes`
table in `../PLAYBOOK.md` would be asserting things about logic that is not in the extract.

**They are not merged into this use case.** Both are separately registered use cases in the
corpus register, at their own priority, with their own directories:
`../` and
the user-pool deletion use case (not in this set). Neither is authored here and neither
directory is created by this work.

## Merge assessment — **no merge**

`07-TIERS.md` §"When merging is legitimate" offers two tests. Both were applied.

**Test 1 — same observable, same response, differing only in threshold or priority: fails
on both halves.** The component alerts fire on two different API calls
(`UpdateUserPool` with `deletionProtection` set to `INACTIVE`; `DeleteUserPool`) with
different request shapes and different consequences. The responses diverge completely: a
deletion-protection disable on a pool that still exists is a *pre-incident* — the pool, its
users, its app clients and its passwords are all intact, and the response is to set
`DeletionProtection` back to `ACTIVE` and ask why. Once `DeleteUserPool` has succeeded there
is nothing to re-protect: every user account is gone and, as `../PLAYBOOK.md` §5 and
§Residual Risk record, passwords cannot be exported from Cognito and therefore cannot be
restored. Different containment, different eradication, different residual risk.

**Test 2 — a FLOW rule that is purely the composition of building blocks you are already
shipping, adding no new observable: fails on "no new observable".** The flow adds one that
neither component carries and neither can express: **ordering, bounded, on the same pool.**
Stage 2 must follow stage 1 inside 30 minutes with the same
`requestParameters.userPoolId`. That sequence is the entire thesis of this use case —
deletion protection has no reason to be turned off except to permit a deletion, and AWS
provides no force flag on `DeleteUserPool`, so the disable is a **mandatory** separate
preceding call rather than an incidental one. Neither component sees the other; a disable
alone is ambiguous, a deletion alone may be of a pool that was never protected, and only the
pair is unambiguous intent.

The test's own precondition also does not hold: it applies to a flow over building blocks
"you are already shipping". These components are shipped by other directories in the
register, not by this one, so folding the flow into a playbook that does not exist here
would leave it homeless.

**Verdict: one playbook, this one.** The two component alerts appear in `../PLAYBOOK.md` §2
as their own trigger rows at their own priorities, and in `../detections/sigma_t1485.yml` as
two `low`/`informational` base rules feeding a `temporal_ordered` correlation — which is the
shape `03-DETECTION-STANDARD.md` prescribes for exactly this case.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../` | **Separate.** The pool still exists. Response is to restore the flag and investigate the principal; nothing is lost and nothing needs rebuilding |
| the user-pool deletion use case (not in this set) | **Separate.** A deletion with no preceding disable is either a pool that was never protected — which is the default state, so this is most of them — or a pool whose protection was turned off outside the 30-minute window. Same destruction, materially weaker intent evidence, and a different triage question ("was this a planned decommission?") |
| `../../cognito.impact.identity-pool-deletion-detected/` | **Separate.** A different service surface entirely (`cognito-identity.amazonaws.com`, not `cognito-idp.amazonaws.com`), a different resource, and no deletion-protection concept exists for identity pools — so there is no sequence to detect and the whole thesis of this playbook is inapplicable |

## Threshold and window, as inherited

The flow's second stage carries `timeframeMs: 1800000` — 30 minutes. That is retained in the
shipped correlation and the reasoning is stated in `../detections/sigma_t1485.yml` rather
than inherited silently: the disable and the delete are two calls a scripted actor makes back
to back, so the interval is seconds, and 30 minutes is generous headroom that still excludes
an unrelated decommission days later. The two component alerts are `logs_threshold` with a
threshold of `0.0` over a 10-minute window, which is the source format's way of expressing
"fire on every match" — they are per-event rules, not volume rules, and the extract records
the `0.0` verbatim rather than normalising it away.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata — identifies the
source on sight while bearing on nothing about whether the rules are correct. What is
retained is the complete detection logic: name, priority, type, MITRE label, the query
verbatim, threshold, window, group-by, and for the flow alert its stage structure and
timeframes.

One correction beyond de-identification is recorded here rather than in the extract, because
it concerns a field the extractor does not emit. Its
live replacement is T1685, and it is a **defensible** label for stage 1 alone: deletion
protection is a guardrail and turning it off is the disabling of a control. It is not
defensible for the use case as a whole, whose outcome is destruction. The corrected mapping
and its reasoning are in `../PLAYBOOK.md` §6. The `mitre:` line the extractor does emit
(`T1485/TA0040`) is the source's structured label and is correct.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal path
is not resolvable to whoever receives it.

**Merge test — applied, not assumed. Three source rules, one use case.** `User Pool Deletion
Protection Disabled` and `User Pool Deletion Detected` are the components; the third is the ordered
flow over them. Deletion protection exists specifically to make the second call fail, so disabling
it first is the only way the sequence completes — the pair is the technique and each half alone has
an ordinary reading (a protection toggle during migration, a deletion of a pool that never had
protection).

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.
