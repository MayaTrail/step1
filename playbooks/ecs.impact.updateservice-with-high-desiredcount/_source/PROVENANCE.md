# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single high-`desiredCount` alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| UpdateService with High DesiredCount | P3 | per-event | T1496/TA0040 |

## Merge decision — no merge

**One source rule, one playbook.** The source set holds two sibling rules with the **same MITRE
label** (T1496/TA0040) and a similar magnitude shape, so both were tested rather than assumed
apart:

| Candidate | Test 1 — same observable, same response, differing only in threshold? | Test 2 — pure composition of shipped building blocks? | Verdict |
|-----------|------|------|---------|
| `RunTask with High TaskCount` (P4) | **No.** Different event, different field (`requestParameters.count`, not `desiredCount`), and a decisively different **response**: a service maintains its count and replaces stopped tasks, so containment is *reset the count, then stop tasks* and the ordering is load-bearing; `RunTask` launches one-shot tasks that do not respawn, so there is nothing to reset and stopping them is sufficient. Same motive, different procedure | No | **Separate** |
| `RegisterTaskDefinition with Resource-Intensive Parameters` (P4) | **No.** Different event and a different observable — container `cpu`/`memory` magnitude, not task count. It is the *payload* half rather than the multiplier | No | **Separate** |

Sharing the T1496 mapping is explicitly **not** grounds to merge: `07-TIERS.md` states that
sharing a technique is not sufficient, and here the containment procedures genuinely differ.

## A finding about a rule outside this playbook

`RunTask with High TaskCount` matches `requestParameters.count.keyword:/\d{4}/`. AWS documents
`RunTask`'s `count` as *"You can specify up to 10 tasks for each call"*, corroborated by the
service quota *"Tasks launched per run-task — 10 — not adjustable"*. A Lucene `regexp` term is
anchored, so `/\d{4}/` requires exactly four digits. **The rule can therefore never fire**: no
valid `RunTask` carries a four-digit `count`, and an invalid one is rejected before it becomes a
success event. This is reported upward rather than fixed here, because that rule is not in this
batch's scope — but it is the same defect class as the ECS Exec rule's `accountId:"anonymous"`
conjunct, and a `RunTask` loop remains a live route to the outcome this playbook covers.

## Three defects in the rule that IS in scope

Recorded here because the extract is what they are auditable against:

1. `requestParameters.desiredCount.keyword` — a `.keyword` subfield exists only on a
   string-mapped field. AWS documents `desiredCount` as **Type: Integer** and CloudTrail
   serialises it as a JSON number, so under a numeric mapping the clause matches nothing.
2. `/\d{4}/` is anchored, so it means *exactly four digits*. Coverage is `[1000, 5000]` — the
   ceiling because AWS caps "Tasks per service" at 5,000, not adjustable — and the blind spot is
   everything from the service's own baseline up to 999.
3. **No success filter.** Alone among the five ECS rules in this batch, the extract shows this
   one without `NOT _exists_:errorCode`, so a denied scale-out raises the same alert at the same
   priority as a completed one.

The corrected rules split success from denial and replace the regex with a numeric comparison;
the threshold's derivation from AWS quota figures is in `../detections/sigma_t1496_001.yml` and
`../PLAYBOOK.md` §2.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../ecs.stealth.service-is-deleted/` | **Separate**, but note the shared field: `desiredCount: 0` is the destructive direction of the same parameter and the mandatory precursor to deletion. It is shipped as a base rule *there* and *in* `../../ecs.stealth.cluster-is-deleted/`, not here, because this playbook's subject is magnitude upward |
| `../../ecs.stealth.service-is-created/` | **Separate.** Creating a service and scaling an existing one are different events with different blast radii; the created service brings its own image and role, while scaling multiplies whatever was already there |

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding — payload field lists, entity
labels, product-specific field prefixes, internal enums and packaging metadata —
identifies the source on sight while bearing on nothing about whether the rules are
correct. What is retained is the complete detection logic: name, priority, type, MITRE
label, the query verbatim, threshold, window and group-by.

No substitution was needed in this extract.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote it, and
an internal path is not resolvable to whoever receives it.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
