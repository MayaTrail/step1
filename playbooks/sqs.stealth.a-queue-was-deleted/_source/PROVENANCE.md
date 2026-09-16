# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | Both queue-deletion alerts — the per-event one and its volume variant |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| A Queue Was Deleted | P3 | per-event | — |
| Excessive Queue Deletion | P3 | volume, threshold 5 in 5m | — |

## Merge decision — merge test 1

These two source rules are shipped as **one playbook**, under
**`07-TIERS.md` §"When merging is legitimate", test 1: *same observable, same response,
differing only in threshold or priority***.

The extract is the evidence. Both rules carry the **byte-identical query** —
`eventSource:"sqs.amazonaws.com" AND eventName:"DeleteQueue" AND NOT _exists_:errorCode` —
the **same priority** (P3) and the **same MITRE label**. The only difference in the entire
pair is that one fires per event and the other requires five inside five minutes. There is
no second observable: nothing in the volume rule inspects a field the per-event rule does
not.

The response test was applied separately and is what actually decided it. `DeleteQueue`
is irreversible at one queue and at fifty: the messages are gone either way, the queue
name is unusable for 60 seconds either way, and the recreate path is the same IaC apply
run once or run in a loop. Containment is identical (deny `sqs:DeleteQueue` to the acting
principal, revoke its sessions), eradication is identical (recreate from source of truth,
restore producer and consumer wiring, right-size the permission), and the residual risk is
identical (in-flight and stored messages are unrecoverable; queue attributes survive only
if they were in IaC). Volume changes the **urgency and the size of the work-list**, not a
single step of the procedure — so it belongs in §2's trigger table as a second row at its
own priority, which is exactly what test 1 prescribes.

`Excessive Queue Deletion` therefore has **no directory of its own**. It is the P1 row in
§2 and the `sqs_queue_deleted_at_volume` correlation document in
`../detections/sigma_t1485.yml`.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../sqs.stealth.a-queue-was-purged/` | **Separate.** `PurgeQueue` destroys the messages and leaves the queue, its policy, its subscriptions and its metrics intact — so the pipeline keeps running and nothing breaks. `DeleteQueue` destroys the container, and every producer and consumer starts erroring. Different blast radius, different eradication (there is nothing to recreate after a purge), different residual risk. Not a volume variant of anything |
| `../../sqs.stealth.excessive-queue-creation/` | **Separate.** Different event, opposite direction, and the response is to *remove* resources rather than restore them |

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

## A finding about the extractor, not about these rules

`Excessive Queue Deletion` is a volume-shaped alert. The shared extractor read only the
threshold-bearing shapes it already knew about and **silently dropped the query, the
threshold and the window** for volume-shaped ones — leaving the extract unauditable for
precisely the rules whose threshold is the thing under dispute. The extractor was fixed
(the shape is now in its lookup chain, and it reads the alternate threshold key), and the
extract above was regenerated. This is the same failure class its own inline comment
records for per-event alerts; it is reported upward rather than left in place.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote it, and
an internal path is not resolvable to whoever receives it.

**Merge test — applied, not assumed. Two source rules, one use case.** `A Queue Was Deleted` is the
single-event rule and `Excessive Queue Deletion` is a volume rule over the same event. That is a
base rule and a correlation over it, which authoring rule **B1** requires be modelled exactly that
way rather than as in-rule aggregation. One deletion and many deletions are the same technique at
two scales, with one response — they differ in severity, not in kind.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
