# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single queue-purge alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| A Queue Was Purged | P3 | per-event | T1578/TA0005 |

## Not merged

Tested against `../../sqs.stealth.a-queue-was-deleted/` — which *is* itself a merge of two
source rules — and kept separate. Both destroy messages, so test 1's "same observable" is
superficially arguable, but it fails on both limbs. The observable differs: `PurgeQueue`
and `DeleteQueue` are different APIs producing different events, and the volume-variant
relationship that justified the deletion merge does not exist here. The response differs
more sharply still: after a delete there is a queue to recreate, producers and consumers to
repoint, and a 60-second name-reuse constraint to sequence around; after a purge the queue
is untouched and there is nothing to rebuild — the entire response is evidence
reconstruction and principal containment, because the only thing that changed is that the
messages are gone.

That asymmetry is also why this one is the quieter incident of the two, and why its P3 is
arguably the worst-calibrated priority in the SQS set: a delete breaks every consumer
within a minute and pages someone regardless of the alert; a purge breaks nothing and is
invisible outside this event.

## Cross-references

- `../../sqs.stealth.a-queue-was-deleted/` — the destructive sibling that also removes the
  container
- `../../sqs.collection.an-sqs-queue-attributes-were-changed/` — reducing
  `MessageRetentionPeriod` is a **third** way to destroy messages, and it is neither a
  purge nor a delete

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding — payload field lists, entity
labels, product-specific field prefixes, internal enums and packaging metadata —
identifies the source on sight while bearing on nothing about whether the rules are
correct. What is retained is the complete detection logic: name, priority, type, MITRE
label, the query verbatim, threshold, window and group-by. Every claim in the "Detection
Rule Quality Notes" table in `../PLAYBOOK.md` §2 is checkable against it.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS
documentation only — a deployed rule travels outside the organisation that wrote it, and
an internal path is not resolvable to whoever receives it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
