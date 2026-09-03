# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single queue-creation-volume alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| Excessive Queue Creation | P4 | volume, threshold 5 in 5m | — |

## Not merged

Tested against `../../sqs.stealth.a-queue-was-deleted/` — which merges *its* per-event and
volume rules under test 1 — and kept separate. There is no per-event creation rule in the
source set for it to be the volume variant of, the event is different, and the response
runs in the opposite direction: the work is to identify and **remove** resources the
attacker added, not to restore resources it destroyed. Sharing a service and a volume shape
is not grounds to merge.

## Two mapping defects, one of them auditable here and one of them not

Creating queues
impairs no defence, so the label is wrong on the merits as well as stale.

**Observed during extraction and not auditable from the extract:** the alert's own prose
description names a *different* technique from its machine-readable label — and that one,
`T1531` (*Account Access Removal*), is live but describes locking legitimate users out of
their accounts, which is neither what the rule detects nor what creating a queue does. So
the rule ships two mutually contradictory mappings and both are wrong. The extractor keeps
detection logic and drops prose, so the extract carries only the label; the contradiction is
recorded here because a reviewer diffing the extract cannot otherwise see it. The corrected
mapping and the reasoning behind it are in `../PLAYBOOK.md` §6.

## Cross-references

- `../../sqs.collection.an-sqs-queue-attributes-were-changed/` — the event that gives a
  newly created queue a purpose. A `CreateQueue` followed by a `RedrivePolicy` naming the
  new queue is message diversion, and that correlation ships in the sibling directory

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
