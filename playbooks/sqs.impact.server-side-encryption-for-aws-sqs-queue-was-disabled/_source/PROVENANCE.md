# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single encryption-disable alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| Server-Side Encryption for AWS SQS Queue Was Disabled | P4 | per-event | T1565/TA0040 |

## Not merged

Shares its event name — `SetQueueAttributes` — with
`../../sqs.collection.an-sqs-queue-attributes-were-changed/`, and the merge test was
applied and failed on both limbs. The reasoning is written out once, in that directory's
`PROVENANCE.md` §"Not merged"; the short form is that the two rules discriminate on
different keys of the same `Attributes` map and their eradication procedures are not
supersets of one another.

## Two things about this rule that the extract makes checkable

The query is the only one in the SQS set that inspects a **request field** rather than just
an event name, which makes it the strongest rule of the six as written — and it still has
two defects that are visible in the extract without any AWS knowledge:

1. It matches `eventName:"setqueueattributes"`, **lower-case**, where every sibling rule in
   the same pack matches `eventName:"SetQueueAttributes"`. The five other SQS rules are
   internally consistent on casing and this one is not.
2. It requires `requestParameters.attributes.KmsMasterKeyId` to be present-and-empty. A
   call that disables SSE-SQS instead of SSE-KMS does not carry that key at all, so the
   condition cannot be met and the rule cannot fire on that path.

Both are analysed with their consequences in `../PLAYBOOK.md` §2.

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

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.
