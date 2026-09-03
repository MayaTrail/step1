# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single queue-attribute-change alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| An SQS Queue Attributes Were Changed | P3 | per-event | T1213/TA0009 |

## Not merged — and this is the one that looks like it should be

`../../sqs.impact.server-side-encryption-for-aws-sqs-queue-was-disabled/` fires on the
**same event name from the same event source**: `SetQueueAttributes`. That is as close to
"same observable" as two rules in this set get, and it was tested against
`07-TIERS.md` §"When merging is legitimate" rather than waved through.

**Test 1 fails on the observable.** The two rules do not differ in threshold or priority —
they differ in *which key of the `Attributes` map carries the change*. One is about
`Policy` and `RedrivePolicy`; the other is about `KmsMasterKeyId` and
`SqsManagedSseEnabled`. The event name is shared, the discriminating field is not, and
`07-TIERS.md` is explicit that sharing a service, an API or a technique is not grounds to
merge.

**Test 1 fails again on the response, which is the part that settles it.** Eradication for
a policy grant is to rewrite the queue policy and then establish, from CloudWatch, whether
anything consumed messages while the grant stood. Eradication for an encryption disable is
to re-enable encryption and then treat every message *written after the disable* as having
been stored unencrypted — a window bounded by a different pair of events, over a different
message population, with a different residual risk. Neither procedure is a superset of the
other. They are two use cases that happen to share an API.

What they do share is the discriminator problem, and both playbooks state it: **the event
name alone cannot say which of the two happened.** Only `requestParameters.attributes.*`
can, which is why neither shipped rule matches on the event name alone.

Test 2 (a correlation that is purely a composition of building blocks already shipped) does
not apply — neither rule is a correlation.

## Cross-references

- `../../sqs.stealth.excessive-queue-creation/` — a queue created by an unfamiliar
  principal and then named as a `RedrivePolicy` target from here is one attack, staged in
  two events. The correlation that links them ships in this directory's Sigma
- `../../sqs.impact.server-side-encryption-for-aws-sqs-queue-was-disabled/` — the sibling
  `SetQueueAttributes` use case
- `../../sqs.stealth.a-queue-was-purged/` — the other way to lose a queue's messages
  without deleting the queue

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
