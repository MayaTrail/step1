# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | Both key-disable alerts — the per-event one and its volume variant |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| KMS Key Disabled | P4 | per-event | T1486/TA0040 |
| Multiple KMS Keys Disabled | P3 | volume, threshold 5 in 10m | T1486/TA0040 |

## Merge decision — merge test 1

These two source rules ship as **one playbook**, under **`07-TIERS.md` §"When merging is
legitimate", test 1: *same observable, same response, differing only in threshold or
priority***.

**Same observable.** The extract is the evidence: both rules carry the byte-identical query
`eventSource:"kms.amazonaws.com"  AND eventName:"disablekey"` — including the same doubled
space and the same lower-cased event name — and the same MITRE label. Nothing in the volume
rule inspects a field the per-event rule does not.

**Same response, and this is what actually decided it.** `DisableKey` is completely
reversible: `EnableKey` restores the key with no data loss, no re-encryption, no clock and no
irreversible step anywhere in the procedure. Containment is the same two commands at one key
and at fifty — `enable-key`, then deny the principal `kms:DisableKey` — run once or run in a
loop. Eradication is the same sweep. Recovery is the same key-state assertion. Residual risk
is the same: the operations refused during the window have already failed and `EnableKey`
does not replay them. Volume changes the urgency and the size of the work-list, not one step
of the procedure, so it belongs in §2's trigger table as a second row at its own priority —
which is exactly what test 1 prescribes.

`Multiple KMS Keys Disabled` therefore has **no directory of its own**. It is the P0 row in §2
and the `value_count` correlation document in `../detections/sigma_t1489.yml`, retuned from
the source's five keys to three with the tuning basis stated in the rule.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../kms.impact.kms-key-scheduled-deletion/` | **Separate**, and deliberately so — this was the closest merge call in the service. Same service, same principal, same one-line call shape, and both are "the key stops working". But `ScheduleKeyDeletion` starts a 7–30 day clock after which the key, its material and all its metadata are deleted and every ciphertext under it is permanently unrecoverable. That gives the deletion sibling a deadline-bound containment (`CancelKeyDeletion`), an ordering constraint this playbook does not have (the cancel returns the key to `Disabled`, so `EnableKey` must follow it and fails if it precedes it), and a residual risk that includes permanent data loss. Different containment, different recovery ordering, different residual risk — test 1's own exclusion applies |
| `../../kms.impact.multiple-kms-keys-scheduled-deletion/` | **Separate**, for the same reason and one more: at volume the containment work-list comes from a live `list-keys`/`describe-key` state sweep rather than from the alerting events, because the alert fires at its threshold while the actor's set is unbounded |
| `../../kms.impact.key-created/` | **Separate.** Opposite direction, no impact at the moment of the event, and the response is investigative rather than restorative |

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals are
packaged in a proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata — identifies the source
on sight while bearing on nothing about whether the rules are correct. What is retained is the
complete detection logic: name, priority, type, MITRE label, the query verbatim, threshold,
window and group-by.

No substitution was applied to these two extracts. Both label themselves `T1486/TA0040`; T1486
and TA0040 are both live as of the currency check on 2026-08-29, so they are written verbatim.
The mapping is nonetheless disputed on the merits — see the mapping note in
`../detections/detection_note_t1489.md`.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal path is
not resolvable to whoever receives it.

**Merge test — applied, not assumed. Two source rules, one use case.** `KMS Key Disabled` is the
single-event rule and `Multiple KMS Keys Disabled` is a volume rule over the same event — a base
rule and a correlation, which is the structure authoring rule **B1** requires. The response to one
disabled key and to many is the same procedure at different scale, so splitting them would duplicate
it to vary a threshold.

**Tier:** 1, on criterion 3 of `07-TIERS.md` — *the blast radius is not in the event*.
