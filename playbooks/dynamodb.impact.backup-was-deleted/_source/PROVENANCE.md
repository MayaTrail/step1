# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The single "Backup Was Deleted" alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alert captured

| Alert | Priority | Type | Source MITRE label |
|-------|----------|------|--------------------|
| Backup Was Deleted | P3 | per-event | T1490/TA0040 |

The MITRE label is **correct**, which is rare in this set and is recorded as such in
`../PLAYBOOK.md` §6 rather than passed over.

## Merge decision — no merge

This use case ships **on its own**. Both merge tests in `07-TIERS.md` §"When merging is
legitimate" were applied and both fail.

**Test 1 — same observable, same response, differing only in threshold or priority.** The only
candidate in the set that touches backups at all is `../../dynamodb.impact.backup-was-listed/`,
and it fails the test on the first clause: `ListBackups` and `DeleteBackup` are different
events with different `readOnly` semantics, and one enumerates while the other destroys. There
is no volume variant of this rule anywhere in the set, so there is nothing for test 1 to merge
in; the `event_count` correlation in `../detections/sigma_t1490.yml` supplies one rather than
inheriting it.

The response test fails independently and decisively. Here the response is to establish what
recovery points survive, restore the PITR posture, and race the 35-day expiry on any
`$DeletedTableBackup`. For the listing use case the response is to determine what the actor
learned and whether they acted on it — no restoration is involved because nothing was destroyed.

**Test 2 — a FLOW/correlation rule that is purely the composition of building blocks already
shipped.** Not applicable: the source rule is a per-event alert, not a flow rule.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../dynamodb.impact.backup-was-listed/` | **Separate.** Enumeration versus destruction. Nothing is restored after a listing, and the two are joined by a correlation in that directory rather than by collapsing them |
| `../../dynamodb.impact.multiple-tables-deleted/` | **Separate.** Different observable and different blast radius — a recovery point is not the live data. The relationship is expressed as the `temporal_ordered` backup-then-table correlation shipped in that directory, which is the correct way to state a sequence |
| `../../dynamodb.stealth.deletion-protection-disabled/` | **Separate.** Also a precondition for unrecoverable destruction, by a different mechanism: that one removes the guard on the operation, this one removes the way back afterwards |

## A gap in the source set, recorded here because it is not a defect in any single rule

Nothing in the set covers `UpdateContinuousBackups`. Disabling point-in-time recovery, or
reducing `RecoveryPeriodInDays` from its default of 35 to 1, destroys far more recovery
capability than deleting any single on-demand backup — and the reduction case leaves PITR
reporting as `ENABLED`, so it passes every check that asks only whether PITR is on. The gap is
carried as a shipped rule in `../detections/sigma_t1490.yml`, with an explicit caveat in that
rule's own comment block: AWS's enumerated list of DynamoDB control-plane operations logged by
default **omits `UpdateContinuousBackups`** while including `DescribeContinuousBackups`. That is
almost certainly a documentation omission, but it was not verifiable against primary
documentation, and shipping an unverified rule silently is the failure this corpus exists to
avoid. The rule tells its deployer to confirm the event in their own trail first.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals are
packaged in a proprietary format whose scaffolding — payload field lists, entity labels,
product-specific field prefixes, internal enums and packaging metadata — identifies the source
on sight while bearing on nothing about whether the rule is correct. What is retained is the
complete detection logic: name, priority, type, MITRE label, the query verbatim, threshold,
window, unique-count keypath and group-by.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
