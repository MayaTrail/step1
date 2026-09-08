# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — `Database Instance/Cluster Was Created With No Encryption` |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Window | Group-by | Source MITRE label |
|-------|----------|------|--------|----------|--------------------|
| Database Instance/Cluster Was Created With No Encryption | P2 | threshold, `> 0` | 30m | `userIdentity.arn` | — |

A `logs_threshold` alert with a threshold of `0` is a per-event alert wearing a volume
shape: it fires on the first matching document in the window.

## Merge decision — NO MERGE

Neither test in `07-TIERS.md` §"When merging is legitimate" applies.

**Test 1** fails on the observable. The source set's `RDS Instance Creation` and `RDS Cluster
Creation` alerts (both P4) match the same event names with **no encryption condition**, and
`Multiple Instance Creation by Same User in Short Time Window` counts distinct identifiers
over the same events. Those are plausible merge candidates on the event name alone — and
they fail the test on the field that matters. This rule's discriminator is
`storageEncrypted: false`; theirs is the bare create. An encrypted create is a non-event
here and a full alert there. The responses are unrelated: this one ends in a
snapshot-copy-restore migration with downtime, theirs end in "is this instance authorised".

**Test 2** does not apply: this is not a correlation rule.

## Tier decision — TIER 2

None of the five promotion tests holds. The eradication is genuinely awkward — encryption
cannot be enabled in place, so the fix is snapshot, copy with a key, restore, cut over, and
that means downtime and a new endpoint — but awkward is not the same as *ordered such that a
step severs something a later step needs*. Nothing is destroyed by the remediation; the
original unencrypted instance stays available until the cutover is complete, which is what
makes the migration safe to run. The blast radius is fully readable from live state after
containment.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| The source set's `RDS Instance Creation` and `RDS Cluster Creation` alerts (P4) | **Separate.** Same event names, no encryption condition. Merging would put a P4 provisioning-audit signal and a P2 control-failure signal on one triage path, and the response to "an instance was created" is not a fraction of the response to "an instance was created unencrypted" |
| The source set's `Multiple Instance/Cluster Creation by Same User in Short Time Window` alerts | **Separate.** Volume over the same create events, again with no encryption condition. This is the shape test 1 exists for, and it still fails: the observable differs by the discriminating field, not by threshold |
| `../../rds.exfiltration.snapshot-made-public/` | **Separate, and the consequence.** An unencrypted database is the precondition for a snapshot that can be shared with `all` — a snapshot encrypted with the default `aws/rds` key cannot be shared at all, and a customer-managed-key snapshot cannot be made public. That relationship is the detection thesis here and is cross-referenced in §2 and §6, but the observable, the containment and the eradication share nothing |
| `../../rds.exfiltration.database-instancecluster-made-public/` | **Separate.** `publiclyAccessible` and `storageEncrypted` are independent parameters on the same calls. A create can set either, both or neither, and the two findings have nothing in common in §3 onwards |

## MITRE label dispute

Both the revoked ID and its replacement are wrong on
the merits: creating a database without storage encryption disables no logging and modifies no
tool.

The corrected primary is **T1578.002 — Create Cloud Instance** (Defense Impairment): the
observable is the creation of a cloud database resource provisioned without a control that
would otherwise constrain the adversary. **T1537 — Transfer Data to Cloud Account**
(Exfiltration) is carried as a genuine second mapping for the enabling relationship above.

Stated plainly, because the honest answer belongs in the record: **ATT&CK has no technique
for "provisioned without encryption at rest."** T1600 (*Weaken Encryption*) is live but
scoped to network devices. The mapping above is the closest defensible pair, and §6 of
`../PLAYBOOK.md` says so rather than implying a cleaner fit exists.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals
are packaged in a proprietary format whose scaffolding identifies the source on sight while
bearing on nothing about whether the rules are correct. What is retained is the complete
detection logic: name, priority, type, MITRE label, the query verbatim, threshold, window
and group-by.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal path
is not resolvable to whoever receives it.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.
