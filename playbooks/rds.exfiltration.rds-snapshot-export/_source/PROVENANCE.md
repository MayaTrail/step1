# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | One alert — `RDS Snapshot Export` |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Window | Group-by | Source MITRE label |
|-------|----------|------|--------|----------|--------------------|
| RDS Snapshot Export | P2 | threshold, `> 0` | 30m | `userIdentity.arn` | T1567.002/TA0010 |

A `logs_threshold` alert with a threshold of `0` is a per-event alert wearing a volume
shape: it fires on the first matching document in the window.

## Merge decision — NO MERGE

Neither test in `07-TIERS.md` §"When merging is legitimate" applies.

**Test 1** fails on the observable. No other rule in the source set matches
`StartExportTask`. The nearest by intent are `Snapshot Made Public` and `Database
Instance/Cluster Made Public`; both leave the data inside RDS and change who may reach it,
while this one **moves the data out of RDS entirely**, into S3, as Parquet, where a
different service's access controls and a different service's logging govern it from then
on. The response has a whole phase the others do not: the S3 object review.

**Test 2** does not apply: this is not a correlation rule. The source set's `Building Block
- Privileged API Calls` does count `StartExportTask` among six event names, but it is a
building block feeding nothing this playbook ships, and its unique-count-over-event-names
shape is a different observable — how many *distinct privileged calls* one principal made,
not that an export happened.

## Tier decision — TIER 2

None of the five promotion tests holds cleanly. The blast radius is retrievable after
containment: the export task record survives in `DescribeExportTasks`, and the S3 objects
survive in the bucket with their own inventory, so nothing about the incident becomes
unknowable once the task is cancelled. The one complication — that the blast radius extends
into a second service — is a breadth problem, not an ordering or evidence problem, and it is
handled by one investigation query and one containment step. The export IAM role and its
KMS key add a third-party dimension worth watching, but neither reaches account takeover in
one hop.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../rds.exfiltration.snapshot-made-public/` | **Separate.** Sharing grants a restore right on a copy that stays in RDS's control plane; exporting writes readable Parquet into S3. The evidence, the containment and the residual risk all differ — an export is recoverable by deleting the objects, a share is not recoverable at all once someone has copied the snapshot |
| `../../_superseded/aws.exfiltration.s3-bucket-public-exposure/` | **Separate, and downstream.** That playbook covers a bucket being exposed. This one covers database contents arriving in a bucket. §3 here hands off to it explicitly when the destination bucket turns out to be reachable |
| The source set's `Building Block - Privileged API Calls` | **Separate.** Different observable — a distinct-event-name count over six APIs, with no success filter and no export-specific field. It is a discovery-shaped building block, not a volume variant of this rule |
| The source set's `Building Block - DB Snapshots Viewed` | **Separate.** `DescribeDBSnapshots` is reconnaissance that often precedes an export; it appears here as a P3 trigger row and a correlation component, not as a merged rule |

## MITRE label dispute — none

The source labels this rule **T1567.002 / TA0010** — *Exfiltration Over Web Service:
Exfiltration to Cloud Storage*, Exfiltration tactic. That is correct and it is retained as
the primary. **T1530 — Data from Cloud Storage** (Collection) is added as a genuine second
mapping: once the Parquet lands in S3, reading it is a cloud-storage read, and that is the
step the export makes possible. This is the only one of the five RDS rules in this batch
whose source mapping needed no correction.

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
