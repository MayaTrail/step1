# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: Multiple Tables Created |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**The rule cannot fire.** It matches `eventName:"createtable"`; CloudTrail emits `CreateTable`, and
on a case-sensitive field the lowercase form matches nothing. This is the ninth instance of that
defect class across this source set.

**Its threshold is five tables in sixty seconds, which is a deployment.** An infrastructure apply
standing up an environment creates tables in a burst; a person creating them by hand does not reach
five in a minute. So the rule is tuned to catch exactly the traffic it should ignore, and to miss a
slower actor entirely. The window is widened to ten minutes here and the provisioning allowlist does
the discrimination — a tighter window excludes the actor along with the pipeline.

**And it maps to data manipulation.** `T1565` is about altering stored or transmitted data. Creating
an empty table alters nothing: the resource is new and contains no data at all. What mass table
creation actually consumes is capacity and money, which is `T1496 — Resource Hijacking`. Where tables
are being created to stage data for extraction, the extraction is the finding and lives in
`../../dynamodb.collection.table-scanned/` — the shape worth watching is creation followed by writes
into the new table, which the shipped query surfaces.

**One thing worth saying in the rule's favour:** `CreateTable` is control-plane and logged by
default, so unlike three of the five DynamoDB rules in this source set it does not depend on data
events being purchased. Corrected for casing and threshold, it works everywhere.

**MITRE:** `T1496 — Resource Hijacking`, verified live 2026-08-30. The source's `T1565 — Data
Manipulation` describes something the operation cannot do.

**Merge test:** not applicable — one source rule, one use case. Kept apart from
`../../dynamodb.defense-evasion.table-configuration-modified/` because creating a resource and
reconfiguring an existing one have different responses, and apart from the read and write atoms
because an empty table involves no data at all.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `dynamodb.*` playbook is in `../../_ground-truth/dynamodb.md`, audited
2026-08-30. §5 covers the casing defect.
