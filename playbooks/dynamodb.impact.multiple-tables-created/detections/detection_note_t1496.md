# Detection Note — T1496 (Resource Hijacking)

**Signal:** tables created at volume, and — the shape that actually matters — a new table being
written into.

## The rule cannot fire

It matches `eventName:"createtable"`. CloudTrail emits `CreateTable`, so on a case-sensitive field
it matches nothing. Ninth instance of this defect class in the source set.

## The threshold is tuned backwards

Five tables in **sixty seconds** is a deployment burst. An infrastructure apply reaches it; a person
creating tables by hand does not. So the rule catches exactly the traffic it should ignore and misses
a slower actor entirely.

Widened to ten minutes here, with the provisioning allowlist doing the discrimination — a tighter
window excludes the actor along with the pipeline.

## An empty table alters nothing

The source maps this to `T1565 — Data Manipulation`. `CreateTable` produces a resource containing no
data, so there is nothing to manipulate. What mass creation consumes is capacity and money:
`T1496 — Resource Hijacking`.

The shape worth watching is creation **followed by writes** into the new table, which is staging for
extraction. The query surfaces it, and the read side lives in
`../../dynamodb.collection.table-scanned/`.

## Response levers

**A new empty table rarely needs containment.** It costs capacity until deleted. Treat it as context
unless something wrote into it or the volume is unexplained.

**`CreateTable` is control-plane and logged by default.** Unlike three of the five DynamoDB rules in
this source set, this one does not depend on data events. Corrected for casing and threshold, it
works in every account — worth noting because it makes this the cheapest DynamoDB coverage available.

**Check the billing mode.** `PAY_PER_REQUEST` tables cost nothing at rest, so a mass-creation
campaign aimed at cost is more likely to use provisioned capacity. It is a weak signal but it is free.

**MITRE:** `T1496 — Resource Hijacking`, verified live 2026-08-30. The source's `T1565 — Data
Manipulation` describes something `CreateTable` cannot do.

**GuardDuty:** no finding type covers DynamoDB.

**Files here:**
- `sigma_t1496.yml` — three documents: a `value_count` correlation at five tables in ten minutes
  (medium), `dynamodb_table_created_unexpected` (low), and `dynamodb_table_created` as the
  informational base rule.
- `kql_t1496.kql` — flags creation followed by writes as the staging shape, and states inline why
  volume alone is weak.

Full response procedure is in `../PLAYBOOK.md`.
