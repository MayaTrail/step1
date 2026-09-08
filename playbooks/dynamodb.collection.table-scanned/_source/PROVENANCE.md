# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: A Table Was Scanned |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

**`Scan` is data-plane, so the rule is inert in a default account.** AWS lists it among the
operations for which *"you must enable logging of data plane API activity in CloudTrail"*. Data
events are off by default and billable. The rule does not say so, and an empty result from it means
"not recorded" rather than "did not happen".

**It maps to a reconnaissance technique about public sources.** `T1596 — Search Open Technical
Databases` covers WHOIS, passive DNS, CDN and public scan databases — searching things the adversary
does **not** own. Scanning your own DynamoDB table is reading stored data, which is
`T1530 — Data from Cloud Storage`. This and the `T1505` mapping on the item rules are the two least
defensible mappings in the whole source set.

**And `Scan` is ordinary.** Analytics jobs, exports and small-table lookups scan constantly, so a
single scan is not a finding and a flat threshold on scan count reproduces the noise. Two things
separate a walk from a workload, and both are in the request the rule already matches:

- **`select`** — a scan with `select: COUNT` reads the table and returns only a number. It cannot be
  exfiltration. Only `ALL_ATTRIBUTES` and `ALL_PROJECTED_ATTRIBUTES` move the rows.
- **Breadth** — an application scans its own table repeatedly; a principal scanning several tables is
  not an application.

**It also watches one of three read paths.** `Query` reads a partition and, without a narrowing key
condition, reads a great deal. PartiQL `ExecuteStatement` compiles a `SELECT` to a Scan or Query
under a different event name. Both are included here so the breadth correlation sees them.

**A smaller defect:** the rule filters on `NOT _exists_:errorMessage` rather than `errorCode`.
`errorCode` is CloudTrail's canonical failure field; `errorMessage` is not always present on a
failure, so the filter admits some failed calls as successes.

**MITRE:** `T1530 — Data from Cloud Storage`, verified live 2026-08-30. The source's `T1596` is a
Reconnaissance technique and is wrong.

**Merge test:** not applicable — one source rule, one use case. Kept apart from
`../../dynamodb.impact.table-items-modified-or-destroyed/` because reading and writing have opposite
responses: a read has already happened and is contained by rotating what the data protects, while a
write is contained by restoring it.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `dynamodb.*` playbook is in `../../_ground-truth/dynamodb.md`, audited
2026-08-30. §1 covers the data-event precondition and §2 the PartiQL paths.
