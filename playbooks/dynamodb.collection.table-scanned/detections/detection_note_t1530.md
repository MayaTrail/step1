# Detection Note — T1530 (Data from Cloud Storage)

**Signal:** tables read at breadth, and full scans that actually return item data.

## The rule is inert in a default account

`Scan` is a **data-plane** operation: *"you must enable logging of data plane API activity in
CloudTrail."* Data events are off by default and billable, and the rule does not say so. An empty
result means "not recorded", not "did not happen" — check `get-event-selectors` before concluding
anything.

## It maps to a reconnaissance technique about public sources

`T1596 — Search Open Technical Databases` covers WHOIS, passive DNS and public scan databases —
searching things the adversary does **not** own. Scanning your own table is reading stored data:
`T1530`.

## `Scan` is ordinary, so the rule needs a discriminator

Analytics jobs and exports scan constantly. A flat threshold on scan count reproduces that noise.
Two things separate a walk from a workload, and both are already in the request:

- **`select`.** A scan with `select: COUNT` reads the table and returns only a number — it cannot be
  exfiltration. Only `ALL_ATTRIBUTES` and `ALL_PROJECTED_ATTRIBUTES` move the rows. Rating those
  identically is what makes a Scan rule unusable.
- **Breadth.** An application scans its own table repeatedly; a principal scanning several tables is
  not an application. That correlation needs no allowlist to be meaningful, which is why it carries
  the severity.

## Three read paths, one watched

`Scan` reads the whole table. `Query` reads a partition, and without a narrowing key condition reads
a great deal. PartiQL `ExecuteStatement` compiles a `SELECT` to a Scan or Query under a different
event name entirely. All three are in the base rule so the breadth correlation sees them.

## Response levers

**Containment is rotation, not revocation.** The read has already happened. What matters is what the
items protect — credentials, tokens, personal data — and that is a schema question answered outside
AWS.

**`ListTables` before the reads is the strongest shape.** An application reads the table it was
configured with and does not enumerate first.

**Check `select` before escalating.** A COUNT-only scan moved nothing, and that distinction is
available in the event at no cost.

**Scoped IAM is the durable fix.** A role with `dynamodb:Scan` on `Resource: "*"` can walk every
table; scoped to its own table ARN it cannot. That is the difference between one compromised task
role and a registry-wide read.

**MITRE:** `T1530 — Data from Cloud Storage`, verified live 2026-08-30. The source's
`T1596 — Search Open Technical Databases` is a Reconnaissance technique about public sources and is
wrong.

**GuardDuty:** no finding type covers DynamoDB. `Exfiltration:S3/AnomalousBehavior` is the nearest
analogue for a different service, so these rules are the only coverage.

**Files here:**
- `sigma_t1530.yml` — four documents: a `value_count` correlation on **distinct tables** (high, the
  routable output), `dynamodb_full_scan_returning_data` (medium, gated on `select`),
  `dynamodb_table_read_unfamiliar_principal` (low), and `dynamodb_table_read` as the informational
  base rule covering all three read paths.
- `kql_t1530.kql` — separates COUNT-only scans from those returning data, flags unbounded full
  scans, detects enumeration preceding the reads, and states inline that an empty result may mean
  data events are off.

Full response procedure is in `../PLAYBOOK.md`.
