# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | **Building block with no shipped logic** — no query, no threshold, no group-by |
| Scope captured | One entry: High Invocation Count |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

## This is a new use case, not a corrected rule, and the distinction is deliberate

All four Bedrock entries in the source pack are **building blocks** carrying no query, no threshold
and no grouping — CloudWatch metric alarms for cost and availability, and not alerting rules. The
extract shows exactly that, so there is nothing here to audit a correction against.

The `Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 therefore does **not** invent defects
in a rule that has no logic. It records what the source provides and what a security detection for
this service needs instead. Manufacturing a defect table for an empty rule would be the same
failure this project keeps documenting elsewhere: a check that cannot fail, dressed as diligence.

The security exposure it replaces the gap with is specific. A credential carrying
`bedrock:InvokeModel` spends money at the account owner's expense and produces text on demand.
Nothing is exfiltrated, so data-loss controls see nothing; no instance is launched, so
compute-oriented controls see nothing; and the cost lands in a service most accounts do not watch.

**MITRE:** the source maps this to nothing. `T1496 — Resource Hijacking` for the volume and
cost outcome, `T1526 — Cloud Service Discovery` for the model-breadth rule which observes
enumeration, and `T1078.004 — Valid Accounts: Cloud Accounts` for the unused-Region rule. All
verified live 2026-08-30.

**Merge test:** the four documents here are one use case — a credential being used for model
compute — observed through volume, breadth and Region. None has a source rule of its own.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.

Service ground truth for every `bedrock.*` playbook is in `../../_ground-truth/bedrock.md`, audited on
2026-08-30. Logging being off by default is §1; the endpoint coverage gap is §2; the record shape
and the caller-supplied field are §3; the 100 KB rule is §4.
