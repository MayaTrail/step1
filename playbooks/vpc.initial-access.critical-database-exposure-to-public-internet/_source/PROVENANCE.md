# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Critical Database Exposure to Public Internet |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**The defect worth naming here** is `NOT action:"reject"`. AWS documents exactly two values for
that field, `ACCEPT` and `REJECT`, both uppercase. On a case-sensitive backend the exclusion
matches nothing, so the rule fires on refused connections as readily as on accepted ones — and it
is rated P1. A blocked internet scan and a live database exposure arrive as the same alert, which
is the fastest way to teach an on-call to ignore both. The corrected rule matches `ACCEPT`
positively, which cannot fail in that direction.

The port list is rebuilt rather than corrected. The source lists `3303`, `3309` and `5429`, none
of which is a database port in common deployment; `5429` is one digit from `5439`, Redshift, which
suggests a transposition. Meanwhile MongoDB, Redis, OpenSearch, Memcached and Cassandra are
absent, and those are the engines most often found exposed because several historically shipped
with no authentication enabled by default.

**MITRE:** `T1190 — Exploit Public-Facing Application`, the source's own mapping, kept and
verified live 2026-08-30. `T1595 — Active Scanning` is carried by the probe rules, which observe
reconnaissance rather than exploitation. Both PRE/IaaS considerations are as recorded in
`../../_ground-truth/vpc.md` §10.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `vpc.*` playbook is in `../../_ground-truth/vpc.md`, audited on
2026-08-30. `action` semantics are §5; version-2-versus-custom format is §2; the `dstaddr` versus
`pkt-dstaddr` distinction is §3; the Block Public Access effect on `bytes` is §8.
