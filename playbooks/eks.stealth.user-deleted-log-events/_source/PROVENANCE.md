# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query string over Kubernetes audit events |
| Scope captured | One alerting rule: User Deleted Log Events |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public MITRE, AWS and Kubernetes documentation only.

**MITRE note:** Live mapping is **T1685.002 — Disable or Modify Tools: Disable or Modify Cloud
Log**, tactic **Defense Impairment (TA0112)**. Verified with `tools/attack_currency_check.py`;
revoked techniques are served as redirect stubs and still return HTTP 200.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `eks.*` playbook is in `../../_ground-truth/eks.md`, audited once
on 2026-08-29. The audit-policy analysis that makes this rule unfireable is §3 of that file.
