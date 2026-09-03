# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query string with priority, threshold, window and MITRE labels |
| Scope captured | One alerting rule: No Logs From AWS WAF |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project,
including this one. Shipped `references:` cite public MITRE and AWS documentation only.

**MITRE note:** The live mapping is **T1685.002 — Disable or Modify Tools: Disable or Modify
Cloud Log**, tactic **Defense Impairment (TA0112)**. TA0005 was renamed *Stealth*.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `waf.*` playbook is in `../../_ground-truth/waf.md`, audited
once on 2026-08-29 and reused rather than re-derived.
