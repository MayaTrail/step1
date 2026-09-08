# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query string over Kubernetes audit events |
| Scope captured | One alerting rule: Unauthorized User Trying to Get Secrets |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public MITRE, AWS and Kubernetes documentation only.

**MITRE:** mapped to **T1552.007 — Unsecured Credentials: Container API Credentials**, which
is the on-point technique for reading secrets through the Kubernetes API. The source rule
carries `t1021` (Remote Services), which describes lateral movement over a remote service
protocol rather than credential access through an API — a mapping-precision correction, not
an operational defect. Verified live with `tools/attack_currency_check.py`.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `eks.*` playbook is in `../../_ground-truth/eks.md`, audited once
on 2026-08-29. The audit-policy levels and the `list` trap are §3; the identity systems and
the containment asymmetry are §5.
