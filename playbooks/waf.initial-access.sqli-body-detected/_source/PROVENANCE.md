# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query string with priority, threshold, window and MITRE labels |
| Scope captured | One alerting rule: SQLi Body Detected |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project,
including this one. Shipped `references:` cite public MITRE and AWS documentation only.

**Merge test:** not applicable — one source rule, one use case, one playbook. The three
sibling SQLi rules in the same source pack (`SQLi Query Args`, `SQLi URI Path`,
`SQLi Cookie`) are separate use cases and were **not** absorbed: they inspect different
request components, are unaffected by the body size limit that dominates this playbook's
§2 and §6, and one of them (`SQLi_URIPath`) has a different label-casing hazard. Merge
test 1 fails on "same response".

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `waf.*` playbook is in `../../_ground-truth/waf.md`, audited
once on 2026-08-29 and reused rather than re-derived.
