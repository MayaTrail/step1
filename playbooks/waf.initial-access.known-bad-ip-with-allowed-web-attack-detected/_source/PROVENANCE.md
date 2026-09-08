# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query string with priority, threshold, window and MITRE labels |
| Scope captured | One alerting rule: Known-Bad IP with Allowed Web Attack Detected |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project,
including this one. Shipped `references:` cite public MITRE and AWS documentation only.

**Merge test:** not applicable — one source rule, one use case. The sibling
`Flow Alert - Known-Bad IP Followed by Allowed Web Attack` in the same source pack is a
FLOW composition of the same two building blocks across a time window rather than within
one request. Under `07-TIERS.md` merge test 2 it would fold into this playbook as a
correlation document — but it is a **separate catalogue entry** and is left for its own
pass rather than absorbed here without the extract to audit against.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `waf.*` playbook is in `../../_ground-truth/waf.md`, audited
once on 2026-08-29 and reused rather than re-derived. The evaluation-order analysis that
drives this playbook's §2 is §7 of that file.
