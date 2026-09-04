# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Image Tag Overwrite Enabled |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is fully readable in `original_rules.yml`, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**Merge test:** not applicable — one source rule, one use case.
`../../ecr.privilege-escalation.repository-policy-applied/` is the adjacent use case and is
cross-referenced rather than folded in.

**Tier:** 1, on criterion 3 of `07-TIERS.md` — *the blast radius is not in the event*.

Service ground truth is inline in the shipped files.
