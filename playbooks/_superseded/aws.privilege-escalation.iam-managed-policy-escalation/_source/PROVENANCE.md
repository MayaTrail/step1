# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The managed-policy escalation and admin-attach alerts, seven in total |
| Retrieved | 2026-08-27 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority |
|-------|----------|
| CreatePolicyVersion - Overly Permissive Policy | P2 |
| SetDefaultPolicyVersion | P2 |
| Building Block - Admin Policy Attached (internal ID 33) | building block |
| Building Block - AttachUserPolicy | building block |
| Building Block - AttachRolePolicy | building block |
| Building Block - AttachGroupPolicy | building block |
| Policy Escalation — FLOW, stages (49 AND 33) OR (49 AND 27) | P3 |

Internal ID 49 (`Privileged API Calls`) and 27 (`Unexpected Trusts - Wildcard As
Principal`) are referenced by the flow but belong to other techniques. The three inline
policy-write alerts from the same source set are captured in
`../../../iam.privilege-escalation.inline-policy-grant/_source/`.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately. The originals are packaged in a proprietary format whose
scaffolding — payload field lists, entity labels, product-specific field prefixes,
internal enums and packaging metadata — identifies the source on sight while bearing on
nothing about whether the rules are correct. What is retained is the complete detection
logic: name, priority, type, the Lucene query verbatim, threshold, window and group-by.
Every claim in the "Detection Rule Quality Notes" table in `../PLAYBOOK.md` §2 is
checkable against it.

The shipped `references:` blocks in `detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal
path is not resolvable to whoever receives it.
