# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Repository Policy Applied |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project. The
source rule excluded one named operator principal by ARN; that name is rendered
`<one-named-operator-principal-REDACTED>` in the extract, and the shipped rules use a populated
allowlist block instead of a hard-coded identity.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**The defect is that the rule watches the call and never the policy.** `SetRepositoryPolicy`
replaces the repository's entire resource policy, so the event that grants an external account
push access and the event that tightens a policy are the same event name with the same
success. Without reading `requestParameters.policyText` the rule cannot tell them apart, and in
an estate that manages ECR through infrastructure code it fires on every apply.

**A single hard-coded principal exclusion is not an allowlist.** It cannot be reviewed, it
breaks silently when that principal is rotated or renamed, and it names an individual inside
detection logic. The shipped rules use a `known_provisioners` block populated before deployment.

**MITRE:** the source carries `T1484` (Domain or Tenant Policy Modification), which describes
identity-provider policy rather than a resource policy on a container registry. Mapped here to
`T1098 — Account Manipulation` for the grant itself, with `T1525 — Implant Internal Image` as
the objective a push grant enables. Both verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth is inline in the shipped files; ECR has no `_ground-truth/` file because
this is the only `ecr.*` use case authored so far.
