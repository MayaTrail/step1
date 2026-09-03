# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | The three inline policy-write alerts |
| Retrieved | 2026-08-27 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority |
|-------|----------|
| PutUserPolicy - Overly Permissive Policy | P2 |
| PutRolePolicy - Overly Permissive Policy | P2 |
| PutGroupPolicy - Overly Permissive Policy | P2 |

The managed-policy alerts from the same source set (`CreatePolicyVersion`,
`SetDefaultPolicyVersion`, the `Attach*Policy` building blocks and the `Policy Escalation`
flow) are captured in `../../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/_source/`.

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

**Merge test — applied, not assumed.** Three source rules become one use case.
`PutUserPolicy`, `PutRolePolicy` and `PutGroupPolicy` are the same operation against the three
principal types IAM has: they embed a policy document directly on a principal, they share a
response (read the document, delete the inline policy, revoke sessions), and the difference between
them is *which* principal is affected — a blast-radius dimension, not a different technique.
Splitting them would produce three playbooks with one identical procedure.

Note that the source pack itself did not treat them identically: `PutUserPolicy` and
`PutGroupPolicy` test `Action:"*"` **or** `Resource:"*"`, while `PutRolePolicy` tests `Action:"*"`
only. Same technique, three rules, two different conditions — so a role inline policy granting
narrow actions over `Resource:"*"` was matched on users and groups and not on roles. The unified
rule here removes that asymmetry, and rates `Resource:"*"` alone as the non-finding it usually is.

**Not merged with the managed-policy siblings, and the reason is the response.** Inline policies are
embedded on the principal and are deleted with `DeleteRolePolicy`; managed policies are shared
objects that are detached, and the same document may be attached elsewhere. They also differ in
visibility — an inline policy does not appear in any policy-attachment listing. See
`../../iam.privilege-escalation.admin-policy-attached/` for the managed route,
`../../iam.privilege-escalation.policy-version-overly-permissive/` for authoring a managed document,
and `../../iam.privilege-escalation.default-policy-version-reverted/` for activating one.

Service ground truth for every `iam.*` playbook is in `../../_ground-truth/iam.md`, audited 2026-08-30.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
