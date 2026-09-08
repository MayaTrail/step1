# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: SetDefaultPolicyVersion |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of seven folded into
`aws.privilege-escalation.iam-managed-policy-escalation`, alongside four building blocks and a flow
covering an entirely different technique (attaching a policy to a principal).

**The technique this rule names grants permissions without carrying any.**
`SetDefaultPolicyVersion` takes `PolicyArn` and `VersionId`, and nothing else — there is no
`policyDocument` on the request. That matters beyond this rule: the *other* two "overly permissive
policy" rules in the same pack both work by regexing `policyDocument`, so neither can see this
technique at all. The permissive text was authored earlier, possibly legitimately, and activating it
writes nothing.

**The rule watches one of the two calls that do this.** `CreatePolicyVersion` with
`SetAsDefault: true` makes the new version operative in a single call — AWS: *"When this parameter
is `true`, the new policy version becomes the operative version. That is, it becomes the version
that is in effect for the IAM users, groups, and roles that the policy is attached to."* It emits no
`SetDefaultPolicyVersion` event, so the source rule misses the more direct form entirely.

**Its blast radius is unbounded and not knowable from the event.** AWS: *"This operation affects all
users, groups, and roles that the policy is attached to."* One call re-permissions every attached
principal, and the event names none of them. AWS documents the answer in the same paragraph — *"use
`ListEntitiesForPolicy`"* — and the playbook runs it before rating anything.

**Old versions are the interesting ones, and this is why the technique exists.** A managed policy
holds up to five versions, so up to four non-operative ones linger at any time. An over-broad draft
that was tightened months ago is still there, and one call makes it live again. No policy edit
occurs, so a change-review process that inspects policy *diffs* never sees it. `VersionId` matches
`v[1-9][0-9]*`, so a **lower** number than the current default is a revert backwards — a direction
the shipped rules rate above a forward move.

**Rated P2 with no MITRE mapping.** Shipped at high for the single activation, critical for the
authored-then-activated pair.

**MITRE:** the source maps this rule to **nothing**. `T1098.003 — Account Manipulation: Additional
Cloud Roles` is the mapping: the operation adds permissions to principals. `T1484 — Domain or Tenant
Policy Modification` was considered and set aside — it is written for directory and tenant policy
rather than an identity policy attached to principals. Both verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. It is kept apart from
`../../iam.privilege-escalation.policy-version-overly-permissive/` because that one inspects a document
this one does not have, and apart from `../../iam.privilege-escalation.admin-policy-attached/` because
attaching a policy and re-pointing a policy's version are different operations with different blast
radii.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `iam.*` playbook is in `../../_ground-truth/iam.md`, audited 2026-08-30.
§1 covers this operation, §2 the version limit and §3 the `SetAsDefault` bypass.
