# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string with regex predicates |
| Scope captured | One alerting rule: CreatePolicyVersion - Overly Permissive Policy |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously one of seven folded into
`aws.privilege-escalation.iam-managed-policy-escalation`.

**A substring match cannot read a policy.** The rule requires `"Effect":"Allow"` **and**
(`"Action":"*"` **or** `"Resource":"*"`) to appear anywhere in the serialised document. It cannot
answer the question that decides whether the policy is dangerous: do the `Allow` and the wildcard
sit in the **same statement**? A document with a narrow `Allow` and a separate `Deny` on
`Action:"*"` — the safest shape available — satisfies every clause.

Credit where it is due: the regex anchors on exactly `"*"`, so it does **not** confuse `"s3:Get*"`
with `"*"`. That part is correct, and it is the part most rules of this kind get wrong. The
statement-scoping is what it cannot do — and neither can Sigma or KQL, which is why the shipped
rules over-match by design and the playbook resolves each hit by **parsing** the document.

**`Resource: "*"` is normal, and OR-ing it with `Action: "*"` is the largest false-positive source
in the pack.** Many legitimate actions accept no other value: `s3:ListAllMyBuckets`,
`ec2:DescribeInstances`, `iam:ListRoles`. A correct least-privilege policy for any of them contains
`Resource: "*"`. `Action: "*"` is administrative; `Resource: "*"` is a shape. Alerting on both at one
severity teaches responders that this entire rule family is noise, which is how the real ones get
closed unread. The shipped set rates them differently, and the `Resource`-only case ships at
informational specifically to record that it is expected.

**A version that is not default grants nothing.** AWS: `SetAsDefault` *"becomes the version that is
in effect for the IAM users, groups, and roles that the policy is attached to."* Without it the new
version is dormant. The source rule never reads the flag, so it rates an unactivated draft
identically to a live escalation — and misses that a dormant permissive version is a **pre-loaded**
escalation, one `SetDefaultPolicyVersion` call away, with no document write for anyone to review.
Those are two findings with different urgencies and different remediations, and both ship.

**And it only watches `CreatePolicyVersion`.** A brand-new policy created administrative is the same
escalation under `CreatePolicy`, which the pack does not cover anywhere.

**Encoding, stated to prevent the opposite error:** `requestParameters.policyDocument` is **raw
JSON**. Percent-encoding is a property of what IAM *returns* — `GetPolicyVersion`, `GetRolePolicy`
and their siblings state *"Policies returned by this operation are URL-encoded compliant with RFC
3986"*. Decoding the request parameter would corrupt a literal `%2F` in an S3 prefix condition. This
is authoring rule **A4**, and it was previously recorded backwards in this project.

**MITRE:** the source maps this rule to **nothing**. `T1098.003 — Account Manipulation: Additional
Cloud Roles`, verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. It deliberately overlaps with
`../../iam.privilege-escalation.default-policy-version-reverted/` on the create-and-activate shape: that
directory reads the **activation** and its blast radius, this one reads the **document**. Neither
subsumes the other — activation can happen with no document at all, and a document can be authored
with no activation.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.

Service ground truth for every `iam.*` playbook is in `../../_ground-truth/iam.md`, audited 2026-08-30.
§3 covers `SetAsDefault`, §4 the encoding split and §5 why substring matching fails here.
