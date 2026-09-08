# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rules over query strings, plus one flow correlating them |
| Scope captured | Five rules: Policy Escalation (flow), Building Block - Admin Policy Attached, and the three per-principal-type Attach building blocks |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously five of seven rules folded into
`aws.privilege-escalation.iam-managed-policy-escalation`, alongside two rules covering entirely
different techniques (managed policy version authoring and activation).

**Merge test — why five source rules become one use case, and it is applied rather than assumed.**
`AttachUserPolicy`, `AttachRolePolicy` and `AttachGroupPolicy` are the same operation against the
three principal types IAM has. They share a response: identify the grantee, remove the attachment,
establish what was done with the permissions. Splitting them would produce three playbooks with one
identical procedure, and the blast-radius difference between them is a **severity dimension**, not a
use case — which is how it is modelled here. The two rules that were *not* merged in
(`SetDefaultPolicyVersion`, `CreatePolicyVersion`) have different responses and different evidence,
and they are separate directories.

**"Administrative" is not one policy name.** The source rule matches
`requestParameters.policyArn:AdministratorAccess`, a substring on the ARN. That fails in both
directions:

- It **misses** `PowerUserAccess`, `IAMFullAccess`, and every customer-managed policy granting
  `Action: "*"` under a name like `AppRuntimePolicy`. Attaching any of those is the same escalation.
- It **matches** a customer-managed policy merely *named* something containing `AdministratorAccess`,
  which grants whatever its document says.

The shipped rule uses an explicit list, and the playbook derives the account's real one by reading
policy documents rather than by pattern-matching names.

**The three rules filter service principals three different ways, for no stated reason.**
`AttachRolePolicy` excludes `userIdentity.invokedBy` of `cloudformation.amazonaws.com` and
`sso.amazonaws.com`; `AttachUserPolicy` and `AttachGroupPolicy` exclude nothing. Same operation,
three filters. The SSO exclusion matters most: an escalation performed through SSO's role
provisioning is invisible on roles and visible on users — an arbitrary blind spot rather than a
decision. One consistent exclusion is applied here, and it is stated so it can be argued with.

**Attaching to a group escalates every member, and the event names none of them.**
`AttachGroupPolicy` has the largest blast radius of the three and the pack rates it identically to
attaching to a single user. Resolving it requires `GetGroup`, and **future** members are not
enumerable at all — anyone added later inherits the grant with no further event. It ships one level
higher for that reason.

**The flow rule references its components by opaque numeric ID** (`(49 AND 33) OR (49 AND 27)`),
which cannot be audited against anything, and is rated P3 — below the P2 its sibling rules carry.
It is replaced by a named `value_count` correlation on fan-out, which is the volume dimension the
pack has nowhere.

**MITRE:** the source maps these rules to **nothing**. `T1098.003 — Account Manipulation: Additional
Cloud Roles`, verified live 2026-08-30.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.

Service ground truth for every `iam.*` playbook is in `../../_ground-truth/iam.md`, audited 2026-08-30.
