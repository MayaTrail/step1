# Detection Note — T1098.003 (Account Manipulation: Additional Cloud Roles)

**Signal:** an administrative managed policy attached to a user, role or group — where
"administrative" has to be defined from the account rather than from a policy name.

## "Administrative" is not one policy name

The source rule matches `requestParameters.policyArn:AdministratorAccess` — a substring on the ARN.
That is wrong in both directions:

- It **misses** `PowerUserAccess`, `IAMFullAccess`, and any customer-managed policy granting
  `Action: "*"` under an ordinary-looking name. Attaching those is the same escalation.
- It **matches** any policy merely *named* something containing `AdministratorAccess`, whatever its
  document actually says.

The shipped rule uses an explicit list, and the list in it is a **starting point, not an answer**.
The account's real list is derived by reading policy documents — §4 of the playbook does it — and in
a mature estate the home-grown administrative policies are usually the ones that matter.

## Three principal types, one use case, three different filters

`AttachUserPolicy`, `AttachRolePolicy` and `AttachGroupPolicy` are one operation against the three
principal types IAM has, so they merge. What does not merge is the source pack's filtering:
`AttachRolePolicy` excludes `invokedBy` of CloudFormation and SSO; the other two exclude nothing.

The SSO exclusion is the consequential one. An escalation performed through SSO's role provisioning
is invisible on roles and visible on users — an arbitrary blind spot rather than a decision. One
consistent exclusion is applied here, stated plainly so it can be argued with rather than inherited.

## Attaching to a group is the largest blast radius and is rated lowest

`AttachGroupPolicy` grants to every **current and future** member. The event carries only the group
name, so current members need `GetGroup` to enumerate — and future members are not enumerable at
all. Anyone added to that group later inherits the grant with **no further event**.

That last point is why a group attachment is worth removing rather than monitoring, and why it ships
a level above the other two here where the pack rates all three the same.

## Response levers

**Enumerate before rating.** `GetGroup` for a group attachment; for a role, the trust policy decides
who can actually use the escalation — a role nobody can assume is a smaller problem than a role
assumable by an application.

**Self-grant is the highest-signal shape and needs a field comparison.** A principal attaching an
administrative policy to itself is unambiguous, but it requires comparing the caller ARN to the
grantee name — which Sigma cannot express. The KQL does it; if you deploy only the Sigma, that
verdict is not available.

**Detaching is not the whole fix for a role.** Existing sessions issued while the policy was
attached keep their permissions until expiry. The deny-by-token-issue-time policy in §3 is what
actually revokes them.

**Check whether the policy was authored just before it was attached.** Author-then-attach by one
principal is the complete escalation in two calls, and the authoring half is covered in
`../../iam.privilege-escalation.policy-version-overly-permissive/`.

**MITRE:** the source maps these rules to **nothing**. `T1098.003 — Account Manipulation: Additional
Cloud Roles`, verified live 2026-08-30.

**GuardDuty:** `PrivilegeEscalation:IAMUser/AnomalousBehavior` is driven by CloudTrail management
events and may surface an unusual IAM call from an unusual principal. It is an anomaly detector
rather than a rule about administrative policies, so it will not fire when the caller routinely
attaches policies — which is the case these rules exist for.

**Files here:**
- `sigma_t1098_003.yml` — four documents: `iam_admin_policy_attached` (critical),
  `iam_policy_attached_to_group` (high, for the unbounded blast radius), `iam_policy_attached`
  (informational base rule), and a `value_count` correlation for attachments to three or more
  distinct principals in an hour (critical), replacing the source pack's flow rule that referenced
  its components by opaque numeric ID.
- `kql_t1098_003.kql` — detects the self-grant shape, separates customer-managed policies that the
  list cannot classify, and states inline that group membership is only half enumerable.

Full response procedure is in `../PLAYBOOK.md`.
