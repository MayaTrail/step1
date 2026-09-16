# Detection Note — T1098.003 (Account Manipulation: Additional Cloud Roles)

**Signal:** the operative version of a managed policy changing — an escalation that writes no policy
text and names no affected principal.

## The event grants permissions and carries none

`SetDefaultPolicyVersion` takes `PolicyArn` and `VersionId`. There is no `policyDocument`.

That is not a quirk, it is the technique. The two sibling rules in the same source pack both work by
regexing `policyDocument`, so **neither can see this at all** — and the permissive text they are
looking for was authored earlier, possibly by someone with a legitimate reason, possibly months ago.

## One call, two names

`CreatePolicyVersion` with `SetAsDefault: true` reaches the same end state in a single call:

> *"When this parameter is `true`, the new policy version becomes the operative version. That is, it
> becomes the version that is in effect for the IAM users, groups, and roles that the policy is
> attached to."*

It emits no `SetDefaultPolicyVersion` event. A rule scoped to that name — which is what the source
ships — misses the more direct form. Both are covered here, and the create form is the only shape in
this directory where the granted permissions are readable from the event itself.

## Old versions are why this works

A managed policy holds at most five versions, so up to four non-operative ones sit there at any
time. An over-broad draft that was tightened later is still available, and one call makes it
operative again.

Nothing is written. A change-review process that inspects policy diffs sees no diff. `VersionId`
matches `v[1-9][0-9]*`, so a **lower** number than the current default means a revert backwards —
the direction that ships at the higher rating, because a forward move is usually a deployment.

## Response levers

**`ListEntitiesForPolicy` before anything else.** AWS: *"This operation affects all users, groups,
and roles that the policy is attached to. To list the users, groups, and roles that the policy is
attached to, use ListEntitiesForPolicy."* The same event is a non-issue on a policy attached to
nothing and an account-wide escalation on one attached to a hundred roles, and only this call tells
you which.

**`GetPolicyVersion` is how you learn what was granted** — and its output is percent-encoded, unlike
the request parameters, so decode conditionally (authoring rule A4, `tools/decode_policy_documents.py`).

**Reverting is one call and is usually the right first action.** The previous default version still
exists unless someone deleted it, so containment is `set-default-policy-version` back to it. Confirm
the target version is the one you think it is first — the safe version is not always the highest
number.

**Watch `DeletePolicyVersion` alongside.** On a policy already holding five versions, an actor must
delete one before authoring a new one. That deletion is ordinary maintenance and it also destroys
the only record of what that version contained — there is no recovery afterwards.

**MITRE:** the source maps this rule to **nothing**. `T1098.003 — Account Manipulation: Additional
Cloud Roles`, verified live 2026-08-30. `T1484 — Domain or Tenant Policy Modification` was
considered and set aside: it is written for directory and tenant policy rather than an identity
policy attached to principals.

**GuardDuty:** no finding type covers managed policy version manipulation.
`PrivilegeEscalation:IAMUser/AnomalousBehavior` is a CloudTrail-driven anomaly detector that may
surface an unusual IAM call from an unusual principal, but it is not a rule about policy versions and
will not fire on a provisioning role doing this deliberately.

**Files here:**
- `sigma_t1098_003.yml` — four documents: `iam_default_policy_version_changed` (high),
  `iam_policy_version_created_as_default` (high, the one-call form the source rule cannot see),
  `iam_policy_version_created` (informational base rule), and a `temporal_ordered` correlation for
  authored-then-activated by one principal (critical).
- `kql_t1098_003.kql` — covers both call names, compares version numbers to detect a backwards
  revert, and states inline that the blast radius requires `ListEntitiesForPolicy`.

Full response procedure is in `../PLAYBOOK.md`.
