# IAM — verified service behaviour

Audited 2026-08-30 against AWS documentation. Every claim below is quoted or directly derived from
a cited page. Shared by every `iam.*` playbook; do not restate it in each one.

---

## 1. `SetDefaultPolicyVersion` grants permissions without carrying any

Source: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetDefaultPolicyVersion.html

> Sets the specified version of the specified policy as the policy's default (operative) version.
> **This operation affects all users, groups, and roles that the policy is attached to.**

Its only request parameters are **`PolicyArn`** and **`VersionId`**. There is no policy document.

Three consequences, and they shape every rule in `iam.privilege-escalation.default-policy-version-reverted`:

- **The event cannot tell you what was granted.** A rule that inspects `policyDocument` sees nothing,
  because the field does not exist on this call. Resolving it requires `GetPolicyVersion`.
- **The blast radius is not in the event either.** One call re-permissions every principal the policy
  is attached to. AWS names the way to enumerate them: *"To list the users, groups, and roles that
  the policy is attached to, use ListEntitiesForPolicy."*
- **No policy content is ever written.** The permissive text was authored earlier — possibly by
  someone else, possibly legitimately. Every detection built on inspecting policy documents at write
  time is blind to this technique.

`VersionId` matches `v[1-9][0-9]*`, so versions are `v1`, `v2`, … and a *lower* number than the
current default means a revert to an older version.

## 2. Five versions, which is why old permissive text lingers

Source: https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html

> A managed policy can have up to five versions. If the policy has five versions, you must delete an
> existing version using `DeletePolicyVersion` before you create a new version.

So a policy carries up to four non-operative versions at any time. If any of them was permissive —
an over-broad draft that was later tightened, for instance — it stays available indefinitely, and
one `SetDefaultPolicyVersion` call makes it operative again. The attacker does not need to write
anything, and a change-review process that looks at policy *edits* never sees it.

## 3. `SetAsDefault` makes the escalation a single event with a different name

> **SetAsDefault** — Specifies whether to set this version as the policy's default version. When
> this parameter is `true`, the new policy version becomes the operative version. That is, it
> becomes the version that is in effect for the IAM users, groups, and roles that the policy is
> attached to. Required: No

This cuts both ways and both halves matter:

- **`CreatePolicyVersion` with `SetAsDefault=true` escalates in one call and emits no
  `SetDefaultPolicyVersion` event.** A rule watching only `SetDefaultPolicyVersion` misses the whole
  technique. The source pack has exactly that gap.
- **`CreatePolicyVersion` without `SetAsDefault` grants nothing at all.** The new version is
  dormant. A rule that alerts on a permissive `CreatePolicyVersion` without reading `setAsDefault`
  cannot tell an operative escalation from a draft nobody has activated — and rates them the same.

## 4. Policy-document encoding: request raw, response encoded

This is authoring rule **A4** and is restated here only as a pointer, because getting it backwards
inverts a detection thesis:

- `requestParameters.policyDocument` and `.assumeRolePolicyDocument` are **raw JSON**.
- `GetRolePolicy`, `GetUserPolicy`, `GetPolicyVersion` and `GetRole` state that *"Policies returned
  by this operation are URL-encoded compliant with RFC 3986"* — so decode **conditionally**, only
  what actually begins `%`. `tools/decode_policy_documents.py` implements the conditional form.

## 5. Substring matching cannot read a policy, and the source pack relies on it

Every "overly permissive" rule in the source pack is a regex over the serialised document, of the
shape `"Effect":"Allow"` AND (`"Action":"*"` OR `"Resource":"*"`). A substring match cannot answer
the three questions that decide whether a policy is dangerous:

| Question | Why a regex gets it wrong |
|---|---|
| Is the statement `Allow` or `Deny`? | Both strings appear in a document containing either. A policy whose *only* wildcard is inside a `Deny` — the safest possible shape — matches. |
| Is `Action` exactly `"*"`, or merely something containing one? | `"s3:Get*"` contains an asterisk. So does `"*"`. Only one of them is administrative. |
| Do the `Allow` and the wildcard sit in the **same** statement? | A document with a narrow `Allow` and a separate `Deny *` matches every clause while granting nothing. |

`Resource: "*"` deserves separate mention: it is **normal**. Many legitimate actions accept no other
value — `s3:ListAllMyBuckets`, `ec2:DescribeInstances`, `iam:ListRoles`. Treating `Resource: "*"` as
equivalent to `Action: "*"` is the single largest false-positive source in the source pack, and the
rules here rate the two differently for that reason.

## 6. IAM events reach only `us-east-1` trails

IAM is a global service. Per `../_ground-truth/cloudtrail.md` §4, its events are recorded in
`us-east-1` and CloudTrail *"delivers global service events only to single-Region trails in US East
(N. Virginia)"*. A single-Region trail anywhere else receives **no IAM events at all**, so every
playbook in this service depends on a multi-Region trail existing — and a coverage review that only
confirms "a trail exists" can report green while all of this is invisible.

---

## MITRE currency, verified 2026-08-30

| ID | Status | Name | Tactic |
|---|---|---|---|
| `T1098` | live | Account Manipulation | Persistence |
| `T1098.001` | live | Account Manipulation: Additional Cloud Credentials | Persistence |
| `T1098.003` | live | Account Manipulation: Additional Cloud Roles | Persistence |
| `T1548` | live | Abuse Elevation Control Mechanism | Privilege Escalation |
| `T1078.004` | live | Valid Accounts: Cloud Accounts | Persistence |
| `T1484` | live | Domain or Tenant Policy Modification | Privilege Escalation |

`T1098.003 — Additional Cloud Roles` is the precise mapping for attaching or granting a policy that
raises a principal's permissions. `T1484` covers modifying the policy object itself rather than the
principal's attachments, which is what the version-manipulation techniques do.
