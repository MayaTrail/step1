# Detection Note — T1098.003 (Account Manipulation: Additional Cloud Roles)

**Signal:** a policy document granting `Action: "*"` — and whether it is actually in effect.

## A substring match cannot read a policy

The source rule requires `"Effect":"Allow"` and (`"Action":"*"` or `"Resource":"*"`) somewhere in
the document. The question it cannot answer is whether the `Allow` and the wildcard are in the
**same statement**. A narrow `Allow` beside a separate `Deny` on `Action:"*"` — the safest shape
there is — matches every clause.

Neither Sigma nor KQL can scope a substring to a JSON statement, so the shipped rules over-match
**by design**, and the playbook resolves each hit by parsing the document rather than matching it.
The `PossibleDenyOnly` column in the query is the cheap approximation: a document with a wildcard and
no `Allow` at all is almost certainly a Deny policy.

Worth saying: the source regex anchors on exactly `"*"`, so it does **not** confuse `"s3:Get*"` with
`"*"`. That is the part most rules of this kind get wrong, and this one gets it right.

## `Resource: "*"` is normal

`s3:ListAllMyBuckets`, `ec2:DescribeInstances` and `iam:ListRoles` accept no other `Resource` value.
A correct least-privilege policy for any of them contains `Resource: "*"`.

The source rule ORs it with `Action: "*"` at the same severity. That is the largest false-positive
source in the pack, and its real cost is not the volume — it is that it teaches responders this
whole rule family is noise, which is how the genuine ones get closed unread. Here the `Resource`-only
shape ships at **informational**, explicitly to record that it is expected rather than to alert on it.

## A dormant version grants nothing — and is a different finding

> *"When this parameter is `true`, the new policy version becomes the operative version."*

Without `SetAsDefault`, the new version is inert. The source rule never reads the flag, so a draft
awaiting approval and a live administrative grant produce the same alert.

Splitting them gives two findings with different remediations. The live one is an escalation to
contain. The dormant one is a **pre-loaded** escalation: the permissive text now sits inside a policy
that may be attached to dozens of principals, and one `SetDefaultPolicyVersion` call activates it
with no document write for a change review to catch. The correct response to the second is to delete
the version, not to watch it.

## Response levers

**Parse, do not read.** `tools/decode_policy_documents.py` answers the three questions a substring
cannot: `Allow` or `Deny`, `Action` exactly `"*"` or merely containing one, and whether the two are
in the same statement.

**Do not decode `requestParameters`.** It is raw JSON. Percent-encoding applies to what IAM
*returns* — `GetPolicyVersion` and its siblings — so decoding is conditional, applied only to input
beginning `%`. Decoding unconditionally corrupts a literal `%2F` in an S3 prefix condition
(authoring rule A4).

**Check `CreatePolicy` as well as `CreatePolicyVersion`.** A new administrative policy is the same
escalation under an event name the source pack watches nowhere. It is also the earliest signal: a
newly created policy is attached to nothing, so intent is visible before any principal gains
anything.

**Delete dormant permissive versions rather than monitoring them.** They are the raw material for
`../../iam.privilege-escalation.default-policy-version-reverted/`, which needs no document write at
all.

**MITRE:** the source maps this rule to **nothing**. `T1098.003 — Account Manipulation: Additional
Cloud Roles`, verified live 2026-08-30.

**GuardDuty:** no finding type covers IAM policy content.
`PrivilegeEscalation:IAMUser/AnomalousBehavior` may surface an unusual IAM call from an unusual
principal, but it does not read policy documents and will not fire on a permissive policy authored
by a principal that authors policies routinely.

**Files here:**
- `sigma_t1098_003.yml` — four documents: `iam_policy_version_admin_and_default` (critical),
  `iam_policy_created_admin` (high, the `CreatePolicy` gap), `iam_policy_version_admin_dormant`
  (medium, the pre-loaded case), and `iam_policy_resource_wildcard_only` (informational, shipped to
  record that `Resource: "*"` is expected).
- `kql_t1098_003.kql` — separates live from dormant from `Resource`-only, and states inline that
  same-statement scoping is beyond what any query of this shape can decide.

Full response procedure is in `../PLAYBOOK.md`.
