# Detection Note — T1098.003 (IAM Managed Policy Escalation)

**Signal:** a new version of a customer-managed policy is created whose document grants
an escalation primitive or an unrestricted action and is promoted to default — or an
administrator-equivalent AWS managed policy is attached to a principal outright.

**Scope.** Managed route only: `CreatePolicyVersion` → `SetDefaultPolicyVersion`, and
`AttachUserPolicy` / `AttachRolePolicy` / `AttachGroupPolicy`. The inline route —
`PutUserPolicy` and its siblings — escalates one named principal with no version history,
and ships in `../../../iam.privilege-escalation.inline-policy-grant/`.

**The blast radius is a count, not a name.** This is the property that separates the two
routes. An inline grant escalates the principal named in the request, and you can read
that name off the event. A promoted policy version applies to **every principal the
policy is already attached to**, and that set appears nowhere in the CloudTrail event —
it has to be retrieved with `iam:ListEntitiesForPolicy` at response time. A responder who
triages this from the event alone will under-scope the incident, sometimes by an order of
magnitude.

**The compensation is that rollback is clean.** Managed policies are versioned, so the
pre-incident document is still retrievable through `GetPolicyVersion` and a single
`set-default-policy-version` reverses the grant for every affected principal at once. The
inline route has no such target — there, deletion destroys the only copy.

## What the original rules got wrong

**`SetDefaultPolicyVersion` alerted P2 on a bare event-name match.** That is exactly what
every legitimate policy rollback looks like. It fires on routine operations, gets muted
within a week, and takes the escalation sequence with it. Neither half of the two-call
technique is suspicious alone — `CreatePolicyVersion` without `--set-as-default` changes
nothing at all — so the **ordered sequence, grouped by principal and policy ARN**, is the
only form of this signal worth deploying.

**`requestParameters.policyArn:AdministratorAccess` was an unanchored term match.** It
also matches `AdministratorAccess-Amplify` and `AdministratorAccess-AWSElasticBeanstalk`,
which are narrowly-scoped service policies routine in any account running those services.
Anchoring with `|endswith: ':policy/AdministratorAccess'` removes them. `IAMFullAccess` is
added because it grants the entire IAM surface — account takeover in one further hop —
without the word Administrator anywhere in its name.

**The `Policy Escalation` flow was tautological.** It combined a building block matching
twelve IAM event names with a second block matching a strict subset of those same names,
at a zero-millisecond timeframe. A single `AttachUserPolicy` of `AdministratorAccess`
satisfies both stages simultaneously, so the flow fired on precisely the events its
second stage already caught and added nothing. A correlation is only worth its complexity
when the stages are genuinely distinct and genuinely ordered.

**The document regex allowed zero-or-one space, on one line.**
`requestParameters.policyDocument` is **raw JSON** in whatever whitespace the client sent,
and `--policy-document file://policy.json` submits it pretty-printed across newlines — so
`\x22Effect\x22:[ ]?\x22Allow\x22` misses every document written the ordinary way.
Percent-encoding is a property of what IAM *returns* (`responseElements`, the `Get*Policy`
APIs), not of request parameters; decoding a request parameter actively corrupts it. The
full treatment is in the inline sibling's note and applies identically here.

## Field shape — the trap specific to this route

`CreatePolicyVersion` **nests** its response:

```
responseElements.policyVersion.versionId       (correct)
responseElements.policyVersion.isDefaultVersion (correct — tells you if --set-as-default
                                                 was used, so no second call is coming)
responseElements.versionId                     (null, always)
```

`isDefaultVersion` is worth reading carefully. When it is `true` the version went live on
creation and there is no `SetDefaultPolicyVersion` event to correlate against — a
sequence-only detection misses it entirely, which is why the shipped Sigma alerts on the
escalating document at `high` in its own right rather than relying on the correlation.

The `Statement` / `Action` / `Resource` scalar-or-array shape guards apply here exactly as
they do on the inline route. Both playbooks call the same shared decoder,
`tools/decode_policy_documents.py`, so the guards live in one place.

## Response levers

**Get the blast radius before you roll back.** `list-entities-for-policy` names every
user, role and group holding the policy. Rolling back first removes the grant but also
removes your ability to enumerate who held it, and the CloudTrail event never carried
that list.

**Roll the default version back; do not delete the policy.** It is attached to principals
that still need it. `set-default-policy-version` is the reversal.

> The CLI verb is `aws iam set-default-policy-version`, from the API name
> `SetDefaultPolicyVersion`. `set-policy-default-version` does not exist and fails at the
> point of rollback.

**Capture every version before touching the default pointer.** A policy holds at most
five versions. An actor escalating through one already at the cap must call
`DeletePolicyVersion` first, and that document is then unrecoverable from IAM — so the
history you are about to diff may already be incomplete. `DeletePolicyVersion`
immediately preceding `CreatePolicyVersion` on the same ARN is a reliable precursor.

**Error strings:** `AccessDenied` on denial — not `Client.`-prefixed like EC2. Non-denial
errors on this path, which must **not** be counted as probing: `LimitExceeded` (the
five-version cap), `MalformedPolicyDocument`, `NoSuchEntity`, `InvalidInput`.

**MITRE:** the source alerts tag T1548 (*Abuse Elevation Control Mechanism*), which
describes bypassing an elevation control. Nothing is bypassed — the permission is granted
through the supported API by a principal authorised to call it. **T1098.003**
(*Account Manipulation: Additional Cloud Roles*) is the precise mapping. Mapping-precision,
not an operational defect.

**Severity:** the source rates these P2. IR view **High**, P0 where the promoted document
is an unconditioned `*:*` — one call escalating every attached principal is not a
next-business-day finding.

**GuardDuty:** no finding type detects the version promotion itself.
`PrivilegeEscalation:IAMUser/AnomalousBehavior` may fire behaviourally but will not when
the promoting principal routinely manages IAM policy, so it cannot be the control.

**Files here:**
- `sigma_t1098_003.yml` — five documents: admin managed-policy attach (`high`), escalating
  policy version created (`high`), the `CreatePolicyVersion` → `SetDefaultPolicyVersion`
  sequence correlation (`high`) and its two base rules (`low`).
- `kql_t1098_003.kql` — the decoded, statement-parsed version, plus the sequence and
  admin-attach companions and the blast-radius and five-version-cap notes.
- Shared decoder: `tools/decode_policy_documents.py` in the kit root.

The denied-IAM-write volume correlation covering probing on **both** routes ships once, in
`../../../iam.privilege-escalation.inline-policy-grant/detections/sigma_t1098_003.yml` —
an actor probing does not know in advance which route will work, so splitting that signal
in two would destroy it.

Full response procedure is in `../PLAYBOOK.md`.
