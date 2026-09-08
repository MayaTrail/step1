# Detection Note — T1098.003 (IAM Inline Policy Grant)

**Signal:** an **inline** IAM policy document is written onto a user, role or group that
hands it an action from which it can reach account administrator unaided — most sharply
when the caller is also the grantee.

**Scope.** Inline route only: `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`. The
managed route — `CreatePolicyVersion` → `SetDefaultPolicyVersion`, and attaching
`AdministratorAccess` — escalates every principal the policy is attached to rather than
one, and is reversible because managed policies are versioned. Different response,
separate directory: `../../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/`.

**The grant is the whole attack.** There is no exploit, no payload, and no second
stage. `PutUserPolicy` succeeds or it does not, and if it succeeds the account is
already lost. Techniques whose playbooks describe "then the attacker does X" have a
window between foothold and impact; this one does not. Containment therefore **captures
the inline document before removing it** — the document is unversioned and exists nowhere
else once deleted — and only then revokes sessions.

**What the original rules got wrong.** They regexed the policy document for the
literal characters `"Effect":"Allow"` and `"Action":"*"`, carried no `errorCode`
filter, and never compared the caller to the grantee.

## The encoding claim, corrected — and the real hazard

An earlier revision of this note, and house rule A4, asserted that CloudTrail stores
`requestParameters.policyDocument` percent-encoded. **That is wrong, and it pointed the
critique of the source rules at a defect that does not exist.** The direction matters:

```
requestParameters.policyDocument   ->  RAW JSON, in the client's own whitespace
responseElements.*  /  Get*Policy  ->  percent-encoded, RFC 3986
```

AWS's `PutRolePolicy` reference documents no encoding on the request parameter, its sample
request carries bare JSON, and its accepted pattern `[\u0009\u000A\u000D\u0020-\u00FF]+`
admits tab, LF and CR — literal whitespace a percent-encoded string could not contain.
`GetRolePolicy` says the opposite about its output: *"Policies returned by this operation
are URL-encoded compliant with RFC 3986."* botocore closes the loop, registering
`json_decode_policies` on `after-call.iam` — response-side only, with no request-side
counterpart. **Decode responses. Never decode request parameters:** `unquote` turns a
literal `%2F` in an S3 key-prefix condition into `/`, and `unquote_plus` additionally
turns every `+` into a space, corrupting ARNs and tag values that legally contain one.

The real request-side hazard is **whitespace**. The source regex is
`\x22Effect\x22:[ ]?\x22Allow\x22` — zero-or-one space, on one line. A document
submitted the ordinary way, `--policy-document file://policy.json`, is pretty-printed
across newlines with indentation, and the regex misses it completely. That is an
encoding-independent, verifiable false negative, and it is the defect the top row of the
§2 table should have named.

The fix is the same either way: match tokens, not punctuation with assumed spacing. IAM
action names and the word `Allow` are whitespace-independent and appear identically in
both forms, which is why the shipped rules survived the corrected thesis unchanged.

## What no substring rule can do

Three questions decide whether a policy document is an escalation, and none of them
survive being flattened into substring matches:

1. **Is the statement Allow or Deny?** A permissions boundary that *denies*
   `iam:CreateAccessKey` contains the same tokens as a policy that grants it.
2. **Is `Action` exactly `*`, or is it `s3:Get*`?** Both contain an asterisk.
3. **Do the Allow and the escalation action sit in the same statement?** A document can
   Allow something harmless and Deny the primitive and match every rule above.
4. **Is the grant expressed as `NotAction`?** `{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"*"}`
   grants everything except one action. A parser reading only `Action` sees an empty list
   and stays silent — this was a real miss, now covered by a `NotAction` block in the
   Sigma and by `HasNotAction` in the KQL and the shared decoder.
5. **Is it a service wildcard?** `"Action":"iam:*"` is full IAM control, one call from
   administrator, and contains none of the named primitives. Its own sibling block now.

`sigma_t1098_003.yml` matches tokens; it does not answer these. The KQL companion
does, via `parse_json()` → `mv-expand` over the statement array, and **Query 2** of the
playbook does the same in `python3` via the shared `tools/decode_policy_documents.py`. **Treat a Sigma hit as a trigger for
the decode, not as a disposition.** That split is deliberate and is the same shape as
the rule-plus-drift-detector pairing in the `lambda_updatecode_nondeploy` note.

## Shape guards — the sweep fails silently without them

IAM accepts three fields in two shapes each, and the permissive shape is the one that
breaks naive iteration:

```
Statement  : a single object   OR  an array of objects
Action     : a string          OR  an array of strings
Resource   : a string          OR  an array of strings
```

`any(.Statement[]; ...)` against a single-object `Statement` iterates the object's
*values* and errors on `.Effect`, which in a `jq` pipeline means the statement is
skipped and the sweep reports clean. Normalise first, in both dialects:

```
jq   (.Statement // [] | if type=="object" then [.] else . end)
KQL  iff(gettype(Doc.Statement) == "array", Doc.Statement, pack_array(Doc.Statement))
```

The same guard applies to `Action` and `Resource`. This is shared with the
`iam_role_trust_backdoor` note, which parses trust policies with identical shape
hazards.

## The self-grant test

The single highest-confidence discriminator available here is not in the policy
document at all: **did the caller grant the permission to itself?**

```
userIdentity.arn  ->  IAM user      : name is the LAST '/' segment
                  ->  assumed-role  : role name is the SECOND '/' segment,
                                      the last segment is the SESSION name
requestParameters.userName / .roleName / .groupName  ->  the grantee
```

Reusing the user-parsing idiom on an assumed-role ARN compares a *session name*
against a role name and never matches, so the check quietly returns "not a self
grant" for exactly the principals most likely to be doing it. Both dialects in this
directory branch on the ARN type before extracting.

No legitimate workflow has a principal widen its own permissions. An IaC pipeline
grants to the resources it manages, not to the role it is running as.

## Response levers

**Permissions boundaries are the only structural control.** Detection tells you the
grant happened; a boundary caps what the grant can confer. It is also the only
control that still works when the granting principal is *legitimately* allowed to
write IAM policy, which is the case that defeats every allowlist.

**Inline policies are invisible to the obvious audit.**
`list-attached-user-policies` returns managed policies only. Inline policies need
`list-user-policies`, a different call. A responder sweeping for "who has admin"
with the first call sees a clean account. Both playbook sweeps call both.

**Inline policies have no version history — this is the whole reason the two routes are
separate playbooks.** A managed policy overwritten via `CreatePolicyVersion` leaves the
prior version retrievable through `GetPolicyVersion`, so the managed route has a clean
rollback target. `PutUserPolicy` onto an existing inline policy name replaces it
outright: the previous document exists nowhere except the earlier CloudTrail event.
Capture it before remediating or it is gone permanently, which is why Containment Step 1
here captures before it deletes.

**Error strings:** denials are `AccessDenied`. Not `Client.`-prefixed like EC2, and
not `AccessDeniedException` on this path — that form comes from service-evaluated
denials, which IAM policy writes are not. Match prefix-tolerantly anyway and confirm
against a real denied event in your own trail. Non-denial errors these calls throw,
which must **not** be counted as probing: `MalformedPolicyDocument`, `LimitExceeded`,
`NoSuchEntity`, `InvalidInput`.

**MITRE:** the source rules tag T1548 (*Abuse Elevation Control Mechanism*), which
describes bypassing an elevation control — UAC, sudo, setuid. Nothing is bypassed
here; the permission is granted through the supported API by a principal authorised
to call it. **T1098.003 (*Account Manipulation: Additional Cloud Roles*)** is the
precise mapping and is what this directory carries. A mapping-precision note, not an
operational defect — the source alerts fire on the right events.

**Severity:** the source rates these P2. IR view **High**, and P0 for the self-grant
and unconditioned-`*:*` cases. A P2 that pages nobody overnight is the wrong
disposition for an event whose completion *is* the compromise.

**GuardDuty:** no finding type detects the grant itself. `PrivilegeEscalation:IAMUser/AnomalousBehavior`
may fire on the anomaly, but it is behavioural and must not be relied on as the
control — it will not fire when the granting principal routinely writes IAM policy.

**Files here:**
- `sigma_t1098_003.yml` — four documents: inline escalation-primitive grant (`high`),
  inline wildcard grant (`medium`, encoding-fragile by construction), and a denied-write
  volume correlation (`medium`) with its base rule (`low`). The denied-write rule spans
  both routes deliberately: an actor probing does not know in advance which will work.
- `kql_t1098_003.kql` — the decoded, statement-parsed version, plus the denied-probe
  companion.
- The decoder itself is shared tooling: `tools/decode_policy_documents.py` in the kit
  root, used by this playbook's Query 2 and by the managed-policy sibling.

Full response procedure is in `../PLAYBOOK.md`.
