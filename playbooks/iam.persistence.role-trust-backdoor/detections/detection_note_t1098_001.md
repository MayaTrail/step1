# Detection Note — T1098.001 (IAM Role Trust-Policy Backdoor)

**Signal:** a role's **trust policy** is rewritten so that a principal outside the
organisation — a foreign 12-digit account, `"AWS":"*"`, or an unfamiliar OIDC/SAML
provider — may call `sts:AssumeRole` on it, with **no `Condition` confining who that
principal may be**.

**This is resource-based-policy persistence, one of the few classes credential rotation
does not touch.** Most AWS persistence playbooks end with "rotate the credential"; this one,
a backdoored S3 bucket policy, a Lambda resource policy and a KMS key policy do not. Rotate
every access key, every console password, every session token in the account, and a
backdoored trust policy still works — because the attacker holds no credential of yours. They hold an
identity of their own that your account has been told to trust. The role, its ARN, its
attached policies, its tags and its last-used timestamp are all unchanged; a single
document that nobody routinely reads now names one extra principal.

**What the original rules got wrong** — one matched `UpdateAssumeRolePolicy` by name with
no content inspection at all and no principal check, at P2; the other inspected the
document but only for a literal wildcard, at P3. Between them, the ordinary case — a trust
naming one specific foreign account — is matched by neither, and the case that *is* matched
is rated below the rule that fires on every IaC trust edit.

## Where the trust document lives, and the field split that breaks a naive port

Two events write a trust policy, and they use different field names:

```
UpdateAssumeRolePolicy  ->  requestParameters.policyDocument
CreateRole              ->  requestParameters.assumeRolePolicyDocument
```

They **never co-occur on one event**. The source rule ORs them, which is right. A Sigma
port that puts both `|contains` keys in one `selection:` block ANDs them, and the result is
a P0 rule that can never fire — a silent false negative that looks like a quiet
environment. `sigma_t1098_001.yml` keeps them as sibling blocks in every rule.

`CreateRole` also nests its response: `responseElements.role.arn`, `.roleName`, `.roleId`,
`.assumeRolePolicyDocument`. A flat `responseElements.arn` yields `null` silently. This is
the same nesting hazard as `CreateAccessKey` → `responseElements.accessKey.accessKeyId`,
described in the `iam_inline_escalation_primitive_granted` note.

`UpdateAssumeRolePolicy` returns **no** `responseElements` at all, and it **overwrites**
the previous trust policy. The only surviving copy of what the trust used to be is the
earlier CloudTrail event that set it — which is why the playbook's Containment Step 1
captures the current document before restoring, and why a baseline of trust policies is a
§1 preparation item rather than a nice-to-have.

## Encoding: the direction matters, and it is the opposite of the folklore

`requestParameters.policyDocument` and `.assumeRolePolicyDocument` are **raw JSON**. The
accepted pattern for both parameters explicitly admits tab, line feed and carriage
return — literal whitespace a percent-encoded string could not contain — and both API
reference sample requests carry bare JSON. Percent-encoding (RFC 3986) is a property of
what IAM **returns**: `GetRole` states that policies it returns are URL-encoded, and the
AWS CLI and boto3 decode responses for you through a handler registered on `after-call.iam`
with no request-side counterpart.

So the request-side hazard is **whitespace, not encoding**:

```
compact  {"Principal":{"AWS":"999988887777"}}
pretty   {\n    "Principal": {\n        "AWS": "999988887777"\n    }\n}
```

A regex that allows zero-or-one space after a colon matches the first and misses the
second, and a trust policy submitted with `--assume-role-policy-document file://trust.json`
is the second. Every pattern in `sigma_t1098_001.yml` is either a bare alphanumeric token
(`Federated`, a 12-digit account ID) or a `|re` carrying explicit `\s*`.

The decoder in `tools/decode_policy_documents.py` decodes **conditionally** — only input
that actually starts percent-encoded — which is what lets the same tool read a CloudTrail
request parameter and a `get-role` response without corrupting either.

## The Condition is the discriminator, not the principal

A trust naming a foreign account is not by itself a finding. It is how third-party access
is *supposed* to work, and alerting on the principal alone pages on every partner
integration until somebody mutes the rule.

```
BACKDOOR    "Principal": {"AWS": "999988887777"},
            "Action": "sts:AssumeRole"

LEGITIMATE  "Principal": {"AWS": "999988887777"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "<per-customer id>"}}
```

`sts:ExternalId` exists to address the confused-deputy problem: the third party must supply
a value only it and you know. `aws:PrincipalOrgID` binds the caller to an AWS Organizations
membership. For a federated trust the equivalent is pinning the token — a `Condition` on
the provider's `:sub` or `:aud` claim, which is what makes a CI-provider trust safe rather
than "anyone with an account at that provider".

**The absence of any of these on a trust that reaches outside the organisation is the
finding.** Both the KQL and the shared decoder test exactly that pair.

## Shape guards — the sweep reports clean without them

A trust policy is the same grammar as an identity policy plus a `Principal`, and the
resource-policy family it belongs to carries one more permissive shape than the identity
case:

```
Statement   : a single object   OR  an array of objects
Principal   : an object         OR  the bare string "*"     <- resource policies
Principal.AWS / .Federated / .Service : a string  OR  an array
```

For anonymous access AWS documents `"Principal": "*"` and `"Principal": {"AWS": "*"}` as
equivalent, so a parser that reaches for `.Principal.AWS` and finds a string returns nothing
on the more dangerous of the two forms. Iterating the bare string yields its characters;
iterating an object yields its keys. Both failure modes are silent. A **role trust policy**
refuses the bare form specifically (`ROLE_TRUST_POLICY_UNSUPPORTED_WILDCARD_IN_PRINCIPAL`),
so on this path the guard costs nothing and earns its keep in the bucket-policy and
Lambda-resource-policy dialects that share the same parser.

```
jq   (.Statement // [] | if type=="object" then [.] else . end)
KQL  iff(gettype(Doc.Statement) == "array", Doc.Statement, pack_array(Doc.Statement))
```

The `Statement` and scalar-or-array guards are shared with the
`iam_inline_escalation_primitive_granted` note; the `Principal` guard is specific to
resource-based policies and applies equally to a bucket policy or a Lambda resource policy.

**`NotPrincipal` is NOT a trust-policy shape, and treating it as one sends a responder
hunting a document that was never stored.** AWS prohibits it twice over — *"`NotPrincipal`
must be used with `"Effect":"Deny"`"* and *"You cannot use the `NotPrincipal` element in an
IAM identity-based policy nor in an IAM role trust policy"* — and Access Analyzer publishes
the rejection as the ERROR check `ROLE_TRUST_POLICY_SYNTAX_ERROR_NOTPRINCIPAL`. The write
fails with `MalformedPolicyDocument`, which sets `errorCode`, which every rule here already
filters out: a verdict on this shape would be dead twice, at the API and at the rule. What
the shape *is* is evidence on the **error path** — an actor trying a principal form IAM
refuses. The shared decoder keeps its `NotPrincipal` branch gated on `Effect == "Deny"`,
where it serves the resource-policy dialects (bucket policies, VPC endpoint policies) that
do accept it; the trust path never reaches it.

## What the source rules could never have caught

Three of the wildcard rule's four branches name a shape a role trust policy **rejects**,
and each is published by AWS as an Access Analyzer ERROR check or a User Guide prohibition.
One evidentiary standard, applied three times:

```
"Service":"*"     "The service principal in an IAM policy can't be "Service": "*""
"Federated":"*"   INVALID_FEDERATED_PRINCIPAL_SYNTAX_IN_ROLE_TRUST_POLICY
"Principal":"*"   ROLE_TRUST_POLICY_UNSUPPORTED_WILDCARD_IN_PRINCIPAL   (bare form)
```

All three fail with `MalformedPolicyDocument`, which sets `errorCode`, which the rule
already excludes — dead twice over. `{"AWS":"*"}` is the **one** wildcard form AWS documents
as accepted in a trust policy, and it is the one the shipped rule matches. The general
statement that `"Principal":"*"` and `{"AWS":"*"}` are equivalent is about resource-based
policies at large; the role-trust dialect is narrower, and the bare form is refused there.
The cost of the reduction is exactly that one shape, and it reappears on the error path
where it belongs.

A fourth defect cuts across all four branches and is a **dialect** problem, not a content
one. The source regexes do carry
`\s*` — but they are Lucene `regexp` terms, and Lucene's RegExp grammar has no `\s`
shorthand (`\<char>` means that literal character), so `\s*` reads as "zero or more letter
`s`" and matches nothing in a pretty-printed `"Principal":  {`. Sigma `|re` on a backend
with RE2/PCRE/.NET semantics — or Lucene 9 and later — defines `\s`; on Lucene 8 substitute
an explicit `[ \t\n\r]*`, the four characters the parameter's own pattern admits.

Neither rule looks at the denied path, so a principal probing which role it is allowed to
reshape is invisible. `iam_trust_write_denied` plus its correlation covers that, kept
strictly separate from the success path: reconnaissance and a completed rewrite are
different incidents.

## "Was it used" — a verified pivot, with a verified limit

When a principal in another account assumes a role here, **this** account's trail carries
its own `AssumeRole` event, in a `userIdentity` shape nothing else produces:

```
"userIdentity": { "type": "AWSAccount", "principalId": "AIDA...",
                  "accountId": "<the CALLING account>" }
```

There is no `userIdentity.arn`. A "who used this role" query keyed on the ARN returns
nothing and reads as *not used*. Federated use lands as `WebIdentityUser` or `SAMLUser`
with a `userIdentity.identityProvider`. All of these are **management** events — this is
not a data-plane blind spot, and `lookup-events` retrieves them.

The `sharedEventID` is the same GUID in both accounts' trails. If the calling account is
one you own, that GUID is how you attribute the session to a named principal there; your
copy only ever names the account.

**The limit:** AWS documents that CloudTrail does **not** log denied STS requests in the
target account for cross-account role assumptions. An empty result is evidence about
successful use only. Never present it as "nobody tried".

## Response levers

**Restoring the trust policy ends new sessions, not existing ones.** `UpdateAssumeRolePolicy`
back to the baseline stops the attacker minting *new* credentials; sessions already issued
run to their expiry — up to `MaxSessionDuration`, which is settable to 12 hours. Revoking
them needs a `Deny` on `aws:TokenIssueTime` before the cutoff, and that denies only tokens
issued *before* it. Restore the trust first, then revoke, in that order; the reverse leaves
a window in which the attacker re-assumes with a fresh, undenied `TokenIssueTime`.

**IAM Access Analyzer is the control that does not depend on catching the write.** With the
organization as its zone of trust, it analyses role trust policies and raises a finding for
every role reachable by a principal outside that zone — including roles backdoored before
the detection existed. AWS documents up to 30 minutes between a policy change and the finding
update. For external access it analyses resources in the Region where it is enabled — **but
an IAM role is a global resource**, and AWS states that a role trust policy granting external
access "generates a finding in each enabled Region". Read that in both directions: one
backdoored role produces N identical findings to archive, and an analyzer enabled in a single
Region was **not** blind to roles used elsewhere.

**Error strings:** IAM policy denials are `AccessDenied`; service-evaluated denials are
`AccessDeniedException` — match the substring and confirm the exact form against a real
denied event in your own trail. Non-denial errors these calls throw, which must **not** be
counted as probing: `MalformedPolicyDocument`, `NoSuchEntity`, `LimitExceeded`,
`ServiceFailure`, and `UnmodifiableEntity` — the last meaning a service-linked role, which
AWS describes as "protected AWS resources" that only the depending service may modify — plus
`EntityAlreadyExists`, `InvalidInput` and `ConcurrentModification` on `CreateRole`. One of
them is not inert: a `MalformedPolicyDocument` whose document names `NotPrincipal`,
`"Federated":"*"`, `"Service":"*"` or a bare `"Principal":"*"` is an actor trying a rejected
principal shape, and belongs beside the `AccessDenied` probing rather than beside a stored
backdoor.

**MITRE:** the account-principal rules carry `T1098.003` (*Additional Cloud Roles*) beside
`T1098.001`, and T1098.003 is the closer of the two: its published text says adversaries "may
add roles to adversary-controlled accounts **outside the victim cloud tenant**", letting those
external accounts act inside the tenant without creating or modifying a victim-owned account
— this technique, described. `T1098.001` (*Additional Cloud Credentials*) is kept because the
rewritten trust is a credential source the adversary controls, added alongside the legitimate
ones, though its own description does not mention trust policies. Both carry Persistence
(TA0003) and Privilege Escalation (TA0004), so the pair changes no disposition. For the
**federated** variant `T1484.002` (*Trust Modification*) is closer still and is explicit about
AWS: adding an identity provider lets an adversary federate in. Its tactics are **Defense
Impairment (TA0112)** and Privilege Escalation — *not* Persistence — so
`iam_role_trust_unknown_federated_provider` carries `attack.defense-impairment` beside its
persistence tag. `attack.defense-evasion` is retired; TA0005 is now **Stealth** and is not a
tactic of anything here. A mapping-precision note, not an operational defect — the source
alerts fire on the right events.

**Severity:** the source rates these P2 and P3. IR view **High**, and **P0** for a foreign
account, a wildcard principal, or an unrecognised provider with no confining `Condition`.
A P3 on "any AWS principal on the internet may assume this role" is the wrong disposition
by two levels, and the P2 sits above it on the bare event-name rule that fires on every
legitimate trust edit — so the more severe finding arrives with the lower priority.

**GuardDuty:** no finding type detects a trust-policy backdoor. The IAM finding types are
all `Resource Type: AccessKey`. The nearest is `PrivilegeEscalation:IAMUser/AnomalousBehavior`,
whose category AWS describes as "operations that change IAM policies, roles, and users, such
as, `AssociateIamInstanceProfile`, `AddUserToGroup`, or `PutUserPolicy`" — an
`UpdateAssumeRolePolicy` is squarely that. `Persistence:IAMUser/AnomalousBehavior` is the
tactic match but the wrong API family: its examples are `CreateAccessKey`, `ImportKeyPair`
and `ModifyInstanceAttribute`. Either may fire behaviourally on an anomalous caller, and
neither fires at all when the principal that rewrites trust policies routinely rewrites trust
policies. Do not rely on GuardDuty as the control.

**Files here:**
- `sigma_t1098_001.yml` — seven documents: external account principal (`high`), wildcard
  principal (`high`), unrecognised federated provider (`high`, dual-tagged T1484.002 and
  `attack.defense-impairment`), trust rewritten by an unexpected principal (`medium`),
  external `AssumeRole` into this account (`high` — it backs a P1 alert, and a P1 signal on a
  `medium` rule routes to the wrong queue), and the denied-write base rule (`low`) with its
  volume correlation (`medium`). There is deliberately **no** oversized/omitted-document rule:
  a trust policy is quota-capped ~12x below CloudTrail's 100 KB omission threshold, so such a
  rule could never fire.
- `kql_t1098_001.kql` — the decoded, statement-parsed, per-principal version with the
  Condition test, plus the commented "was it used" companion and the field-shape notes.
- The decoder is shared tooling: `tools/decode_policy_documents.py` in the kit root,
  extended here with `Principal` handling and driven by Query 2 of the playbook. Its
  `NotPrincipal` branch is gated on `Effect == "Deny"` and is unreachable from the trust
  path; it exists for the resource-policy dialects that share the tool. It is the same tool
  the two IAM policy-grant playbooks and the S3 bucket-exposure playbook call, and their
  identity-policy behaviour is byte-for-byte unchanged.

Full response procedure is in `../PLAYBOOK.md`.
