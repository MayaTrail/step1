# Detection Note — T1098 (Lambda Resource-Policy Backdoor)

**Signal:** a statement is added to a Lambda function's **resource-based** policy granting
invoke rights to a principal that nothing confines — an account outside the organisation,
a bare `*` with no `principalOrgID`, or an AWS service principal carrying neither
`sourceArn` nor `sourceAccount`.

**This is the only technique in the set where the grant lives on the resource, not on an
identity.** Its neighbours — the inline-policy grant, the managed-policy escalation, the
role-trust backdoor — all write onto a principal, so rotating that principal's credentials,
revoking its sessions or repairing its trust policy ends the access. None of that touches
this. The function keeps its code, its `CodeSha256`, its execution role, its environment
variables and its event source mappings. Only the answer to "who may call it" changed, and
that answer is stored on the function.

**What the original rules got wrong** — two rules cover this API and **neither returns a
single event**, before any question of content arises.

## The event name, which is where both rules die

AWS documents the CloudTrail event name for this API as **`AddPermission20150331v2`**, not
`AddPermission`. The Lambda CloudTrail reference lists the versioned form explicitly,
alongside `RemovePermission20150331v2`, `UpdateFunctionCode20150331v2` and
`UpdateFunctionConfiguration20150331v2`.

```
rule A   eventName.keyword:/addpermission.*/          -> lower-case, case-sensitive field
rule B   eventName.keyword:/AddPermission|RemovePermission/  -> anchored, no suffix allowed
```

Rule A has the trailing `.*` that would absorb the version suffix but spells the name in
lower case, and a `keyword` subfield is indexed verbatim — regexp matching is
case-sensitive unless `case_insensitive` is set, which defaults to false. Rule B has the
casing right but no `.*`, and Lucene anchors a regexp to the **entire** term, so the
alternation demands the event name be exactly `AddPermission` or exactly
`RemovePermission`.

Each rule holds exactly one of the two properties it needs. The pack's own sibling rules
settle the argument: they match `/UpdateFunctionCode.*/` and
`/UpdateFunctionConfiguration.*/` **with** the `.*`, which is only necessary if the suffix
exists. The authors knew, and dropped it here.

The fix is `|startswith`, which matches the bare and the versioned form alike and cannot
be broken by a future suffix. **Confirm the exact string in your own trail before
deploying** — this is the one claim in this directory that a single `lookup-events` call
in your account can settle, and the correction is safe under either observation.

The same trap catches the responder, not just the rule: `aws cloudtrail lookup-events
--lookup-attributes AttributeKey=EventName,AttributeValue=AddPermission` matches exactly
and returns nothing. Query 1 of the playbook loops over both forms for that reason.

## The discriminator is confinement, not the principal

`AddPermission` is what every S3 trigger, EventBridge rule and API Gateway integration
does at deploy time. The principal alone does not separate them either —
`s3.amazonaws.com` is the most common legitimate value on the API and also the
confused-deputy shape. What separates them is whether anything **bounds** the grant:

```
service principal   confined by   sourceArn   or   sourceAccount   (nothing else)
wildcard principal  confined by   principalOrgID                   (nothing else)
account / ARN       confined by   being in your organisation       (external list)
```

AWS states the consequence in the `AddPermission` reference itself: *"If you grant
permission to a service principal without specifying the source, other accounts could
potentially configure resources in their account to invoke your Lambda function."* A
statement naming `s3.amazonaws.com` with no `sourceArn` and no `sourceAccount` means any
bucket in any AWS account can be pointed at your function. Neither source rule reads
`requestParameters.principal` at all, so both would score that identically to a correctly
scoped trigger.

The inverse also matters, and a naive rule gets it wrong: `Principal: "*"` **with**
`aws:PrincipalOrgID` is AWS's own documented organisation-wide grant. A rule that fires on
`*` alone alerts on the recommended pattern. `no_org_id` in the Sigma exists for that.

## What no substring rule can do

Two questions decide the disposition and neither is a substring question:

1. **Is this account ID one of ours?** It needs the organisation's account list. The Sigma
   carries a placeholder allowlist that must be populated; the KQL carries `OrgAccounts`.
2. **What does the whole policy say now?** `AddPermission` events show **one statement
   each**, and only within the log window. A responder reconstructing the policy from
   events alone misses every statement added before retention began. **`GetPolicy` is the
   only call that returns the whole document**, which is why the playbook's account-wide
   sweep is built on it rather than on CloudTrail.

The shared decoder in `tools/decode_policy_documents.py` is deliberately **not** used for
this technique. Its trust-policy evaluator classifies every `Service` principal as
informational without testing `sourceArn` or `sourceAccount` — which is exactly the
discriminator here, so routing this policy shape through it would report the
confused-deputy grant as benign. Query 2 of the playbook does the parse inline, with the
same scalar-or-array shape guards the decoder documents.

## The response-shape trap

`AddPermission` returns `{"Statement": "..."}` — the statement it just added, as a **JSON
string**, not an object.

```
responseElements.statement          -> a string of JSON
responseElements.statement.Principal -> null, silently, forever
responseElements.statement | fromjson | .Principal  -> the actual grant
```

It is also only the one statement. `GetPolicy` returns `Policy` — also a JSON string — and
that one is the whole document.

## Was it used — and why absence proves less here

**`lambda:Invoke` is a data event** (`resources.type` `AWS::Lambda::Function`), off by
default. `lookup-events` returns zero for it forever, and that zero must never be reported
as "the backdoor was not used". This is the opposite of the IAM siblings, where management
events are complete and an empty result is real evidence.

Where a Lambda data-event trail does exist, one field-shape choice decides whether the query
works at all: **match the function on `resources[].ARN`, never on
`requestParameters.functionName`.** `resources.ARN` is the identity CloudTrail's own advanced
event selectors use for `AWS::Lambda::Function`, so it is normalised to the unqualified
function ARN. `requestParameters.functionName` is **caller-typed** — it carries whatever the
caller passed, which may be a bare name, a full ARN, or an alias- or version-qualified ARN —
so name equality silently drops every invoke made in a form you did not anticipate, and an
attacker testing a backdoor has no reason to use the form you guessed. Write the query to
tolerate a null or absent `requestParameters` rather than depending on either. For a
cross-account invoke the event lands in the **function owner's** trail with
`userIdentity.accountId` set to the calling account — that mismatch against
`recipientAccountId` is the proof.

> An earlier revision of this note, and house rule A10, asserted that a *synchronous* invoke
> records `requestParameters: null`. AWS does not document that, and a published AWS example
> shows a `RequestResponse` invoke with `requestParameters` populated. The prescription above
> is unchanged; only its stated reason was wrong. A10 was corrected on 2026-08-29.

Without a data trail the fallback is the CloudWatch `AWS/Lambda` `Invocations` metric,
which shows *whether* the function ran but never *who* called it.

## Adjacent exposure — function URLs, and where the boundary is

`CreateFunctionUrlConfig` with `AuthType: NONE` publishes an unauthenticated HTTPS
endpoint. **Scope decision: the resource-policy half is this technique; the URL
configuration is a sibling exposure.** The URL grants nothing on its own — AWS is explicit
that a function URL whose policy does not allow `lambda:InvokeFunctionUrl` and
`lambda:InvokeFunction` returns 403 even with `AuthType: NONE`. The load-bearing half is
`AddPermission` with `principal *`, which the primary rule already matches. The
configuration half ships as a commented companion in the KQL and as a P1 trigger.

**Since October 2025 the public path is TWO `AddPermission` calls, not one.** AWS: *"Starting
in October 2025, new function URLs will require both `lambda:InvokeFunctionUrl` and
`lambda:InvokeFunction` permissions."* The CLI cannot combine them:

```
add-permission --action lambda:InvokeFunctionUrl --principal * --function-url-auth-type NONE
add-permission --action lambda:InvokeFunction    --principal * --invoked-via-function-url
```

Both carry `principal *` with no `principalOrgID`, so the primary rule fires twice, seconds
apart, on the same function. Two hits are the expected shape, not a duplicate — and a
single hit on `lambda:InvokeFunctionUrl` alone is an incomplete backdoor that returns 403
until the second call lands.

Two further facts belong in the response: the console and SAM add the statements for you,
so the pairing may arrive as one operation, whereas the CLI, CloudFormation and the API
require explicit `add-permission` calls; and **deleting a function URL does not delete the
associated resource-based policy** — AWS: *"If you delete a function URL with auth type
`NONE`, Lambda doesn't automatically delete the associated resource-based policy."* An
orphaned public grant outlives the endpoint that justified it.

## Response levers

**Removing the statement is immediately effective and needs no session revocation.**
Authorization is evaluated per request against the current policy, so the outside caller
loses access on its next call. Nothing about the invoker needs to be contained — its
ability came entirely from your resource.

**Capture the policy before you remove anything.** A function's resource policy has no
version history. `RemovePermission` deletes the statement outright, and `PutResourcePolicy`
replaces the entire document; in both cases the prior content survives only in the
CloudTrail event. This is the same evidence-first ordering as the inline-policy sibling and
for the same reason.

**Removing the statement does not undo an invocation.** A synchronous invoke returns the
handler's response body to its caller. If the function reads a database, decrypts a secret
or proxies an internal API, that data left the account and no policy change recalls it.

**Sweep every region.** Lambda is regional — unlike IAM, whose events all land in
`us-east-1`. A single-region sweep reports clean on an account backdoored elsewhere.

**Error strings:** IAM-policy denials on this path are `AccessDenied`; service-evaluated
denials are `AccessDeniedException` — match both, prefix-tolerantly, and confirm against a
real denied event. Codes that are **not** denials and must not be counted as probing:
`PublicPolicyException`, `ResourceConflictException` (that `StatementId` already exists),
`ResourceNotFoundException`, `InvalidParameterValueException`, `PreconditionFailedException`
(stale `RevisionId`), `PolicyLengthExceededException`, `TooManyRequestsException`.
Lambda's errors are not `Client.`-prefixed like EC2's.

**There is no size-based evasion path.** The function resource policy is capped at 20 KB,
and `PutResourcePolicy`'s `Policy` parameter at 20,480 characters — both far below
CloudTrail's 100 KB `requestParameters` omission threshold. An oversized document is
rejected with `PolicyLengthExceededException` and never stored, so no companion rule for
an omitted-parameters event is shippable here. Same conclusion as the IAM siblings, from a
different quota.

**MITRE:** the source rules tag **T1584** (*Compromise Infrastructure*), tactic **TA0042**
(*Resource Development*) — a technique about an adversary taking over third-party
infrastructure **before** an operation, to stage it from. Nothing here is pre-operational
and nothing third-party is compromised: the actor already holds credentials in the victim
account and manipulates a resource inside it to keep them. **T1098 (*Account
Manipulation*)**, tactic **Persistence (TA0003)**, is the correct mapping and is what this
directory carries. The parent technique is the right precision level: T1098's cloud
sub-techniques — `.001` Additional Cloud Credentials and `.003` Additional Cloud Roles —
are both identity-side, and no sub-technique covers a grant written onto a **resource**.
This is a substantive mapping error rather than a precision note: T1584/TA0042 routes the
alert into a pre-attack bucket, and one of the two source rules carries no mapping at all.

**Severity:** the source rules rate these **P4** and **P3**. IR view **High, P0**. The
grant survives every credential-side remediation, it is invisible to
`list-attached-role-policies` and to any permissions boundary or SCP on your own
principals, and in most accounts its exercise is unlogged. A P4 does not page.

**GuardDuty:** **no finding type detects this.** GuardDuty Lambda Protection monitors a
function's *network activity* — `Backdoor:Lambda/C&CActivity.B`,
`CryptoCurrency:Lambda/BitcoinTool.B`, `UnauthorizedAccess:Lambda/MaliciousIPCaller` — which
is about what the code does once running, not about who is permitted to run it. It will not
fire on a policy change, and it will not fire on a benign-looking invocation from an
attacker-controlled account. Do not treat its silence as coverage.

**IAM Access Analyzer external-access findings are the control that does watch this
surface — with one blind spot.** AWS lists *AWS Lambda functions and layers* among the
supported resource types and states that it *"reports external access based on
resource-based policies attached to functions and layers"* but *"doesn't report external
access based on resource-based policies attached to aliases and specific versions invoked
using a qualified ARN."* `AddPermission` takes a `Qualifier`, so a grant added to
`my-function:prod` is invisible to Access Analyzer while remaining fully usable. The
CloudTrail event and a `GetPolicy` sweep that iterates qualifiers are the only cover for
that case. The continuous config-side check is the AWS Config managed rule
`LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED` (`AWS::Lambda::Function`, configuration-change
triggered), which is `NON_COMPLIANT` for an empty or wildcard `Principal` **and** for an
S3-invoked function whose statement carries no source-limiting condition — the
confused-deputy shape, checked without an analyst.

**Resource control policies do not apply to Lambda.** An RCP is the standard answer when
the threat actor is a principal in someone else's account, and AWS Organizations' list of
services whose actions RCPs apply to does not include `lambda` (verified 2026-08-28). An
RCP denying `lambda:InvokeFunction` on a foreign `aws:PrincipalOrgID` is unenforceable. An
SCP cannot reach the invoker either, since SCPs bind only principals inside your own
organisation. The organisation-level control that *does* work constrains the call that
creates the grant — see the prevention block in `kql_t1098.kql`.

**Files here:**
- `sigma_t1098.yml` — five documents: unconfined-principal grant (`high`), external-account
  grant (`high`, needs the organisation allowlist populated), wholesale policy replacement
  via `PutResourcePolicy` (`medium`), public policy blocked by the public-access block
  (`medium`), and a `value_count` correlation escalating a three-function sweep (`high`).
- `kql_t1098.kql` — the parsed version, with the organisation-account comparison the Sigma
  cannot express, plus commented companions for the data-plane invoke pivot and for
  unauthenticated function URLs.

Sibling techniques sharing traps with this one: the role-trust backdoor
(`../../iam.persistence.role-trust-backdoor/`) shares the external-principal
discriminator and the policy-shape guards; the code-overwrite playbook in `reference/`
shares the Lambda data-plane invoke caveat.

Full response procedure is in `../PLAYBOOK.md`.
