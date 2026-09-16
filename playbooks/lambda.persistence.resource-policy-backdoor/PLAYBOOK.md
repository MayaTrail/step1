# IR Playbook: Lambda Resource-Policy Backdoor — Persistent Invoke Grant through `lambda:AddPermission`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Account manipulation (a statement is added to a Lambda function's resource-based policy, granting invoke rights to a principal outside the account's control) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0. The grant lives on the **resource**, so every credential-side remediation a responder reaches for first — rotating access keys, revoking sessions, repairing a role's trust policy, redeploying the function's code — leaves it fully intact. It is invisible to `list-attached-role-policies`, to a permissions boundary, and to any SCP written against your own principals, because the principal it empowers is not yours. And in a default account its *exercise* is unlogged: `lambda:Invoke` is a data event, off unless someone turned it on. The source rules rate this **P4** and **P3**; a P4 does not page, and neither rule fires at all (§2). Raising the disposition is the change that matters before any rule logic is touched |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1098 |
| Services in Scope | Lambda, CloudTrail (management **and** Lambda data events), IAM, STS, CloudWatch, Organizations (SCP), IAM Access Analyzer, AWS Config, plus every service the function's execution role can reach |

**What the technique does:** the actor calls `lambda:AddPermission` against a function it can already modify. One call appends one statement to that function's resource-based policy — `Principal` set to a foreign 12-digit account ID or IAM ARN, to a bare `*`, or to an AWS service principal such as `s3.amazonaws.com` with neither `SourceArn` nor `SourceAccount` to bound it — with `Action` `lambda:InvokeFunction`. The function's code, its `CodeSha256`, its execution role, its environment variables and its event-source mappings are all untouched. Only the answer to *who may call it* changed, and that answer is stored on the function. The whole-document variant is `lambda:PutResourcePolicy`, which AWS states outright *"replaces any existing policy on the Lambda resource"* — one call, no version history, the prior document gone.

> `AddPermission` also accepts a `Qualifier`, so the statement can be attached to a **version or alias** (`my-function:prod`) rather than to the function. That placement is fully usable and is a documented blind spot for IAM Access Analyzer — see §6.

**Why this is potent, and why the usual reflexes miss it.** The reflex after an IAM incident is to rotate the actor's credentials and revoke its sessions. That is exactly the remediation this technique is immune to: the grant does not reference the actor at all, and the account that will use it never authenticated to you. The second reflex is to audit permissions from the identity side — `list-attached-role-policies`, `list-role-policies`, the permissions boundary, the SCP — and every one of those enumerates *your* principals. Nothing in that sweep touches a foreign account's ability to invoke your function. The third reflex, diffing against the previous version, returns nothing: a Lambda resource policy is **not versioned**, so `RemovePermission` and `PutResourcePolicy` each destroy the only live copy of what the function used to permit. That single property drives the evidence-first containment ordering in §3.

**Detection is whether anything confines the granted principal, not the event name.** `AddPermission` is what every S3 trigger, EventBridge rule and API Gateway integration does at deploy time, so the event name carries no signal whatsoever; what separates a backdoor from a wiring change is the presence or absence of a bound — `SourceArn`/`SourceAccount` for a service principal, `PrincipalOrgID` for a wildcard, membership of your organisation for an account ID. The source rules never read `requestParameters.principal`, and in fact never match a single event: both spell the event name in a form that cannot survive the version suffix AWS documents for it (§2).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing Lambda **management** events. Lambda is **regional** — unlike IAM, whose events all land in `us-east-1`, a Lambda grant is recorded only in the function's own region, so every sweep below iterates regions
- **The CloudTrail event name is not the API name.** AWS documents it: *"In the CloudTrail log file, the `eventName` might include date and version information, but it is still referring to the same public API action"*, and names this one explicitly as **`AddPermission20150331v2`**, alongside `RemovePermission20150331v2`, `UpdateFunctionCode20150331v2` and `UpdateFunctionConfiguration20150331v2`. Every rule and every `lookup-events` call must match by prefix, never by equality
- `AddPermission` carries `requestParameters.functionName`, `.statementId`, `.principal`, `.action`, and — only when the caller supplied them — `.sourceArn`, `.sourceAccount`, `.principalOrgID`, `.qualifier`, `.eventSourceToken`, `.functionUrlAuthType`, `.invokedViaFunctionUrl`, `.revisionId`. **Absence is the signal**, so a rule must test for the field being null rather than for a value
- `responseElements.statement` is the statement Lambda actually wrote, returned as a **JSON string, not an object** — `.statement.Principal` is `null` forever, `.statement | fromjson | .Principal` is the value — and it is **one statement only**. **`GetPolicy` is the only call that returns the entire resource policy** (`Policy`, again a JSON string, plus `RevisionId`), so reconstructing from `AddPermission` events alone misses everything added before your retention window began. That is why the account-wide sweep in §2 is built on `GetPolicy` and not on CloudTrail
- **Lambda data events for `AWS::Lambda::Function`**, whose only logged data API is `Invoke`. Off by default. Without them the "was it used" question is unanswerable and `lookup-events` returns zero forever — a zero that must never be reported as "the backdoor was not used"
- A **baseline export of every function's resource policy**, per region and per qualifier, refreshed on a schedule. A resource policy is unversioned; after the fact this cannot be reconstructed

**Alerting (must be pre-configured)**
- **`AddPermission` granting invoke to a bare `*` principal with no `principalOrgID` → P0**
- **`AddPermission` granting invoke to an account ID or IAM ARN outside the organisation → P0**
- **`AddPermission` naming an AWS service principal with neither `sourceArn` nor `sourceAccount` → P0**
- **One principal adding unconfined invoke grants to three or more distinct functions in fifteen minutes → P1**
- **`PutResourcePolicy` replacing a function's entire resource-based policy → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation and specifically not the principal that wrote the grant
- `jq`; the region list (`ec2:DescribeRegions`) and `lambda:GetPolicy` / `lambda:ListFunctions` / `lambda:ListAliases` / `lambda:ListVersionsByFunction` on every account in scope
- The resource-policy baseline, and the list of pipeline role ARNs legitimately permitted to call `lambda:AddPermission`
- Evidence storage **outside** the account under investigation — the prior policy exists nowhere else once you remove a statement

**Known IOC Baselines**
- Every 12-digit account ID in your organisation, plus your own, so a foreign `Principal` is recognisable on sight. This is the same list the shipped rules require populated before deploy
- Which service principals legitimately invoke which functions, and the `SourceArn` each should carry — an S3 trigger with no `SourceArn` is a finding even when the bucket is yours
- Which principals may call `lambda:AddPermission` at all: in most accounts one IaC deployment role, everything else an incident

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `AddPermission` with `principal` `*` and no `principalOrgID` — the function is invokable by anyone | CloudTrail (management) | T1098 |
| P0 | `AddPermission` with `principal` a 12-digit account ID or IAM ARN outside the organisation allowlist | CloudTrail (management) | T1098 |
| P0 | `AddPermission` with an AWS service principal (`*.amazonaws.com`) and neither `sourceArn` nor `sourceAccount` — the confused deputy | CloudTrail (management) | T1098 |
| P1 | One `userIdentity.arn` adding unconfined grants to ≥3 distinct `functionName` values inside 15 minutes | CloudTrail (management) | T1098 |
| P1 | `PutResourcePolicy` — the whole document replaced, prior content recoverable only from this event | CloudTrail (management) | T1098 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `AddPermission` / `PutResourcePolicy` rejected with `PublicPolicyException` — the caller **had** the permission; only the public-access block stopped it | CloudTrail (management) | T1098 |
| P2 | `CreateFunctionUrlConfig` / `UpdateFunctionUrlConfig` with `authType: NONE` | CloudTrail (management) | T1098 |
| P2 | `ListFunctions` / `GetPolicy` enumeration burst by one principal immediately followed by an `AddPermission` | CloudTrail (management) | T1098 |
| P3 | Repeated `AddPermission` denials (`AccessDenied` / `AccessDeniedException`) by one principal — boundary mapping | CloudTrail (management) | T1098 |
| P3 | A function's live resource policy drifting from the §1 baseline with no corresponding `AddPermission` event in the window | Lambda `GetPolicy` drift check | T1098 |

### Detection Rule Quality Notes

Two source rules cover this API and **neither returns a single event**, before any question of content arises; a third bundles the cleanup call in as though it were signal.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName.keyword:/addpermission.*/` — lower-case, against a case-sensitive `keyword` subfield | Matches nothing. A `keyword` field is indexed verbatim and Lucene regexp matching is case-sensitive unless `case_insensitive` is set, which defaults to false. The rule has the trailing `.*` that would absorb the version suffix and then throws it away on casing | `eventName|startswith: 'AddPermission'`, which matches the documented `AddPermission20150331v2` and the bare form alike |
| `eventName.keyword:/AddPermission\|RemovePermission/` — correct casing, no `.*` | Also matches nothing. Lucene anchors a regexp to the **whole term**, so this demands the event name be exactly `AddPermission`. AWS documents it as `AddPermission20150331v2`. The same pack's sibling rules match `/UpdateFunctionCode.*/` and `/UpdateFunctionConfiguration.*/` **with** the `.*` — the suffix was known and dropped here | One prefix match across both rules; delete the alternation |
| `RemovePermission` matched as signal, ORed with `AddPermission` | A deletion is the *remediation*, not the persistence. Alerting on it inverts the signal and buries the grant under the cleanup: an operator tidying up stale statements generates the same alert as an attacker planting one, and the responder's own containment in §3 re-fires the rule | `RemovePermission` belongs in the evidence trail and in §5's verification, never in the alerting path. Alert on `AddPermission` and `PutResourcePolicy` only |
| `userIdentity.type:"IAMUser"` on the resource-policy rule | Restricts a P0 to the one principal type an attacker is least likely to be holding. A stolen role session (`AssumedRole`), a federated identity, or the pipeline role itself all evade it. The pack's own adjacent rules apply the same filter, so the blind spot is systemic | Drop the principal-type filter. Discriminate on the grant's content, then exclude known pipeline ARNs by allowlist |
| `requestParameters.principal` is never read by any of the rules | This is the entire discriminator. `AddPermission` is what every S3 trigger and EventBridge rule does at deploy time; without the principal and its confinement the rule is an event-name match on a routine deployment call, and it scores a correctly scoped `s3.amazonaws.com` trigger identically to a wildcard grant to the internet | Three sibling blocks: wildcard principal without `principalOrgID`; service principal without `sourceArn` **and** without `sourceAccount`; account/ARN principal not on the organisation allowlist |
| `NOT _exists_:errorCode` is present, but `PublicPolicyException` is treated as an ordinary failure and dropped | That code means the caller **held** `lambda:AddPermission` and the account's public-access block rejected the *content*. It is the highest-value near-miss the technique produces and the rules discard it silently | Success path filtered to `errorCode: null`; a separate `medium` rule on `PublicPolicyException` for the blocked attempt |
| `NOT sourceIPAddress.keyword:/.*amazonaws.com/` | Excludes anything AWS-initiated, which discards a grant made through CloudFormation or from a compromised in-account compute role — a normal delivery path for this technique | Keep the AWS-service source visible and disposition on the principal and the grant's confinement instead |
| P4 / P3 with no MITRE mapping on one rule and T1584/TA0042 on the other | T1584 is *Compromise Infrastructure*, a pre-operational technique about taking over third-party infrastructure. Nothing here is pre-operational and nothing third-party is compromised. The mapping routes an account-persistence alert into a pre-attack bucket, and a P4 does not page | **T1098**, Persistence (TA0003), `level: high`. See the mapping note in §6 |

**Recommended detection — an invoke grant added to a Lambda resource policy that nothing confines.**

```yaml
# Lambda Resource-Policy Backdoor (T1098)
#
# EVENT NAME. AWS documents the CloudTrail event name for this API as
# `AddPermission20150331v2`, not `AddPermission` — the Lambda CloudTrail reference lists
# the versioned form explicitly, alongside `RemovePermission20150331v2`,
# `UpdateFunctionCode20150331v2` and `UpdateFunctionConfiguration20150331v2`. Both source
# rules on this technique match the event name in a way that cannot survive that suffix:
# one regexes `/addpermission.*/` against a case-sensitive keyword field, the other
# regexes `/AddPermission|RemovePermission/` where Lucene anchors the pattern to the whole
# term. Neither returns a single event. Every rule below uses `|startswith`, which matches
# the bare and the versioned form alike.
#
# DISCRIMINATOR. `AddPermission` is what every S3 trigger, EventBridge rule and API
# Gateway integration does at deploy time, so the event name carries no signal. What
# separates a backdoor from a wiring change is whether anything CONFINES the granted
# principal: a bare `*` with no `principalOrgID` is public; an AWS service principal with
# neither `sourceArn` nor `sourceAccount` lets ANY account's bucket, rule or API invoke
# the function — the confused-deputy shape AWS warns about in the AddPermission reference.
# Neither source rule reads `requestParameters.principal` at all.
#
# The grant lives on the RESOURCE. It survives access-key rotation, session revocation,
# role-trust repair and code redeployment, and it is invisible to every identity-side
# audit. That is why the severity here is high and the source rules' P4/P3 is not.
title: Lambda resource policy grants invoke to an unconfined principal
id: 774df8de-170d-4a09-ab1a-86ce33e82bb4
name: lambda_resource_policy_unconfined_grant
status: experimental
description: >-
  A statement was added to a Lambda function's resource-based policy naming a principal
  that nothing confines — a bare wildcard with no organisation condition, or an AWS
  service principal carrying neither a source ARN nor a source account. Any outside
  caller, or any account's bucket, rule or API, can then invoke the function under its
  execution role.
references:
  - https://attack.mitre.org/techniques/T1098/                                       # retrieved 2026-08-28
  - https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html              # retrieved 2026-08-28
  - https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html   # retrieved 2026-08-28
  - https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html        # retrieved 2026-08-28
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  # `|startswith`, never equality — see the event-name note in the header.
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'AddPermission'
  # The backslash is REQUIRED. An unescaped `*` is a Sigma wildcard: written as '*' this
  # block matches every principal and the rule fires on every deploy.
  wildcard_principal:
    requestParameters.principal: '\*'
  # Every AWS service principal is a domain-style identifier ending .amazonaws.com
  # (s3.amazonaws.com, events.amazonaws.com, apigateway.amazonaws.com, and the regional
  # forms such as logs.us-east-1.amazonaws.com). No account ID or IAM ARN ends that way.
  service_principal:
    requestParameters.principal|endswith: '.amazonaws.com'
  # `field: null` matches when the field is ABSENT. `principal: "*"` WITH principalOrgID
  # is AWS's own documented organisation-wide grant and must not fire; without it the
  # function is public. CloudTrail lower-cases the first character of the API parameter
  # name, so `PrincipalOrgID` should arrive as `principalOrgID` — both plausible casings
  # are required absent, which costs nothing and makes the rule casing-proof.
  no_org_id:
    requestParameters.principalOrgID: null
  no_org_id_alt:
    requestParameters.principalOrgId: null
  # sourceArn and sourceAccount are the ONLY confinements AddPermission accepts for a
  # service principal. Either one present makes the statement bounded; both absent is the
  # confused deputy. Kept as separate blocks so each stays single-keyed.
  no_source_arn:
    requestParameters.sourceArn: null
  no_source_account:
    requestParameters.sourceAccount: null
  success:
    errorCode: null
  condition: selection and success and ((wildcard_principal and no_org_id and no_org_id_alt) or (service_principal and no_source_arn and no_source_account))
falsepositives:
  - >-
    A function URL with auth type NONE created through the CLI, CloudFormation or the
    API. Since October 2025 that path requires TWO statements, both with `principal *`:
    action `lambda:InvokeFunctionUrl` with `lambda:FunctionUrlAuthType = NONE`, and
    action `lambda:InvokeFunction` with `lambda:InvokedViaFunctionUrl = true`. Expect two
    hits seconds apart on one function — that is the shape, not a duplicate. Either way
    it is a true positive about an unauthenticated HTTPS endpoint, not a false one.
    Confirm the URL was intended; if it was not, treat it as this technique.
  - A single-account S3 or EventBridge wiring where the operator omitted `--source-arn`
    out of habit. The grant is still unconfined and still lets another account's bucket
    invoke the function; fix the wiring rather than filtering the rule.
level: high
---
# Cross-account grants cannot be judged without knowing which accounts are yours. This
# rule therefore ships with a placeholder allowlist and MUST be populated before deploy:
# every account ID in your organisation, plus your own. Left unpopulated it fires on every
# cross-account grant including legitimate in-organisation ones — noisy, but failing in
# the direction that surfaces the grant rather than hiding it.
title: Lambda resource policy grants invoke to an account outside the organisation
id: ef60045d-36e8-4324-9ecd-45e6504a46c4
name: lambda_resource_policy_external_account_grant
status: experimental
description: >-
  A Lambda function's resource-based policy was extended to an AWS account ID or IAM ARN
  that is not on the organisation allowlist. The grant persists on the resource and is
  unaffected by rotating credentials in either account.
references:
  - https://attack.mitre.org/techniques/T1098/                                       # retrieved 2026-08-28
  - https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html              # retrieved 2026-08-28
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'AddPermission'
  account_id_principal:
    requestParameters.principal|re: '^[0-9]{12}$'
  arn_principal:
    requestParameters.principal|startswith: 'arn:aws'
  # POPULATE BEFORE DEPLOYING. Include your OWN account ID: a same-account grant is
  # ordinary and belongs here. `|contains` so that both the bare account ID and an IAM ARN
  # embedding it are covered by one entry.
  organisation_accounts:
    requestParameters.principal|contains:
      - '000000000000'   # replace with this account's ID
      - '111111111111'   # replace with each sibling account in the organisation
  success:
    errorCode: null
  condition: selection and success and (account_id_principal or arn_principal) and not organisation_accounts
falsepositives:
  - A newly onboarded organisation account not yet added to `organisation_accounts`.
    Reconcile against AWS Organizations rather than muting the rule.
  - A deliberate third-party integration. Record it in the §1 baseline and add the
    account, so that the next unrecorded account remains signal.
level: high
---
# `PutResourcePolicy` REPLACES the function's entire resource policy — AWS states it
# outright: "This operation replaces any existing policy on the Lambda resource. If you
# previously added permissions using the AddPermission operation, the new policy
# overwrites those permissions." There is no version history, so the prior document
# survives only in this event. It also accepts the full IAM condition-key grammar and
# multiple principals in one call, where AddPermission accepts one principal and only
# aws:SourceArn / aws:SourceAccount / aws:PrincipalOrgID.
#
# justified: the condition is not a bare event-name match — it is filtered to successful
# calls — and this API is genuinely rare. Nothing in ordinary operation replaces a
# function's whole resource policy; console, CLI and IaC wiring all use AddPermission.
# Matching on the call itself is correct here, and the alternative — matching the document
# body for a wildcard principal — is a substring test on a field whose meaning is
# structural, which is exactly the defect the sibling IAM playbooks document.
title: Lambda function resource policy replaced wholesale
id: 1fb7568d-e728-492b-9974-1c954bb67054
name: lambda_resource_policy_wholesale_replacement
status: experimental
description: >-
  A Lambda function's entire resource-based policy was replaced in one call. The previous
  document is not versioned and exists nowhere else, so this event is the only record of
  what the function's policy used to permit.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_PutResourcePolicy.html          # retrieved 2026-08-28
  - https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html   # retrieved 2026-08-28
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'PutResourcePolicy'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - An IaC provider that has adopted the whole-document API for managing function
    permissions. Baseline which pipeline roles use it; anything else is unexplained.
level: medium
---
# Lambda's account-level public-access block rejects a resource-based policy that would
# make the function public, with `PublicPolicyException` (HTTP 400) — documented on both
# AddPermission and PutResourcePolicy. The error is therefore a record of an ATTEMPT to
# publish a function that the platform stopped. It is not a denial: an actor without
# lambda:AddPermission gets AccessDenied instead, so this code means the caller HAD the
# permission and the content was the problem.
title: Lambda public resource policy blocked by public-access block
id: c749181d-58f2-4fb8-898a-01245ad14e93
name: lambda_public_policy_blocked
status: experimental
description: >-
  A call to add a Lambda resource-policy statement was rejected because the statement
  would have granted public access. The caller held the permission; only the account's
  public-access block stopped the function from becoming internet-reachable.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html              # retrieved 2026-08-28
  - https://docs.aws.amazon.com/lambda/latest/api/API_PutResourcePolicy.html          # retrieved 2026-08-28
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith:
      - 'AddPermission'
      - 'PutResourcePolicy'
  blocked:
    errorCode: 'PublicPolicyException'
  condition: selection and blocked
falsepositives:
  - >-
    A deployment that creates a function URL with auth type NONE in an account where the
    public-access block is on. This is a recurring, legitimate collision — the deployment
    must set the block's BlockPublicPolicy to false for that function, or stop publishing
    it. Correlate with `CreateFunctionUrlConfig` from the same principal in the same
    minute before dispositioning.
level: medium
---
# Threshold basis — derived from documented technique behaviour, not an observed count.
# The technique's own baseline is ONE function: a single backdoor is the whole attack, and
# `lambda_resource_policy_unconfined_grant` above already fires high on it. This
# correlation is not the detector; it is a severity escalator that separates one wiring
# mistake from a sweep. An actor who holds lambda:AddPermission and has run ListFunctions
# grants across everything it can reach, and does it in one sitting. Three distinct
# functions in fifteen minutes by one principal, each carrying an unconfined grant, sits
# above any single legitimate change and below a full IaC redeploy of a large stack —
# which is why the pipeline roles belong in the allowlist of the base rule's environment.
# Baseline against your own account before deploying: `gte` at the count you actually see
# a pipeline touch, never `gt` at it.
title: Lambda resource-policy backdoor planted across multiple functions
id: efaa7777-7bcc-4254-9d30-1fc46892b1fb
status: experimental
description: >-
  One principal added an unconfined invoke grant to three or more distinct Lambda
  functions inside fifteen minutes. That is an enumeration sweep converting every
  reachable function into a re-entry point, not a configuration change.
references:
  - https://attack.mitre.org/techniques/T1098/                                       # retrieved 2026-08-28
tags:
  - attack.persistence
  - attack.t1098
correlation:
  type: value_count
  rules:
    - lambda_resource_policy_unconfined_grant
  group-by:
    - userIdentity.arn
  timespan: 15m
  # `field` belongs INSIDE `condition` for a value_count correlation — it is the field
  # whose DISTINCT values are counted. A top-level `field:` under `correlation:` is not
  # in the specification and leaves the rule with no field to count, which fails
  # conversion rather than firing wrongly.
  condition:
    gte: 3
    field: requestParameters.functionName
level: high
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1098.yml`; the file's leading comment block, which records what the source rules got wrong, is not repeated here because §2 above says the same thing in prose. Four further documents ship in that file: the external-account grant (`high`, requires the organisation allowlist populated before deploy), wholesale replacement via `PutResourcePolicy` (`medium`), the `PublicPolicyException` blocked attempt (`medium`), and a `value_count` correlation escalating a three-function sweep (`high`). **Deploy the file, not this excerpt.**

**What this rule structurally cannot do.** It cannot decide whether an account ID is yours — that is a lookup against the organisation's account list, not a substring test, which is why the second shipped rule and the KQL both carry an allowlist that fails *noisily* when left unpopulated. It cannot see the whole policy: an `AddPermission` event is one statement inside one retention window, so Query 2 goes to `GetPolicy` instead. And it cannot see a grant planted before logging began, or one attached to a **qualifier** — `AddPermission --qualifier prod` writes onto the alias, which IAM Access Analyzer explicitly does not report on (§6), so only a `GetPolicy` sweep that iterates qualifiers finds it.

**On error strings.** Denials arrive in both documented forms and both must be matched: AWS's own Lambda CloudTrail example shows `"errorCode": "AccessDenied"` with an `errorMessage` beginning `User: ... is not authorized to perform:`, while the Lambda API's common-error list defines `AccessDeniedException` (HTTP 403). Neither carries EC2's `Client.` prefix — match prefix-tolerantly and confirm against a real denied event in your own trail. Seven further codes on this path are **not** denials and must never be counted as probing; they are enumerated with their HTTP statuses in §6's reference table, along with the reason there is no size-based evasion path here.

---

### Key Investigation Queries

> **Lambda is regional.** A grant is recorded only in the function's own region, so a single-region sweep reports clean on an account backdoored elsewhere — the opposite of the IAM siblings, whose events all land in `us-east-1`. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows. **`lookup-events` matches `EventName` exactly**, so every call below loops over the versioned and bare spellings.

#### Query 1 — Reconstruct: who granted invoke on which function, to whom, and was it bounded

```bash
REGION="us-east-1"; WINDOW="24 hours ago"

# Exact-match attribute: the versioned name AWS documents, the bare name, and the
# whole-document API. Omitting the versioned form is how the source rules returned zero.
for EV in AddPermission20150331v2 AddPermission PutResourcePolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "lambda.amazonaws.com") |
    (.requestParameters // {}) as $rp |
    # responseElements.statement is a JSON STRING. Reaching into it without this
    # fromjson yields null for every field, silently, forever.
    ((.responseElements.statement // "") | if . == "" then {} else fromjson end) as $st |
    {time: .eventTime, event: .eventName, region: .awsRegion,
     caller_arn: (.userIdentity.arn // "(none)"),
     access_key: (.userIdentity.accessKeyId // "(none)"),  # feeds ACCESS_KEY_ID in Query 4
     function: ($rp.functionName // "(whole-policy call)"),
     qualifier: ($rp.qualifier // ""),                     # empty = attached to the function
     statement_id: ($rp.statementId // ($st.Sid // "(none)")),
     principal: ($rp.principal // "(see policy_document)"),
     granted_action: ($rp.action // "(see policy_document)"),
     source_arn: ($rp.sourceArn // null),
     source_account: ($rp.sourceAccount // null),
     org_id: ($rp.principalOrgID // $rp.principalOrgId // null),
     revision_id: ($rp.revisionId // null),
     policy_document: ($rp.policy // null),                # PutResourcePolicy only
     confined: (($rp.sourceArn // $rp.sourceAccount // $rp.principalOrgID
                 // $rp.principalOrgId // null) != null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

**`confined: false` with `error: "SUCCESS"` ends the investigation phase** — go to Containment. Read `principal` next: a 12-digit value or an `arn:aws:iam::` ARN not in your organisation, a bare `*`, or a `*.amazonaws.com` service principal all mean the same disposition. A `qualifier` that is not empty tells you the statement is on a **version or alias**, so every later command needs `--qualifier` or it will operate on the wrong policy and report success having changed nothing. Rows with `error: "PublicPolicyException"` are attempts the platform stopped — the caller held the permission, so treat them as compromise of that principal even though no grant landed. Rows with `AccessDenied` / `AccessDeniedException` are the probing path; count them per `caller_arn`, never score them as grants. For a `PutResourcePolicy` row, `policy_document` is the **only** surviving copy of what the policy became and the prior document is already gone. Record `caller_arn`, `access_key`, `function`, `qualifier`, `statement_id` and the grant `time`.

#### Query 2 — Sweep: read every function's WHOLE policy, in every region, including qualifiers

`AddPermission` events show one statement each and only within retention. `GetPolicy` is the only call that returns the complete document, so the account-wide hunt is built on it.

```bash
# jq, not grep. Statement is a scalar OR an array; Principal is a string OR an object
# whose values are strings OR arrays; Action is a string OR an array. Iterating a bare
# object yields its KEYS, so an unguarded sweep skips single-statement policies silently.
# Condition KEY NAMES are compared lower-cased: Lambda writes "AWS:SourceArn" for a
# service grant but "aws:PrincipalOrgID" for an org grant, and IAM treats both as equal.
CLASSIFY='
  (.Statement // [] | if type=="object" then [.] else . end)[]
  | select(.Effect == "Allow") | . as $s
  | ( ($s.Principal // {})
      | if type=="string" then [.]
        elif type=="object" then [ to_entries[] | .value
                                   | if type=="string" then [.] else . end | .[] ]
        else [] end ) as $princs
  | ( ($s.Action // []) | if type=="string" then [.] else . end ) as $acts
  | ( [ ($s.Condition // {}) | to_entries[] | .value | to_entries[] | .key | ascii_downcase ] ) as $ck
  | { sid: ($s.Sid // "(no-sid)"), principals: $princs, actions: $acts, condition_keys: $ck,
      public:  ($princs | any(. == "*")),
      service: ($princs | any(endswith(".amazonaws.com"))),
      bounded: ($ck | any(. == "aws:sourcearn" or . == "aws:sourceaccount"
                          or . == "aws:principalorgid" or . == "aws:principalorgpaths"
                          or . == "aws:sourceorgid" or . == "aws:sourceorgpaths")) }
  | select((.public or .service or ((.principals | any(test("^[0-9]{12}$|^arn:aws"))))) and (.bounded | not))
'
ORG_ACCOUNTS="000000000000 111111111111"        # populate: every account in your org, plus your own
INCONCLUSIVE=0

for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  for FN in $(aws lambda list-functions --region "$R" \
                --query 'Functions[].FunctionName' --output text); do
    # Sweep the function itself, then every alias and published version: AddPermission
    # takes a Qualifier, and a grant placed on an alias is invisible to Access Analyzer.
    QUALS=$(aws lambda list-aliases --function-name "$FN" --region "$R" \
              --query 'Aliases[].Name' --output text)
    QUALS="$QUALS $(aws lambda list-versions-by-function --function-name "$FN" --region "$R" \
              --query 'Versions[?Version!=`$LATEST`].Version' --output text)"
    for Q in "" $QUALS; do
      if [ -z "$Q" ]; then
        RAW=$(aws lambda get-policy --function-name "$FN" --region "$R" --output json 2>&1)
      else
        RAW=$(aws lambda get-policy --function-name "$FN" --qualifier "$Q" --region "$R" --output json 2>&1)
      fi
      RC=$?
      TARGET="$R/$FN${Q:+:$Q}"
      if [ "$RC" -ne 0 ]; then
        # No policy at all is CLEAN. Anything else is a check that did not run.
        case "$RAW" in
          *ResourceNotFoundException*) continue ;;
          *) echo "[!] INCONCLUSIVE $TARGET — get-policy failed: $(echo "$RAW" | tr '\n' ' ' | cut -c1-140)"
             INCONCLUSIVE=$((INCONCLUSIVE+1)); continue ;;
        esac
      fi
      # A jq failure here must NOT reach the same branch as "no unconfined statements".
      # Suppressing it would let an unparseable policy read as clean — the exact shape
      # that makes a sweep certify a backdoored function. Empty input is checked FIRST:
      # jq on empty stdin emits nothing and exits 0, so it would otherwise read as clean.
      if [ -z "$RAW" ]; then
        echo "[!] INCONCLUSIVE $TARGET — get-policy returned success with an empty body"
        INCONCLUSIVE=$((INCONCLUSIVE+1))
      elif ! CLASSIFIED=$(printf '%s' "$RAW" | jq -r '.Policy' 2>&1 | jq -c "$CLASSIFY" 2>&1); then
        echo "[!] INCONCLUSIVE $TARGET — policy returned but could not be parsed: $(printf '%s' "$CLASSIFIED" | tr '\n' ' ' | cut -c1-140)"
        INCONCLUSIVE=$((INCONCLUSIVE+1))
      else
        printf '%s\n' "$CLASSIFIED" | while read -r ST; do
          [ -n "$ST" ] && echo "[!] $TARGET unconfined grant: $ST"
        done
      fi
    done
    sleep 0.1        # GetPolicy is quota-capped at 15 requests/second, account-wide
  done
done
echo "[i] Reconcile every [!] principal against your organisation list: $ORG_ACCOUNTS"
[ "$INCONCLUSIVE" -eq 0 ] && echo "[OK] Sweep completed with no unreadable policies" \
                          || echo "[!] $INCONCLUSIVE policy read(s) failed — sweep is INCOMPLETE, do not report clean"
```

Every `[!] ... unconfined grant` is a function any outside caller — or any account's bucket, rule or API — can invoke right now, incident-related or not. Reconcile against the §1 baseline: present here and absent there is this incident; present in both is pre-existing exposure for the §6 findings. A `principals` array containing a 12-digit ID is only a finding if that ID is not in `ORG_ACCOUNTS`; a `service: true` row with `bounded: false` is a finding regardless of which service it names. **An `[!] INCONCLUSIVE` line is not a pass** — the credential, the region or the permission was wrong, and those functions were never checked.

#### Query 3 — Was it used: the data-plane invoke pivot, keyed on `resources[].ARN`

`lambda:Invoke` is the only Lambda **data** API CloudTrail logs, under `resources.type` `AWS::Lambda::Function`, and it is off by default. `lookup-events` returns zero for it forever. Establish whether the telemetry exists before drawing any conclusion from its absence.

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
LOG_GROUP="<cloudtrail-cloudwatch-log-group>"     # the group your Lambda data-event trail delivers to
CONTAINED_AT="<iso8601-containment-timestamp>"

DATA_TRAILS=0
for T in $(aws cloudtrail list-trails --region "$REGION" \
             --query 'Trails[].TrailARN' --output text); do
  SEL=$(aws cloudtrail get-event-selectors --trail-name "$T" --region "$REGION" --output json 2>&1) || continue
  echo "$SEL" | grep -q 'AWS::Lambda::Function' && DATA_TRAILS=$((DATA_TRAILS+1))
done

if [ "$DATA_TRAILS" -eq 0 ]; then
  echo "[!] INCONCLUSIVE — no trail in $REGION selects AWS::Lambda::Function data events."
  echo "[!] Invocation of $FUNCTION is UNLOGGED. Absence of evidence is NOT evidence of absence:"
  echo "[!] treat the backdoor as exercised and work the execution role's blast radius (§3 Step 4)."
else
  # resources[].ARN is the UNQUALIFIED base ARN, normalised by CloudTrail itself, and is
  # the field CloudTrail's own advanced event selectors key on. requestParameters.functionName
  # is whatever the CALLER typed — a bare name, a partial ARN, a full ARN, or a name with an
  # alias suffix ("my-fn:prod") — and on the synchronous path it may not be recorded at all.
  # Filtering on it drops exactly the invokes an attacker testing a backdoor makes.
  aws logs filter-log-events --log-group-name "$LOG_GROUP" --region "$REGION" \
    --start-time "$(($(date -u -d "$CONTAINED_AT" +%s) * 1000))" \
    --filter-pattern '{ $.eventName = "Invoke" }' --output json | \
    jq -r --arg fn "$FUNCTION" '.events[].message
      | fromjson
      | (if has("Records") then .Records[] else . end)
      | select(.eventSource == "lambda.amazonaws.com" and .eventName == "Invoke")
      | select(any(.resources[]?;
          ((.type // "") == "AWS::Lambda::Function")
          and (((.ARN // "") | split(":") | (.[6] // "")) == $fn)))
      | {time: .eventTime,
         function_arn: ([.resources[]? | select(.type == "AWS::Lambda::Function") | .ARN] | first),
         caller: (.userIdentity.arn // "(unauthenticated / function URL)"),
         caller_account: (.userIdentity.accountId // "(none)"),
         owner_account: .recipientAccountId,
         cross_account: ((.userIdentity.accountId // "") != (.recipientAccountId // "")),
         invocation_type: (.requestParameters.invocationType // "not recorded"),
         ip: .sourceIPAddress}' | \
    jq -s 'sort_by(.time)'
fi

# Fallback when no data trail exists: the metric proves WHETHER it ran, never WHO called it.
aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations \
  --dimensions Name=FunctionName,Value="$FUNCTION" \
  --start-time "$CONTAINED_AT" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum --region "$REGION" --output json | \
  jq -r '.Datapoints | sort_by(.Timestamp) | .[] | "\(.Timestamp) invocations=\(.Sum)"'
```

`cross_account: true` is the proof the backdoor was exercised: a cross-account invoke lands in the **function owner's** trail, `recipientAccountId` is you, and `userIdentity.accountId` is the caller — that mismatch cannot be produced by any in-account activity. `invocation_type: "not recorded"` is an expected shape on this path, not missing data; the query never reads that field to identify the function, which is the point. If the `[!] INCONCLUSIVE` branch fired, the CloudWatch fallback still tells you the function ran — it just cannot separate the attacker's calls from the legitimate trigger's, so every invocation in the exposure window must be treated as potentially attacker-driven.

#### Query 4 — Session reconstruction: everything the granting principal did

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
GRANT_TIME="<time-from-Query-1>"          # ISO8601, the moment the grant succeeded

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg t "$GRANT_TIME" '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     phase: (if .eventTime > $t then "AFTER-GRANT" else "before" end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

The management-plane view of the actor. Look for the enumeration that preceded the grant (`ListFunctions`, `GetPolicy`, `GetFunction`) and for other persistence after it: further `AddPermission` calls in other regions, `CreateFunctionUrlConfig`, `UpdateFunctionCode` (`reference/PLAYBOOK.md`), `UpdateAssumeRolePolicy` (`../iam.persistence.role-trust-backdoor/`), `PutUserPolicy` / `PutRolePolicy` (`../iam.privilege-escalation.inline-policy-grant/`), `CreateAccessKey`. **Run this once per region the actor touched** — Query 1's `region` field lists them, and Lambda management events do not aggregate into `us-east-1`. Management events are complete, so an empty `AFTER-GRANT` set is real evidence *this credential* did nothing further; it is not evidence the grant went unused, which is Query 3's question and a different log entirely.

#### Query 5 — Adjacent exposure: unauthenticated function URLs and orphaned public grants

```bash
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws lambda list-functions --region "$R" --query 'Functions[].FunctionName' --output text | \
    tr '\t' '\n' | while read -r FN; do
      [ -z "$FN" ] && continue
      if U=$(aws lambda list-function-url-configs --function-name "$FN" --region "$R" --output json 2>&1); then
        printf '%s' "$U" | jq -r --arg r "$R" --arg fn "$FN" '.FunctionUrlConfigs[]? |
          select(.AuthType == "NONE") |
          "[!] \($r)/\($fn) function URL AuthType NONE — \(.FunctionUrl)"'
      else
        echo "[!] INCONCLUSIVE $R/$FN — cannot list function URL configs: $(printf '%s' "$U" | tr '\n' ' ' | cut -c1-120)"
      fi
    done
done
echo "[i] Cross-check each against Query 2: a URL with NO matching public statement returns 403 and is inert."
echo "[i] Deleting a function URL does NOT delete its resource-policy statements — an orphaned"
echo "[i] public grant outlives the endpoint that justified it and stays exploitable."
```

AWS documents the pairing precisely: an `AuthType: NONE` URL grants nothing on its own — *"users get a 403 Forbidden error code"* unless the resource policy allows both `lambda:InvokeFunctionUrl` and `lambda:InvokeFunction`. Since October 2025 the public path therefore requires **two** statements, and the CLI cannot combine them, so expect two `AddPermission` events seconds apart on one function: two hits are the shape, not a duplicate. A URL here **with** a matching pair in Query 2 is a live unauthenticated endpoint; a pair in Query 2 with **no** URL here is the orphan case and must still be removed.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Removing the statement is immediately effective and needs no session revocation — Lambda evaluates authorization per request against the current policy, so the outside caller loses access on its next call, and the invoker itself needs no containment because its ability came entirely from your resource. Two things reorder the usual sequence. First, a Lambda resource policy is **unversioned**, so the removal destroys the only live copy: capture before you cut. Second, every invocation that already landed ran under the function's **execution role**, so the grant must come off *before* that role's sessions are revoked — otherwise the attacker simply invokes again and receives freshly minted role credentials that the revocation cutoff no longer covers.

> Run every command under the **break-glass responder credentials** from §1, not under any principal being contained, and not under the principal that wrote the grant.

#### Step 1 — Capture the entire policy before touching it

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
QUALIFIER="<qualifier-from-Query-1>"        # empty string if the grant is on the function
EVIDENCE="/tmp/ir-lambda-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVIDENCE"

if [ -z "$QUALIFIER" ]; then
  RAW=$(aws lambda get-policy --function-name "$FUNCTION" --region "$REGION" --output json 2>&1)
else
  RAW=$(aws lambda get-policy --function-name "$FUNCTION" --qualifier "$QUALIFIER" \
          --region "$REGION" --output json 2>&1)
fi
if [ $? -eq 0 ] && [ -n "$RAW" ]; then
  printf '%s\n' "$RAW" > "$EVIDENCE/policy-${FUNCTION}${QUALIFIER:+-$QUALIFIER}.json"
  printf '%s\n' "$RAW" | jq -r '.Policy' | jq . > "$EVIDENCE/policy-${FUNCTION}${QUALIFIER:+-$QUALIFIER}-expanded.json"
  echo "[OK] Captured policy and RevisionId to $EVIDENCE"
  printf '%s\n' "$RAW" | jq -r '.RevisionId'
else
  echo "[FAIL] Could not read the policy: $(printf '%s' "$RAW" | tr '\n' ' ' | cut -c1-160)"
  echo "[FAIL] Do NOT proceed to Step 2 — removal would destroy an uncaptured document."
fi
```

> Copy `$EVIDENCE` **out of the account** before Step 2. There is no version history, no `Get*PolicyVersion`, and no console history for a Lambda resource policy; once the statement is gone the only other record is the CloudTrail event, which ages out.

#### Step 2 — Remove the backdoor statement

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
QUALIFIER="<qualifier-from-Query-1>"
SID="<statement-id-from-Query-1>"
REVISION="<revision-id-from-Step-1>"          # optional; guards against a concurrent edit

RM=(aws lambda remove-permission --function-name "$FUNCTION" --statement-id "$SID" --region "$REGION")
[ -n "$QUALIFIER" ] && RM+=(--qualifier "$QUALIFIER")
[ -n "$REVISION" ]  && RM+=(--revision-id "$REVISION")

if OUT=$("${RM[@]}" 2>&1); then
  echo "[OK] Removed statement '$SID' from $FUNCTION${QUALIFIER:+:$QUALIFIER} — effective on the next request"
else
  case "$OUT" in
    *PreconditionFailedException*)
      echo "[!] RevisionId is stale — the policy changed since Step 1. Someone else is editing it."
      echo "[!] Re-run Step 1, diff against the captured copy, and escalate before retrying." ;;
    *ResourceNotFoundException*)
      echo "[!] '$SID' is not present on $FUNCTION${QUALIFIER:+:$QUALIFIER} — wrong qualifier, wrong region, or already removed." ;;
    *) echo "[FAIL] remove-permission failed: $(printf '%s' "$OUT" | tr '\n' ' ' | cut -c1-160)" ;;
  esac
fi
```

Repeat for **every** statement Query 1 and Query 2 flagged, in every region and on every qualifier. Removing the last statement deletes the policy object entirely, which is why §5's verification treats `ResourceNotFoundException` as a pass rather than an error.

#### Step 3 — Block the grant from being re-added, and close the URL half

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
FN_ARN="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION}"

# BlockPublicPolicy rejects a policy that WOULD grant public access (PublicPolicyException);
# RestrictPublicResource blocks public access even if such a policy already exists. Both
# default to true, so an account where this technique succeeded publicly has them turned off.
# The operation and both setting names are documented; the CLI STRUCTURE SHORTHAND below is
# the standard Key=value form rather than a form quoted from the CLI reference — if it is
# rejected, pass the equivalent JSON with --public-access-block-config file://config.json.
aws lambda put-public-access-block-config --resource-arn "$FN_ARN" --region "$REGION" \
  --public-access-block-config BlockPublicPolicy=true,RestrictPublicResource=true && \
  echo "[OK] Public-access block enforced on $FUNCTION"

# An AuthType NONE URL is inert once its statements are gone (403), but leave nothing behind.
if aws lambda get-function-url-config --function-name "$FUNCTION" --region "$REGION" \
     --query 'AuthType' --output text 2>/dev/null | grep -qx NONE; then
  echo "[!] $FUNCTION has an AuthType NONE function URL — confirm it was intended before deleting:"
  echo "    aws lambda delete-function-url-config --function-name $FUNCTION --region $REGION"
fi
```

> `RestrictPublicResource=true` blocks public access to the function **even where a policy allows it**, so confirm no legitimate unauthenticated URL depends on this function before enforcing it account-wide. Enforcing it on the compromised function alone is safe and is the right first move.

#### Step 4 — Treat the function's execution role as exposed

Every invocation that already landed ran the function's code under its execution role, and the role's credentials were live inside that execution environment. This step is ordered **after** Step 2 deliberately: revoking sessions while the grant is still in place lets the attacker invoke once more and receive credentials issued after the cutoff.

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"

EXEC_ROLE=$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
              --query 'Role' --output text | awk -F'/' '{print $NF}')
if [ -n "$EXEC_ROLE" ] && [ "$EXEC_ROLE" != "None" ]; then
  aws iam put-role-policy --role-name "$EXEC_ROLE" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}]}' && \
    echo "[OK] Revoked pre-existing sessions for execution role $EXEC_ROLE"
  aws iam list-attached-role-policies --role-name "$EXEC_ROLE" --output table
  aws iam list-role-policies          --role-name "$EXEC_ROLE" --output table
else
  echo "[FAIL] Could not resolve the execution role for $FUNCTION — resolve it manually before closing"
fi
```

> **What this does not fix.** `aws:TokenIssueTime` denies only tokens issued **before** the cutoff, and it kills nothing the attacker already *did*. A synchronous invoke returns the handler's response body to its caller, so anything the function read left the account on the first call. Enumerate what the role could reach from the output above and rotate every secret in that set — but do not blanket-rotate: the reads it performed (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`) are **management** events in your default trail and name exactly which secrets were touched.

#### Step 5 — Contain the principal that wrote the grant

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVOKE_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}'
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["lambda:AddPermission","lambda:PutResourcePolicy","lambda:RemovePermission","lambda:CreateFunctionUrlConfig","lambda:UpdateFunctionUrlConfig","lambda:AddLayerVersionPermission","lambda:PutPublicAccessBlockConfig"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')        # user ARN: name = LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive && \
      echo "[OK] Disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyLambdaPolicyWrite" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further resource-policy writes by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')         # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document "$REVOKE_DOC" && echo "[OK] Revoked sessions for role $R"
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyLambdaPolicyWrite" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further resource-policy writes by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> `lambda:RemovePermission` is in the deny set on purpose: it is the actor's cleanup path, and once containment has captured the evidence there is no reason the suspect principal should be able to erase statements. Do all removals with the break-glass credential, not by relaxing this. If the grant arrived through CloudFormation, `userIdentity.arn` is still the submitting principal and `invokedBy` is `cloudformation.amazonaws.com` — contain the principal *and* disable the stack's update path, or the next drift reconciliation re-applies the permission.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every grant in the window has been reversed, everywhere

Work Query 2's full list, not the event that raised the alert. An actor holding `lambda:AddPermission` and a `ListFunctions` result grants across everything it can reach, and the correlation in the shipped rules exists precisely because that fan-out is the normal shape. For each `[!]` line: the region, the function, the qualifier and the `sid` are all in the output, and each needs its own `remove-permission`. Any function that produced `[!] INCONCLUSIVE` was never examined — obtain a credential that can read it and re-run before closing.

#### Remove the rest of the persistence the same principal established

From Query 4's `AFTER-GRANT` rows, in order of how long each outlives the statement you just deleted:

- **Function URLs** — `delete-function-url-config` for anything created in the window, and remember the resource-policy statements do not go with it
- **Layer permissions** — `AddLayerVersionPermission` is the same technique against a layer, and a shared layer version is code the attacker controls that your functions import
- **Event source mappings** — `CreateEventSourceMapping` wires a queue or stream the attacker owns to your function, which is invocation without any resource-policy statement at all
- **Code and configuration tampering** — `UpdateFunctionCode` is `reference/PLAYBOOK.md`; `UpdateFunctionConfiguration` is the layer/environment route
- **Identity-side persistence** — `UpdateAssumeRolePolicy` is `../iam.persistence.role-trust-backdoor/`; `PutUserPolicy` / `PutRolePolicy` is `../iam.privilege-escalation.inline-policy-grant/`; `CreateAccessKey` keys are independent re-entry paths that reference nothing you have fixed

#### Right-size the permission that made this possible

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  RN=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  aws iam list-attached-role-policies --role-name "$RN" --output table
  aws iam list-role-policies          --role-name "$RN" --output table
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  UN=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  aws iam list-attached-user-policies --user-name "$UN" --output table
  aws iam list-user-policies          --user-name "$UN" --output table
else
  echo "[i] Root or federated principal — identify the granting permission through your IdP"
fi
```

The durable fix is not stripping `lambda:AddPermission` from every deployment role; IaC legitimately needs it to wire triggers. It is constraining **which principal a caller may grant invoke rights to**, which Lambda supports natively through the `lambda:Principal` condition key. See §6.

#### Remove the emergency policies once clean

```bash
PLANTING_ROLE="<planting-role-name>"; EXEC_ROLE_NAME="<execution-role-name>"
PLANTING_USER="<planting-user-name>"
LEFTOVER=0

for RN in "$PLANTING_ROLE" "$EXEC_ROLE_NAME"; do
  for PN in EmergencyRevokeSessions EmergencyDenyLambdaPolicyWrite; do
    aws iam delete-role-policy --role-name "$RN" --policy-name "$PN" 2>/dev/null
  done
  # Assert the removal rather than announcing it. A listing failure is INCONCLUSIVE, not
  # a pass — an unconditional "[OK] removed" here is a check that cannot fail.
  if L=$(aws iam list-role-policies --role-name "$RN" --query 'PolicyNames[]' --output text 2>&1); then
    for PN in EmergencyRevokeSessions EmergencyDenyLambdaPolicyWrite; do
      printf '%s' "$L" | tr '\t' '\n' | grep -qx "$PN" && \
        { echo "[FAIL] $PN still attached to role $RN"; LEFTOVER=$((LEFTOVER+1)); }
    done
  else
    echo "[!] INCONCLUSIVE — cannot list inline policies on role $RN: $(printf '%s' "$L" | tr '\n' ' ' | cut -c1-120)"
    LEFTOVER=$((LEFTOVER+1))
  fi
done

# Containment Step 5 uses put-user-policy when the planting principal was an IAM USER —
# delete-role-policy does not cover that path.
aws iam delete-user-policy --user-name "$PLANTING_USER" \
  --policy-name "EmergencyDenyLambdaPolicyWrite" 2>/dev/null
if L=$(aws iam list-user-policies --user-name "$PLANTING_USER" --query 'PolicyNames[]' --output text 2>&1); then
  printf '%s' "$L" | tr '\t' '\n' | grep -qx "EmergencyDenyLambdaPolicyWrite" && \
    { echo "[FAIL] EmergencyDenyLambdaPolicyWrite still attached to user $PLANTING_USER"; LEFTOVER=$((LEFTOVER+1)); }
else
  echo "[i] $PLANTING_USER is not an IAM user in this account — skip if containment used the role path"
fi

[ "$LEFTOVER" -eq 0 ] && echo "[OK] All emergency policies removed" \
                      || echo "[FAIL] $LEFTOVER emergency policy/policies unremoved or unverified"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the backdoor statement is gone from the exact resource it was on

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
QUALIFIER="<qualifier-from-Query-1>"
SID="<statement-id-from-Query-1>"

if [ -z "$QUALIFIER" ]; then
  RAW=$(aws lambda get-policy --function-name "$FUNCTION" --region "$REGION" --output json 2>&1)
else
  RAW=$(aws lambda get-policy --function-name "$FUNCTION" --qualifier "$QUALIFIER" \
          --region "$REGION" --output json 2>&1)
fi
RC=$?

# Removing the last statement deletes the policy object, so ResourceNotFoundException is a
# PASS here. Every other failure is a check that did not run and must never print [OK].
if [ "$RC" -ne 0 ]; then
  case "$RAW" in
    *ResourceNotFoundException*)
      echo "[OK] $FUNCTION${QUALIFIER:+:$QUALIFIER} has no resource policy at all — '$SID' is gone" ;;
    *)
      echo "[!] INCONCLUSIVE — get-policy failed: $(printf '%s' "$RAW" | tr '\n' ' ' | cut -c1-160)"
      echo "[!] The statement's status is UNKNOWN. Fix the credential/region and re-run." ;;
  esac
else
  FOUND=$(printf '%s' "$RAW" | jq -r '.Policy' | \
          jq -r --arg sid "$SID" '[(.Statement // [] | if type=="object" then [.] else . end)[]
                                   | select(.Sid == $sid)] | length')
  case "$FOUND" in
    0) echo "[OK] '$SID' is absent from $FUNCTION${QUALIFIER:+:$QUALIFIER}" ;;
    ""|*[!0-9]*) echo "[!] INCONCLUSIVE — could not parse the returned policy document" ;;
    *) echo "[FAIL] '$SID' is STILL present on $FUNCTION${QUALIFIER:+:$QUALIFIER}" ;;
  esac
fi
```

> **Then re-run Query 2 in full**, across every region and every qualifier. Pass condition: zero `[!] ... unconfined grant` lines **and** zero `[!] INCONCLUSIVE` lines. Any unconfined grant that still appears and is present in the §1 baseline is pre-existing exposure rather than this incident — record it in the §6 findings and remediate it on its own timeline.

#### Verify the public-access block is actually enforcing

```bash
REGION="us-east-1"
FUNCTION="<function-from-Query-1>"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
FN_ARN="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION}"

CFG=$(aws lambda get-public-access-block-config --resource-arn "$FN_ARN" --region "$REGION" \
        --output json 2>&1)
if [ $? -ne 0 ]; then
  echo "[!] INCONCLUSIVE — get-public-access-block-config failed: $(printf '%s' "$CFG" | tr '\n' ' ' | cut -c1-160)"
else
  BPP=$(printf '%s' "$CFG" | jq -r '.PublicAccessBlockConfig.BlockPublicPolicy')
  RPR=$(printf '%s' "$CFG" | jq -r '.PublicAccessBlockConfig.RestrictPublicResource')
  # jq on empty stdin emits nothing and exits 0, so an empty capture must be separated
  # from a real "false" before either is compared.
  if [ -z "$BPP" ] || [ -z "$RPR" ]; then
    echo "[!] INCONCLUSIVE — the call succeeded but returned no block configuration to read"
  elif [ "$BPP" = "true" ] && [ "$RPR" = "true" ]; then
    echo "[OK] Public-access block enforcing on $FUNCTION (BlockPublicPolicy=$BPP RestrictPublicResource=$RPR)"
  else
    echo "[FAIL] $FUNCTION BlockPublicPolicy=$BPP RestrictPublicResource=$RPR — a public grant can be re-added"
  fi
fi
```

> **Then re-run Query 3** with `CONTAINED_AT` set to the Step-2 removal timestamp. The data-event trail keeps recording invokes after the statement is removed, so this check can still emit a signal — which is what makes it a check: a post-containment `cross_account: true` row means the grant was **not** fully removed, in another region, on another qualifier, or as a second statement. If Query 3 printed `[!] INCONCLUSIVE`, this stays UNVERIFIED; enable Lambda data events before closing and do not record the invocation question as answered.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rules MUST fire on:"
echo '  eventSource=lambda.amazonaws.com  eventName=AddPermission20150331v2  errorCode absent'
echo '  requestParameters {"functionName":"target","statementId":"x","action":"lambda:InvokeFunction","principal":"s3.amazonaws.com"}'
echo '    -> lambda_resource_policy_unconfined_grant (high): service principal, no sourceArn, no sourceAccount'
echo '  requestParameters {"principal":"*"}                     -> same rule, wildcard branch'
echo '  requestParameters {"principal":"999999999999"}          -> external-account rule (high)'
echo '  eventName=PutResourcePolicy, errorCode absent           -> wholesale-replacement rule (medium)'
echo '  eventName=AddPermission20150331v2, errorCode=PublicPolicyException -> blocked-attempt rule (medium)'
echo
echo "The rules MUST NOT fire on:"
echo '  1. {"principal":"s3.amazonaws.com","sourceArn":"arn:aws:s3:::my-bucket"} — a bounded trigger'
echo '  2. {"principal":"s3.amazonaws.com","sourceAccount":"111122223333"} — bounded the other way'
echo '  3. {"principal":"*","principalOrgID":"o-abc123"} — AWS'"'"'s own documented org-wide grant'
echo '  4. eventName=RemovePermission20150331v2 — that is REMEDIATION, and a rule that alerts'
echo '     on it fires on this playbook'"'"'s own Containment Step 2'
echo '  5. The same AddPermission with errorCode=AccessDenied — that is the probing path at P3'
echo
echo "Regression guard: a rule written with eventName EQUAL to \"AddPermission\" matches NONE of"
echo "the positives above, because AWS documents the CloudTrail name as AddPermission20150331v2."
echo "That single-character-class difference is the whole defect in both source rules."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could grant invoke rights on a function to an arbitrary outside principal | `lambda:AddPermission` held outside the deployment pipeline, with no `lambda:Principal` condition capping which principals a grant may name |
| The grant was not detected | Both deployed rules matched the event name in a form that cannot match `AddPermission20150331v2`, so neither had ever returned an event; neither read `requestParameters.principal` |
| The cleanup call was treated as signal | `RemovePermission` was ORed into the alert, so a deletion scored as persistence and the responder's own remediation re-fires the rule |
| The grant survived the identity-side response | Credential rotation, session revocation and trust-policy repair were treated as sufficient; none of them touches a policy attached to a resource |
| Whether the backdoor was exercised is unanswerable | Lambda data events were not enabled, so `Invoke` is unlogged and the only remaining evidence is an aggregate CloudWatch metric with no caller identity |
| The prior policy could not be reconstructed | Lambda resource policies are unversioned and no scheduled baseline export existed, so "what could invoke this function yesterday" has no answer outside CloudTrail retention |

### Recommended Guardrails

**Constrain which principals a grant may name — the control that fits this technique**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// lambda:Principal is documented for AddPermission and RemovePermission: it "lets you
// restrict the service or account that a user can grant invocation access to on a
// function's resource-based policy". StringNotLike, never StringNotEquals — the
// allowlist carries wildcards, and Deny + an equality operator against a wildcarded
// value matches everything and denies every legitimate trigger wiring.
{
  "Effect": "Deny",
  "Action": ["lambda:AddPermission"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "lambda:Principal": [
        "s3.amazonaws.com", "events.amazonaws.com", "apigateway.amazonaws.com",
        "sns.amazonaws.com", "logs.*.amazonaws.com",
        "000000000000", "111111111111"
      ]
    }
  }
}
```

**Restrict the whole-document API to the pipeline**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// PutResourcePolicy replaces the entire policy in one call. lambda:Principal is
// documented for AddPermission/RemovePermission and NOT for PutResourcePolicy, so
// conditioning on it here would be a Deny whose key is absent from the request context —
// which a negated string operator evaluates TRUE, denying every call. Scope on the
// caller instead, with ArnNotLike because the value is wildcarded.
{
  "Effect": "Deny",
  "Action": ["lambda:PutResourcePolicy", "lambda:PutPublicAccessBlockConfig"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"]
    }
  }
}
```

**Deny unauthenticated function URLs**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// AWS's own documented form for this control. StringNotEquals is correct HERE because
// the value is a fixed enum with no wildcard: AuthType is exactly AWS_IAM or NONE.
{
  "Effect": "Deny",
  "Action": ["lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig"],
  "Resource": "*",
  "Condition": { "StringNotEquals": { "lambda:FunctionUrlAuthType": "AWS_IAM" } }
}
```

> **A resource control policy is not available for this technique, and an SCP cannot reach the invoker.** RCPs are the standard answer when the threat actor is a principal in someone else's account, but AWS Organizations' list of services whose actions RCPs apply to does not include `lambda` (re-verified 2026-08-29: S3, STS, KMS, SQS, Secrets Manager, DynamoDB, EventBridge, ECR, CloudFront, CloudWatch Logs and others — no lambda prefix). An RCP denying `lambda:InvokeFunction` on a foreign `aws:PrincipalOrgID` is unenforceable, not merely awkward. An SCP cannot substitute: AWS states SCPs *"don't affect users or roles from accounts outside the organization"*, so a deny conditioned on a foreign org ID never evaluates against the account that would use the backdoor. The three fragments above all work because they constrain **your own** principal making the grant, which is inside an SCP's reach. Do not report the invoke side as covered.

**Structural controls**
- **Turn on Lambda's public-access block account-wide.** `BlockPublicPolicy` rejects a policy that would grant public access (`PublicPolicyException`); `RestrictPublicResource` blocks public access even where one already exists. Both default to `true`, so an account where this succeeded publicly has them switched off — find out why before switching them back
- **Deploy the AWS Config managed rule `LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED`** (`AWS::Lambda::Function`, configuration-change triggered): `NON_COMPLIANT` for an empty or wildcard `Principal` **and**, explicitly, for a function invoked from S3 whose policy carries no condition limiting access such as `AWS:SourceAccount` — the confused-deputy case, checked continuously without an analyst
- **Enable IAM Access Analyzer external-access findings**, with the alias blind spot in the reference table below covered by the `GetPolicy` sweep
- **Always pass `--source-arn` when wiring a service trigger** and treat its absence as a defect in the IaC module, not a rule to tune. It is compared with `StringLike`, so a bounded prefix works when the exact resource is unknown at deploy time
- **Export every function's resource policy on a schedule**, per region and per qualifier — the only way to answer "what changed" for an object AWS does not version

**Detection improvements**
- Match the event name by **prefix**, never by equality, on every Lambda rule in the estate — the same defect disables the `UpdateFunctionCode` and `UpdateFunctionConfiguration` rules if they are ever tightened
- Alert on the **absence** of `sourceArn` / `sourceAccount` / `principalOrgID`, not on the presence of a value; this technique's signal is a field that is not there
- Take `RemovePermission` out of the alerting path entirely and keep it in the evidence trail
- Add the `GetPolicy` drift check as a scheduled job: it is the only detector that sees a grant planted before your log retention began, or on a qualifier

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 — Account Manipulation |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `lambda:AddPermission` (one statement) · `lambda:PutResourcePolicy` (whole document, replaces) · `lambda:AddLayerVersionPermission` (same technique against a layer) |
| Event source | `lambda.amazonaws.com` — **regional**, and the CloudTrail `eventName` is **`AddPermission20150331v2`** / `RemovePermission20150331v2`, not the API name. Match by prefix |
| Key discriminator | Whether anything **confines** the granted principal: `sourceArn` or `sourceAccount` for a service principal, `principalOrgID` for a wildcard, organisation membership for an account ID. Not the event name, and not the principal alone — `s3.amazonaws.com` is both the commonest legitimate value and the confused-deputy shape |
| Ground-truth signal | The whole policy from `GetPolicy` (`Policy`, a JSON **string**, plus `RevisionId`). `AddPermission` events carry one statement each and only within retention, so events alone cannot reconstruct it |
| "Was it used" pivot | **Data-plane** `Invoke`, `resources.type` `AWS::Lambda::Function`, off by default and absent from `lookup-events` forever. Match on **`resources[].ARN`** — CloudTrail normalises it to the unqualified base ARN, which is also the field its own advanced event selectors key on. `requestParameters.functionName` mirrors whatever the caller typed (bare name, partial ARN, full ARN, or alias-qualified) and on the synchronous path may not be recorded at all, so filtering on it drops exactly the invokes an attacker testing a backdoor makes. Proof of exercise is `userIdentity.accountId` ≠ `recipientAccountId` in the **function owner's** trail |
| Field-shape traps | `responseElements.statement` and `GetPolicy`'s `Policy` are JSON **strings** needing a second parse. Confinement fields are present only when supplied — test for null, not for a value. Condition **key names** vary in case (`AWS:SourceArn` from a service grant, `aws:PrincipalOrgID` from an org grant): compare lower-cased |
| Blast radius | Every invocation runs under the function's **execution role**, and a synchronous invoke returns the handler's response body to the caller. The grant is also durable: it survives key rotation, session revocation, trust-policy repair and code redeployment |
| Error strings | Denials: `AccessDenied` (AWS's own Lambda CloudTrail example) **and** `AccessDeniedException` (Lambda common errors, HTTP 403) — match both, prefix-tolerantly, and confirm against a real denied event. Not `Client.`-prefixed. Non-denials on this path: `PublicPolicyException` (400), `ResourceConflictException` (409), `ResourceNotFoundException` (404), `InvalidParameterValueException` (400), `PreconditionFailedException` (412), `PolicyLengthExceededException` (400), `TooManyRequestsException` (429), `ServiceException` (500) |
| Size / omission | No size-based evasion path. Resource policy quota 20 KB; `PutResourcePolicy`'s `Policy` parameter capped at 20,480 characters — both far below CloudTrail's 100 KB `requestParameters` omission threshold, so an oversized document is rejected with `PolicyLengthExceededException` and never stored |
| Reversal semantics | `RemovePermission` is effective on the next request — authorization is evaluated per request against current policy, and the invoker needs no containment. But the policy is **unversioned**: removal destroys the only live copy, and removing the last statement deletes the policy object so `GetPolicy` then throws `ResourceNotFoundException` |
| Coverage blind spot | IAM Access Analyzer *"reports external access based on resource-based policies attached to functions and layers"* but *"doesn't report external access based on resource-based policies attached to aliases and specific versions invoked using a qualified ARN"*. A grant added with `--qualifier` is invisible to it while remaining fully usable |
| GuardDuty | No finding type detects this. Lambda Protection watches a function's **network activity** once running (`Backdoor:Lambda/C&CActivity.B`, `UnauthorizedAccess:Lambda/MaliciousIPCaller`), not who is permitted to run it. Its silence is not coverage |
| Sibling techniques | `../iam.persistence.role-trust-backdoor/` — same external-principal discriminator, identity side. `reference/PLAYBOOK.md` — same Lambda data-plane invoke caveat |

**MITRE mapping note:** the source rules tag **T1584** (*Compromise Infrastructure*), tactic **TA0042** (*Resource Development*) — a technique describing an adversary taking over third-party infrastructure **before** an operation, to stage it from. Nothing here is pre-operational and nothing third-party is compromised: the actor already holds credentials in the victim account and manipulates a resource inside it to keep them. This is a substantive mapping error rather than a precision note, because T1584/TA0042 routes an account-persistence alert into a pre-attack bucket where it will not be triaged as an active intrusion; the second rule carries no mapping at all. **T1098** (*Account Manipulation*), tactic **Persistence (TA0003)**, is correct and is what the shipped rules carry. The parent technique is the right precision level: T1098's cloud sub-techniques `.001` (Additional Cloud Credentials) and `.003` (Additional Cloud Roles) are both identity-side, and no sub-technique covers a grant written onto a **resource**.

### Residual Risk

**Everything the backdoor already returned has already been returned.** Removing the statement stops the next call and does nothing about the ones that landed. A synchronous invoke hands the handler's response body straight to its caller, so any data the function reads — a database row, a decrypted secret, an internal API's answer — left the account on the first invocation and no policy change recalls it. Without Lambda data events you cannot even enumerate how many times that happened: the CloudWatch `Invocations` metric shows the function ran and never who called it, and that gap is unclosable retrospectively.

**The execution role is exposed for as long as its credentials remain valid**, and `aws:TokenIssueTime` revokes only what was issued before the cutoff — so the real remediation is rotating every secret the role could reach. Those reads are at least enumerable: `secretsmanager:GetSecretValue`, `ssm:GetParameter*` and `kms:Decrypt` are **management** events in a default trail and name exactly which secrets were touched. The genuinely dark read is `s3:GetObject`, which is data-plane; absent an S3 data trail, any object the role could reach must be treated as disclosed.

**The prior policy is gone.** A Lambda resource policy has no version history and no `Get*PolicyVersion`. Once you removed the statement, the only surviving record of what the function used to permit is the `$EVIDENCE` capture from Containment Step 1 and the CloudTrail events behind it. When those age out, the question becomes permanently unanswerable — keep the capture outside the account.

**Other placements of the same grant may remain.** The sweep is only as complete as the regions, qualifiers and accounts you could read. Every `[!] INCONCLUSIVE` line is a function whose policy was never examined, a grant on an **alias** is invisible to Access Analyzer, and a layer version shared through `AddLayerVersionPermission` is attacker-controlled code your functions import without any function-level statement at all. Close those before declaring the account clean.

**Detection coverage stays partial by construction.** The rules see the moment of granting. They cannot see a grant planted before your retention window began, and they cannot decide whether an account ID is yours without the allowlist being kept current as the organisation changes. The scheduled `GetPolicy` sweep is what converts this from an alert into a control; until it runs continuously, a backdoor planted quietly enough reaches an analyst only if something else fires.
