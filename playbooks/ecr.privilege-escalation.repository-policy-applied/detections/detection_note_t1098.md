# Detection Note — T1098 (ECR Repository Policy Applied)

**Signal:** `SetRepositoryPolicy` whose `policyText` names an image-**write** action; the same
call made with `force: true`; one principal applying policies to three or more repositories in
thirty minutes; `DeleteRepositoryPolicy`; and the denials, counted separately.

**A repository policy is the registry's resource-based policy, and the dangerous grant is
push, not pull.** AWS: *"By default, only the AWS account that created the repository has
access to the repository."* `SetRepositoryPolicy` replaces that default with a document naming
Principals. A pull grant exposes image *contents* — real, and a data-exposure incident. A
**push** grant (`ecr:PutImage` plus the three layer-upload actions, or `ecr:*`) exposes the
*deployment path*: the grantee can write images into a repository your workloads deploy from.
Paired with a mutable tag — `../../ecr.stealth.image-tag-overwrite-enabled/` — that is a
complete container supply-chain compromise established by two API calls, and the second one is
a legitimate `docker push`.

**What the original rule got wrong** — it matches `eventName:"SetRepositoryPolicy"` with a
success filter and one hard-coded principal exclusion, and never opens the document. Three
consequences:

1. **Every IaC run that applies a repository policy fires it**, at the same priority as a
   cross-account push grant. That is how a rule gets muted inside a week, and once muted the
   grant that matters arrives in a suppressed channel.
2. **`force: true` is invisible to it.** AWS requires `force` only when the document *"would
   prevent you from setting another policy in the future"* — a lock-out, which outside a
   ticketed change has no benign reading.
3. **The removal is invisible to it.** `DeleteRepositoryPolicy` is not matched at all, and it
   is an evidence event (below).

## `Principal: "*"` is not anonymous — and the distinction cuts both ways

AWS is explicit: *"Amazon ECR requires that users have permission to make calls to the
`ecr:GetAuthorizationToken` API through an IAM policy before they can authenticate to a
registry and push or pull any images from any Amazon ECR repository."* `GetAuthorizationToken`
is registry-level and IAM-only; a repository policy cannot grant it.

So a wildcard principal on an ECR repository does **not** expose it to unauthenticated internet
traffic the way a public S3 bucket policy does. It exposes it to **every AWS account**, because
any account holder can grant themselves `ecr:GetAuthorizationToken` in their own account and
then present that token. Neither "it is public" nor "it is fine, they still need
GetAuthorizationToken" is the correct reading. The correct reading is **"any AWS customer who
knows the repository URI"**, and for a push grant that is indistinguishable from public in
every way that matters to an incident.

AWS also documents the intersection: *"If a user or role is allowed to perform an action
through a repository policy but is denied permission through an IAM policy (or vice versa) then
the action will be denied."* Within your own account an IAM deny still holds. Across accounts
it does not help you at all — the grantee's IAM policy is written by the grantee.

## The policy is its own only record

**ECR keeps no version history for repository policies**, and the two ways a policy disappears
are not symmetrical — a distinction worth getting right, because it decides whether evidence
still exists:

- **`DeleteRepositoryPolicy` returns the document it removed.** Its response elements are
  `policyText`, `registryId` and `repositoryName`, so the delete event itself preserves what was
  in force. This is frequently the cleanest surviving copy.
- **A second `SetRepositoryPolicy` silently replaces the previous document** and carries no
  trace of it. After an overwrite, the only copy of what was granted is
  `requestParameters.policyText` in the *earlier* applying event — bounded by trail retention
  and by `lookup-events`' ninety-day Event history.

So the destructive path is the overwrite, not the delete. That is why the playbook's first
containment step is a **capture**, not a fix, and it is one reason this use case is authored at
Tier 1: an overwrite during remediation destroys the evidence (test 4 of `07-TIERS.md`), and
the set of principals who held access has to be reconstructed before the grant is closed
(test 3).

## Encoding, whitespace, and why every match is on an action token

Rule **A4** applies directly and the direction matters. `requestParameters.policyText` is the
document **as the client sent it — raw JSON, not percent-encoded**. A `|contains` therefore
matches it, and a decode step on the request parameter is wrong. Percent-encoding is a property
of what AWS *returns*.

What varies on the request side is **whitespace**. AWS's own `SetRepositoryPolicy` reference
shows the request compact —
`"policyText": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowPull\",...`
— and the response pretty-printed, with spaces around every colon:
`"{\n  \"Version\" : \"2012-10-17\",\n  \"Statement\" : [ {\n    \"Sid\" : \"AllowPull\",...`.
A document submitted with `--policy-text file://policy.json` carries whatever the file had. So
a pattern keyed on `"Effect":"Allow"` or `"Principal":"*"` misses a pretty-printed document
entirely.

Every Sigma match in this file is therefore on an **action token** — `ecr:PutImage`,
`ecr:UploadLayerPart`, `ecr:*` — strings with no interior punctuation and no assumed spacing.
The structural questions are handed to a parser:

- Is the statement `Allow` or `Deny`?
- Which Principal, and is `Statement` a single object or an array? Is `Principal` an object or
  the bare string `"*"`? Is `Principal.AWS` a string or an array?
- Is there a `Condition` that genuinely confines the grant (`aws:PrincipalOrgID`,
  `aws:PrincipalArn`, `aws:SourceArn`) or merely one that exists?
- Is there a `NotAction`? An `Allow` with `NotAction` grants everything *except* what it lists,
  and a reader that inspects only `Action` is silent on it.

`tools/decode_policy_documents.py` answers all of those, and it guards `Statement`,
`Principal` and `Action` for the object-or-array and string-or-array shapes that make an
unguarded `jq` sweep report clean on exactly the grant it exists to find. Its default `auto`
mode routes a `Principal`-bearing statement to the **trust-policy** evaluator, which is a
different resource-policy dialect from an ECR repository policy: it answers *"which outside
principals are named, and does a Condition confine them"* — exactly the ECR question — but it
knows nothing about ECR's action set, so the push-versus-pull judgement stays with the token
match. Use both; neither alone is sufficient. Its verdict prefixes are `[!] PUBLIC`,
`[!] EXTERNAL`, `[i] CONFINED`, `[i] INTERNAL`, `[i] SERVICE` and `[i] UNPARSED`.

`policyText` is capped at **10,240 characters**, far below CloudTrail's 100 KB
`requestParameters` omission threshold, so there is no size-based evasion path here and no
omission companion rule to ship. An oversized document is rejected outright with
`InvalidParameterException` and never stored.

## Which repository actions belong in which grant

| Grant | Actions in the document |
|-------|-------------------------|
| Pull (read the images) | `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` |
| Push (write the images) | `ecr:PutImage`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:BatchCheckLayerAvailability` |
| Everything | `ecr:*` |
| Never grantable by a repository policy | `ecr:GetAuthorizationToken` — registry-level, IAM only |

A policy granting the layer actions but not `ecr:PutImage` still hands over most of the push
path and should be read as a push grant that is one statement short.

## Response levers

**Error strings:** `SetRepositoryPolicy` documents `InvalidParameterException`, `RepositoryNotFoundException` and
`ServerException`. `DeleteRepositoryPolicy` documents those three plus
`RepositoryPolicyNotFoundException` — *"the specified repository and registry combination does
not have an associated repository policy"*, which on a cleanup path means the policy was already
gone and is worth distinguishing from a failure. Denials
come from ECR's common set: **`AccessDeniedException`** (HTTP 403) and **`NotAuthorized`**
(HTTP 401) are documented; the bare **`AccessDenied`** form is what IAM-evaluated denials
produce across AWS and is widely observed but is not in ECR's documented list. Match all three
prefix-tolerantly and confirm against a real denied event. The remaining common errors —
`ExpiredTokenException`, `ThrottlingException`, `ValidationError`, `UnrecognizedClientException`,
`ServiceUnavailable`, `InternalFailure`, `OptInRequired`, `IncompleteSignature` — are triage
noise here but belong in any denial-counting query, so that probing is never scored as success.

**GuardDuty:** There is **no GuardDuty finding type for ECR repository policy changes.** IAM Access Analyzer
*does* analyse ECR repository policies for external access and is the right standing control —
but it reports the exposure, not the moment of change, and it will not tell you what was
granted after the policy has been overwritten.

**MITRE:** The source maps **T1484 / TA0004** — *Domain or Tenant Policy Modification*. T1484 covers
identity-tenant policy: Group Policy objects, federated trust settings, tenant-wide
configuration that changes who is authenticated and how. A container-registry resource policy
is not that, so the mapping is wrong on the merits even though the ID resolves.

Corrected: **T1098 — Account Manipulation**, carried under Persistence (TA0003) with Privilege
Escalation (TA0004) as the second tactic, matching how the sibling resource-policy use cases in
this corpus are mapped (`../../lambda.persistence.resource-policy-backdoor/` and
`../../sns.collection.sns-topic-was-created-with-public-publish-permissions/` both use T1098).
Consistency here is deliberate: a responder moving between resource-policy playbooks should
find the same identifier. The directory's `privilege-escalation` segment tracks the source's
TA0004 label, which is defensible for the push-grant reading — the grantee gains an ability
they did not have — even though the durable property is persistence.

**Severity:** **High**, against the source's **P3**. A push grant on a repository that production deploys
from is a supply-chain compromise waiting on one `docker push`, the grant survives credential
rotation and session revocation because it is attached to the resource rather than to an
identity, and removing it destroys the record of what it said.

**Files here:**

- `sigma_t1098.yml` — six documents: the push grant (`high`), the forced policy (`high`), a
  base rule (`informational`), a `value_count` correlation firing `high` at three distinct
  repositories in thirty minutes, the policy removal (`medium`, whose response carries the deleted document), and the
  denials (`medium`, counted separately from grants).
- `kql_t1098.kql` — extracts the twelve-digit account numbers named in the document, subtracts
  your own organisation's, and joins to the cross-account pushes and pulls that actually
  happened under the grant, which is the difference between an exposure and an incident.

Siblings: `../../ecr.stealth.image-tag-overwrite-enabled/` is the other half of the
supply-chain attack this grant enables; the repository-creation use case (not in this set) covers a
repository created by an actor to receive images;
the excessive-image-push use case (not in this set) covers the pushes themselves.

Full response procedure is in `../PLAYBOOK.md`.
