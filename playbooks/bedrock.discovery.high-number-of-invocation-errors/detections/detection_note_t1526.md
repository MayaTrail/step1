# Detection Note — T1526 (Cloud Service Discovery) / T1078.004 (Valid Accounts: Cloud Accounts)

**Signal:** one access key refused across an unusual number of distinct models — a permission map
being drawn.

**The error code is the information the attacker is buying, and keeping the codes apart is the whole
detection.** An availability alarm counts "errors" and merges three answers that mean different
things:

- **`AccessDeniedException`** — the model exists and is enabled in this Region, and this principal
  cannot use it. That is a **positive** result for enumeration: it maps the boundary.
- **`ValidationException`** — not enabled in this Region, or the request shape is wrong. Separates
  *not available* from *not allowed*, which is precisely the distinction being sought.
- **`ThrottlingException`** — the call was **permitted** and rate-limited. **One of these among a
  hundred refusals outweighs all of them**, because it means a model answered.

**The source entry has no logic to correct.** It is a building block — no query, no threshold, no
grouping — a CloudWatch metric alarm for availability. This is a new security use case, and the §2
table says that rather than manufacturing defects in an empty rule.

## CloudTrail-only, and that is a strength here

A call that failed authorisation produced no invocation, so model invocation logging has nothing to
say about it — which matters because that logging is **off by default**. This detection therefore
works in the common case where it was never enabled, unlike its sibling at
`../../bedrock.impact.high-invocation-count/`, which needs either plane.

The consequence for grouping: there is no `identity.arn` here, and CloudTrail's
`userIdentity.accessKeyId` is the better key anyway. One leaked credential is used across several
sessions, and the key is what identifies the credential rather than the session.

## The one success matters more than the hundred failures

`SuccessAfterSweep` in the KQL is the column to read first. A sweep that produced nothing tells you
a credential was explored and found wanting — worth revoking, not worth waking anyone. A sweep with
one success tells you **which model the attacker now has**, and `OkModels` names it. That model is
the scope of everything that follows, including the cost exposure covered in the sibling playbook.

## Response levers

**Revocation is ordinary and the triage is not.** This is credential misuse; the containment is the
standard one. What this playbook adds is the scope: which models were reachable, in which Regions,
and whether any answered.

**Model access is per-Region.** A sweep in one Region that found nothing says nothing about another
Region — an actor exploring a credential naturally moves between them, and the `Regions` column is
the check. `../../bedrock.impact.high-invocation-count/` carries the unexpected-Region rule for the
successful case.

**A guardrail refusal is not an API error.** When a guardrail intervenes, the call **succeeds** and
the response carries the intervention. It appears in the invocation log, not in CloudTrail's error
codes, so an absence of errors is not evidence that the content was acceptable — and this rule
cannot see guardrail activity at all.

**`PutFoundationModelEntitlement` closes the loop.** An actor who maps the boundary and then finds
they can widen it does so through model access enablement. It is shipped here at medium because
legitimate enablement is routine — the finding is enablement by a principal outside the platform
function, or in a Region nobody operates in.

**MITRE:** the source maps this to nothing. `T1526 — Cloud Service Discovery` for the enumeration,
`T1078.004 — Valid Accounts: Cloud Accounts` on the volume rule. Both verified live 2026-08-30.

**Severity:** high for model breadth, medium for volume alone and for entitlement changes. Breadth
is rated higher because volume with low breadth is usually a broken application retrying, which is a
defect worth fixing rather than an attack.

**GuardDuty:** no coverage. There is no finding type for Bedrock. The credential-oriented findings
key on anomalous API behaviour generally, and a credential used only against `bedrock-runtime` may
produce nothing at all.

**Files here:**
- `sigma_t1526.yml` — four documents: `bedrock_invocation_refused` (informational base rule), a
  `value_count` correlation on distinct models per access key (high), an `event_count` correlation
  on refusal volume (medium), and `bedrock_model_entitlement_changed` (medium).
- `kql_t1526.kql` — the error codes kept apart, with `SuccessAfterSweep` and `OkModels` naming what
  the enumeration found.

Full response procedure is in `../PLAYBOOK.md`.
