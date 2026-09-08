# IR Playbook: Model Access Enumeration — a credential mapping what it can reach through `InvokeModel` refusals

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Discovery (a credential is being swept against foundation models to establish what it is permitted to use) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. The sweep costs the attacker nothing, produces no successful invocation and therefore no cost signal and no invocation-log record — CloudTrail is the only place it exists. And it is preparation: what follows is the use of whichever model answered. |
| MITRE Tactics | Discovery |
| MITRE Techniques | T1526 |
| Services in Scope | Bedrock, Bedrock Runtime, IAM, CloudTrail |

**What the technique does:** somebody has a credential and does not know what it is worth. They call
`InvokeModel` against model after model and read the failures. `AccessDeniedException` means the
model is there and enabled and they cannot use it. `ValidationException` means it is not enabled in
this Region. `ThrottlingException` means the call was **permitted**. Within a few dozen requests they
have a map of the account's model access and the boundary of the credential's permission — and, if
one call succeeded, a model they can use at the owner's expense.

**Why the usual reflexes miss it.** The reflex is a metric alarm on error count, which is what the
source pack ships — and it merges three error codes that answer three different questions. The
second reflex is to look in the model invocation log, which has nothing: a call that failed
authorisation produced no invocation to log, and that log is off by default anyway. The third is to
treat failures as noise, which is exactly right for one failure and exactly wrong for forty against
forty different models.

**Detection thesis:** count **distinct models refused per access key**. The breadth is the survey,
and the single `ThrottlingException` or success among the refusals is the finding.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail data events for `bedrock-runtime.amazonaws.com`.** This is the only source for this
  technique — refusals produce no invocation log — so its absence makes the whole use case
  undetectable rather than degraded.
- **CloudTrail management events for `bedrock.amazonaws.com`**, for `PutFoundationModelEntitlement`
  and the model-access family.
- **Model invocation logging enabled**, for the half of the incident that succeeds. Off by default,
  cannot be applied retroactively, and covered in `../bedrock.impact.high-invocation-count/`.

**Alerting (must be pre-configured)**
- **One access key refused across five or more distinct models within an hour → P0**
- **A `ThrottlingException` alongside more than ten `AccessDeniedException` from the same key → P0**
- **100 or more refusals from one access key within an hour → P1**
- **`PutFoundationModelEntitlement` by a principal outside the platform function → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- The list of models the organisation has enabled, per Region. It is what turns "forty refusals"
  into "they now know we have these four".

**Known IOC Baselines**
- Model routers and evaluation harnesses that legitimately discover available models at start-up.
  They produce exactly this shape, once per deployment, on a schedule somebody can name.
- Which principals should reach Bedrock at all. In most estates the list is short, which makes an
  unfamiliar access key the finding before the breadth is even counted.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | One `userIdentity.accessKeyId` refused across ≥ 5 distinct `modelId` values in an hour | CloudTrail (`bedrock-runtime`, correlation) | T1526 |
| P0 | A `ThrottlingException` from a key that also produced more than ten `AccessDeniedException` — one model answered | CloudTrail (`bedrock-runtime`) | T1526 |
| P0 | A successful invocation from a key that was refused across ≥ 5 models in the same window | CloudTrail (`bedrock-runtime`) | T1526 |
| P1 | ≥ 100 refusals from one access key within an hour | CloudTrail (`bedrock-runtime`, correlation) | T1078.004 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutFoundationModelEntitlement` by a principal outside the platform function, or in an unused Region | CloudTrail (`bedrock`) | T1526 |
| P2 | Refusals from one key spread across multiple Regions — model access is per-Region and a sweep moves between them | CloudTrail (`bedrock-runtime`) | T1526 |
| P3 | Sustained refusals against one or two models — usually a broken application, and worth fixing either way | CloudTrail (`bedrock-runtime`) | T1078.004 |

### Detection Rule Quality Notes

The source entry is a **building block with no query, no threshold and no grouping** — a CloudWatch
metric alarm for availability. There is no logic to audit, so this table records what the source
provides against what a security detection needs, rather than inventing defects in an empty rule.

| Issue | Impact | Correction |
|-------|--------|-----------|
| The source entry carries no detection logic at all | Nothing fires. Bedrock enumeration has no coverage in the pack — the gap is total rather than defective | Four documents on the CloudTrail error stream, covering breadth, volume and the entitlement grant |
| An error-count alarm merges the error codes | `AccessDeniedException`, `ValidationException` and `ThrottlingException` answer three different questions, and the third means the call was **permitted**. Merging them discards the one result that matters | Each code counted separately, with a verdict that reads a single `ThrottlingException` as outranking a hundred denials |
| A count has no actor | A metric alarm says the account is producing errors, not which credential is producing them — and the credential is the only fact containment needs | Group by `userIdentity.accessKeyId`, which identifies the credential rather than the session |
| Breadth is not measured | Volume with low breadth is a broken application retrying; breadth is a survey. They need different responses and a single count cannot separate them | Distinct `modelId` count as the primary rule, volume as a separate lower-confidence one |
| Nothing looks for the success among the failures | The purpose of the sweep is to find the one model that answers. A rule watching only errors reports the survey and misses its result | `SuccessAfterSweep` in the KQL, and a P0 trigger on a success from a key refused across five or more models |
| No control-plane coverage | An actor who maps the boundary and can widen it does so through model access enablement, which is a different event source entirely | `bedrock_model_entitlement_changed` on `bedrock.amazonaws.com` |

**Recommended detection — breadth, and the one call that succeeded.**

```yaml
# Model access enumeration through invocation errors (T1526 / T1078.004)
#
# THE SOURCE ENTRY IS A BUILDING BLOCK WITH NO LOGIC — no query, no threshold, no grouping. It is a
# CloudWatch metric alarm for availability. There is nothing to correct, and this file does not
# manufacture defects in an empty rule; it is a new security use case, and ../PLAYBOOK.md §2 says so.
#
# THE ERROR TYPE IS THE INFORMATION THE ATTACKER IS BUYING, AND THAT IS THE WHOLE DETECTION.
# A credential holder who does not know what they hold sweeps models and reads the failures:
#
#   AccessDeniedException      -> the model EXISTS and is enabled here, and this principal is not
#                                 permitted. That is a positive result for enumeration: it maps the
#                                 boundary of the permission.
#   ValidationException        -> the model is not enabled in this Region, or the request shape is
#                                 wrong for that model. Distinguishes "not available" from "not
#                                 allowed", which is exactly the distinction an attacker wants.
#   ResourceNotFoundException  -> no such model identifier here.
#   ThrottlingException        -> the request was permitted and rate-limited, which confirms access.
#   ServiceQuotaExceededException / ModelNotReadyException -> also confirm the model is reachable.
#
# So a burst of AccessDenied across many distinct modelIds is a permission map being drawn, and a
# SINGLE ThrottlingException among them is more significant than all of them — it means one model
# answered. An availability alarm counting "errors" merges all of these into one number and loses
# every distinction that matters.
#
# ERRORS ARE IN CLOUDTRAIL, NOT IN THE INVOCATION LOG. Model invocation logging records invocations;
# a call that failed authorisation produced no invocation to log. So this use case is CloudTrail-only
# by construction, which also means it works in the common case where invocation logging was never
# enabled — the opposite of the sibling playbook on invocation volume.
#
# identity.arn HAS NO EQUIVALENT HERE. In CloudTrail the actor is userIdentity.arn and the key is
# userIdentity.accessKeyId, which is the better grouping key for a credential being explored: one
# leaked key may be used from several sessions.
title: Bedrock invocation refused
id: 2f5a70c8-4b19-4ed6-93a2-c07f18b5e246
name: bedrock_invocation_refused
status: experimental
description: >-
  A Bedrock runtime call failed. Base rule for the correlations below and not for direct alerting —
  a single refusal is an application using a model it is not entitled to, which is a deployment
  problem. The error codes are enumerated rather than matching any failure, because each one tells
  the caller something different and the corrected detections read that difference.
references:
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'bedrock-runtime.amazonaws.com'
    eventName:
      - 'InvokeModel'
      - 'InvokeModelWithResponseStream'
      - 'Converse'
      - 'ConverseStream'
  refused:
    errorCode:
      - 'AccessDeniedException'
      - 'AccessDenied'
      - 'ValidationException'
      - 'ResourceNotFoundException'
      - 'ThrottlingException'
      - 'ServiceQuotaExceededException'
      - 'ModelNotReadyException'
  condition: selection and refused
level: informational
---
title: One credential refused across many distinct models
id: 8d0c364f-7a25-41be-b980-53e2914cf7a0
status: experimental
description: >-
  A single access key was refused against an unusual number of distinct models. This is a permission
  map being drawn: each AccessDeniedException confirms the model exists and is enabled in the
  Region while this principal cannot use it, and each ValidationException separates "not available
  here" from "not allowed". The sweep costs the attacker nothing and produces no successful
  invocation, so no cost signal and no invocation-log record exists — this rule and CloudTrail are
  the only places it appears. group-by is the access key rather than the ARN, because one leaked
  credential is used across several sessions and the key is what identifies it.
references:
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: value_count
  rules:
    - bedrock_invocation_refused
  group-by:
    - userIdentity.accessKeyId
  timespan: 1h
  condition:
    field: requestParameters.modelId
    gte: 5
falsepositives:
  - >-
    A model router or evaluation harness discovering which models are available at start-up, which
    produces exactly this shape once per deployment. Distinguished by recurring on a schedule and by
    the principal being nameable; exclude by key or role, not by raising the count.
level: high
---
title: Sustained refusals from one credential
id: 4b19e07d-58ca-42f3-a6c1-90d7325be814
status: experimental
description: >-
  Volume of refusals from one access key, regardless of model breadth. Separated from the breadth
  rule because they catch different things: breadth is a survey, and volume with low breadth is a
  credential being retried against a single target — a script that does not know it has already
  failed, or one waiting for an entitlement to be granted. Lower confidence than breadth and worth
  having, because a broken application produces the same shape and both are worth someone's
  attention.
references:
  - https://attack.mitre.org/techniques/T1078/004/
tags:
  - attack.discovery
  - attack.t1078.004
correlation:
  type: event_count
  rules:
    - bedrock_invocation_refused
  group-by:
    - userIdentity.accessKeyId
  timespan: 1h
  condition:
    gte: 100
falsepositives:
  - >-
    An application whose entitlement was revoked and which retries in a loop. Common, genuinely a
    defect, and it should be fixed rather than allowlisted — an application retrying a forbidden
    call forever is a problem whichever way the permission question lands.
level: medium
---
title: Bedrock model access entitlement changed
id: c7241b95-6e30-49da-8f07-1a5b83c60d29
name: bedrock_model_entitlement_changed
status: experimental
description: >-
  Model access was requested or granted in the account. This is the control-plane companion to the
  enumeration rules and it closes the loop: an actor who maps the permission boundary and then finds
  they can widen it does so here. Model access is per-Region and per-model, so a grant in a Region
  nobody operates in is the same signal as an invocation from one. It is shipped at medium because
  legitimate enablement is routine — the finding is enablement by a principal outside the platform
  function, or in an unexpected Region.
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'bedrock.amazonaws.com'
    eventName:
      - 'PutFoundationModelEntitlement'
      - 'CreateModelInvocationJob'
      - 'PutUseCaseForModelAccess'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own model enablement.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A team enabling a model they intend to use. Routine, and the alert is how you learn it happened
    without a request — the Region in the same event is the fastest triage field.
level: medium
```

What this set structurally cannot do: it cannot show what was sent to the model that answered —
refusals leave no invocation log, and the success leaves one only if invocation logging was already
enabled. It cannot see guardrail refusals, which are not API errors: the call succeeds and the
response carries the intervention.

---

### Key Investigation Queries

> All queries read CloudTrail. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events
> per page** — paginate on `NextToken` or use your log platform. Model access is per-Region: run
> these in every Region where Bedrock is enabled, and in the ones where it is not.

#### Query 1 — Reconstruct: what this credential tried, and what it learned

```bash
REGION="us-east-1"
KEY="<access-key-from-the-alert>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$KEY" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "bedrock-runtime.amazonaws.com") |
    {time: .eventTime, event: .eventName,
     model: (.requestParameters.modelId // "-"),
     error: (.errorCode // "SUCCESS"),
     region: .awsRegion, ip: .sourceIPAddress, agent: .userAgent}' | \
  jq -s 'group_by(.error) | map({error: .[0].error, count: length,
                                 models: (map(.model) | unique)})'
```

Read the groups. The `SUCCESS` group — if it exists — names the models the credential can actually
use, and that is the scope of the rest of the incident. `ThrottlingException` belongs with it: the
call was permitted. The `AccessDeniedException` group is what the attacker now knows exists and is
enabled, which is a disclosure even where nothing succeeded.

#### Query 2 — Sweep: is the same credential doing this elsewhere

```bash
KEY="<access-key>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  N=$(aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$KEY" \
        --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
      jq '[.Events[].CloudTrailEvent | fromjson
           | select(.eventSource == "bedrock-runtime.amazonaws.com")] | length')
  [ "${N:-0}" -gt 0 ] && echo "[!] $REGION: $N bedrock-runtime call(s) from $KEY"
done
echo "[i] Model access is per-Region. A sweep that found nothing in one Region says nothing about"
echo "    another, and an actor exploring a credential moves between them."
```

#### Query 3 — Inspect: what the credential is and what else it reached

```bash
KEY="<access-key>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)
REGION="us-east-1"

echo "== everything this key did, by service =="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$KEY" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {src: .eventSource, event: .eventName, error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'

echo
echo "== which models are enabled here, so the disclosure can be sized =="
aws bedrock list-foundation-models --region "$REGION" --output json 2>/dev/null | \
  jq -r '.modelSummaries[] | select(.modelLifecycle.status == "ACTIVE") | .modelId' | head -30
```

A credential being swept against Bedrock is usually being swept against everything. The per-service
grouping shows whether Bedrock was the target or one stop on a tour, and the source addresses
usually settle whether this is a workload at all.

#### Query 4 — Full session reconstruction, and whether entitlements changed

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in PutFoundationModelEntitlement PutUseCaseForModelAccess \
          PutModelInvocationLoggingConfiguration DeleteModelInvocationLoggingConfiguration; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       region: .awsRegion, error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

An entitlement granted shortly after a sweep is the loop closing: the actor mapped the boundary and
then moved it. A `DeleteModelInvocationLoggingConfiguration` in the same window is a different and
worse finding — covered in `../bedrock.stealth.low-invocation-count/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Revoke, then establish what the sweep found. The second is what sizes the incident.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Revoke the credential

```bash
KEY="<access-key>"
PRINCIPAL="<arn-from-Query-1>"

if echo "$PRINCIPAL" | grep -q ":user/"; then
  U=$(echo "$PRINCIPAL" | awk -F'/' '{print $NF}')       # user ARN: name = last segment
  aws iam update-access-key --user-name "$U" --access-key-id "$KEY" --status Inactive \
    && echo "[OK] deactivated $KEY"
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
elif echo "$PRINCIPAL" | grep -q ":assumed-role/"; then
  R=$(echo "$PRINCIPAL" | awk -F'/' '{print $2}')        # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $PRINCIPAL is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

#### Step 2 — Establish whether anything answered

```bash
echo "[i] From Query 1's grouped output:"
echo "    SUCCESS present            -> the models listed are what the credential could use."
echo "                                  Go to ../bedrock.impact.high-invocation-count/ for the"
echo "                                  cost and content half; that is now the live incident."
echo "    ThrottlingException only   -> the call was PERMITTED and rate-limited. Treat as success."
echo "    AccessDenied / Validation  -> the sweep found nothing usable. Still a disclosure: the"
echo "                                  attacker now knows which models exist and are enabled."
```

This is the step that decides whether the incident ends here. A sweep that found nothing is a
revocation and a note; a sweep with one success is the beginning of the resource-hijacking playbook.

#### Step 3 — Size the disclosure even where nothing succeeded

Every `AccessDeniedException` told the caller that a model exists and is enabled in that Region.
That is information about the account's configuration, obtained for free and not recoverable. It is
worth recording, because it shapes what a second attempt with a better credential would go straight
to.

#### Step 4 — Check whether the boundary moved

Query 4's entitlement events. An actor who maps the permission boundary and then finds they can
widen it does so through model access enablement, and that is a materially larger incident than the
sweep — it means the credential carries `bedrock:PutFoundationModelEntitlement` or equivalent.

---

## 4. Eradication

### Remove Attacker Access

#### Find the leak

The credential reached the attacker from somewhere — a repository, a build log, an image layer, an
environment file. Rotating without finding the source means rotating again.

#### Scope the Bedrock permission to named models

`bedrock:InvokeModel` on `*` is what makes a sweep worth performing. Scoping it to the model ARNs a
workload actually uses turns forty informative refusals into forty uninformative ones, and makes
the breadth detection far more precise as a side effect.

#### Restrict Regions

Model access is per-Region and an unused Region is where a sweep goes. An SCP on
`aws:RequestedRegion` for the Bedrock actions removes most of the search space.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or retired.

---

## 5. Recovery

### Restore Clean State

#### Verify the credential is inactive and no longer calling

```bash
KEY="<access-key>"
REGION="us-east-1"
SINCE=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)

N=$(aws cloudtrail lookup-events \
      --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$KEY" \
      --start-time "$SINCE" --region "$REGION" --output json | jq '.Events | length')
[ "${N:-0}" -eq 0 ] && echo "[OK] no calls from $KEY in the last hour" \
                    || echo "[FAIL] $N call(s) from $KEY since revocation — check the key status and the role trust policy"
```

#### Verify no principal has unrestricted model access

Re-run the policy sweep from `../bedrock.impact.high-invocation-count/` §5. A grant on `*` is what
makes enumeration productive.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire at high on:"
echo "  one accessKeyId with AccessDeniedException across 6 distinct modelId values in an hour"
echo "and MUST escalate on:"
echo "  the same key producing ONE ThrottlingException among those refusals"
echo "  (the call was PERMITTED — that single event outweighs every denial beside it)"
echo "The rule MUST NOT fire at high on:"
echo "  200 AccessDeniedException against ONE model from one key"
echo "  (a broken application retrying — real, worth fixing, and not enumeration)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A credential could sweep every model in the account | `bedrock:InvokeModel` granted on `*` rather than on named model ARNs |
| The sweep produced no alert | The only Bedrock rule was a metric alarm on error count with no actor and no breadth measure |
| The one permitted call was lost among the refusals | Error codes were merged, and `ThrottlingException` means the call succeeded |
| The sweep reached Regions nobody uses | No Region restriction on the Bedrock actions, and model access is per-Region |
| Nothing recorded what the attacker learned | The disclosure — which models exist and are enabled — is not tracked as an outcome |

### Recommended Guardrails

**Restrict Bedrock to the Regions in use**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
             "bedrock:Converse", "bedrock:ConverseStream",
             "bedrock:PutFoundationModelEntitlement"],
  "Resource": "*",
  "Condition": { "StringNotEquals": { "aws:RequestedRegion": ["us-east-1", "eu-west-1"] } }
}
```

**Structural controls**
- Scope `bedrock:InvokeModel` to named model ARNs. It is the control that makes a sweep
  uninformative rather than merely detected.
- Keep model enablement in the platform function. `PutFoundationModelEntitlement` in an application
  role's policy is how a mapped boundary gets widened.
- Enable model invocation logging before it is needed. This use case does not require it — refusals
  produce no invocation — but the half that succeeds does, and it cannot be applied retroactively.

**Detection improvements**
- Count distinct models, not errors. Breadth is the survey; volume with low breadth is a broken
  application.
- Keep the error codes apart. `ThrottlingException` means permitted, and merging it with
  `AccessDeniedException` discards the only result the attacker was looking for.
- Group by access key rather than by ARN or session. One leaked credential is used across many
  sessions, and the key is what identifies it.
- Watch the entitlement events alongside the runtime errors. The sweep and the grant that follows it
  are one incident in two event sources.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1526 — Cloud Service Discovery |
| MITRE tactic | Discovery (TA0007) |
| Primary API | `bedrock:InvokeModel` and its siblings, failing; `bedrock:PutFoundationModelEntitlement` where the boundary is widened |
| Event source | `bedrock-runtime.amazonaws.com` data events in CloudTrail. **Not** the model invocation log — a refused call produces no invocation |
| Key discriminator | Distinct `modelId` count per `userIdentity.accessKeyId`, with the error codes kept apart |
| Ground-truth signal | The CloudTrail error stream itself. A `ThrottlingException` or a success among the refusals names what the credential can actually reach |
| "Was it used" pivot | The `SUCCESS` group in Query 1. If it is non-empty, the incident continues in `../bedrock.impact.high-invocation-count/` |
| Blast radius | The models the credential could reach, plus the configuration disclosure — which models exist and are enabled — which is not recoverable |
| Error strings | `AccessDeniedException` (exists, not permitted), `ValidationException` (not enabled here, or bad request shape), `ResourceNotFoundException`, `ThrottlingException` (**permitted** and rate-limited), `ServiceQuotaExceededException`, `ModelNotReadyException` |

**MITRE mapping note:** the source entry maps to nothing and carries no detection logic — it is a
CloudWatch metric building block. `T1526 — Cloud Service Discovery` describes what the sweep
achieves: a map of which cloud services and models the credential can reach.
`T1078.004 — Valid Accounts: Cloud Accounts` is carried by the volume rule, which observes a
credential in use rather than a survey. Both verified live 2026-08-30.

### Residual Risk

Every `AccessDeniedException` told the caller that a model exists and is enabled in that Region.
That disclosure is free, permanent and not recoverable — a second attempt with a better credential
starts from a map rather than from nothing. If anything succeeded, what was sent to it is knowable
only where model invocation logging was already enabled, and it is off by default. A guardrail
refusal is not an API error, so this rule cannot see one and an absence of errors is not evidence
that the content was acceptable. And the sweep may have continued in a Region not checked: model
access is per-Region, and a clean result in one says nothing about another.
