# IR Playbook: SQS Queue Attributes Changed — Resource-Policy Grant and Message Diversion via `sqs:SetQueueAttributes`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Account manipulation / Collection (a queue's resource policy, dead-letter target or retention is rewritten so an outside principal can read, divert or destroy its messages) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** for the wildcard and cross-account grants. Completion of the call *is* the exposure — the grant is live on the next authorization evaluation, there is no exploitation stage after it, and the consumption it enables is invisible in a default trail. The source rule rates this **P3**, the same priority it gives queue deletion, which sorts "an outside account can now read this message stream" into the same queue as "somebody changed a visibility timeout". The redrive and retention paths are Medium: their malicious and benign forms differ by a value, not by a shape |
| MITRE Tactics | Persistence (TA0003), Collection (TA0009) |
| MITRE Techniques | T1098 (primary), T1213 (secondary) — both verified live 2026-08-29 |
| Services in Scope | SQS, CloudTrail (management + SQS data events), CloudWatch (`AWS/SQS`), IAM, KMS, Organizations (SCP/RCP), and every producer or consumer wired to the queue |

**What the technique does:** the actor calls `sqs:SetQueueAttributes` on a queue it can already modify,
carrying an `Attributes` map; one call is enough. Writing `Policy` replaces the queue's
**resource-based** access policy wholesale — no merge, no version history, no response
object — so an Allow naming `"Principal": "*"` or an outside account on `sqs:ReceiveMessage`
makes the message stream readable by someone holding no credential here. Writing
`RedrivePolicy` repoints `deadLetterTargetArn` at a queue the actor controls, so SQS itself
moves every message exceeding `maxReceiveCount` out of the account. Writing
`MessageRetentionPeriod` below the backlog's age expires and deletes it within fifteen
minutes. The access now lives on the resource: rotating keys, revoking sessions and
repairing role trust all leave the grant exactly where it is.

**Detection thesis.** The discriminator is **which key of `requestParameters.attributes` the
call carries and what that key's value says** — never the event name, because
`SetQueueAttributes` is equally how a deploy tunes a timeout and how the sibling
encryption-disable incident presents
(`../sqs.impact.server-side-encryption-for-aws-sqs-queue-was-disabled/`; the redrive target
usually comes from `../sqs.stealth.excessive-queue-creation/`). The source rule matches the
event name and the absence of an error code and inspects no attribute at all.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing SQS **management** events — exactly eleven
  operations: `AddPermission`, `CancelMessageMoveTask`, `CreateQueue`, `DeleteQueue`,
  `ListMessageMoveTasks`, `PurgeQueue`, `RemovePermission`, `SetQueueAttributes`,
  `StartMessageMoveTask`, `TagQueue`, `UntagQueue`
- **SQS data events enabled** (advanced event selector on `resources.type =
  AWS::SQS::Queue`). Without them `ReceiveMessage`/`SendMessage`/`DeleteMessage` are invisible
  forever, and so are `ListQueues`/`GetQueueUrl`/`GetQueueAttributes` — so **enumeration and
  queue-policy reads produce no management event at all**, and their absence is never
  evidence that they did not happen
- `SetQueueAttributes` carries `requestParameters.queueUrl` and
  `requestParameters.attributes.<Name>`; top-level names are lower-camel, **map keys keep
  their documented casing** (`Policy`, `RedrivePolicy`, `MessageRetentionPeriod`,
  `KmsMasterKeyId`, `SqsManagedSseEnabled`). AWS publishes no management-event example for
  this API — confirm the path against one real event. `attributes.Policy` is **raw JSON**; do
  not decode it, and there is **no `responseElements`** (HTTP 200, empty body)
- A **known-good policy per queue held in IaC** (`Policy` is unversioned) and retained
  CloudWatch `AWS/SQS` metrics, whose single `QueueName` dimension proves consumption
  happened but never who did it

**Alerting (must be pre-configured)**
- **`SetQueueAttributes` writing a `Policy` that Allows a wildcard or out-of-organisation principal → P0**
- **`SetQueueAttributes` writing any `Policy` by a principal outside the queue-administration allowlist → P0**
- **`CreateQueue` followed within 15 minutes by a `RedrivePolicy` change from the same principal → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `SetQueueAttributes` whose `attributes.Policy` Allows `"Principal": "*"` with no `Condition` | CloudTrail (management) | T1098 |
| P0 | `SetQueueAttributes` writing `attributes.Policy` by a principal not on the queue-administration allowlist | CloudTrail (management) | T1098 |
| P1 | `CreateQueue` then `RedrivePolicy` naming a queue, same principal, within 15 minutes | CloudTrail (management) | T1213 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `attributes.RedrivePolicy` whose `deadLetterTargetArn` names an account outside the organisation | CloudTrail (management) | T1213 |
| P2 | `attributes.MessageRetentionPeriod` reduced below the queue's backlog age | CloudTrail (management) | T1485 |
| P2 | `NumberOfEmptyReceives`/`NumberOfMessagesReceived` rising with no new consumer deployed | CloudWatch `AWS/SQS` | T1213 |

### Detection Rule Quality Notes

The source rule matches an event name and the absence of an error code, and inspects none of
the attributes that decide what the call actually did.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"SetQueueAttributes"` with no content test | Fires on every Terraform or CloudFormation apply that touches a queue, every autoscaling redrive adjustment and every visibility-timeout tune — a configuration-change audit trail labelled as a security alert, and muted within a week | Require a specific key of `requestParameters.attributes` and test that key's value |
| No principal check, and the same rule also covers the encryption disable | The deployment pipeline cannot be separated from a human in the console or a stolen role session — the strongest discriminator available goes unused — and two incidents with different eradication paths and different residual risk arrive on one alert carrying no field that tells them apart | Allowlist the queue-administration roles, and split on `attributes.Policy`/`.RedrivePolicy` here, `attributes.KmsMasterKeyId`/`.SqsManagedSseEnabled` in the sibling directory |
| `MessageRetentionPeriod` covered nowhere in the source set, and P3 throughout | A retention reduction below the backlog age expires those messages within 15 minutes — destruction neither the purge nor the delete alert can see — while an out-of-organisation read grant is triaged alongside a timeout change | Ship a rule on the attribute's presence, with the analyst comparing the value; P0 for the wildcard and unallowlisted-policy paths |

**Recommended detection — a queue policy granting access to a wildcard principal.**

```yaml
# SQS Queue Attribute Manipulation (T1098 / T1213)
#
# ONE EVENT NAME, TWO INCIDENTS. `SetQueueAttributes` carries the queue's resource policy,
# its KMS key, its redrive policy, its retention period and its visibility timeout in a
# single `Attributes` map. The event name therefore says that *something* about the queue
# changed and nothing about what — a resource-policy grant to an outside account and an
# encryption disable are the same `eventName` from the same `eventSource`. The source rule
# matches that name with no content test at all, so it fires on every autoscaling redrive
# tweak and every Terraform apply, and it cannot tell those two incidents apart. Every rule
# below discriminates on a key of `requestParameters.attributes`, never on the event name.
# The encryption path is the sibling directory
# ../../sqs.impact.server-side-encryption-for-aws-sqs-queue-was-disabled/.
#
# FIELD SHAPE. The API's request body is {"Attributes": {"<Name>": "<value>"}, "QueueUrl":
# "..."}. CloudTrail lower-cases the first character of top-level API parameter names — AWS's
# own SQS CloudTrail example shows `requestParameters.queueUrl` — while the KEYS INSIDE the
# map are data, not parameter names, and keep the exact casing the API reference documents:
# `Policy`, `RedrivePolicy`, `MessageRetentionPeriod`, `KmsMasterKeyId`,
# `SqsManagedSseEnabled`. AWS publishes no management-event example for SetQueueAttributes,
# so `requestParameters.attributes.<Name>` is corroborated by observed events and by the
# request syntax rather than documented outright. Confirm it against one real event before
# deploying.
#
# NO SIZE-EVASION RULE SHIPS HERE. An SQS access policy is capped at 8,192 bytes (AWS SQS
# policy quotas: Bytes 8,192, Statements 20, Principals 50, Conditions 10, Actions per
# statement 7). CloudTrail omits `requestParameters` only above 100 KB, so the document can
# never be large enough to be dropped. An oversized policy is rejected outright with
# InvalidAttributeValue or OverLimit and never produces a success event.
#
# DO NOT DECODE THE REQUEST. `requestParameters.attributes.Policy` is raw JSON in whatever
# whitespace the client sent. Percent-encoding is a property of what IAM-style read APIs
# RETURN, not of a CloudTrail request parameter, and the percent-encoding visible in AWS's
# query-protocol sample request is HTTP form encoding of the wire request — not what
# CloudTrail records. The real hazard on this field is whitespace: `--attributes
# file://attrs.json` submits the document pretty-printed. Every pattern below is either a
# bare token or a whitespace-tolerant regex for that reason.
title: SQS queue policy grants access to a wildcard principal
id: 58487eaf-3437-4732-98fb-2535fc9df001
name: sqs_queue_policy_wildcard_principal
status: experimental
description: >-
  A queue's access policy was set to a document naming `*` as a principal. Any AWS identity
  — and, if the queue is also unencrypted, any anonymous caller — can then send to or
  receive from the queue, and a receive silently starves the legitimate consumer.
references:
  - https://attack.mitre.org/techniques/T1098/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
  - attack.collection
  - attack.t1213
logsource:
  product: aws
  service: cloudtrail
detection:
  # Every content test is its own sibling block, so no block ANDs two keys that cannot
  # co-occur on one event. The regex covers "Principal":"*", {"AWS":"*"} and {"AWS":["*"]}
  # across any whitespace; the `\\?` groups are REQUIRED, because a platform that indexes the
  # raw serialised event delivers this nested JSON string's quotes backslash-escaped.
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'SetQueueAttributes'
  wildcard_principal:
    requestParameters.attributes.Policy|re: '\\?"Principal\\?"\s*:\s*(\{\s*\\?"AWS\\?"\s*:\s*)?(\[\s*)?\\?"\*\\?"'
  success:
    errorCode: null
  condition: selection and wildcard_principal and success
falsepositives:
  - >-
    A `"Principal":"*"` bounded by `aws:PrincipalOrgID` or `aws:SourceArn` is AWS's
    documented organisation-wide or service-fronted pattern. This rule does not read
    `Condition`, so it fires on those too — a true finding about scope, not a compromise.
level: high
---
# POPULATE `queue_admin_pipeline` BEFORE DEPLOYING. Unpopulated it fires on every legitimate
# IaC apply. The point of the rule is that in most accounts exactly one deployment role and
# one break-glass role have any business rewriting a queue policy, and everything else is an
# incident — including a human in the console.
title: SQS queue policy rewritten outside the queue-administration pipeline
id: dfc9e557-2b38-4a67-b5d8-988bb6daa9be
name: sqs_queue_policy_changed_outside_pipeline
status: experimental
description: >-
  A queue's access policy was replaced by a principal that is not on the
  queue-administration allowlist. `SetQueueAttributes` writes the `Policy` attribute
  wholesale — there is no merge, no version history and no response object — so this event
  is the only surviving record of what the queue used to permit.
references:
  - https://attack.mitre.org/techniques/T1098/                                                        # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'SetQueueAttributes'
  # Presence test for the Policy key. `Statement` is a bare token that every valid policy
  # document contains and that no whitespace style can break apart — unlike
  # `"Effect": "Allow"`, whose punctuation-with-assumed-spacing is what makes the source
  # rules in the IAM siblings miss pretty-printed documents.
  policy_present:
    requestParameters.attributes.Policy|contains: 'Statement'
  queue_admin_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  success:
    errorCode: null
  condition: selection and policy_present and success and not queue_admin_pipeline
falsepositives:
  - >-
    A newly introduced deployment role not yet added to the allowlist. Reconcile against the
    roles that actually run your infrastructure pipeline rather than muting the rule — the
    allowlist is the whole discriminator.
level: high
---
# The redrive policy names the queue that failed messages are moved to. Repointing it at an
# attacker-controlled queue diverts every message that exceeds `maxReceiveCount` — and an
# attacker who also sets `VisibilityTimeout` low, or simply receives and abandons messages,
# controls how fast that happens. Nothing about the source queue looks wrong afterwards.
title: SQS dead-letter target repointed
id: f964994a-8a5c-42c9-87ce-6e5cc3c3607e
name: sqs_queue_redrive_policy_changed
status: experimental
description: >-
  A queue's `RedrivePolicy` was rewritten, changing which queue receives messages that
  exceed the maximum receive count. Read `deadLetterTargetArn` out of the event and confirm
  the account segment of that ARN is yours — the redrive target may legally sit in another
  account.
references:
  - https://attack.mitre.org/techniques/T1213/                                                        # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html # retrieved 2026-08-29
tags:
  - attack.collection
  - attack.t1213
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'SetQueueAttributes'
  # `deadLetterTargetArn` is the one token a redrive policy cannot omit, and it is a bare
  # identifier, so this presence test survives any whitespace style.
  redrive_present:
    requestParameters.attributes.RedrivePolicy|contains: 'deadLetterTargetArn'
  success:
    errorCode: null
  condition: selection and redrive_present and success
falsepositives:
  - >-
    Legitimate DLQ wiring at deploy time. This is common, which is why the rule is medium
    and why the value of the finding is in reading the target ARN's account ID, not in the
    event itself. Pair it with the `sqs_create_then_redirect` correlation below, which is
    the shape that is not routine.
level: medium
---
# The third way to destroy a queue's messages, and the only one that is not called
# DeleteQueue or PurgeQueue. AWS: "Changes made to the MessageRetentionPeriod attribute can
# take up to 15 minutes and will impact existing messages in the queue potentially causing
# them to be expired and deleted if the MessageRetentionPeriod is reduced below the age of
# existing messages." A drop to the 60-second floor destroys a backlog under a name that
# reads as a tuning change, and neither destruction alert in the sibling directories fires.
title: SQS message retention period rewritten
id: 717d15e7-9fb6-4288-9a5e-e91131aabbcb
name: sqs_queue_retention_period_changed
status: experimental
description: >-
  A queue's `MessageRetentionPeriod` was set. Reducing it below the age of the messages
  already in the queue expires and deletes them within 15 minutes. Compare the value in the
  event against the queue's previous retention — a decrease is a destructive change.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1485/                                                        # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'SetQueueAttributes'
  # Presence test written as "any run of digits" rather than an `|exists` modifier, which
  # not every backend implements. The attribute is documented as a string of seconds, so
  # this matches whenever the key is present and never when it is absent.
  retention_present:
    requestParameters.attributes.MessageRetentionPeriod|re: '^[0-9]+$'
  success:
    errorCode: null
  condition: selection and retention_present and success
falsepositives:
  - >-
    Raising retention, and setting it at queue creation time, are both routine. Sigma cannot
    compare the new value against the old one; the analyst must. Treat any value at or near
    the 60-second floor on a queue that previously held a backlog as destruction.
level: medium
---
# Base rule — sequence component only, not for direct alerting. Carries the success filter
# so that a DENIED CreateQueue followed by a legitimate redrive change cannot compose into a
# high-severity correlation.
title: SQS queue created
id: c7efde47-cfd0-4029-bd1e-03316eb50f67
name: sqs_queue_created
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'CreateQueue'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# Threshold basis — derived from documented behaviour, not from an observed count. This
# correlation has no count to tune: it is an ORDERED PAIR, and the technique's own baseline
# is exactly one of each. A principal that creates a queue and then names a queue as a
# redrive target within the same quarter-hour has built a destination and pointed traffic at
# it, which is the whole of the diversion technique. Fifteen minutes is chosen to span a
# hand-driven two-step without spanning an unrelated deployment an hour later; shorten it if
# your pipeline does both in one apply, which would otherwise make every stack creation a
# hit. The event ordering is conveyed by the correlation TYPE — do not add an `ordered:` key.
title: SQS queue created and immediately named as a dead-letter target
id: cfe5b966-4a81-458b-bd98-aa040e8994fa
status: experimental
description: >-
  One principal created a queue and then rewrote another queue's `RedrivePolicy` inside
  fifteen minutes. That is a diversion channel being stood up and wired in, staged across
  two events neither of which is remarkable on its own.
references:
  - https://attack.mitre.org/techniques/T1213/ # retrieved 2026-08-29
tags:
  - attack.collection
  - attack.t1213
correlation:
  type: temporal_ordered
  rules:
    - sqs_queue_created
    - sqs_queue_redrive_policy_changed
  group-by:
    - userIdentity.arn
  timespan: 15m
level: high
```

Sigma cannot compare a value against a previous one, so it separates neither a retention
increase from a reduction nor an in-organisation redrive target from an outside one; both
comparisons live in `detections/kql_t1098.kql`. Neither rule sees whether the grant was
*used* — that is data-plane, and routes to CloudWatch (Query 2).

---

### Key Investigation Queries

> SQS is regional — run these in the queue's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: who changed which queue's attributes, and to what

```bash
REGION="us-east-1"
RAW=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SetQueueAttributes \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no changes'."
else
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "sqs.amazonaws.com") | (.requestParameters.attributes // {}) as $a |
    {time: .eventTime, caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     queue_url: .requestParameters.queueUrl,
     queue_name: (.requestParameters.queueUrl // "" | split("/") | last),
     attrs_changed: ($a|keys), policy: ($a.Policy // null), redrive: ($a.RedrivePolicy // null),
     retention: ($a.MessageRetentionPeriod // null), kms_key: ($a.KmsMasterKeyId // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
fi
```

Read `attrs_changed` first — the field the source rule never looks at, and the one that says
which incident this is: a `Policy` entry is this playbook, `KmsMasterKeyId` or
`SqsManagedSseEnabled` the sibling directory. Record `queue_url`, `queue_name`, `caller_arn`
and `access_key` as IOCs; `policy` is raw JSON — read it, do not decode it. An error of
`AccessDeniedException`/`NotAuthorized` repeated across queues is boundary mapping.

#### Query 2 — Sweep every queue's live policy, then ask whether the grant was used

```bash
REGION="us-east-1"
ORG_ACCOUNTS="000000000000 111111111111"   # populate: every account ID in your organisation
# Statement is legal as an object OR an array, Principal as a string or {"AWS": string|array}.
# Without both guards a single-statement policy - the shape an attacker writes - is skipped
# or errors and the sweep reports the queue clean. `.Action` is not read here.
NORM='[ ((.Statement//[])|if type=="object" then [.] else . end)[] | select((.Effect//"")=="Allow")
   | ((.Principal//{})|if type=="string" then [.] else ((.AWS//[])|if type=="string" then [.] else . end) end) as $p
   | ($p|map(select(test("[0-9]{12}"))|capture("(?<a>[0-9]{12})").a)|unique) as $ids
   | select(any($p[]?;.=="*") or (($ids-($org|split(" ")))|length>0)) | ($p|tostring) ] | join(", ")'
for Q in $(aws sqs list-queues --region "$REGION" --query 'QueueUrls[]' --output text); do
  ATTR=$(aws sqs get-queue-attributes --queue-url "$Q" --attribute-names Policy \
           --region "$REGION" --output json)
  POL=$(printf '%s' "$ATTR" | jq -r '.Attributes.Policy // empty')
  if   [ -z "$ATTR" ]; then echo "[!] INCONCLUSIVE $Q - get-queue-attributes returned nothing"
  elif [ -z "$POL"  ]; then echo "[i] $Q has NO queue policy - a real SQS state, not a failed read"
  elif ! BAD=$(printf '%s' "$POL" | jq -r --arg org "$ORG_ACCOUNTS" "$NORM"); then
                            echo "[!] INCONCLUSIVE $Q - the policy document did not parse"
  elif [ -n "$BAD" ]; then  echo "[!] $Q grants to: $BAD"
  else                      echo "[OK] $Q - no wildcard or out-of-organisation principal"; fi
done
# Was it used? ReceiveMessage is a DATA event, so metrics answer this, not lookup-events.
STATS=$(aws cloudwatch get-metric-statistics --namespace AWS/SQS --period 3600 --statistics Sum \
  --metric-name NumberOfMessagesReceived --region "$REGION" --output json \
  --dimensions Name=QueueName,Value="<queue-name-from-Query-1>" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
[ -z "$STATS" ] && echo "[!] INCONCLUSIVE - CloudWatch call failed; consumption unknown, not zero"
printf '%s' "$STATS" | jq -r '.Datapoints|sort_by(.Timestamp)[]|"\(.Timestamp) received=\(.Sum)"'
```

Every `[!]` naming principals is a queue whose live policy Allows a wildcard or
out-of-organisation principal: the account-wide blast radius, and the eradication work-list.
`[i]` marks a queue that genuinely has no policy — a different fact from a failed read.
A `received` count during the grant window your consumers cannot account for is evidence of
consumption, but the dimension is `QueueName` alone, so it can never say **who**. Repeat for
`NumberOfEmptyReceives` — an outside poller on an *empty* queue appears there and nowhere else.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CreateQueue SetQueueAttributes"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "sqs.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Grouped by caller rather than by resource,
because the question eradication needs answered is *how much of this is one actor's work* — a
per-resource list cannot say. `access_key` is emitted because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` whether or not it happened; the preamble's caveat applies.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN: one credential is used across many sessions, and
the key identifies the credential. The per-service grouping answers what this playbook cannot —
whether this technique was the objective or one stop on a tour. A service in that list with no
business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID, so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The grant lives on the **resource**: containing the principal does not remove it, and
removing it does not contain the principal — both are required. Capture the current policy
*before* overwriting it, because `Policy` is unversioned and this is the last moment the
compromised document exists anywhere.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Preserve, then replace, the queue policy

```bash
REGION="us-east-1"; QUEUE_URL="<queue-url-from-Query-1>"
CUR=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names Policy \
        --region "$REGION" --output json)
if [ -z "$CUR" ]; then
  echo "[!] INCONCLUSIVE - could not read the current policy. STOP: fix the credential before"
  echo "    overwriting, or the only surviving copy of the compromised document is destroyed."
else
  printf '%s' "$CUR" | jq -r '.Attributes.Policy // "NO-POLICY-SET"' > ./queue-policy-preattack.json
  echo "[OK] current policy preserved to ./queue-policy-preattack.json"
fi
# Apply the known-good document from IaC. The owner-only fallback below ALSO strips any
# Service-principal statement letting SNS, EventBridge or S3 notifications deliver here -
# an outage. Restore those statements in the SAME call, not afterwards.
ACCT=$(aws sts get-caller-identity --query Account --output text)
QARN=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names QueueArn \
         --region "$REGION" --query 'Attributes.QueueArn' --output text)
GOOD=$(printf '{"Version":"2012-10-17","Statement":[{"Sid":"OwnerOnly","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sqs:*","Resource":"%s"}]}' "$ACCT" "$QARN")
aws sqs set-queue-attributes --queue-url "$QUEUE_URL" --attributes "Policy=$GOOD" --region "$REGION"
echo "[i] policy replaced - asserted in Recovery; changes take up to 60s to propagate"
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sqs:SetQueueAttributes","sqs:AddPermission","sqs:RemovePermission","sqs:CreateQueue"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenySqsAdmin" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenySqsAdmin" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied SQS administration for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

> `aws:TokenIssueTime` revokes only sessions issued **before** the cutoff; a credential
> re-fetched afterwards gets a newer issue time and is not denied.

---

## 4. Eradication

### Remove Attacker Access

- **Rewrite every queue Query 2 flagged `[!]`**, not only the one in the alert — a
  resource-based grant outlives every identity-side action in §3, so a queue left unfixed is
  a live re-entry point after the incident is closed.
- **Close the second path to the same document.** `sqs:AddPermission` writes statements into
  the identical policy; AWS's guidance is that removing the ability to change queue
  permissions requires denying `AddPermission`, `RemovePermission` **and**
  `SetQueueAttributes` — denying one of the three is not a control.
- **Export, then delete, any queue the actor created as a redrive target** (it may hold
  diverted messages — `../sqs.stealth.excessive-queue-creation/`) and **right-size the
  permission**: `sqs:SetQueueAttributes` and `sqs:AddPermission` belong to the deployment
  pipeline and the break-glass role and to nothing else.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3
  could have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
  for P in EmergencyDenySqsAdmin EmergencyRevokeSessions; do
    aws iam delete-role-policy --role-name "$R" --policy-name "$P"; done
  LEFT=$(aws iam list-role-policies --role-name "$R" --query 'PolicyNames[]' --output text)
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  aws iam delete-user-policy --user-name "$U" --policy-name "EmergencyDenySqsAdmin"
  LEFT=$(aws iam list-user-policies --user-name "$U" --query 'PolicyNames[]' --output text)
else LEFT="UNCHECKED"; fi
case "$LEFT" in
  UNCHECKED)   echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify the live queue policy is byte-for-byte the known-good document

```bash
REGION="us-east-1"; QUEUE_URL="<queue-url-from-Query-1>"
BASELINE_FILE="<path-to-the-IaC-queue-policy-json>"
RESP=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names Policy \
         --region "$REGION" --output json)
# jq -S canonicalises key order, so formatting is not a false FAIL. A jq failure leaves its
# variable holding the error text, and that can never equal the other side, so a parse error
# cannot reach the [OK] branch.
LIVE=$(printf '%s' "$RESP" | jq -r '.Attributes.Policy // empty' | jq -S -c . 2>&1)
WANT=$(jq -S -c . < "$BASELINE_FILE" 2>&1)
if [ -z "$RESP" ] || [ ! -s "$BASELINE_FILE" ]; then
  echo "[!] INCONCLUSIVE - the read failed or the baseline file is missing. Not clean, not"
  echo "    dirty: unknown. Do not close on this."
elif [ "$LIVE" = "$WANT" ]; then echo "[OK] live queue policy matches the known-good document"
else echo "[FAIL] live policy differs from baseline"; echo "  live: $LIVE"; echo "  want: $WANT"; fi
```

A `[FAIL]` is expected while §3's owner-only fallback is still in place: it means the real
policy has not been restored yet, which is what this check is for. It can also mean Step 1's
60-second propagation had not completed — re-run before concluding.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     SetQueueAttributes / sqs.amazonaws.com / no errorCode, with"
echo "  requestParameters.attributes.Policy carrying an Allow whose Principal is a wildcard -"
echo "  bare, {\"AWS\":\"*\"} or {\"AWS\":[\"*\"]} - in ANY whitespace, pretty-printed included."
echo "MUST NOT fire on: the same call carrying only VisibilityTimeout; a Policy whose only"
echo "  Principal is a Service principal; a denied call."
echo "EXPECTED FP, by design: a wildcard Allow bounded by aws:PrincipalOrgID - the rule does"
echo "  not read Condition. A real finding about scope; disposition it, do not filter."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the deployment pipeline could rewrite a queue's resource policy | `sqs:SetQueueAttributes` and `sqs:AddPermission` granted broadly; no SCP confining who may administer a queue |
| The grant went unnoticed until it was used | The alert matched an event name with no content test, so the signal arrived inside a stream of routine configuration changes |
| Nobody could say what the queue used to permit | The `Policy` attribute is unversioned and was not held in IaC; the CloudTrail event was the only copy |
| Nobody could say who consumed the messages | SQS data events were off, so `ReceiveMessage` was never recorded, and CloudWatch metrics carry no principal dimension |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches every principal and denies queue administration outright.
{
  "Effect": "Deny",
  "Action": ["sqs:SetQueueAttributes", "sqs:AddPermission", "sqs:RemovePermission"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the *caller*: cross-account permissions do not apply to
  `SetQueueAttributes`, so the caller is always an in-organisation principal. It does **not**
  stop an outside principal from *using* an existing grant, and it does not affect
  resource-based policies. That control is a **Resource control policy** denying `sqs:*` on
  `"StringNotEquals": {"aws:PrincipalOrgID": "<org-id>"}` with a
  `"Bool": {"aws:PrincipalIsAWSService": "false"}` guard — without the guard it denies
  service-initiated delivery from SNS, EventBridge and S3 and causes an outage.
- Hold every queue policy in IaC and reconcile on a schedule, and enable SQS data events on
  queues carrying high-value messages **before** an incident — afterwards the consumption is
  already unattributable.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 — Account Manipulation (primary); T1213 — Data from Information Repositories (secondary) |
| Primary API | `sqs:SetQueueAttributes` writing `Policy`, `RedrivePolicy` or `MessageRetentionPeriod`; `sqs:AddPermission` as the second path to the same document |
| Event source | `sqs.amazonaws.com`, **management** plane, regional — verified against AWS's SQS CloudTrail documentation |
| Key discriminator | Which key of `requestParameters.attributes` the call carries, and that key's value — never the event name |
| "Was it used" pivot | **Data plane.** `ReceiveMessage`/`SendMessage`/`DeleteMessage`, and also `ListQueues`/`GetQueueUrl`/`GetQueueAttributes`, are SQS data events, off by default; `lookup-events` returns zero for them forever. Use CloudWatch `AWS/SQS` — `NumberOfMessagesReceived`, `NumberOfEmptyReceives`, `NumberOfMessagesDeleted`. Dimension `QueueName` only, so consumption is provable and attribution is not |
| Blast radius | Every message in and passing through the queue, plus anything downstream that trusts it. The grant is resource-based, so key rotation, session revocation and role-trust repair do not touch it |
| Document limits | Queue policy 8,192 bytes; 20 statements; 50 principals; 10 conditions; 7 actions per statement — far below CloudTrail's 100 KB omission threshold, so **no size-evasion path exists and no oversized-document rule ships** |
| Error strings | `AccessDeniedException` and `NotAuthorized` are both documented denials; the bare `AccessDenied` form is widely observed but is **not** in SQS's documented list — match all three. Operation-specific: `InvalidAddress`, `InvalidAttributeName`, `InvalidAttributeValue`, `InvalidSecurity`, `OverLimit`, `QueueDoesNotExist`, `RequestThrottled`, `UnsupportedOperation` |

**MITRE mapping note.** The source maps T1213 / TA0009 alone. T1213 names the *outcome*;
what CloudTrail records is the **grant**, which is T1098 — IaaS is in its platform list, its
tactics are Persistence and Privilege Escalation. Both are carried, T1098 first. The
`collection` segment of this directory's name tracks the source's tactic label. A
mapping-precision note, not a defect.

### Residual Risk

Every message that left the queue while the grant stood is gone and **you cannot enumerate
which ones**: `ReceiveMessage` was not logged, and message bodies are redacted
(`HIDDEN_DUE_TO_SECURITY_REASONS`) even where data events are on. If the actor consumed and
deleted, the legitimate consumer never saw those messages at all, so the gap reads as a
producer failure rather than a theft. Messages already diverted into a redrive target in
another account stay there. A retention reduction that has already expired a backlog is
irreversible, and every downstream effect the messages should have had is not undone by
repairing the policy.
