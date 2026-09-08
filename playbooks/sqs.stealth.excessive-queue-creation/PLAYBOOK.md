# IR Playbook: Excessive SQS Queue Creation — Staging Diversion Channels and Public Queues via `sqs:CreateQueue`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Resource hijacking / Staging (queues are created outside the lifecycle pipeline, some of them already public or destined to receive diverted messages) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Medium** for the volume case — the source's **P4** is close to right, and this is the one rule in the SQS set whose priority is not badly miscalibrated. **High** for a queue created with a wildcard-principal policy, because it is exposed from its first second and no policy-change rule will ever see it |
| MITRE Tactics | Impact (TA0040), Persistence (TA0003) |
| MITRE Techniques | T1496 (primary), T1098 (on the public-at-birth path) — both verified live 2026-08-29 |
| Services in Scope | SQS, CloudTrail (management + SQS data events), CloudWatch (`AWS/SQS`), Cost Explorer, IAM, Organizations (SCP) |

**What the technique does:** the actor calls `sqs:CreateQueue`, optionally passing an `Attributes` map on
the same call. Creating queues is cheap and almost consequence-free, so the count is the least
interesting thing about this behaviour — what matters is what each queue is *for*. Three
readings have teeth. A queue created with a `Policy` naming `"Principal": "*"` is **public
from its first second**, and because the policy arrived on the creation call, no
`SetQueueAttributes` event ever exists for it and every rule in the sibling policy playbook
stays silent for that queue's whole life. A queue created by an unfamiliar principal that is
then named as another queue's `deadLetterTargetArn` is a **diversion channel**, staged across
two individually unremarkable events. And a burst of queues is unsanctioned consumption of
account resources — the weakest of the three, and the only one the source rule expresses.

**Detection thesis.** The discriminator is **the calling principal**, and after that the
`attributes` map on the creation call. `CreateQueue` is what every stack deployment does, so
volume alone separates nothing; the source rule counts five in five minutes without ever
checking who called, so every CloudFormation fan-out topology and every ephemeral test
environment fires it.

> The diversion correlation — create, then repoint a redrive policy at the new queue — ships
> in `../sqs.collection.an-sqs-queue-attributes-were-changed/`. A `CreateQueue` returning
> `QueueDeletedRecently` is a **name-takeover** attempt and belongs to
> `../sqs.stealth.a-queue-was-deleted/`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing SQS **management** events. `CreateQueue` carries
  `requestParameters.queueName`, an optional `requestParameters.attributes` map and
  `requestParameters.tags`, and returns `responseElements.queueUrl` — **flat**, matching the
  API's bare `{"QueueUrl": ...}` Response Syntax, which has no wrapper object to nest under.
  Attribute values are always **strings**
- SQS **data events** on the queues that matter. Without them `SendMessage`/`ReceiveMessage`
  are invisible, and so are `ListQueues`/`GetQueueUrl`/`GetQueueAttributes` — so **the
  enumeration that usually precedes a creation burst produces no management event at all**
- CloudWatch `AWS/SQS` `NumberOfMessagesSent` and `NumberOfMessagesReceived` per `QueueName`.
  These separate a queue that is a channel from one that is clutter; AWS emits SQS metrics only
  while a queue is active, so a queue with no datapoints has genuinely never been used
- A baseline of which principals own queue lifecycle, and a naming convention for queues the
  pipeline creates — an unfamiliar name is a faster triage signal than a count
- Cost Explorer access. SQS bills **per request, not per queue**, so an idle queue costs
  effectively nothing and a resource-abuse case is made there rather than in CloudTrail

**Alerting (must be pre-configured)**
- **`CreateQueue` carrying an `attributes.Policy` that Allows a wildcard principal → P0**
- **Five or more `CreateQueue` successes by one non-pipeline principal within five minutes → P1**
- **A queue created outside the pipeline later named as another queue's `deadLetterTargetArn` → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- **The normal value for this measure, per resource, from a quiet week.** The rule compares against a resource's own history rather than a fleet average, so without the baseline the threshold is a guess.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `CreateQueue` whose `attributes.Policy` Allows `"Principal": "*"` | CloudTrail (management) | T1098 |
| P1 | Five or more `CreateQueue` successes by one non-pipeline principal within five minutes | CloudTrail (management) | T1496 |
| P1 | A queue created outside the pipeline later named as another queue's `deadLetterTargetArn` | CloudTrail (management) | T1098 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CreateQueue` with `attributes.SqsManagedSseEnabled` = `false` — unencrypted at birth | CloudTrail (management) | T1600 |
| P2 | A created queue that never emits `NumberOfMessagesSent` — clutter, or a channel not yet used | CloudWatch `AWS/SQS` | T1496 |
| P3 | `CreateQueue` returning `QueueNameExists` or `QueueDeletedRecently` — name collision or takeover attempt | CloudTrail (management) | T1496 |

### Detection Rule Quality Notes

The source rule counts an event name and never checks who called — and it ships two MITRE
mappings that contradict each other.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"CreateQueue"` counted with no principal check | Every CloudFormation stack that stands up a fan-out topology fires it, and so does every ephemeral test environment. In an account where queue lifecycle belongs to a pipeline, the caller is the entire signal and it is unused | Exclude the pipeline roles from what the correlation counts, and keep the source's five-in-five-minutes threshold on the filtered stream |
| Nothing inspects the `attributes` map on the creation call | A queue created with a wildcard-principal `Policy` is public from its first second, and because the policy arrived on `CreateQueue` there is **never** a `SetQueueAttributes` event, so every rule in the sibling policy directory stays silent for that queue's whole life | Ship a rule on `requestParameters.attributes.Policy` at creation time |
| Volume treated as the finding | Fifty empty queues are clutter; one public queue is an exposure. Ranking by count inverts the severity | Make the correlation a severity escalator over a filtered base rule, not the detector |

**Recommended detection — a queue created outside the queue-lifecycle pipeline.**

```yaml
# Excessive SQS Queue Creation (T1496)
#
# THE WEAKEST SIGNAL IN THE SET, AND WORTH SAYING SO. A queue costs almost nothing and holds
# nothing until something writes to it, so "many queues appeared" is not on its own a security
# event — which is why the corrected rules below are built around what a created queue is FOR
# rather than around the count. Three readings have teeth, in descending order of sharpness:
# a queue created ALREADY PUBLIC (Rule 2); a queue created by an unfamiliar principal that is
# then named as another queue's `RedrivePolicy` target, which is message diversion staged
# across two ordinary events (the correlation ships in
# ../../sqs.collection.an-sqs-queue-attributes-were-changed/); and unsanctioned consumption of
# account resources, which is the volume reading the source rule expresses.
#
# THE SOURCE RULE matches `eventName:"CreateQueue"` with a success filter and an anomaly
# threshold of five in five minutes, and looks at nothing else. Every CloudFormation stack
# that stands up a fan-out topology fires it; so does every ephemeral test environment. It
# never checks the caller, which in an account where queue lifecycle belongs to a pipeline is
# the entire signal. The threshold itself is defensible and is retained below — see the
# correlation's tuning note — but only once the pipeline is excluded from what it counts.
#
# Tools); the rule's own prose names T1531 (Account Access Removal). Creating a queue is
# neither. See the mapping note in ../PLAYBOOK.md §6.
#
# FIELD SHAPE. `CreateQueue` carries `requestParameters.queueName`, an optional
# `requestParameters.attributes` map and `requestParameters.tags`, and returns
# `responseElements.queueUrl` — FLAT, matching the API's bare {"QueueUrl": "..."} Response
# Syntax, which has no wrapper object to nest under. Attribute values are always STRINGS.
title: SQS queue created outside the queue-lifecycle pipeline
id: b43734f7-77b3-46e0-bfa1-cf1355b09cd5
name: sqs_queue_created_outside_pipeline
status: experimental
description: >-
  A queue was created by a principal that does not own queue lifecycle. On its own this is a
  low-value observation; it exists to be counted by the correlation below and to be joined
  against later redrive and policy changes naming the new queue.
references:
  - https://attack.mitre.org/techniques/T1496/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1496
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'CreateQueue'
  # POPULATE BEFORE DEPLOYING. Unpopulated, this counts every pipeline-created queue and the
  # correlation fires on every stack deployment.
  queue_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  success:
    errorCode: null
  condition: selection and success and not queue_lifecycle_pipeline
falsepositives:
  - >-
    Engineers creating queues by hand in a development account. Expected there, and the reason
    this rule is `low` on its own — the signal is the correlation and the joins, not the event.
level: low
---
# A queue that is PUBLIC AT BIRTH. CreateQueue accepts the same `Policy` attribute as
# SetQueueAttributes, so a queue can be created already open to a wildcard principal in one
# call — and no `SetQueueAttributes` event ever exists for it, so every rule in the sibling
# policy playbook stays silent for the whole life of that queue.
title: SQS queue created with a wildcard-principal access policy
id: 83303aaf-b595-4386-b89a-6977af9b42ab
name: sqs_queue_created_public
status: experimental
description: >-
  A queue was created with an access policy that Allows `*` as a principal. Because the policy
  arrives on the creation call, no attribute-change event is ever recorded for it and the
  policy-change rules in the sibling directory never fire.
references:
  - https://attack.mitre.org/techniques/T1098/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html  # retrieved 2026-08-29
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
  # Covers "Principal":"*", {"AWS":"*"} and {"AWS":["*"]} across any whitespace. The `\\?`
  # groups are REQUIRED: a platform that indexes the raw serialised event delivers this nested
  # JSON string's quotes backslash-escaped, and without the optional backslash the rule fires
  # on one platform and never on the other.
  wildcard_principal:
    requestParameters.attributes.Policy|re: '\\?"Principal\\?"\s*:\s*(\{\s*\\?"AWS\\?"\s*:\s*)?(\[\s*)?\\?"\*\\?"'
  success:
    errorCode: null
  condition: selection and wildcard_principal and success
falsepositives:
  - >-
    A wildcard principal bounded by an `aws:SourceArn` or `aws:PrincipalOrgID` condition is
    AWS's documented service-fronted or organisation-wide pattern. This rule does not read
    `Condition`, so it fires on those too — a finding about scope, not a compromise.
level: high
---
# Threshold basis — the source rule's own five-in-five-minutes is retained, and it is
# defensible once the pipeline is excluded from what it counts. Creating five queues inside
# five minutes is not something a person does by hand; the processes that legitimately do it
# are stack deployments, and those run under the pipeline role the base rule already removes.
# `gte` at the baseline, never `gt`, so a burst of exactly five does not fall through.
# Re-baseline before deploying: in a development account where engineers stand up their own
# topologies under their own identity, raise it rather than muting the rule. This correlation
# is a SEVERITY ESCALATOR, not the detector — a single queue created public (Rule 2) is worse
# than fifty created empty.
title: SQS queues created at volume by one principal outside the pipeline
id: 9b2f3a06-39b1-4335-a6b3-bf7129479e67
status: experimental
description: >-
  One non-pipeline principal created five or more queues inside five minutes. Read it as
  unsanctioned consumption of account resources, and check each new queue against the
  redrive-target and policy-grant rules in the sibling directory before dismissing it.
references:
  - https://attack.mitre.org/techniques/T1496/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1496
correlation:
  type: event_count
  rules:
    - sqs_queue_created_outside_pipeline
  group-by:
    - userIdentity.arn
  timespan: 5m
  condition:
    gte: 5
level: medium
```

That rule is `low` on purpose: on its own, a queue created outside the pipeline is an
observation, not an alert. It exists to be counted by the correlation and joined against later
redrive and policy changes. What no Sigma rule can do is match a **created queue name** against
the ARN inside a later `deadLetterTargetArn` — the two live in different fields on different
events, and in the interesting case the two principals differ.
`detections/kql_t1496.kql` does that join.

---

### Key Investigation Queries

> SQS is regional — run these in the queue's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: who created what, with what attributes, and did anything point at it

```bash
REGION="us-east-1"
RAW=$(for EV in CreateQueue SetQueueAttributes; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no queues were created'."
else
  # CreateQueue names the queue in requestParameters.queueName and returns
  # responseElements.queueUrl (flat, no wrapper). A RedrivePolicy names its TARGET inside a
  # nested JSON string, so the ARN's last colon-field is extracted to give a comparable name.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "sqs.amazonaws.com") | (.requestParameters.attributes // {}) as $a |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     queue_name: (.requestParameters.queueName //
                  ((.requestParameters.queueUrl // "") | split("/") | last)),
     queue_url: (.responseElements.queueUrl // .requestParameters.queueUrl),
     born_public: (($a.Policy // "") | test("\"Principal\"[[:space:]]*:")),
     born_unencrypted: (($a.SqsManagedSseEnabled // "") == "false"),
     redrive_target: (($a.RedrivePolicy // "") |
                      if . == "" then null
                      else (try (fromjson.deadLetterTargetArn | split(":") | last) catch "UNPARSEABLE") end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

Read it as two lists. Any `CreateQueue` with `born_public` true is the P0 finding — that queue
has no `SetQueueAttributes` event and no policy rule will ever fire on it. Then match each
`redrive_target` name against the `queue_name` of a recent `CreateQueue`: a hit means a queue
was stood up and then pointed at, which is diversion, and if the two `caller_arn` values differ
it is worse. `error` values of `QueueNameExists` or `QueueDeletedRecently` are collisions or
name-takeover attempts, not creations — count them separately. Record `queue_name`,
`caller_arn` and `access_key` as IOCs.

#### Query 2 — Which of the new queues are actually channels, and which are clutter

```bash
REGION="us-east-1"
CREATED_QUEUES="<space-separated-queue-names-from-Query-1>"
SINCE="$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for QN in $CREATED_QUEUES; do
  SENT=$(aws cloudwatch get-metric-statistics --namespace AWS/SQS --period 86400 --statistics Sum \
    --metric-name NumberOfMessagesSent --dimensions Name=QueueName,Value="$QN" \
    --region "$REGION" --output json --start-time "$SINCE" --end-time "$NOW")
  RECV=$(aws cloudwatch get-metric-statistics --namespace AWS/SQS --period 86400 --statistics Sum \
    --metric-name NumberOfMessagesReceived --dimensions Name=QueueName,Value="$QN" \
    --region "$REGION" --output json --start-time "$SINCE" --end-time "$NOW")
  if [ -z "$SENT" ] || [ -z "$RECV" ]; then
    echo "[!] INCONCLUSIVE $QN - a CloudWatch call failed; usage is unknown, not zero"
    continue
  fi
  S=$(printf '%s' "$SENT" | jq '[.Datapoints[].Sum] | add // 0')
  R=$(printf '%s' "$RECV" | jq '[.Datapoints[].Sum] | add // 0')
  # Both datapoint arrays are legitimately empty for a queue that has never been used, so the
  # emptiness test above is what separates "never used" from "could not check".
  if   [ "$S" = "0" ] && [ "$R" = "0" ]; then echo "[i] $QN unused - no sends, no receives (clutter, or a channel not yet used)"
  else                                        echo "[!] $QN IN USE - sent=$S received=$R (this is a channel; find out whose)"; fi
done
```

An `[!] ... IN USE` queue that nobody owns is the real finding: something is writing to a queue
your pipeline did not create, or something is reading from one. `[i] unused` is not innocence —
a diversion target sits idle until the source queue starts failing messages, so re-run this
after any redrive change. `[!] INCONCLUSIVE` must never be collapsed into `[i] unused`.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CreateQueue"
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

Nothing here is destroyed, so containment is about closing the exposure the new queues create
and stopping more from appearing. Deal with the public queues first — they are reachable now —
then stop the principal, then decide what to delete.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Close any queue that was created public

```bash
REGION="us-east-1"
PUBLIC_QUEUES="<space-separated-public-queue-names-from-Query-1>"
ACCT=$(aws sts get-caller-identity --query Account --output text)

for QN in $PUBLIC_QUEUES; do
  URL=$(aws sqs get-queue-url --queue-name "$QN" --region "$REGION" --query QueueUrl --output text)
  if [ -z "$URL" ]; then
    echo "[!] INCONCLUSIVE $QN - could not resolve the queue URL; it may already be gone"
    continue
  fi
  # Preserve the policy first: SetQueueAttributes overwrites it wholesale and keeps no history,
  # so this event and this file are the only records of what the queue permitted.
  aws sqs get-queue-attributes --queue-url "$URL" --attribute-names Policy --region "$REGION" \
    --output json | jq -r '.Attributes.Policy // "NO-POLICY-SET"' > "./queue-policy-${QN}.json"
  ARN=$(aws sqs get-queue-attributes --queue-url "$URL" --attribute-names QueueArn \
          --region "$REGION" --query 'Attributes.QueueArn' --output text)
  GOOD=$(printf '{"Version":"2012-10-17","Statement":[{"Sid":"OwnerOnly","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sqs:*","Resource":"%s"}]}' "$ACCT" "$ARN")
  aws sqs set-queue-attributes --queue-url "$URL" --attributes "Policy=$GOOD" --region "$REGION"
  echo "[i] $QN policy replaced with owner-only; asserted in Recovery (60s to propagate)"
done
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sqs:CreateQueue","sqs:SetQueueAttributes","sqs:AddPermission"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenySqsCreate" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenySqsCreate" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied queue creation for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Do not delete a queue before draining it.** Any queue Query 2 marked `IN USE` may hold
  diverted messages, and `DeleteQueue` destroys them irrecoverably
  (`../sqs.stealth.a-queue-was-deleted/`). Export the contents, capture the policy and
  attributes as evidence, and only then remove it.
- **Break the diversion before removing the target.** If a created queue is named in another
  queue's `RedrivePolicy`, fix the *source* queue's redrive policy first — deleting the target
  while the source still points at it leaves failed messages with nowhere to go, which is an
  outage you caused during eradication.
- **Re-check the queues that were left in place.** A queue created unencrypted stays
  unencrypted until an explicit attribute change; nothing re-enables itself
  (`../sqs.impact.server-side-encryption-for-aws-sqs-queue-was-disabled/`).
- **Right-size the permission.** `sqs:CreateQueue` belongs to the deployment pipeline. Denying
  it also removes the public-at-birth path, which is otherwise invisible to every
  policy-change rule in the sibling directory.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# A principal that is neither user nor role must reach INCONCLUSIVE, never the clean branch.
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenySqsCreate EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenySqsCreate"
    LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text);;
  *) N=""; LEFT="UNCHECKED";;
esac
case "$LEFT" in
  UNCHECKED)   echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify no surviving queue is reachable by a wildcard principal

```bash
REGION="us-east-1"
REVIEWED_QUEUES="<space-separated-queue-names-from-Query-1>"
BAD_TOTAL=0; CHECKED=0
for QN in $REVIEWED_QUEUES; do
  URL=$(aws sqs get-queue-url --queue-name "$QN" --region "$REGION" --query QueueUrl --output text)
  if [ -z "$URL" ]; then
    echo "[i] $QN no longer exists - removed during eradication"; continue
  fi
  # QueueArn is requested alongside Policy on purpose: get-queue-attributes omits attributes
  # that are not set, so an empty map cannot be distinguished from a failed call without an
  # attribute that always exists.
  A=$(aws sqs get-queue-attributes --queue-url "$URL" --attribute-names QueueArn Policy \
        --region "$REGION" --output json)
  ARN=$(printf '%s' "$A" | jq -r '.Attributes.QueueArn // empty')
  POL=$(printf '%s' "$A" | jq -r '.Attributes.Policy // empty')
  if [ -z "$ARN" ]; then
    echo "[!] INCONCLUSIVE $QN - the read did not return QueueArn; the call failed"; continue
  fi
  CHECKED=$((CHECKED+1))
  if [ -z "$POL" ]; then echo "[OK] $QN has no resource policy"; continue; fi
  # `if ! BAD=$(...)` is deliberate: a policy that does not parse must not reach [OK].
  if ! BAD=$(printf '%s' "$POL" | jq -r '
        [ ((.Statement // []) | if type=="object" then [.] else . end)[]
          | select((.Effect // "") == "Allow")
          | ((.Principal // {}) | if type=="string" then [.]
               else ((.AWS // []) | if type=="string" then [.] else . end) end) as $p
          | select(any($p[]?; . == "*")) | ($p|tostring) ] | join(", ")'); then
    echo "[!] INCONCLUSIVE $QN - the policy document did not parse"
  elif [ -n "$BAD" ]; then echo "[FAIL] $QN still Allows a wildcard principal: $BAD"; BAD_TOTAL=$((BAD_TOTAL+1))
  else echo "[OK] $QN - no wildcard principal"; fi
done
[ "$CHECKED" -eq 0 ] && echo "[!] INCONCLUSIVE - no queue was successfully read; nothing was verified"
[ "$CHECKED" -gt 0 ] && [ "$BAD_TOTAL" -eq 0 ] && echo "[OK] $CHECKED queue(s) checked, none wildcard-reachable"
```

Every branch is reachable after the remediation: the surviving queues still exist and still
return a policy, so a §3 step that did not take lands on `[FAIL]`. The `CHECKED` counter exists
so that a run where *every* read failed cannot end on a clean-looking summary line.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     CreateQueue / sqs.amazonaws.com / no errorCode, by a principal NOT on"
echo "  the lifecycle allowlist - and the correlation at exactly five such events in five"
echo "  minutes from one principal (gte, not gt). The public-at-birth rule must fire on a"
echo "  CreateQueue whose attributes.Policy Allows a wildcard principal, in ANY whitespace."
echo "MUST NOT fire on: CreateQueue by the pipeline role during a stack deployment; a"
echo "  CreateQueue that returned QueueNameExists or QueueDeletedRecently (no queue was made)."
echo "EXPECTED FP, by design: engineers creating queues by hand in a development account, and"
echo "  a wildcard Allow bounded by aws:SourceArn - the rule does not read Condition."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could create queues freely | `sqs:CreateQueue` granted broadly; no SCP confining queue lifecycle, and no naming convention that would make an unfamiliar queue obvious |
| A queue was created already public and no policy rule ever fired | The policy arrived on the `CreateQueue` call, so no `SetQueueAttributes` event exists — the sibling directory's rules cannot see a queue that was never modified |
| The creation burst was indistinguishable from a deployment | The alert counted an event name without excluding the pipeline, so it fired on stack deployments and was tuned out |
| Nobody could say which new queues were actually in use | SQS data events were off, so sends and receives were never recorded; only `AWS/SQS` metrics distinguish a channel from clutter, and they carry no principal |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches every principal and denies queue creation outright.
{
  "Effect": "Deny",
  "Action": ["sqs:CreateQueue", "sqs:SetQueueAttributes"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the caller, which is always an in-organisation principal here: AWS states
  cross-account permissions do not apply to `CreateQueue`. It closes the public-at-birth path
  as a side effect, which no detection rule in the sibling directory can see. Pair it with a
  queue naming convention the pipeline enforces, so an unfamiliar name is a triage signal
  rather than a research task, and with periodic reconciliation of live queues against IaC —
  a queue that exists and is not in any template is the finding.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1496 — Resource Hijacking (primary, volume reading); T1098 — Account Manipulation (the public-at-birth path) |
| Primary API | `sqs:CreateQueue`, optionally carrying `attributes.Policy`, `attributes.SqsManagedSseEnabled` and `tags` on the same call |
| Event source | `sqs.amazonaws.com`, **management** plane, regional — verified against AWS's SQS CloudTrail documentation |
| Key discriminator | The calling principal, then the `attributes` map on the creation call. Volume alone separates nothing — `CreateQueue` is what every stack deployment does |
| Field shape | `requestParameters.queueName`, `requestParameters.attributes.*`, `requestParameters.tags`; `responseElements.queueUrl` is **flat**, matching the API's bare `{"QueueUrl": ...}` Response Syntax. Attribute values are strings |
| "Was it used" pivot | **Data plane.** Sends and receives are SQS data events, off by default; `lookup-events` returns zero for them forever. Use `AWS/SQS` `NumberOfMessagesSent`/`NumberOfMessagesReceived` per `QueueName` — a created queue with traffic is a channel, one with no datapoints has genuinely never been used. Neither metric carries a principal |
| Blast radius | Small for an idle queue — SQS bills per request, not per queue. Large for a public one (any account can send or receive) and for a diversion target (it receives whatever the source queue fails to process) |
| Idempotence caveat | `CreateQueue` with an existing name and identical attributes **returns the existing URL and creates nothing**, so an event count is an upper bound on queues created, never an exact one. A name clash with different attributes returns `QueueNameExists` |
| Error strings | Denials: `AccessDeniedException` and `NotAuthorized` are both documented; the bare `AccessDenied` form is widely observed but **not** in SQS's documented list — match all three. `CreateQueue`'s own set: `InvalidAddress`, `InvalidAttributeName`, `InvalidAttributeValue`, `InvalidSecurity`, `QueueDeletedRecently`, `QueueNameExists`, `RequestThrottled`, `UnsupportedOperation`. Tagging on creation also needs `sqs:TagQueue`, so a tagged create can be denied on a permission the operator did not know was involved |

**MITRE mapping note.** This source rule ships **two mutually contradictory mappings and both
are wrong**. Its own prose names T1531 (Account Access Removal), which is live but
describes locking legitimate users out of their accounts. The correction is T1496 (Resource
Hijacking, Impact) for the volume reading and T1098 on the public-at-birth path. Be honest
about the fit: ATT&CK has **no** technique that cleanly covers creating messaging
infrastructure inside a victim account to stage diversion, and T1496 is the closest defensible
live mapping rather than an exact one.

### Residual Risk

A queue you decided to leave in place is still a resource somebody outside your pipeline
created, and if it was public before §3 closed it, **anything already sent or received through
it is unrecoverable and unattributable** — sends and receives are data-plane, and bodies are
redacted even where data events are on. A diversion target that Query 2 showed as unused is not
innocent: it stays idle until the source queue begins failing messages, so an idle queue plus a
live `RedrivePolicy` pointing at it is a channel waiting to open. Queues created unencrypted
stay unencrypted until an explicit attribute change, because nothing re-enables itself. And a
`CreateQueue` count is an upper bound rather than a total, since an idempotent re-create returns
the existing URL and makes nothing — so the number in the incident record is the number of
calls, not the number of queues.
