# IR Playbook: SQS Queue Deleted — Irreversible Message Destruction and Name Takeover via `sqs:DeleteQueue`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data destruction / Availability (a queue and every message in it are destroyed; the name may then be taken over by a queue the actor configured) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, for a single deletion as much as for a mass one. Irreversibility does not scale with count: one production queue destroyed is already unrecoverable, and the difference between one and fifty is the size of the work-list, not the severity of the loss. The source rates both **P3**, which is defensible for the volume rule and too low for the single deletion |
| MITRE Tactics | Impact (TA0040), Stealth (TA0005) |
| MITRE Techniques | T1485 (primary), T1070 (secondary) — both verified live 2026-08-29 |
| Services in Scope | SQS, CloudTrail (management + SQS data events), CloudWatch (`AWS/SQS`), IAM, Organizations (SCP), and every producer and consumer wired to the queue |

**This playbook covers two source rules.** "A Queue Was Deleted" and "Excessive Queue
Deletion" carry **byte-identical queries**, the same priority and the same mapping, differing
only in that one fires per event and the other requires five inside five minutes. The
containment, eradication and residual risk are identical, so they are merged under the
tiering rule's **first merge test** — same observable, same response, differing only in
threshold. Both appear as separate rows in §2, and the reasoning is in
`_source/PROVENANCE.md`.

**What the technique does:** the actor calls `sqs:DeleteQueue` with a queue URL. AWS deletes the queue
*"regardless of the queue's contents"*, and *"any messages in the queue are no longer
available"* — stored and in-flight alike, with no recycle bin and no recovery window. The
queue's access policy, encryption setting, redrive wiring and retention period go with it,
surviving only in whatever infrastructure code created them. For up to sixty seconds
afterwards, producers keep succeeding: AWS documents that *"a `SendMessage` request might
succeed, but after 60 seconds the queue and the message you sent no longer exist"*, so the
application-side symptom is delayed and reads as a downstream processing failure. After a
further wait — the same sixty seconds, enforced with `QueueDeletedRecently` — the name can be
recreated, and a queue created under the old name has none of the original policy, encryption
or redrive, while producers addressing it **by name** reconnect without erroring.

**Detection thesis.** The discriminator is **the calling principal**: `DeleteQueue` is what
every stack teardown does, so the only field that separates destruction from maintenance is
whether the caller owns queue lifecycle. The source rules match the event name and the
absence of an error code and never look at `userIdentity.arn`, so they fire on every
Terraform apply that removes a queue and get muted.

> The queue's *messages* can also be destroyed without deleting the queue — by
> `../sqs.stealth.a-queue-was-purged/`, or by reducing `MessageRetentionPeriod` in
> `../sqs.collection.an-sqs-queue-attributes-were-changed/`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing SQS **management** events. `DeleteQueue` carries
  `requestParameters.queueUrl` and returns HTTP 200 with an empty body, so there is **no
  `responseElements`** — the request is the entire record, and the queue's depth, policy and
  encryption setting are not in it. `CreateQueue` carries `requestParameters.queueName` and
  returns `responseElements.queueUrl` (**flat**, matching the API's bare
  `{"QueueUrl": ...}` Response Syntax — there is no wrapper object to nest under)
- SQS **data events** on the queues that matter. Without them `SendMessage`/`ReceiveMessage`
  are invisible, and so are `ListQueues`/`GetQueueUrl`/`GetQueueAttributes` — so **the
  enumeration that precedes a mass deletion produces no management event at all**
- CloudWatch `AWS/SQS` with `ApproximateNumberOfMessagesVisible` retained. This is the **only**
  surviving measure of how much was destroyed, and it must be read at its last datapoint
  **before** the deletion: AWS emits SQS metrics only while a queue is active, so a query
  after the fact returns no datapoints, which is the absence of a queue rather than an empty one
- Every queue's policy, encryption setting, redrive policy and retention **in infrastructure
  code**. After a deletion, IaC is the only place the configuration still exists
- A baseline of which principals own queue lifecycle — in most accounts one deployment role
  and one break-glass role

**Alerting (must be pre-configured)**
- **`DeleteQueue` succeeding for a principal outside the queue-lifecycle allowlist → P0**
- **Five or more `DeleteQueue` successes by one non-pipeline principal within five minutes → P1**
- **`DeleteQueue` followed within 15 minutes by a `CreateQueue` from the same principal → P1**

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
| P0 | `DeleteQueue` succeeding for a principal not on the queue-lifecycle allowlist | CloudTrail (management) | T1485 |
| P1 | Five or more `DeleteQueue` successes by one non-pipeline principal within five minutes | CloudTrail (management) | T1485 |
| P1 | `DeleteQueue` then `CreateQueue` by the same principal within 15 minutes, same queue name | CloudTrail (management) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A queue's `ApproximateNumberOfMessagesVisible` stops emitting with no scheduled teardown | CloudWatch `AWS/SQS` | T1485 |
| P2 | `DeleteQueue` denied repeatedly across queues (`AccessDeniedException`/`NotAuthorized`) — boundary mapping, not destruction | CloudTrail (management) | T1485 |
| P3 | `CreateQueue` returning `QueueDeletedRecently` — a name-takeover attempt inside the 60-second wait | CloudTrail (management) | T1485 |

### Detection Rule Quality Notes

Both source rules match an event name and the absence of an error code, and neither looks at
who called.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"DeleteQueue"` with no principal check, in both rules | Fires on every scheduled stack teardown, every ephemeral test-environment destroy and every Terraform apply that removes a queue. In an account where queue lifecycle belongs to a pipeline, the caller is the entire signal and it is unused | Allowlist the queue-lifecycle roles; alert on everyone else |
| Two rules for one observable, with byte-identical queries and the same priority | Two alerts, two triage paths and two sets of tuning for a single use case whose response does not change with volume | Merge; keep the volume rule as a correlation over the already-filtered rule, so mass **pipeline** teardown does not fire it |
| Nothing covers delete-then-recreate | Queue-name takeover produces two ordinary events and no alert, while producers silently reconnect to a queue with no policy, no encryption and no redrive | Ship the `temporal_ordered` correlation, and confirm the name match by hand or in the KQL |
| P3 priority on the single deletion | An irreversible destruction of a production message store is triaged alongside a configuration change | P0 for a non-pipeline deletion |

**Recommended detection — a queue deleted by a principal outside the lifecycle pipeline.**

```yaml
# SQS Queue Deletion, single and at volume (T1485 / T1070)
#
# ONE PLAYBOOK, TWO SOURCE RULES. The source set carries a per-event "A Queue Was Deleted"
# and a volume "Excessive Queue Deletion" (5 in 5 minutes). Their queries are byte-identical,
# their priorities are identical, and the response to one deletion and to fifty is the same
# procedure run once or run in a loop. They are merged here under the tiering rule's first
# merge test — same observable, same response, differing only in threshold — and the volume
# rule survives as the `sqs_queue_deleted_at_volume` correlation below.
#
# WHAT THE SOURCE RULES DO NOT DO. Both match `eventName:"DeleteQueue"` with a success filter
# and nothing else, so every scheduled teardown, every ephemeral test-stack destroy and every
# Terraform apply that removes a queue fires them. Neither looks at WHO called. In an account
# where queue lifecycle is owned by a pipeline, the caller is the entire signal, and Rule 1
# below is built on it.
#
# IRREVERSIBILITY, AND THE 60-SECOND WINDOW THAT MATTERS TWICE. AWS: "When you delete a queue,
# any messages in the queue are no longer available", and "the deletion process takes up to 60
# seconds. Requests you send involving that queue during the 60 seconds might succeed. For
# example, a SendMessage request might succeed, but after 60 seconds the queue and the message
# you sent no longer exist." Separately: "When you delete a queue, you must wait at least 60
# seconds before creating a queue with the same name" - a second attempt inside that window
# returns `QueueDeletedRecently`. That constraint is what makes the delete-then-recreate
# correlation below detectable as a distinct shape rather than as two unrelated events: an
# actor taking over a queue NAME has to wait, and the pause is visible.
#
# FIELD SHAPE. `DeleteQueue` carries `requestParameters.queueUrl` and returns HTTP 200 with an
# empty body, so there is NO `responseElements` - the request is the entire record, and the
# queue's policy, encryption setting and redrive wiring are not in it. `CreateQueue` carries
# `requestParameters.queueName` and returns `responseElements.queueUrl` (flat, per the API's
# Response Syntax, which has no wrapper object). The two events therefore name the same queue
# through DIFFERENT fields, which is why the correlation groups by principal and the analyst
# confirms the name match.
title: SQS queue deleted by a principal outside the queue-lifecycle pipeline
id: 52cce057-2cee-45cd-b76d-2b9b8bf0bad2
name: sqs_queue_deleted_nonpipeline
status: experimental
description: >-
  A queue was deleted by a principal that does not own queue lifecycle. Deletion is
  irreversible: every stored and in-flight message is gone, and the queue's policy,
  encryption configuration and redrive wiring survive only in whatever infrastructure code
  created them.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteQueue.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
  - attack.stealth
  - attack.t1070
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'DeleteQueue'
  # POPULATE BEFORE DEPLOYING. Unpopulated, this fires on every pipeline teardown. The
  # allowlist IS the discriminator - the event name carries no signal on its own.
  queue_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  success:
    errorCode: null
  condition: selection and success and not queue_lifecycle_pipeline
falsepositives:
  - >-
    An engineer cleaning up a personal or ephemeral queue outside the pipeline. Common in
    development accounts and rare in production ones; if it is common in production, the
    finding is that queue lifecycle is not owned by the pipeline.
level: high
---
# Base rule — sequence component only, not for direct alerting. Carries the success filter so
# a denied CreateQueue cannot compose into the high-severity correlation below.
title: SQS queue created
id: 5cfff3c9-cf1c-4386-8b35-de9759cfd12d
name: sqs_queue_created_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
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
# Threshold basis — the source rules' own 5-in-5-minutes is retained, and here is why it is
# defensible rather than inherited: deleting five queues inside five minutes is not something
# a person does by hand, and the one process that legitimately does it — a stack teardown —
# runs under the pipeline role, which the base rule already excludes. `gte` at the baseline,
# never `gt`, so a run that touches exactly five does not fall through. Re-baseline against
# your own account before deploying; if engineers routinely destroy five-queue dev stacks
# under their own identity, raise it rather than muting the rule.
title: SQS queues deleted at volume by one principal
id: a05452dc-04e0-432f-a910-bee7139c89f6
status: experimental
description: >-
  One non-pipeline principal deleted five or more queues inside five minutes. That is
  destruction at machine speed, not maintenance, and the work-list for recovery is every
  queue in the group.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: event_count
  rules:
    - sqs_queue_deleted_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 5m
  condition:
    gte: 5
level: high
---
# Delete-then-recreate is queue-NAME TAKEOVER, and it is a different incident from a deletion.
# The recreated queue is a new resource: no policy, no encryption beyond the SSE-SQS default,
# no redrive wiring, and whatever attributes the actor chose. Producers that address the queue
# by name reconnect to it without erroring, so nothing looks broken while messages land
# somewhere the actor controls.
#
# The correlation groups by `userIdentity.arn` and NOT by queue name, because DeleteQueue
# names the queue in `requestParameters.queueUrl` while CreateQueue names it in
# `requestParameters.queueName` — Sigma cannot join across two field names. Confirm the names
# match by hand, or use the KQL, which does the join. Fifteen minutes spans the documented
# 60-second `QueueDeletedRecently` wait plus a retry or two without spanning unrelated work.
title: SQS queue deleted and a queue recreated by the same principal
id: 59f6a18c-fd3e-4656-949a-498751d3a43a
status: experimental
description: >-
  One principal deleted a queue and created a queue within fifteen minutes. If the names
  match, the queue's name has been taken over: producers addressing it by name reconnect to a
  resource the actor configured, with none of the original policy, encryption or redrive.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: temporal_ordered
  rules:
    - sqs_queue_deleted_nonpipeline
    - sqs_queue_created_bb
  group-by:
    - userIdentity.arn
  timespan: 15m
level: high
```

The rule cannot say how much was destroyed — `DeleteQueue` carries no depth and has no
response object — and it cannot join the deletion to the recreation on the queue name,
because the two events name the queue through different fields.
`detections/kql_t1485.kql` does that join and additionally flags the sharper case where the
name is recreated by a **different** principal.

---

### Key Investigation Queries

> SQS is regional — run these in the queue's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: who deleted what, and did anything come back under the same name

```bash
REGION="us-east-1"
RAW=$(for EV in DeleteQueue CreateQueue; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no queues were deleted'."
else
  # DeleteQueue names the queue in requestParameters.queueUrl; CreateQueue names it in
  # requestParameters.queueName and returns responseElements.queueUrl (flat, no wrapper).
  # Both are reduced to queue_name here so the two halves can be compared by eye.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "sqs.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     queue_url: (.requestParameters.queueUrl // .responseElements.queueUrl),
     queue_name: (.requestParameters.queueName //
                  ((.requestParameters.queueUrl // "") | split("/") | last)),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

Sort by `queue_name` mentally: a `DeleteQueue` followed by a `CreateQueue` on the same
`queue_name` is **name takeover**, and if the two `caller_arn` values differ it is worse than
takeover — someone else moved in. A `CreateQueue` with `error` = `QueueDeletedRecently` is an
attempted takeover inside the documented 60-second wait, which is an intent signal even
though it failed. Count `error` values separately from successes: repeated
`AccessDeniedException`/`NotAuthorized` is boundary mapping, not destruction. Record
`queue_name`, `caller_arn` and `access_key` as IOCs.

#### Query 2 — How deep was the queue when it died, and what was it configured to do

```bash
REGION="us-east-1"
QUEUE_NAME="<queue-name-from-Query-1>"
DELETED_AT="<iso8601-time-of-the-deletion-from-Query-1>"

# The ONLY surviving measure of what was lost. AWS emits SQS metrics only while a queue is
# active, so this must be read over a window ENDING at the deletion. Reading afterwards
# returns no datapoints - that is the absence of a queue, never an empty queue.
DEPTH=$(aws cloudwatch get-metric-statistics --namespace AWS/SQS --period 300 \
  --statistics Maximum --metric-name ApproximateNumberOfMessagesVisible \
  --dimensions Name=QueueName,Value="$QUEUE_NAME" --region "$REGION" --output json \
  --start-time "$(date -u -d "$DELETED_AT -6 hours" +%Y-%m-%dT%H:%M:%SZ)" --end-time "$DELETED_AT")
if [ -z "$DEPTH" ]; then
  echo "[!] INCONCLUSIVE - the CloudWatch call failed; the destroyed backlog is unknown, not zero"
else
  N=$(printf '%s' "$DEPTH" | jq '.Datapoints | length')
  if [ "$N" -eq 0 ]; then
    echo "[!] INCONCLUSIVE - no datapoints in the 6h before deletion. Either the queue was"
    echo "    idle and emitted nothing, or metric retention has aged out. Not proof of zero."
  else
    printf '%s' "$DEPTH" | jq -r '.Datapoints | sort_by(.Timestamp) | last |
      "last known backlog before deletion: \(.Maximum) messages at \(.Timestamp)"'
  fi
fi

# What the queue was configured to do survives only in IaC and in earlier CloudTrail events.
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=SetQueueAttributes \
  --start-time "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" --region "$REGION" --output json |
  jq -r --arg q "$QUEUE_NAME" '.Events[].CloudTrailEvent | fromjson |
    select((.requestParameters.queueUrl // "") | endswith("/" + $q)) |
    {time: .eventTime, caller: .userIdentity.arn,
     attrs: ((.requestParameters.attributes // {}) | keys),
     policy: (.requestParameters.attributes.Policy // null),
     redrive: (.requestParameters.attributes.RedrivePolicy // null)}' | jq -s 'sort_by(.time)'
```

The backlog figure is the size of the loss and belongs in the incident record; an
`INCONCLUSIVE` here must be written down as unknown rather than rounded to zero. The second
command reconstructs the dead queue's configuration from its own history — that is how you
rebuild a policy and a redrive target that exist nowhere else, and it is bounded by your
CloudTrail retention, so run it early.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CreateQueue DeleteQueue"
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

Deletion is already complete and cannot be undone, so containment is about the **next**
queue, not this one. Stop the principal first; only then rebuild, because recreating a queue
while the actor still holds `sqs:DeleteQueue` invites a second deletion — and note the
documented 60-second wait before the name is reusable.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Stop the principal deleting anything else

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sqs:DeleteQueue","sqs:PurgeQueue","sqs:CreateQueue","sqs:SetQueueAttributes"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenySqsDestroy" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenySqsDestroy" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied SQS destruction for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or"
     echo "    a service principal. Contain manually; neither branch above applies.";;
esac
```

#### Step 2 — Rebuild the queue from infrastructure code, and prove it is yours

```bash
REGION="us-east-1"; QUEUE_NAME="<queue-name-from-Query-1>"

# AWS: "you must wait at least 60 seconds before creating a queue with the same name."
# Inside that window CreateQueue returns QueueDeletedRecently, which is a real state, not a
# failure to handle - so the error is reported rather than swallowed.
OUT=$(aws sqs create-queue --queue-name "$QUEUE_NAME" --region "$REGION" --output json 2>&1)
case "$OUT" in
  *QueueDeletedRecently*) echo "[i] still inside the documented 60-second wait - retry shortly";;
  *QueueNameExists*)      echo "[!] a queue of this name ALREADY EXISTS with different attributes."
                          echo "    Someone recreated it. Do NOT overwrite: investigate name takeover first.";;
  *queueUrl*|*QueueUrl*)  echo "[OK] queue recreated: $(printf '%s' "$OUT" | jq -r '.QueueUrl')";;
  *)                      echo "[!] INCONCLUSIVE - unexpected create-queue output: $OUT";;
esac
# Then reapply policy, encryption and redrive FROM IaC in one apply. A queue recreated bare
# has no access policy, no redrive wiring, and only the SSE-SQS default - which itself applies
# only because no encryption attributes were specified on this call.
```

---

## 4. Eradication

### Remove Attacker Access

- **Rebuild every queue in the deletion set**, not just the one that alerted — the volume
  correlation's group is the work-list — and reapply policy, encryption and redrive from IaC in
  the same apply, because a bare recreated queue is open to anyone the account's identity
  policies permit and encrypted only by the SSE-SQS default.
- **Resolve the name-takeover case before rebuilding.** If Query 1 shows a `CreateQueue` on the
  same name after the deletion, a queue is already there and it is not yours: export its
  messages, capture its policy and attributes as evidence, and only then replace it. Recreating
  over it destroys the evidence of the takeover.
- **Re-point producers and consumers.** A recreated queue has the same URL, so most clients
  reconnect silently — which also means a client that reconnected during the takeover window
  wrote to the actor's queue and will never report an error.
- **Right-size the permission.** `sqs:DeleteQueue` is not needed by any workload at runtime;
  only whatever owns queue lifecycle needs it. The same applies to `sqs:PurgeQueue`
  (`../sqs.stealth.a-queue-was-purged/`).
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
# A principal that is neither user nor role must reach INCONCLUSIVE, never the clean branch.
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenySqsDestroy EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenySqsDestroy"
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

#### Verify the rebuilt queue exists, is yours, and carries the configuration it should

```bash
REGION="us-east-1"; QUEUE_NAME="<queue-name-from-Query-1>"
ACCT=$(aws sts get-caller-identity --query Account --output text)

URL=$(aws sqs get-queue-url --queue-name "$QUEUE_NAME" --region "$REGION" \
        --query 'QueueUrl' --output text)
# QueueArn is requested alongside the configuration attributes on purpose: get-queue-attributes
# omits attributes that are not set, so an empty map cannot be distinguished from a failed call
# without an attribute that always exists.
A=$(aws sqs get-queue-attributes --queue-url "$URL" --region "$REGION" --output json \
      --attribute-names QueueArn Policy KmsMasterKeyId SqsManagedSseEnabled RedrivePolicy)
ARN=$(printf '%s' "$A" | jq -r '.Attributes.QueueArn // empty')
POL=$(printf '%s' "$A" | jq -r '.Attributes.Policy // empty')
SSE=$(printf '%s' "$A" | jq -r 'if (.Attributes.KmsMasterKeyId // "") != "" then "kms"
                                elif (.Attributes.SqsManagedSseEnabled // "") == "true" then "sqs"
                                else "none" end')
if   [ -z "$URL" ] || [ -z "$ARN" ]; then
  echo "[!] INCONCLUSIVE - the queue could not be read back. Not restored, not broken: unknown."
elif ! printf '%s' "$ARN" | grep -q ":${ACCT}:"; then
  echo "[FAIL] the queue named $QUEUE_NAME belongs to account $(printf '%s' "$ARN" | awk -F: '{print $5}'), not $ACCT"
elif [ "$SSE" = "none" ]; then
  echo "[FAIL] rebuilt queue $QUEUE_NAME has NO encryption - the IaC apply did not include it"
elif [ -z "$POL" ]; then
  echo "[FAIL] rebuilt queue $QUEUE_NAME has NO access policy - reapply it from IaC"
else
  echo "[OK] $QUEUE_NAME exists in $ACCT, encrypted ($SSE), with an access policy set"
fi
```

Each branch is reachable after the remediation: the queue exists again, so
`get-queue-attributes` has something to return, and a partial rebuild — the common real
outcome, where the queue comes back without its policy or its encryption — lands on `[FAIL]`
rather than being certified clean.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     DeleteQueue / sqs.amazonaws.com / no errorCode, where userIdentity.arn"
echo "  is NOT on the queue-lifecycle allowlist. The volume correlation must fire at exactly"
echo "  five such events in five minutes from one principal - gte, not gt."
echo "MUST NOT fire on: DeleteQueue by the pipeline role during a stack teardown; a DeleteQueue"
echo "  that returned AccessDeniedException or NotAuthorized (an attempt, not a deletion)."
echo "EXPECTED FP, by design: an engineer removing a personal or ephemeral queue outside the"
echo "  pipeline. If that is common in production, the finding is that queue lifecycle is not"
echo "  owned by the pipeline."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could destroy a queue and everything in it | `sqs:DeleteQueue` granted to a runtime identity that never needs it; no SCP confining queue lifecycle |
| The deletion was not distinguished from routine teardown | Both source rules matched the event name with no principal check, so the signal arrived inside a stream of legitimate destroys |
| Nobody could say how many messages were lost | `ApproximateNumberOfMessagesVisible` was not retained, and it stops emitting the moment the queue is gone — there is no way to read it after the fact |
| The rebuilt queue came back without its policy or encryption | The queue's configuration lived only in the console, not in infrastructure code, so a recreate produced a bare resource |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches every principal and denies queue lifecycle outright.
{
  "Effect": "Deny",
  "Action": ["sqs:DeleteQueue", "sqs:PurgeQueue"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the caller, which is always an in-organisation principal here: AWS states
  cross-account permissions do not apply to `DeleteQueue`. Pair it with queue configuration
  held in IaC — after a deletion that is the only place the policy, encryption and redrive
  still exist — and with `ApproximateNumberOfMessagesVisible` retained long enough to answer
  "how much was lost" after the queue is gone.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction (primary); T1070 — Indicator Removal (secondary, where the queue carried security telemetry) |
| Primary API | `sqs:DeleteQueue`; `sqs:CreateQueue` as the second half of a name takeover |
| Event source | `sqs.amazonaws.com`, **management** plane, regional — verified against AWS's SQS CloudTrail documentation |
| Key discriminator | The calling principal. `DeleteQueue` is what every teardown does; only `userIdentity.arn` separates destruction from maintenance. Volume raises urgency, not severity |
| Field shape | `DeleteQueue`: `requestParameters.queueUrl`, and **no `responseElements`** (HTTP 200, empty body). `CreateQueue`: `requestParameters.queueName`, `responseElements.queueUrl` — **flat**, matching the API's bare `{"QueueUrl": ...}` Response Syntax |
| "Was it used" pivot | Not applicable in the usual sense — the deletion *is* the outcome. The measurable question is how much was lost, answered only by `AWS/SQS` `ApproximateNumberOfMessagesVisible` at its last datapoint **before** deletion; metrics stop when the queue does, so an empty result after the fact is the absence of a queue, never an empty queue |
| Blast radius | Every stored and in-flight message, plus the queue's policy, encryption setting, redrive wiring and retention. Producers keep succeeding for up to 60 seconds while their messages are discarded |
| Error strings | Denials: `AccessDeniedException` and `NotAuthorized` are both documented; the bare `AccessDenied` form is widely observed but **not** in SQS's documented list — match all three. `DeleteQueue`: `InvalidAddress`, `InvalidSecurity`, `QueueDoesNotExist`, `RequestThrottled`, `UnsupportedOperation`. Recreate side: `QueueDeletedRecently` (inside the 60-second wait), `QueueNameExists`, `InvalidAttributeName`, `InvalidAttributeValue` |

T1485 (Data Destruction, Impact) is the
corrected primary; its platform list includes IaaS. T1070 (Indicator Removal, Stealth) is
carried as a genuine second mapping for a queue carrying security telemetry, which is the
reading the directory's `stealth` segment tracks.

### Residual Risk

The messages are gone and **no count of them exists** unless
`ApproximateNumberOfMessagesVisible` was already being retained — the metric stops the moment
the queue does. Everything in flight at deletion is lost silently: consumers that had received
but not deleted those messages will never see them redelivered, and their processing looks
like it simply stopped. For up to sixty seconds after the call, producers kept getting
successful `SendMessage` responses for messages that no longer exist, so any at-least-once
guarantee the application believed it had was untrue for that window and there is no error to
correlate against. If the name was recreated before you got there, every producer addressing
the queue by name has been writing into a resource someone else configured — and if data
events were off, which is the default, there is no record of what was written or read.
