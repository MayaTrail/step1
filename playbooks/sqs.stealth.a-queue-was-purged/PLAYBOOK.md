# IR Playbook: SQS Queue Purged — Irreversible Message Destruction with the Queue Left Intact via `sqs:PurgeQueue`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data destruction / Indicator removal (every message in a queue is destroyed while the queue, its policy, its encryption and its metrics are left exactly as they were) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, against the source rule's **P3** — arguably the worst-calibrated priority in the SQS set. The act is irreversible, the size of the loss is unmeasurable unless a metric happened to be retained, and nothing else in the environment will report it: a deletion pages someone regardless of the alert, a purge is invisible outside this one event |
| MITRE Tactics | Impact (TA0040), Stealth (TA0005) |
| MITRE Techniques | T1485 (primary), T1070 (secondary) — both verified live 2026-08-29 |
| Services in Scope | SQS, CloudTrail (management + SQS data events), CloudWatch (`AWS/SQS`), IAM, Organizations (SCP), and every consumer that was expecting the destroyed messages |

**What the technique does:** the actor calls `sqs:PurgeQueue` with a queue URL. AWS deletes every
available message *including in-flight ones*, and states plainly that *"when you use the
`PurgeQueue` action, you can't retrieve any messages deleted from a queue"*. The queue
survives untouched — same URL, same access policy, same encryption setting, same redrive
wiring, same CloudWatch metrics — so no producer errors, no consumer reconnects, and no
existence or health check changes state. The destruction takes up to sixty seconds, during
which messages sent *before* the call *"might be received but are deleted within the next
minute"* and messages sent *after* it *"might be deleted while the queue is being purged"*:
producers keep receiving successful `SendMessage` responses for messages that are being
discarded. A second purge inside that window returns `PurgeQueueInProgress`.

**Detection thesis.** This event name is genuinely rare, so unlike its siblings the name
carries real signal — but the discriminators the source rule omits are **the calling
principal** and **the error code**. Filtering to success throws away `PurgeQueueInProgress`,
which AWS returns only when the same queue was purged in the previous sixty seconds and which
therefore cannot occur by accident, and it throws away the denials that show a principal
mapping its boundary across queues it cannot reach.

> The queue's messages can also be destroyed by deleting the queue outright
> (`../sqs.stealth.a-queue-was-deleted/`) or by reducing `MessageRetentionPeriod`
> (`../sqs.collection.an-sqs-queue-attributes-were-changed/`). This is the only one of the
> three that leaves nothing broken behind it.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing SQS **management** events. `PurgeQueue` carries
  `requestParameters.queueUrl` and returns HTTP 200 with an empty body, so there is **no
  `responseElements`** and **no count of what was destroyed** anywhere in the record
- CloudWatch `AWS/SQS` `ApproximateNumberOfMessagesVisible` retained. It is the only surviving
  measure of the loss and it must be read at its **last datapoint before the purge**: a purged
  queue still exists and keeps emitting, so a read afterwards returns a perfectly valid
  **zero** that means nothing. `NumberOfMessagesReceived` and `NumberOfEmptyReceives` over the
  hours before the purge are the only indication that anything was consuming
- SQS **data events** on the queues that matter. Without them `ReceiveMessage` is invisible,
  so an actor who *read* the queue and then purged it leaves exactly the same management-plane
  trail as one who only purged it. Even with them on, message bodies are recorded as
  `HIDDEN_DUE_TO_SECURITY_REASONS`
- A record of which queues carry **audit or security telemetry**. Purging one of those is
  indicator removal, not just data loss, and it changes the tactic as well as the urgency
- A baseline of who may purge at all — in most accounts nobody, which is what makes this API
  unusual: it has no legitimate production use

**Alerting (must be pre-configured)**
- **`PurgeQueue` succeeding on any production queue → P0**
- **`PurgeQueue` returning `PurgeQueueInProgress` — a repeat purge inside the 60-second window → P1**
- **Three or more distinct queues purged by one principal within fifteen minutes → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `PurgeQueue` succeeding on a production queue | CloudTrail (management) | T1485 |
| P1 | `PurgeQueue` returning `PurgeQueueInProgress` — the caller asked twice inside 60 seconds | CloudTrail (management) | T1485 |
| P1 | Three or more distinct queues purged by one principal within fifteen minutes | CloudTrail (management) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ApproximateNumberOfMessagesVisible` collapsing to zero with no matching fall in `NumberOfMessagesReceived` | CloudWatch `AWS/SQS` | T1485 |
| P2 | `PurgeQueue` denied across several queues (`AccessDeniedException`/`NotAuthorized`) — boundary mapping, not destruction | CloudTrail (management) | T1485 |
| P3 | `NumberOfMessagesReceived` rising on a queue in the hours before a purge, with no consumer deployment to explain it | CloudWatch `AWS/SQS` | T1070 |

### Detection Rule Quality Notes

The source rule is the closest of the six to workable, because the API is rare enough that the
event name carries signal. It still discards the best evidence it has.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Filters to success only | Throws away `PurgeQueueInProgress`, which AWS returns *only* when the same queue was purged in the previous 60 seconds and which therefore has no accidental cause — the single clearest indication that the caller was making sure the queue stayed empty. Also throws away denials, which show a principal mapping its boundary | Ship a separate rule on the error, and count denials separately from successes |
| No principal check | A developer clearing a dev queue and an actor destroying an audit backlog arrive identically at the same priority | Allowlist purge operators — expected to be a very short list, or empty |
| No volume dimension | One purge and an estate being emptied are the same alert | Add a `value_count` correlation on distinct queue URLs |
| P3 priority | The quietest irreversible act in the service is triaged below events that page somebody anyway | P0 for a production purge |

**Recommended detection — a queue purged.**

```yaml
# SQS Queue Purged (T1485 / T1070)
#
# PURGE IS THE QUIET DESTRUCTION. `DeleteQueue` removes the container and every producer and
# consumer starts erroring within a minute; `PurgeQueue` removes only the MESSAGES and leaves
# the queue, its policy, its encryption, its redrive wiring and its metrics exactly as they
# were. Nothing breaks, no alarm on queue existence fires, consumers simply have nothing to
# read - which is indistinguishable from a quiet period. That is why the sibling deletion
# playbook and this one are separate use cases with different responses, and why a P3 on this
# one is arguably the worst-calibrated priority in the source set: a delete pages someone
# regardless of the alert, a purge is invisible outside this event.
#
# IRREVERSIBLE AND NOT RECONSTRUCTABLE. AWS: "When you use the PurgeQueue action, you can't
# retrieve any messages deleted from a queue." There is no version history and no undo. The
# event itself carries only `requestParameters.queueUrl` and returns HTTP 200 with an empty
# body, so there is NO `responseElements` and no count of what was destroyed. The only
# surviving measure is the AWS/SQS CloudWatch metric ApproximateNumberOfMessagesVisible read
# at its last datapoint BEFORE the purge - and unlike a deletion, the queue still exists
# afterwards and keeps emitting, so a post-purge read returns a legitimate, meaningless zero.
# Reading the metric after the fact and reporting "no messages lost" is the false-clean shape
# this corpus keeps finding.
#
# THE 60-SECOND CONSTRAINT IS A DETECTION OPPORTUNITY. AWS: "The message deletion process
# takes up to 60 seconds", messages sent before the call "might be received but are deleted
# within the next minute", messages sent after "might be deleted while the queue is being
# purged", and a second purge inside that window returns `PurgeQueueInProgress`. So an actor
# making sure a queue stays empty produces a distinctive error trail that a success-only rule
# discards - Rule 2 below keeps it, because the error IS the evidence of intent.
#
# THE SOURCE RULE matches `eventName:"PurgeQueue"` with a success filter and nothing else. The
# event name is genuinely rare, so unlike its siblings this is not hopeless - but it never
# looks at who called, so a developer clearing a dev queue and an actor destroying an audit
# backlog arrive identically, and it discards the denied and in-progress attempts entirely.
title: SQS queue purged
id: 071305ff-31f2-484f-8031-a9fa537f040c
name: sqs_queue_purged
status: experimental
description: >-
  Every message in a queue was destroyed while the queue itself was left intact. Nothing
  downstream errors, so unless this event is alerted on, the loss surfaces only as consumers
  processing nothing.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html  # retrieved 2026-08-29
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
    eventName: 'PurgeQueue'
  success:
    errorCode: null
  # POPULATE. Purging is not part of any normal deployment, so this allowlist is expected to
  # stay small or empty - unlike the deletion sibling's, where teardown is routine. Left empty
  # the rule fires on every purge, which for this API is the correct default.
  purge_operators:
    userIdentity.arn|contains:
      - ':role/BreakGlassAdmin'   # replace, or delete this block entirely
  condition: selection and success and not purge_operators
falsepositives:
  - >-
    A developer clearing a development or test queue by hand. Legitimate and common in
    non-production accounts; in a production account there is no routine reason to purge, so
    treat a production hit as an incident until the owner accounts for it.
level: high
---
# The error is the evidence. `PurgeQueueInProgress` is returned only when a purge was already
# requested on that queue within the last 60 seconds, so it cannot occur by accident: it means
# somebody asked twice. Read together with a preceding success it shows an actor making sure
# the queue stays empty; read alone it shows a purge attempt whose first half may predate your
# retention window. A success-only rule throws this away.
title: SQS repeat purge attempt inside the 60-second window
id: 99d33381-1b8b-4772-b266-cbab30172081
name: sqs_purge_repeat_attempt
status: experimental
description: >-
  A `PurgeQueue` call was rejected with `PurgeQueueInProgress`, which AWS returns only when
  the same queue was purged within the previous 60 seconds. The caller asked twice.
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sqs.amazonaws.com'
    eventName: 'PurgeQueue'
  # Matched with |contains rather than equality: the API reference names the bare code
  # `PurgeQueueInProgress`, while the older query-protocol form carries an
  # `AWS.SimpleQueueService.` prefix. Prefix-tolerant matching covers both; confirm which one
  # your own trail records before narrowing it.
  in_progress:
    errorCode|contains: 'PurgeQueueInProgress'
  condition: selection and in_progress
falsepositives:
  - >-
    A retry loop in an automated test harness that purges before each case. Baseline it; in
    production this error has no benign cause.
level: medium
---
# Threshold basis — derived from documented behaviour, not an observed count. The technique's
# own baseline is ONE queue: a single purge is the whole attack, and `sqs_queue_purged` above
# already fires high on it. This correlation is a severity escalator that separates one
# developer clearing one queue from an actor emptying a message estate. Three distinct queues
# in fifteen minutes sits above any single legitimate purge and below nothing legitimate at
# all, because there is no process that purges three production queues in a quarter of an
# hour. `gte`, never `gt`, so a sweep that touches exactly three does not fall through.
# Baseline against your own account before deploying.
title: SQS queues purged across multiple queues by one principal
id: 0be12849-e97a-468c-ae0d-7f7eec197b48
status: experimental
description: >-
  One principal purged three or more distinct queues inside fifteen minutes. That is an
  estate being emptied, not a queue being cleared.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: value_count
  rules:
    - sqs_queue_purged
  group-by:
    - userIdentity.arn
  timespan: 15m
  # `field` belongs INSIDE `condition` for a value_count correlation — it is the field whose
  # DISTINCT values are counted. A top-level `field:` under `correlation:` is not in the
  # specification and leaves the rule with nothing to count.
  condition:
    gte: 3
    field: requestParameters.queueUrl
level: high
```

The rule cannot say how much was destroyed — the event carries no count and has no response
object — and it cannot distinguish an actor who read the queue before emptying it from one
who only emptied it, because `ReceiveMessage` is data-plane.
`detections/kql_t1485.kql` separates successes, denials and repeat attempts into their own
columns so boundary mapping is never counted as destruction.

---

### Key Investigation Queries

> SQS is regional — run these in the queue's region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: who purged what, how often, and what was refused

```bash
REGION="us-east-1"
RAW=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PurgeQueue \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no queues were purged'."
else
  # Errors are KEPT, not filtered out. PurgeQueueInProgress is returned only when the same
  # queue was purged within the previous 60 seconds, so it cannot occur by accident and is
  # the strongest single indicator of intent this API produces.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "sqs.amazonaws.com") |
    {time: .eventTime, caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     queue_url: .requestParameters.queueUrl,
     queue_name: (.requestParameters.queueUrl // "" | split("/") | last),
     error: (.errorCode // "SUCCESS"),
     verdict: (if (.errorCode // "") == "" then "PURGED - messages destroyed"
               elif ((.errorCode // "") | test("PurgeQueueInProgress")) then "REPEAT PURGE inside the 60s window - no accidental cause"
               else "ATTEMPT REFUSED - boundary mapping, nothing destroyed" end),
     ip: .sourceIPAddress, agent: .userAgent}' | jq -s 'sort_by(.time)'
fi
```

Count the three `verdict` values separately — a principal refused on fifteen queues and
successful on one destroyed one queue, not sixteen. `REPEAT PURGE` with no preceding
`PURGED` in the output means the first purge predates your retention window, so widen
`--start-time` before concluding it failed. Record `queue_name`, `caller_arn` and
`access_key` as IOCs.

#### Query 2 — Size the loss, and ask whether anything read the queue first

```bash
REGION="us-east-1"
QUEUE_NAME="<queue-name-from-Query-1>"
PURGED_AT="<iso8601-time-of-the-purge-from-Query-1>"

# BOUNDED TO END AT THE PURGE. A purged queue still exists and keeps emitting metrics, so a
# read that extends past this timestamp returns a valid zero that means nothing at all.
BACKLOG=$(aws cloudwatch get-metric-statistics --namespace AWS/SQS --period 300 \
  --statistics Maximum --metric-name ApproximateNumberOfMessagesVisible \
  --dimensions Name=QueueName,Value="$QUEUE_NAME" --region "$REGION" --output json \
  --start-time "$(date -u -d "$PURGED_AT -6 hours" +%Y-%m-%dT%H:%M:%SZ)" --end-time "$PURGED_AT")
if [ -z "$BACKLOG" ]; then
  echo "[!] INCONCLUSIVE - the CloudWatch call failed; the destroyed backlog is unknown, not zero"
else
  N=$(printf '%s' "$BACKLOG" | jq '.Datapoints | length')
  if [ "$N" -eq 0 ]; then
    echo "[!] INCONCLUSIVE - no datapoints in the 6h before the purge. Either the queue was"
    echo "    idle or metric retention has aged out. This is not proof that nothing was lost."
  else
    printf '%s' "$BACKLOG" | jq -r '.Datapoints | sort_by(.Timestamp) | last |
      "last known backlog before the purge: \(.Maximum) messages at \(.Timestamp)"'
  fi
fi

# Did anything CONSUME the queue before it was emptied? ReceiveMessage is a DATA event and is
# absent from a default trail forever, so this is the only available answer - and it carries a
# QueueName dimension and nothing else, so it can show that reading happened, never who did it.
READS=$(aws cloudwatch get-metric-statistics --namespace AWS/SQS --period 3600 --statistics Sum \
  --metric-name NumberOfMessagesReceived --dimensions Name=QueueName,Value="$QUEUE_NAME" \
  --region "$REGION" --output json \
  --start-time "$(date -u -d "$PURGED_AT -24 hours" +%Y-%m-%dT%H:%M:%SZ)" --end-time "$PURGED_AT")
[ -z "$READS" ] && echo "[!] INCONCLUSIVE - CloudWatch call failed; prior consumption is unknown, not zero"
printf '%s' "$READS" | jq -r '[.Datapoints[].Sum] | add // 0 |
  "messages received in the 24h before the purge: \(.)"'
```

The backlog figure is the size of the loss and belongs in the incident record; an
`INCONCLUSIVE` must be written down as unknown, never rounded to zero. The receive total is
the exfiltration question: a count your own consumers cannot account for means the queue was
read before it was emptied, and destruction was the cleanup rather than the objective. If SQS
data events were off — the default — say in the record that attribution for those reads does
not exist.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="PurgeQueue"
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

The messages are already gone and nothing can bring them back, so containment is entirely
about the **next** queue. Deny the principal first; the queue itself needs no repair, which is
what makes this incident quiet and what makes evidence capture urgent — the CloudWatch
datapoints that size the loss age out on the metric's retention, not on your incident's.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Stop the principal purging or deleting anything else

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sqs:PurgeQueue","sqs:DeleteQueue","sqs:SetQueueAttributes"],"Resource":"*"}]}'
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

#### Step 2 — Capture the evidence before the metrics age out

```bash
REGION="us-east-1"; QUEUE_NAME="<queue-name-from-Query-1>"
PURGED_AT="<iso8601-time-of-the-purge-from-Query-1>"
OUT="./purge-evidence-${QUEUE_NAME}.json"

# The queue is intact, so its CONFIGURATION is still readable - unlike after a deletion. Take
# it now: it establishes whether the queue was encrypted, who could reach it, and where its
# dead-letter traffic went, all of which frame what the destroyed messages were.
CFG=$(aws sqs get-queue-attributes --queue-url \
        "$(aws sqs get-queue-url --queue-name "$QUEUE_NAME" --region "$REGION" --query QueueUrl --output text)" \
        --attribute-names All --region "$REGION" --output json)
MET=$(aws cloudwatch get-metric-statistics --namespace AWS/SQS --period 300 --statistics Maximum \
        --metric-name ApproximateNumberOfMessagesVisible \
        --dimensions Name=QueueName,Value="$QUEUE_NAME" --region "$REGION" --output json \
        --start-time "$(date -u -d "$PURGED_AT -24 hours" +%Y-%m-%dT%H:%M:%SZ)" --end-time "$PURGED_AT")
if [ -z "$CFG" ] || [ -z "$MET" ]; then
  echo "[!] INCONCLUSIVE - one or both reads returned nothing; evidence capture is INCOMPLETE."
  echo "    Fix the credential or region and re-run before the metric retention window closes."
else
  printf '{"queue":"%s","purged_at":"%s","attributes":%s,"backlog_before":%s}\n' \
    "$QUEUE_NAME" "$PURGED_AT" "$CFG" "$MET" > "$OUT"
  echo "[OK] evidence written to $OUT"
fi
```

---

## 4. Eradication

### Remove Attacker Access

- **There is nothing to restore.** Say so explicitly in the incident record rather than
  leaving a rebuild step that will never be done. The queue is intact and correctly
  configured; only its contents are gone, and they are gone permanently.
- **Work the estate, not the queue.** The `value_count` correlation's group is the list of
  queues emptied by the same principal in the same sitting; each one needs its own backlog
  figure from Query 2 before the metric ages out.
- **Rebuild the message stream from upstream where it exists.** Producers that still hold the
  source data can replay; anything that was only ever in the queue is unrecoverable. Identify
  which consumers had at-least-once expectations over the purge window — AWS documents that
  sends during the purge succeed while the messages are discarded, so those producers received
  no error and will not have retried.
- **Right-size the permission.** `sqs:PurgeQueue` is needed by no workload at runtime. It is
  one of the few AWS actions with no legitimate production use at all, which makes it an easy
  and complete SCP denial rather than a tuning exercise.
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

#### Verify the principal can no longer purge, using a real authorization decision

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
REGION="us-east-1"; QUEUE_NAME="<queue-name-from-Query-1>"
QARN=$(aws sqs get-queue-attributes --queue-url \
         "$(aws sqs get-queue-url --queue-name "$QUEUE_NAME" --region "$REGION" --query QueueUrl --output text)" \
         --attribute-names QueueArn --region "$REGION" --query 'Attributes.QueueArn' --output text)

# The post-containment check CANNOT be "no more purge events", because a contained principal
# generates no events at all and silence would print [OK] for a broken containment as readily
# as for a working one. simulate-principal-policy asks IAM for the decision directly, so the
# assertion has something to be wrong about.
SIM=$(aws iam simulate-principal-policy --policy-source-arn "$SUSPECT_ARN" \
        --action-names sqs:PurgeQueue sqs:DeleteQueue --resource-arns "$QARN" --output json)
if [ -z "$SIM" ]; then
  echo "[!] INCONCLUSIVE - the simulation call failed. Containment is unverified, not confirmed."
  echo "    (simulate-principal-policy needs an IAM user or role ARN, not an assumed-role ARN;"
  echo "     convert arn:aws:sts::ACCT:assumed-role/ROLE/SESSION to arn:aws:iam::ACCT:role/ROLE.)"
else
  ALLOWED=$(printf '%s' "$SIM" | jq -r '[.EvaluationResults[] | select(.EvalDecision != "explicitDeny" and .EvalDecision != "implicitDeny") | .EvalActionName] | join(", ")')
  if [ -n "$ALLOWED" ]; then echo "[FAIL] $SUSPECT_ARN is still permitted: $ALLOWED"
  else                       echo "[OK] both sqs:PurgeQueue and sqs:DeleteQueue are denied for $SUSPECT_ARN"; fi
fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     PurgeQueue / sqs.amazonaws.com / no errorCode. The repeat-attempt rule"
echo "  must fire on the SAME event name with errorCode containing PurgeQueueInProgress, and"
echo "  the correlation at exactly three distinct queueUrl values in fifteen minutes - gte."
echo "MUST NOT fire on: DeleteQueue (that is ../sqs.stealth.a-queue-was-deleted/); a PurgeQueue"
echo "  refused with AccessDeniedException or NotAuthorized, which is an attempt and belongs in"
echo "  the denial column, not the destruction count."
echo "EXPECTED FP, by design: a developer clearing a dev or test queue by hand. In production"
echo "  there is no routine reason to purge, so treat a production hit as an incident."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could destroy a queue's entire contents in one call | `sqs:PurgeQueue` was reachable at all — no workload needs it at runtime, and no SCP denied it |
| The loss was invisible outside the CloudTrail event | Purge leaves the queue, its policy and its metrics intact, so every existence and health check stayed green; the alert was the only signal and it was rated P3 |
| The size of the loss could not be established | `ApproximateNumberOfMessagesVisible` was not retained long enough, and it must be read *before* the purge — afterwards the queue still emits a valid, meaningless zero |
| Nobody could say whether the messages were read before being destroyed | SQS data events were off, so `ReceiveMessage` was never recorded; the metric shows consumption happened but carries no principal |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// PurgeQueue has no legitimate runtime use, so this is one of the rare cases where a bare
// Deny with no condition is correct - no allowlist, no exception, no tuning. If a break-glass
// path is genuinely needed, add StringNotLike (never StringNotEquals) on a wildcarded ARN.
{
  "Effect": "Deny",
  "Action": "sqs:PurgeQueue",
  "Resource": "*"
}
```

- The SCP reaches the caller, which is always an in-organisation principal for this API. Pair
  it with retention on `ApproximateNumberOfMessagesVisible` long enough to answer "how much was
  lost" after the fact, and with SQS data events on any queue carrying audit or security
  telemetry — for those queues a purge is indicator removal, and knowing whether the messages
  were read first changes the incident.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction (primary); T1070 — Indicator Removal (secondary, and a better fit here than on the deletion sibling, because the queue and its health signals survive) |
| Primary API | `sqs:PurgeQueue` |
| Event source | `sqs.amazonaws.com`, **management** plane, regional — verified against AWS's SQS CloudTrail documentation |
| Key discriminator | The calling principal, and the **error code**. `PurgeQueueInProgress` is returned only when the same queue was purged within the previous 60 seconds, so it has no accidental cause and is the clearest evidence of intent this API produces — which is exactly what a success-only filter discards |
| Field shape | `requestParameters.queueUrl` only. HTTP 200 with an empty body, so **no `responseElements`** and **no count** of what was destroyed anywhere in the event |
| "Was it used" pivot | Not applicable — the purge *is* the outcome. The measurable questions are how much was lost (`ApproximateNumberOfMessagesVisible` at its last datapoint **before** the purge; a purged queue keeps emitting, so a later read returns a valid, meaningless zero) and whether it was read first (`NumberOfMessagesReceived` beforehand). Both carry a `QueueName` dimension and nothing else |
| Blast radius | Every stored and in-flight message. Consumers that had received but not deleted a message will never see it redelivered; producers sending during the up-to-60-second window received success responses for messages that were discarded |
| Error strings | Denials: `AccessDeniedException` and `NotAuthorized` are both documented; the bare `AccessDenied` form is widely observed but **not** in SQS's documented list — match all three. `PurgeQueue`'s own set: `InvalidAddress`, `InvalidSecurity`, `PurgeQueueInProgress`, `QueueDoesNotExist`, `RequestThrottled`, `UnsupportedOperation`. Match `PurgeQueueInProgress` prefix-tolerantly — the current API reference names the bare code, the older query-protocol form carries an `AWS.SimpleQueueService.` prefix |

**MITRE mapping note.** The source maps T1578 / TA0005 — *Modify Cloud Compute
Infrastructure*. That ID is live, but T1578 covers compute infrastructure (instances,
snapshots, images); destroying the contents of a message queue is not that, so the mapping is
wrong on the merits even though it resolves. T1485 (Data Destruction, Impact) is the corrected
primary, with IaaS in its platform list. T1070 (Indicator Removal, Stealth) is the second
mapping and is the reading the directory's `stealth` segment tracks — the source's TA0005 is
right for that reading and wrong for the primary one.

### Residual Risk

The messages are gone permanently and **no count of them exists** unless
`ApproximateNumberOfMessagesVisible` was already being retained; the metric keeps emitting
afterwards, so the absence of evidence here looks exactly like evidence of absence. Whether
the queue was **read before it was emptied** is unanswerable in a default trail —
`ReceiveMessage` is data-plane — so destruction and exfiltration-then-cleanup are
indistinguishable, and if the queue carried anything sensitive that ambiguity has to be
resolved in favour of assuming it was read. Consumers that had received but not deleted
messages will never see them redelivered and will simply appear to have stopped working.
Producers that sent during the up-to-60-second purge window received success responses for
messages that were discarded, so any at-least-once guarantee the application believed it had
was untrue for that window, with no error anywhere to correlate against. And nothing about the
queue changed, so every dashboard, alarm and health check that watched it stayed green
throughout.
