# Detection Note — T1485 / T1070 (SQS Queue Purged)

**Signal:** `PurgeQueue` succeeding on a queue — once, again inside the 60-second window, or
across three or more queues by one principal in fifteen minutes.

**Purge is the quiet destruction, and that is the whole reason it is a separate use case
from deletion.** `DeleteQueue` removes the container, and every producer and consumer starts
erroring within a minute. `PurgeQueue` removes only the **messages**: the queue, its access
policy, its encryption setting, its redrive wiring and its CloudWatch metrics are all exactly
as they were. Nothing breaks. No existence alarm fires. Consumers simply have nothing to
read, which is indistinguishable from a quiet period. The sibling
`../../sqs.stealth.a-queue-was-deleted/` was merged with its own volume variant because their
responses are identical; this one stays separate because after a purge there is **nothing to
rebuild** — the entire response is evidence reconstruction and principal containment.

**What the original rule got wrong** — it matches `eventName:"PurgeQueue"` with a success
filter and nothing else. Unlike its five siblings this is not hopeless, because the API is
genuinely rare and the event name carries real signal on its own. Two things are still
missing. It never looks at *who* called, so a developer clearing a dev queue and an actor
destroying an audit backlog arrive identically at the same priority. And by filtering to
success it **discards the denied and in-progress attempts**, which for this API are the
richest evidence available — see below. Its **P3** is arguably the worst-calibrated priority
in the source set: a deletion pages someone regardless of the alert, while a purge is
invisible outside this one event.

## Irreversible, and the size of the loss is not in the event

AWS: *"When you use the `PurgeQueue` action, you can't retrieve any messages deleted from a
queue."* No version history, no undo, no recovery window.

The event is thin. `PurgeQueue` carries `requestParameters.queueUrl` and returns **HTTP 200
with an empty body**, so there is **no `responseElements`** and no count of what was
destroyed. The only surviving measure is the `AWS/SQS` CloudWatch metric
`ApproximateNumberOfMessagesVisible`, read at its **last datapoint before the purge**.

**And here the trap differs from the deletion sibling's.** A deleted queue stops emitting
metrics, so a post-hoc read returns no datapoints. A **purged** queue still exists and keeps
emitting, so a post-hoc read returns a perfectly valid **zero** — and reporting that zero as
"no messages were lost" inverts the finding entirely. Every metric query in the playbook is
bounded to end at the purge timestamp for this reason.

## The 60-second window is a detection opportunity, not just a caveat

AWS documents four things about the purge window, and each one shapes the response:

- *"The message deletion process takes up to 60 seconds. We recommend waiting for 60 seconds
  regardless of your queue's size."*
- *"Messages sent to the queue **before** you call `PurgeQueue` might be received but are
  deleted within the next minute."* So a consumer may receive a message that is about to
  vanish, process it, and then fail to delete it — producing a processing record for a
  message that no longer exists.
- *"Messages sent to the queue **after** you call `PurgeQueue` might be deleted while the
  queue is being purged."* Producers get successful sends for messages that are discarded, so
  the at-least-once guarantee the application believed it had is untrue for that window, with
  no error to correlate against.
- A second purge inside that window returns **`PurgeQueueInProgress`**.

That last one is why `sqs_purge_repeat_attempt` exists. `PurgeQueueInProgress` is returned
*only* when the same queue was purged in the previous 60 seconds, so it **cannot occur by
accident** — it means somebody asked twice, which is an actor making sure the queue stays
empty. Read alone, without a preceding success, it also tells you a purge happened whose
success event may predate your retention. A success-only rule throws all of that away.

The error code is matched with `|contains` rather than equality: the current API reference
names the bare code `PurgeQueueInProgress`, while the older query-protocol form carries an
`AWS.SimpleQueueService.` prefix. Prefix-tolerant matching covers both; confirm which form
your own trail records before narrowing it.

## Destruction and prior exfiltration look identical

`ReceiveMessage` is an SQS **data event** — off by default, absent from CloudTrail Event
history, invisible to `lookup-events` forever without an advanced event selector on
`AWS::SQS::Queue`. So an actor who *read* the queue and then purged it produces exactly the
same management-plane trail as one who only purged it. Message bodies are unavailable either
way: even with data events on, AWS's published example carries `requestParameters.messageBody`
as `HIDDEN_DUE_TO_SECURITY_REASONS`. `NumberOfMessagesReceived` and `NumberOfEmptyReceives` in
the hours before the purge are the only indication that anything was consuming, and they carry
a `QueueName` dimension and nothing else — so they can show that reading happened and never
who did it. State that gap in the incident record rather than treating purge-only as
established.

## Response levers

**Error strings:** SQS documents **two** distinct denial codes: `AccessDeniedException` and `NotAuthorized`
(both HTTP 400, both in the service's Common Errors). The bare `AccessDenied` form is what
IAM-evaluated denials produce across AWS and is widely observed, but it is **not** in SQS's
documented list — match all three and confirm against a real denied event. `PurgeQueue`'s own
set: `InvalidAddress`, `InvalidSecurity`, `PurgeQueueInProgress`, `QueueDoesNotExist`,
`RequestThrottled`, `UnsupportedOperation`. Denials must be counted **separately** from
successes: a principal probing twenty queues produces the same event volume as a real
destruction of twenty queues.

**GuardDuty:** There is **no GuardDuty finding type specific to SQS queue purging.** Do not build the
response on one existing.

**MITRE:** The source maps **T1578 / TA0005** — *Modify Cloud Compute Infrastructure*. T1578 is live, but
it covers compute infrastructure (instances, snapshots, images); destroying the contents of a
message queue is not that, so the mapping is wrong on the merits even though the ID resolves.

The corrected primary is **T1485 — Data Destruction**, Impact (TA0040), whose platform list
includes IaaS. **T1070 — Indicator Removal**, under Stealth (TA0005), is carried as a genuine
second mapping and is a *better* fit here than on the deletion sibling: a purge leaves the
queue and its metrics intact, so if the queue was carrying audit events or security telemetry,
emptying it removes the indicators while leaving every existence and health check green. That
second reading is what the directory's `stealth` segment tracks, and the source's TA0005 is
right for it.

**Severity:** **High**, against the source's **P3**. The act is irreversible, the loss is unmeasurable
unless a metric happened to be retained, and — unlike a deletion — nothing else in the
environment will tell you it happened.

**Files here:**

- `sigma_t1485.yml` — three documents: the purge itself (`high`, with an allowlist expected to
  stay small or empty, unlike the deletion sibling's), the `PurgeQueueInProgress` repeat
  attempt (`medium`, an error kept deliberately as evidence), and a `value_count` correlation
  firing `high` at three distinct queues in fifteen minutes.
- `kql_t1485.kql` — separates successes, denials and repeat attempts into their own columns so
  boundary mapping is never counted as destruction, and explains the metric bounding that keeps
  a post-purge zero from being read as "nothing was lost".

Full response procedure is in `../PLAYBOOK.md`.
