# Detection Note — T1485 / T1070 (SQS Queue Deletion, single and at volume)

**Signal:** `DeleteQueue` succeeding for a principal that does not own queue lifecycle —
once, or five or more times inside five minutes.

**Two source rules, one playbook.** The source set ships "A Queue Was Deleted" (per event)
and "Excessive Queue Deletion" (five in five minutes). Their queries are **byte-identical**,
their priorities are identical, and the response to one deletion and to fifty is the same
procedure run once or run in a loop. They are merged under the tiering rule's first merge
test — same observable, same response, differing only in threshold — with the reasoning
recorded in `../_source/PROVENANCE.md`. The volume rule survives as the
`sqs_queue_deleted_at_volume` correlation, at its own priority in the playbook's trigger
table.

**What the original rules got wrong** — both match `eventName:"DeleteQueue"` with a success
filter and nothing else. Concretely: every scheduled stack teardown, every ephemeral
test-environment destroy and every Terraform apply that removes a queue fires them, and
neither looks at *who* called. In an account where queue lifecycle belongs to a pipeline,
the caller is the entire signal — which is why the corrected rule is built on a principal
allowlist and the volume correlation sits on top of the already-filtered rule rather than on
a bare event match.

## Irreversibility, and the two things the event does not contain

AWS: *"When you delete a queue, any messages in the queue are no longer available."* There
is no recycle bin, no recovery window and no undelete. And the event is thin — `DeleteQueue`
carries `requestParameters.queueUrl` and returns **HTTP 200 with an empty body**, so there
is **no `responseElements`**. Two things a responder needs are therefore not in the record
and not recoverable from AWS afterwards:

1. **How deep the queue was.** The only surviving measure is the `AWS/SQS` CloudWatch metric
   `ApproximateNumberOfMessagesVisible`, read at its **last datapoint before the deletion**.
   AWS emits SQS metrics only when the queue is active, so querying after the fact returns no
   datapoints — that is the absence of a queue, not the absence of a backlog. Reporting it as
   "zero messages lost" is a false negative of exactly the shape this corpus keeps finding.
2. **What the queue was configured to do.** Its access policy, encryption setting, redrive
   wiring and retention period are gone with it. If they were not in infrastructure code,
   they existed only in whatever earlier `SetQueueAttributes` events are still inside your
   CloudTrail retention.

## The 60-second window, twice

AWS documents two distinct 60-second behaviours around deletion, and both matter:

- *"The deletion process takes up to 60 seconds. Requests you send involving that queue
  during the 60 seconds might succeed. For example, a `SendMessage` request might succeed,
  but after 60 seconds the queue and the message you sent no longer exist."* Producers keep
  succeeding for up to a minute while their messages are silently discarded, so the
  application-side symptom is delayed and looks like a downstream processing failure.
- *"When you delete a queue, you must wait at least 60 seconds before creating a queue with
  the same name"*, and a premature attempt returns **`QueueDeletedRecently`**.

That second constraint is what makes **delete-then-recreate detectable as a distinct shape**.
An actor taking over a queue *name* must pause, and the pause is visible. The recreated queue
is a new resource: no access policy, no encryption beyond the SSE-SQS default that applies
only when no encryption attributes are specified, no redrive wiring, and whatever attributes
the actor chose. Producers that address the queue **by name** reconnect without erroring, so
nothing looks broken while messages land in a resource the actor configured.

Sigma cannot join the two halves on the queue name — `DeleteQueue` names it inside
`requestParameters.queueUrl`, `CreateQueue` in `requestParameters.queueName` — so the
correlation groups by `userIdentity.arn` and the analyst confirms the name match.
`kql_t1485.kql` does the join properly, on the URL's last path segment, and additionally
flags the sharper case where the queue is recreated by a **different** principal.

## Denials are not deletions

`DeleteQueue` denials must be counted separately from successes. A principal probing its
boundary across twenty queues produces the same event volume as a real destruction of twenty
queues, and conflating them puts a reconnaissance event and an outage in the same bucket. The
base rule feeding the volume correlation carries `errorCode: null` for this reason, and the
KQL reports `DeniedAttempts` as its own column.

## Data plane

`SendMessage`, `ReceiveMessage` and `DeleteMessage` are SQS **data events** — off by default,
absent from CloudTrail Event history, invisible to `lookup-events` forever without an
advanced event selector on `AWS::SQS::Queue`. So are `ListQueues`, `GetQueueUrl`,
`GetQueueAttributes` and `ListQueueTags`, which means the enumeration that precedes a mass
deletion produces **no management event at all**. Its absence is not evidence that it did not
happen.

## Response levers

**Error strings:** SQS documents **two** distinct denial codes: `AccessDeniedException` and `NotAuthorized`
(both HTTP 400, both in the service's Common Errors). The bare `AccessDenied` form is what
IAM-evaluated denials produce across AWS and is widely observed, but it is **not** in SQS's
documented list — match all three and confirm against a real denied event. Operation-specific
codes: `DeleteQueue` throws `InvalidAddress`, `InvalidSecurity`, `QueueDoesNotExist`,
`RequestThrottled` and `UnsupportedOperation`; the recreate side throws `QueueDeletedRecently`
(inside the 60-second wait), `QueueNameExists` (same name, different attributes),
`InvalidAttributeName`, `InvalidAttributeValue` and the same common set.

**MITRE:** `T1485 — Data Destruction` (Impact), verified live 2026-08-31. Deleting a queue destroys
the messages it holds, and ATT&CK lists cloud infrastructure explicitly under this technique.

**GuardDuty:** There is **no GuardDuty finding type specific to SQS queue deletion.** Identity-side findings
such as `Impact:IAMUser/AnomalousBehavior` may fire on the principal, not on the queue. Do not
build the response on one existing.

The corrected primary is **T1485 — Data Destruction**, Impact (TA0040), whose platform list
includes IaaS and whose description covers destroying data "to interrupt availability to
systems, services, and network resources". **T1070 — Indicator Removal**, under Stealth
(TA0005), is carried as a genuine second mapping for the case where the deleted queue was
carrying security telemetry or audit events, which is the reading the directory's `stealth`
segment tracks. The source's tactic label (TA0005) is right for that second reading and wrong
for the primary one.

**Severity:** **High** for a deletion outside the pipeline, and **High** for the volume case. The source
rates both **P3** — which is defensible for the volume rule and too low for the single
deletion, because irreversibility does not scale with count: one production queue destroyed is
already unrecoverable, and the difference between one and fifty is the size of the work-list,
not the severity of the loss.

**Files here:**

- `sigma_t1485.yml` — four documents: the non-pipeline deletion (`high`), a `CreateQueue` base
  rule (`informational`, sequence component only), an `event_count` correlation firing `high`
  at five deletions in five minutes by one principal, and a `temporal_ordered` correlation
  firing `high` on delete-then-create within fifteen minutes.
- `kql_t1485.kql` — joins deletion to recreation **on the queue name**, which the Sigma
  correlation cannot do, and separates denied attempts from successful deletions.

Full response procedure is in `../PLAYBOOK.md`.
