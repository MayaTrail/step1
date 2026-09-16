# Detection Note — T1496 (Excessive SQS Queue Creation)

**Signal:** queues created at volume by a principal outside the lifecycle pipeline; a queue
created **already public**; and a queue created by one principal that is then named as
another queue's dead-letter target.

**This is the weakest signal in the SQS set, and the note says so rather than dressing it
up.** A queue costs almost nothing and holds nothing until something writes to it, so "many
queues appeared" is not on its own a security event. Everything useful here comes from
asking what a created queue is *for*, and three readings have teeth, in descending order of
sharpness:

1. **A queue created already public.** `CreateQueue` accepts the same `Policy` attribute as
   `SetQueueAttributes`, so a queue can be born open to a wildcard principal in one call —
   and because no `SetQueueAttributes` event ever exists for it, **every rule in the sibling
   policy playbook stays silent for that queue's entire life**. This is the one genuinely
   high-severity finding in the directory.
2. **A queue created by an unfamiliar principal that later becomes another queue's
   `RedrivePolicy` target.** That is message diversion staged across two individually
   unremarkable events, and it is the reason this directory cross-references
   `../../sqs.collection.an-sqs-queue-attributes-were-changed/`, where the ordered correlation
   ships.
3. **Unsanctioned consumption of account resources** — the volume reading the source rule
   expresses, and the weakest of the three.

**What the original rule got wrong** — it matches `eventName:"CreateQueue"` with a success
filter and an anomaly threshold of five in five minutes, and looks at nothing else.
Concretely: every CloudFormation stack that stands up a fan-out topology fires it, and so does
every ephemeral test environment. It never checks the caller, which in an account where queue
lifecycle belongs to a pipeline is the entire signal. Its **threshold is defensible and is
retained** — but only after the pipeline is excluded from what it counts, which is why the
correlation here sits on top of an already-filtered rule rather than on a bare event match.

## Its mapping contradicts itself, and both halves are wrong

The rule carries **two mutually inconsistent** MITRE mappings:

Creating a queue impairs no defence and disables no tool.
- Its own prose names **T1531** (Account Access Removal), which is live but describes locking
  legitimate users out of their accounts — neither what the rule detects nor what creating a
  queue does.

So the rule ships two mappings that disagree with each other, and neither survives contact
with the behaviour. The correction is **T1496 — Resource Hijacking**, Impact (TA0040), for the
volume reading, and **T1098** on the public-at-birth rule, because that one is a
resource-policy grant. State the limitation plainly: ATT&CK has no technique that cleanly
covers *creating messaging infrastructure inside a victim account to stage diversion*, and
T1496 is chosen as the closest defensible live mapping rather than an exact one. The prose
contradiction is recorded in `../_source/PROVENANCE.md`, because the extractor keeps detection
logic and drops descriptions, so a reviewer diffing the extract cannot otherwise see it.

## What CloudTrail gives you, and what it does not

`CreateQueue` carries `requestParameters.queueName`, an optional `requestParameters.attributes`
map and `requestParameters.tags`, and returns `responseElements.queueUrl` — **flat**, matching
the API's bare `{"QueueUrl": "..."}` Response Syntax, which has no wrapper object to nest
under. Attribute values are always **strings**.

Two AWS behaviours shape what the event set looks like:

- *"If you specify the name of an existing queue and provide the exact same names and values
  for all its attributes, the `CreateQueue` action will return the URL of the existing queue
  instead of creating a new one."* So an idempotent redeploy produces a `CreateQueue` event
  that created nothing. The event count is an upper bound on queues created, never an exact
  one.
- *"If you attempt to create a queue with a name that already exists but with different
  attribute names or values, the `CreateQueue` action will return an error"* —
  `QueueNameExists`. And `QueueDeletedRecently` marks an attempt inside the documented
  60-second post-deletion wait, which is a **name-takeover** attempt and belongs to
  `../../sqs.stealth.a-queue-was-deleted/`.

Whether anything was ever written to or read from a new queue is a **data-plane** question:
`SendMessage` and `ReceiveMessage` are SQS data events, off by default. So are `ListQueues`,
`GetQueueUrl` and `GetQueueAttributes` — meaning the enumeration that usually precedes a
creation burst produces **no management event at all**. Use `AWS/SQS`
`NumberOfMessagesSent`/`NumberOfMessagesReceived` per `QueueName` to separate a queue that is a
channel from one that is clutter; AWS emits SQS metrics only while a queue is active, so a
queue with no datapoints has genuinely never been used.

And on the cost reading: SQS bills per request, not per queue, so an idle queue costs
effectively nothing. A resource-abuse case is made in Cost Explorer, not in CloudTrail.

## Response levers

**Error strings:** SQS documents **two** distinct denial codes: `AccessDeniedException` and `NotAuthorized`
(both HTTP 400, both in the service's Common Errors). The bare `AccessDenied` form is what
IAM-evaluated denials produce across AWS and is widely observed, but it is **not** in SQS's
documented list — match all three and confirm against a real denied event. `CreateQueue`'s own
set: `InvalidAddress`, `InvalidAttributeName`, `InvalidAttributeValue`, `InvalidSecurity`,
`QueueDeletedRecently`, `QueueNameExists`, `RequestThrottled`, `UnsupportedOperation`.
Tagging on creation additionally requires `sqs:TagQueue`, so a `CreateQueue` with tags can be
denied on a permission the operator did not realise was involved.

**MITRE:** `T1496 — Resource Hijacking` is the live mapping — mass queue creation consumes account resources and quota rather than impairing a defence. Verified live 2026-08-30.

**GuardDuty:** There is **no GuardDuty finding type specific to SQS queue creation.** Do not build the
response on one existing.

**Severity:** **Medium** for the volume case — the source's **P4** is close to right, and this is the one
rule in the SQS set whose priority is not badly miscalibrated. **High** for the public-at-birth
rule, because that queue is exposed from its first second and no policy-change rule will ever
see it.

## A note on rule-name collisions across this corpus

Three SQS playbooks each ship a `CreateQueue` rule, under three distinct `name:` values
(`sqs_queue_created`, `sqs_queue_created_bb`, `sqs_queue_created_outside_pipeline`), because a
Sigma correlation resolves its components by `name:` within its own file and each playbook must
be deployable on its own. If all three are deployed together, expect the informational base
rules to fire in parallel; only one needs to be kept at an alerting level.

**Files here:**

- `sigma_t1496.yml` — three documents: creation outside the pipeline (`low`, a counting
  primitive rather than an alert), creation with a wildcard-principal policy (`high`), and an
  `event_count` correlation firing `medium` at five creations in five minutes by one principal.
- `kql_t1496.kql` — joins each created queue to any later `RedrivePolicy` that names it,
  matching the created name against the ARN in `deadLetterTargetArn`, which the Sigma
  correlation cannot do because in the interesting case the two principals differ.

Full response procedure is in `../PLAYBOOK.md`.
