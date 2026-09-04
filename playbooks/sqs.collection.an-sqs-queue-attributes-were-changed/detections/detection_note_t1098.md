# Detection Note — T1098 / T1213 (SQS Queue Attribute Manipulation)

**Signal:** a `SetQueueAttributes` call whose `Attributes` map rewrites the queue's access
policy, its dead-letter target, or its message retention — by a principal that is not the
queue-administration pipeline.

**One event name covers two unrelated incidents, and that is the whole problem.**
`SetQueueAttributes` is the single mutator for a queue's resource policy, its KMS key, its
redrive policy, its retention period and its visibility timeout. A grant to an outside
account and an encryption disable produce the *same* `eventSource` and the *same*
`eventName`. Nothing in the event name distinguishes them; only
`requestParameters.attributes.<Key>` does. Any rule that matches the name and stops there
has not detected anything — it has detected that the queue was configured. The encryption
half of the split lives in
`../../sqs.impact.server-side-encryption-for-aws-sqs-queue-was-disabled/`, and both
playbooks state the same discriminator problem from their own side.

**What the original rule got wrong** — it matches `eventSource:"sqs.amazonaws.com"` and
`eventName:"SetQueueAttributes"` with a success filter, and nothing else. Concretely: it
fires on every Terraform or CloudFormation apply that touches a queue, on every
autoscaling redrive adjustment, on every visibility-timeout tuning change, and on the
encryption disable its own sibling rule is supposed to own — while carrying no field that
would let a responder tell any of those apart. It is a configuration-change audit trail
tagged as a security alert. Its priority (P3) is also the same as the queue-deletion
alert's, which puts "somebody changed a timeout" and "an outside account can now read your
messages" in one bucket.

## The load-bearing mechanic: the grant is on the resource, and the use of it is invisible

A queue policy is a **resource-based** policy. It survives access-key rotation, session
revocation, role-trust repair and every identity-side audit — removing it requires
rewriting the queue's `Policy` attribute, and nothing else does.

Then the second half: **you cannot see it being used.** SQS's data/management split is
unusual and worth stating precisely, because it is the opposite of the intuition that
"reads are cheap so they are logged":

| Plane | SQS operations |
|-------|----------------|
| Management — in a default trail, visible to `lookup-events` | `AddPermission`, `CancelMessageMoveTask`, `CreateQueue`, `DeleteQueue`, `ListMessageMoveTasks`, `PurgeQueue`, `RemovePermission`, `SetQueueAttributes`, `StartMessageMoveTask`, `TagQueue`, `UntagQueue` |
| Data — **off by default**, requires an advanced event selector on `AWS::SQS::Queue` | `ChangeMessageVisibility(Batch)`, `DeleteMessage(Batch)`, `GetQueueAttributes`, `GetQueueUrl`, `ListDeadLetterSourceQueues`, `ListQueues`, `ListQueueTags`, `ReceiveMessage`, `SendMessage(Batch)` |

Read that second row again: **`ListQueues`, `GetQueueUrl` and `GetQueueAttributes` are
data events.** An actor can enumerate every queue in the account and read every queue's
current policy without producing a single management event. The reconnaissance that
precedes this technique is free, and its absence from a default trail must never be
reported as "no enumeration occurred".

The "was it used" pivot therefore routes to CloudWatch, namespace `AWS/SQS`:
`NumberOfMessagesReceived` (messages returned to a consumer), `NumberOfEmptyReceives`
(receive calls that returned nothing — the only evidence of someone polling a queue that
happened to be empty) and `NumberOfMessagesDeleted` (a consumer that both took and removed
a message, so the legitimate consumer never saw it). These metrics carry **one dimension,
`QueueName`**. They prove that consumption happened. They cannot say who did it. Attribution
requires SQS data events to have been enabled *before* the incident, and if they were not,
that fact belongs in the incident record rather than being papered over.

Even with data events on, message bodies are not recoverable: AWS's own published data-event
example shows `requestParameters.messageBody` as `HIDDEN_DUE_TO_SECURITY_REASONS`.

## Field shape, encoding, and the two traps

`SetQueueAttributes` sends `{"Attributes": {"<Name>": "<value>"}, "QueueUrl": "..."}`.
CloudTrail lower-cases the first character of **top-level** parameter names — AWS's own SQS
CloudTrail example carries `requestParameters.queueUrl` — while the keys **inside** the map
are data and keep their documented casing: `Policy`, `RedrivePolicy`,
`MessageRetentionPeriod`, `KmsMasterKeyId`, `SqsManagedSseEnabled`. AWS publishes no
management-event example for this API, so `requestParameters.attributes.<Name>` is
corroborated by observed events and by the request syntax rather than documented outright.
**Confirm it against one real event before deploying.**

Two traps follow from that shape:

1. **Do not decode.** `requestParameters.attributes.Policy` is raw JSON in whatever
   whitespace the client sent. Percent-encoding is a property of what the IAM-style *read*
   APIs return, not of a CloudTrail request parameter; the percent-encoding in AWS's
   query-protocol sample request is HTTP form encoding of the wire request, not what
   CloudTrail records. The real hazard is **whitespace** — `--attributes file://attrs.json`
   submits the document pretty-printed across newlines, which is why every pattern in the
   Sigma is a bare token or a whitespace-tolerant regex rather than
   punctuation-with-assumed-spacing.
2. **`Policy` and `RedrivePolicy` are JSON strings nested inside the attributes map.** In
   Sentinel, one `parse_json` gets you the request; reaching into the policy needs a
   *second* one. Skipping it yields empty for every field and a query that finds nothing —
   the same trap the Lambda resource-policy note records for `responseElements.statement`.

**There is no response object.** `SetQueueAttributes` returns HTTP 200 with an empty body,
so `responseElements` is absent. The request is the entire record, and since the `Policy`
attribute is written **wholesale** with no version history, this event is the only place the
queue's previous policy ever existed.

**No size-evasion rule ships here, deliberately.** An SQS access policy is capped at
**8,192 bytes** (policy quotas: Bytes 8,192, Statements 20, Principals 50, Conditions 10,
Actions per statement 7). CloudTrail omits `requestParameters` only above 100 KB, so the
document can never be large enough to be dropped. An oversized policy is rejected with
`InvalidAttributeValue` or `OverLimit` and never produces a success event — which is why
those codes belong in the error-string row rather than in a detection rule.

## The third destruction path

`MessageRetentionPeriod` is documented as taking up to 15 minutes to apply and as expiring
and deleting existing messages when it is reduced below their age. A drop to the 60-second
floor destroys a backlog under an event name that reads as a tuning change, and neither
`../../sqs.stealth.a-queue-was-purged/` nor `../../sqs.stealth.a-queue-was-deleted/` fires.
`sqs_queue_retention_period_changed` exists for that path. Sigma cannot compare the new
value against the old one, so the rule is `medium` and the comparison is the analyst's.

## Response levers

- Rewrite the `Policy` attribute to a known-good document — the only way to remove a
  resource-based grant. Revoking the actor's credentials does not touch it.
- `sqs:AddPermission` is a **second, independent path** to the same resource policy. AWS's
  own guidance: "To remove the ability to change queue permissions, you must deny permission
  to the `AddPermission`, `RemovePermission`, and `SetQueueAttributes` actions." Denying one
  leaves the others open.
- Reconstruct exposure from CloudWatch, not from CloudTrail, and say plainly that
  attribution is unavailable without data events.

## Error strings

SQS documents **two** distinct denial codes and they are not the same string:
`AccessDeniedException` (common errors, HTTP 400) and `NotAuthorized` (common errors, HTTP
400, "You do not have permission to perform this action"). The bare `AccessDenied` form is
what IAM-evaluated denials produce across AWS and is commonly observed, but it is **not** in
SQS's documented list. Match all three prefix-tolerantly and confirm against a real denied
event in your own account. Operation-specific codes for this API: `InvalidAddress`,
`InvalidAttributeName`, `InvalidAttributeValue`, `InvalidSecurity`, `OverLimit`,
`QueueDoesNotExist`, `RequestThrottled`, `UnsupportedOperation`.

## GuardDuty

There is **no GuardDuty finding type specific to SQS queue-policy manipulation.** Related
identity-side findings (`Discovery:IAMUser/AnomalousBehavior`,
`Persistence:IAMUser/AnomalousBehavior`) may fire on the principal, not on the queue.
Do not build the response on their presence.

## MITRE mapping

The source rule maps **T1213 / TA0009**. T1213 describes the *outcome* — data taken from a
repository — while what CloudTrail actually records is the **grant**, which is
**T1098 (Account Manipulation)**, Persistence (TA0003) and Privilege Escalation (TA0004),
with IaaS in its platform list. Both are carried: T1098 as the primary because it names the
observed event, T1213 as a genuine second mapping because it names what the grant is for.
The `collection` segment in this directory's name tracks the source's tactic; the
Classification table carries the corrected pair. A mapping-precision note, not an
operational defect.

## Severity

**High** for the wildcard and cross-account grants, and the source's **P3 is wrong** — it
sorts an outside account gaining read access to a message stream into the same queue as a
timeout tweak. Completion of the call *is* the exposure: there is no exploitation stage
afterwards, the grant is live on the next authorization evaluation, and the consumption it
enables is invisible in a default trail. The redrive and retention rules are `medium`
because their malicious and benign forms are genuinely distinguished by a value the rule
cannot compare.

**MITRE:** the source maps this to `T1213 — Data from Information Repositories`, which covers reading the queue's contents. The attribute change that enables it is `T1098 — Account Manipulation`; both are carried because the rule spans the grant and its purpose. Verified live 2026-08-30.

**GuardDuty:** no finding type covers Amazon SQS. GuardDuty has no SQS resource type, so these rules are the only coverage for this technique.

**Files here:**

- `sigma_t1098.yml` — six documents: the wildcard-principal grant (`high`), the
  policy-rewrite-outside-pipeline rule (`high`), the redrive repoint (`medium`), the
  retention rewrite (`medium`), a `CreateQueue` base rule (`informational`, sequence
  component only), and a `temporal_ordered` correlation firing `high` on
  create-then-repoint by one principal inside fifteen minutes.
- `kql_t1098.kql` — the structural evaluation Sigma cannot express: it parses the policy,
  normalises `Statement`, `Principal` and `Action` across their scalar and array forms, and
  compares the redrive target's account ID against the organisation set.

Full response procedure is in `../PLAYBOOK.md`.
