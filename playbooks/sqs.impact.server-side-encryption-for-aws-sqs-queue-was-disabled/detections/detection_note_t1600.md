# Detection Note — T1600 / T1098 (SQS Server-Side Encryption Disabled)

**Signal:** a `SetQueueAttributes` call that leaves a queue with no encryption at rest —
`KmsMasterKeyId` cleared without `SqsManagedSseEnabled` being turned on in the same call,
or `SqsManagedSseEnabled` set to false outright.

**There is no fallback, and that is the fact the whole playbook rests on.** AWS states it
plainly: *"Amazon SQS allows you to turn off all queue encryption. Therefore, turning off
KMS-SSE, will not automatically enable SQS-SSE. If you wish to enable SQS-SSE after turning
off KMS-SSE, you must add an attribute change in the request."* The default SSE-SQS option
is *"only effective when you create a queue without specifying encryption attributes"*, so
it protects nothing on a queue whose attributes are being set deliberately. Clearing the key
leaves the queue unencrypted, full stop.

**And encryption is an authentication control on this service.** AWS again: *"With SSE
enabled, anonymous `SendMessage` and `ReceiveMessage` requests to the encrypted queue will
be rejected... If you wish to send anonymous requests to an Amazon SQS queue, make sure you
disable SSE."* So disabling SSE is not only a confidentiality change — it is the documented
**precondition for anonymous access**. Paired with a wildcard queue policy it makes the
queue readable and writable with no credential at all. That pairing is the
`sqs_sse_disabled_then_opened` correlation, and it is why this use case cross-references
`../../sqs.collection.an-sqs-queue-attributes-were-changed/` rather than standing alone.

## What the original rule got wrong

The source rule is the strongest of the six SQS rules as written — it is the only one that
inspects a request field rather than an event name. It still has two defects, and both are
visible in `../_source/original_rules.yml` without any AWS knowledge.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"setqueueattributes"` in **lower case**, where the five sibling rules in the same set all match `SetQueueAttributes` | Against a case-sensitive keyword field this is zero events, forever — a rule that looks deployed and detects nothing | Match the documented casing |
| Requires `requestParameters.attributes.KmsMasterKeyId` to be **present and empty** | A call that turns off SSE-SQS sends `SqsManagedSseEnabled=false` and carries no `KmsMasterKeyId` at all, so the condition cannot be met. The entire SSE-SQS disable path is uncovered — and SSE-SQS is the *default* scheme, so it is the more common queue state | Carry both disable paths as sibling blocks, OR-ed |
| No coverage of `CreateQueue` | A queue created with `SqsManagedSseEnabled=false` opts out of default encryption at birth and never produces a `SetQueueAttributes` event, so it is unencrypted for its whole life and no rule ever fires | Ship `sqs_queue_created_unencrypted` |
| P4 priority | Unencrypted storage plus the removal of the control that rejects anonymous requests is not a fourth-tier finding | High for the disable itself |

The rule's one correct instinct is kept: `NOT SqsManagedSseEnabled:"true"` correctly
excludes a **migration** from SSE-KMS to SSE-SQS, where the queue stays encrypted. That
exclusion survives as the `migrating_to_sse_sqs` block.

## The exposure window is bounded on both sides, and that is unusually good news

Two AWS statements make the blast radius computable rather than open-ended:

- *"A message is encrypted only if it is sent after the encryption of a queue is enabled.
  Amazon SQS doesn't encrypt backlogged messages."*
- *"Any encrypted message remains encrypted even if the encryption of its queue is
  disabled."*

So the messages exposed are exactly those **sent between the disable and the re-enable** —
not the backlog that was already there, and not anything written afterwards. The count comes
from the `AWS/SQS` CloudWatch metric `NumberOfMessagesSent` summed over that interval.

What SSE never covered, encrypted or not: *"SSE doesn't encrypt queue metadata (queue name
and attributes), message metadata (message ID, timestamp, and attributes), or per-queue
metrics."* A responder who re-enables encryption and calls the confidentiality question
closed has missed that message *attributes* — where applications routinely put correlation
IDs, tenant identifiers and routing keys — were never protected in the first place.

## An inverted signal, and a way to suppress it

While a queue is SSE-KMS encrypted, each data-key fetch produces a `kms:GenerateDataKey`
event in CloudTrail. When encryption is removed, **those events stop**. An abrupt end to KMS
activity against a queue's key, with no matching fall in `NumberOfMessagesSent`, is
independent corroboration that encryption went away — and it still works if the
`SetQueueAttributes` event itself was missed or aged out.

The same signal can be suppressed without disabling anything: `KmsDataKeyReusePeriodSeconds`
is documented as ranging from 60 to 86,400 seconds with a default of 300. Raising it to the
maximum cuts KMS calls from roughly one every five minutes to one a day, which is a
legitimate cost optimisation and also a straightforward way to make a queue's KMS telemetry
almost disappear. The KQL projects `MaxReusePeriod` for that reason.

## Data plane, and why "no evidence of reads" is not evidence

`ReceiveMessage`, `SendMessage` and `DeleteMessage` are SQS **data events**: off by default,
absent from CloudTrail Event history, and invisible to `lookup-events` forever unless an
advanced event selector on `AWS::SQS::Queue` was configured *before* the incident. So are
`ListQueues`, `GetQueueUrl`, `GetQueueAttributes` and `ListQueueTags` — meaning an actor can
enumerate every queue and read every queue's encryption configuration without producing one
management event. Even where data events are on, the body is redacted: AWS's published
example carries `requestParameters.messageBody` as `HIDDEN_DUE_TO_SECURITY_REASONS`.

## Response levers

- Re-enable encryption **explicitly** — `SqsManagedSseEnabled=true`, or a `KmsMasterKeyId`
  naming your CMK. Nothing re-enables itself, and clearing the wrong attribute a second time
  does not help.
- Check the queue policy in the same breath. If a wildcard principal was admitted while
  encryption was off, the queue was anonymously reachable and the policy is the other half
  of the incident (`../../sqs.collection.an-sqs-queue-attributes-were-changed/`).
- Deny `sqs:SetQueueAttributes` to everything but the deployment pipeline. The same denial
  protects the policy attributes, so one control covers both use cases.

## Error strings

SQS documents **two** distinct denial codes: `AccessDeniedException` and `NotAuthorized`
(both HTTP 400, both in the service's Common Errors). The bare `AccessDenied` form is what
IAM-evaluated denials produce across AWS and is widely observed, but it is **not** in SQS's
documented list — match all three and confirm against a real denied event in your own
account. Operation-specific codes for `SetQueueAttributes`: `InvalidAddress`,
`InvalidAttributeName`, `InvalidAttributeValue`, `InvalidSecurity`, `OverLimit`,
`QueueDoesNotExist`, `RequestThrottled`, `UnsupportedOperation`. A malformed KMS key
identifier surfaces as `InvalidAttributeValue`, not as a KMS error.

## GuardDuty

There is **no GuardDuty finding type specific to SQS encryption changes.** Do not build the
response on one existing.

## MITRE mapping

The source maps **T1565 / TA0040** (Data Manipulation, Impact). Nothing is manipulated and
nothing becomes unavailable, so that is wrong on the merits.

The mapping used here is **T1600 — Weaken Encryption**, whose canonical name describes the
act exactly, under **Defense Impairment (TA0112)**. State the caveat honestly: ATT&CK lists
T1600's platforms as **Network Devices**, so this is a mapping by intent rather than by
platform scope, and ATT&CK currently has no IaaS-scoped technique for "disable encryption at
rest on a cloud data store". **T1098** is carried as a genuine second mapping because the
mechanism is a resource-attribute manipulation, the same call the sibling directory covers.

The `impact` segment in this directory's name tracks the source's tactic label; the
Classification table carries the corrected tactic.

## Severity

**High**, against the source's **P4**. Two things happen at once: messages written from that
moment are stored unencrypted, and the control that rejects anonymous `SendMessage` and
`ReceiveMessage` is gone. The second is the one that gets undersold — it converts a queue
that required a credential into one that may not, and it does so through an event most
review processes read as a configuration tweak.

**MITRE:** the source maps this to `T1565 — Data Manipulation`, which is about altering data rather than removing its protection. `T1600 — Weaken Encryption` names the act, with `T1098` where the change is made through a policy grant. Verified live 2026-08-30.

**GuardDuty:** no finding type covers Amazon SQS. GuardDuty has no SQS resource type, so these rules are the only coverage for this technique.

**Files here:**

- `sigma_t1600.yml` — five documents: the disable itself carrying **both** paths (`high`),
  `CreateQueue` opting out of default encryption (`medium`), the CMK-to-AWS-managed-key
  downgrade (`medium`), a wildcard-policy base rule (`informational`, sequence component
  only), and a `temporal_ordered` correlation firing `high` on disable-then-open within
  thirty minutes.
- `kql_t1600.kql` — pairs each disable with the next policy opening on the same queue by the
  same principal and reports the sequence as one row, which no single Sigma rule can do.

Full response procedure is in `../PLAYBOOK.md`.
