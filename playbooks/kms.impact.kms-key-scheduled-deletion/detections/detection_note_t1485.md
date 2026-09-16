# Detection Note — T1485 / T1486 (KMS Key Scheduled for Deletion)

**Signal:** `ScheduleKeyDeletion` succeeding on a customer managed KMS key — with a second,
higher-confidence rule on an explicitly short waiting period, and a `temporal_ordered`
correlation on the disable-then-destroy sequence.

**This is the only KMS event with a deadline, and the deadline is the entire response.**
`ScheduleKeyDeletion` moves the key to `PendingDeletion` and starts a waiting period of 7–30
days, default 30. During the window the key is unusable; at the end of it AWS deletes the key,
its key material, all associated metadata and every alias that refers to it. AWS states the
consequence without hedging: *"After a KMS key is deleted, you can no longer decrypt the data
that was encrypted under that KMS key, which means that data becomes unrecoverable."* And it is
not recoverable by recreating the key — for symmetric encryption keys, *"You cannot create a new
symmetric encryption KMS key that can decrypt the ciphertexts of a deleted symmetric encryption
KMS key, even if you have the same key material. Metadata unique to each KMS key is
cryptographically bound to each symmetric ciphertext."*

`CancelKeyDeletion` reverses it at any point during the window and not one second after. That
asymmetry is why this rule carries **no principal allowlist**: the only thing it has to achieve
is reaching a human while the window is open, and a suppression that saves a page costs the
entire response opportunity.

**What the original rule got wrong** — it matches `eventName:"schedulekeydeletion"` in **lower
case**, which is not the form CloudTrail writes; AWS's published example carries
`"eventName": "ScheduleKeyDeletion"`. On a case-sensitive field match that returns nothing.
There is no success filter, so a principal denied on twenty keys produces the same alert volume
as one that scheduled twenty. And it never looks at `pendingWindowInDays` — the one field on the
event that carries intent — so a caller who deliberately chose the 7-day minimum is
indistinguishable from a decommission taking the 30-day default. Its **P3** rating is a
scheduling error for an event whose response window can be as short as a week.

## The recovery has an ordering constraint, and getting it wrong looks like success

Three verified facts that must be read together:

1. `CancelKeyDeletion` succeeds **only** on a key in `PendingDeletion`. On any other state it
   returns `KMSInvalidStateException: <key ARN> is not pending deletion`.
2. When it succeeds, *"the key state of the KMS key is `Disabled`. To enable the KMS key, use
   `EnableKey`."* The key is saved and still refuses every cryptographic operation.
3. `EnableKey` **fails** on a key in `PendingDeletion` with
   `KMSInvalidStateException: <key ARN> is pending deletion`.

So the order is fixed — cancel, then enable — and it cannot be reversed or collapsed. The
failure mode this produces is the dangerous one: a responder who cancels the deletion and then
verifies "the key is no longer pending deletion" gets a true result over a key that is still
`Disabled` and still down. Every state check in `../PLAYBOOK.md` therefore enumerates
`Enabled`, `Disabled` and `PendingDeletion` separately and treats "not `PendingDeletion`" as a
non-answer.

There is a fourth ordering hazard, and it is the reason §3's first step is not the cancel:
**`PutKeyPolicy` is permitted on a key that is pending deletion.** So is `GetKeyPolicy`,
`DescribeKey`, `DeleteAlias` and `ListKeys`. An actor can schedule the deletion and then rewrite
the key policy to remove your `kms:CancelKeyDeletion` permission — and because a KMS key policy,
unlike other AWS resource policies, grants nothing to the account implicitly, that is enough to
make the key unrecoverable while the clock runs. Confirm you can still administer the key before
you spend time on anything else.

## Field shapes, verified against AWS's published event examples

| Field | Shape |
|-------|-------|
| `requestParameters.keyId` | Caller-typed — bare key ID or key ARN |
| `requestParameters.pendingWindowInDays` | **Optional.** Absent when the caller took the default of 30. Never compute a deadline from it alone |
| `responseElements.keyId` | Normalised **key ARN**, flat |
| `responseElements.keyState` | `PendingDeletion`, or `PendingReplicaDeletion` for a multi-Region primary that still has replicas |
| `responseElements.deletionDate` | A **human-formatted string** — AWS's own example is `"Apr 12, 2021 18:58:30 PM"` — and **omitted entirely** for `PendingReplicaDeletion`. Not an ISO-8601 timestamp and not safe to arithmetic on |
| `resources[].ARN` | The key ARN, `resources[].type` = `AWS::KMS::Key` |

**The authoritative deadline is `KeyMetadata.DeletionDate` from a live `DescribeKey`**, not
anything on the event. AWS: *"the actual waiting period might be up to 24 hours longer than the
one you scheduled. To get the actual date and time when the KMS key will be deleted, use the
DescribeKey operation."*

## The multi-Region case that has no deadline at all

Scheduling deletion of a multi-Region **primary** key that still has replicas puts it in
`PendingReplicaDeletion` with **no** `deletionDate`, and AWS says *"This status can continue
indefinitely."* The 7–30 day clock starts only when the last replica is deleted. Two
consequences: a deadline board built on the primary's event shows nothing to work, and the
actor's real move is to schedule the replicas — each of which has its own independent key state
in its own Region. Sweep every Region.

## Blast radius is not in the event, and cannot be obtained afterwards

Nothing on a `ScheduleKeyDeletion` event names what is encrypted under the key, and AWS does not
store that: *"AWS KMS does not store this information and does not store any of the
ciphertexts."* Three partial sources exist, none complete:

- **`GetKeyLastUsage`** returns the last successful cryptographic operation and its CloudTrail
  event ID. An **empty** `KeyLastUsage` is not proof of non-use — compare `KeyCreationDate` with
  `TrackingStartDate`, because a key that predates tracking and shows nothing is *unknown*, not
  idle. Only successful cryptographic operations are tracked, with up to an hour of delay, and
  AWS's own guidance is *"Do not solely rely on last usage information when deleting unused
  keys… AWS CloudTrail remains the authoritative source."*
- **CloudTrail `GenerateDataKey` / `Decrypt`** — management events, on by default. For SSE-KMS
  on S3 the `GenerateDataKey` entry carries `requestParameters.encryptionContext` with an
  `aws:s3:arn` key naming the object, which is the nearest thing to an inventory that exists.
- **Key policy, grants and aliases** — who could have used it, which bounds the search.

Once the key is deleted, all three are gone with it and the question becomes permanently
unanswerable. This is the Tier-1 promotion criterion for this use case: the blast radius must be
collected *before* the deadline, and the evidence and the asset are destroyed together.

## Response levers

**Error strings:** `ScheduleKeyDeletion`: `DependencyTimeoutException`, `InvalidArnException`,
`KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, plus common
`AccessDeniedException` / `AccessDenied` (A7 — match both forms).

`CancelKeyDeletion` throws the same set, and its state rejection reads
`KMSInvalidStateException: <key ARN> is not pending deletion (or pending replica deletion).`

Consumer side, while the key is pending deletion, a cryptographic operation returns **either**
`DisabledException: <key ARN> is pending deletion (or pending replica deletion).` **or**
`KMSInvalidStateException: <key ARN> is pending deletion`. AWS's own documented CloudWatch alarm
for this condition keys on the message fragment `<Key ARN> is pending deletion` for exactly that
reason, and it explicitly does **not** fire on `CancelKeyDeletion`, `PutKeyPolicy` or `ListKeys`,
which are all permitted in that state.

**GuardDuty:** There is **no GuardDuty finding type specific to a KMS key being scheduled for deletion.** Do
not build the response on one existing.

**MITRE:** The source maps **T1486 / TA0040** — *Data Encrypted for Impact*. T1486 is live and the
extortion framing is the reason anyone alerts on this, but the adversary encrypts nothing: the
data was already encrypted, by you, and what the adversary destroys is the ability to reverse
that.

The corrected primary is **T1485 — Data Destruction** (Impact, TA0040), whose platform list
includes **IaaS** and whose description covers destroying infrastructure crucial to operations
in a cloud environment. Deleting the key that decrypts a dataset is the most efficient possible
form of destroying the dataset. **T1486** is kept as a second tag.

**T1490 — Inhibit System Recovery** is a genuine third reading and is deliberately not carried
as a tag, because it applies only in the case where the destroyed key protects the backups: an
encrypted snapshot whose KMS key is gone cannot be restored, so the same single call destroys
both the primary copy and the recovery path. Where that is true for your estate, add it.

The sibling `../../kms.impact.kms-key-disabled/` maps **T1489 Service Stop** instead, because
the disable destroys nothing.

**Severity:** **Critical**, against the source's **P3**. This is the only use case in the KMS set where doing
nothing for long enough produces permanent, unrecoverable data loss, and the minimum time in
which that can happen is seven days.

**Files here:**

- `sigma_t1485.yml` — four documents: the scheduled deletion itself (`high`, **no allowlist**,
  and the reasoning for that is in the rule's own comment), the explicit short-window variant
  (`high`), a `DisableKey` base rule (`informational`, present only because a correlation
  resolves base rules by `name:` within the same file), and a `temporal_ordered` correlation
  firing `high` on disable-then-destroy by one principal inside an hour.
- `kql_t1485.kql` — computes the remaining window per key, reports cancellations and the
  `EnableKey` that must follow them, and surfaces any `PutKeyPolicy` written after the schedule,
  which is what explains a cancel that will not succeed.

Full response procedure is in `../PLAYBOOK.md`.
