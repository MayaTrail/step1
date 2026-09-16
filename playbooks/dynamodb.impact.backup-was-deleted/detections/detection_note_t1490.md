# Detection Note — T1490 (DynamoDB Backup Deleted)

**Signal:** `DeleteBackup` succeeding for a principal that does not own backup lifecycle and is
not AWS Backup expiring a recovery point on schedule.

**The source rule covers the least destructive of the three ways to remove recovery.** That is
the finding, and it matters more than any defect in the rule's construction. Deleting one
on-demand backup removes one recovery point. The two paths the rule does not cover remove all
of them at once, and **neither produces a `DeleteBackup` event**.

## The PITR gap

Point-in-time recovery is the real backup story for DynamoDB, and nothing in the source set
touches it.

1. **`UpdateContinuousBackups` with `PointInTimeRecoveryEnabled: false`.** Every restorable
   instant in the window disappears in one call. Nothing is "deleted" in the sense the source
   rule understands, so no alert fires anywhere in the set.
2. **`UpdateContinuousBackups` with a reduced `RecoveryPeriodInDays`.** AWS: *"If you change
   the recovery period and decrease it to a value lower than previously set, your
   `EarliestRestorePoint` will immediately decrease to match your recovery period, and any
   continuous backups that fall outside of the new set value will not be recoverable."* The
   parameter is optional, ranges 1–35 and **defaults to 35**. So `RecoveryPeriodInDays: 1`
   destroys up to 34 days of recovery capability immediately — and PITR still reports
   `ENABLED` on every dashboard and in every compliance check that asks only whether PITR is
   on. This is the quietest destructive operation in DynamoDB.

`sigma_t1490.yml`'s third document covers both, **with a caveat that must be read before
deploying it**: AWS's DynamoDB CloudTrail page enumerates the control-plane operations "logged
by default" and `UpdateContinuousBackups` is **not on that list**, even though
`DescribeContinuousBackups` is. That is very probably a documentation omission — it is a
control-plane API, and there is no plausible mechanism by which its read-side sibling would be
logged and it would not — but "very probably" is not verification. Run
`aws dynamodb update-continuous-backups` against a throwaway table and confirm the event
appears in your own trail before relying on the rule. If it does not appear, the gap is worse
than described here: PITR could be turned off with no management-event record at all, and the
only detection left would be a periodic `DescribeContinuousBackups` sweep.

## The case the request side cannot distinguish

`DeleteBackup` takes exactly one request parameter, `BackupArn`. So from the request alone,
deleting a routine nightly backup and deleting the last remaining copy of a destroyed table
look identical.

When a table with PITR enabled is deleted, DynamoDB "automatically creates a backup snapshot
called a *system backup* and retains it for 35 days", named `{{table-name}}$DeletedTableBackup`.
That snapshot is the **only remaining copy of a table that no longer exists**. Deleting it
makes an earlier destruction permanent, and it is the highest-severity case in this playbook.

The response side can tell them apart: `DeleteBackup` returns a `BackupDescription` wrapper
object containing `BackupDetails` with `BackupName`, `BackupType`, `BackupSizeBytes`,
`BackupStatus` and both timestamps, plus `SourceTableDetails`. **AWS publishes no `DeleteBackup`
CloudTrail example**, so the event paths in the shipped rules are derived from that documented
API response shape plus CloudTrail's usual lowercasing of the leading character — they are not
read off a published event. That uncertainty is why the second rule ORs `backupType == SYSTEM`
against a `backupName` containing the documented suffix rather than ANDing them: with two
derived paths, an AND means one wrong path silently stops the rule firing on the worst case in
the file (rule B4).

## No success filter

The source rule excludes service-initiated deletions and then matches everything else,
**including failures**. A principal denied on twenty backups raises the same twenty alerts as a
real destruction of twenty backups. Operationally the denial case is often the more urgent
finding — it means someone is probing a boundary — but it is not a destruction, and putting the
two in one bucket makes any volume judgement meaningless (rule B6). Every rule here carries
`errorCode: null`, and `kql_t1490.kql` reports `DeniedAttempts` in its own column.

## What the source rule gets right

It excludes AWS Backup's own lifecycle expiries on **both** the user agent and
`userIdentity.invokedBy`, ANDed. That is the correct shape. An AND makes an exclusion
*narrower*, so if only one of the two fields is populated the event is still alerted on — an
exclusion that fails in the direction of more alerts rather than fewer. The shipped rule keys
on `userIdentity.invokedBy` alone, which is the field AWS populates for service-initiated
calls; a user agent can be set to anything.

## Casing

The source rule matches `eventName:"deletebackup"` in lower case, while its siblings in the
same set match `DeleteTable`, `UpdateTable`, `Scan` and `DeleteItem` in the API's own
PascalCase. CloudTrail's `eventName` for this operation is **`DeleteBackup`**. Whether the
lower-case form matches at all is a property of the search platform's index mapping — an
analysed text field lowercases at index time and both work, a keyword field does not and one of
the two casings in the same rule set is dead. Which one is dead is not a property of the
technique, so a port of these rules to any other engine must normalise casing first or roughly
half of them will silently stop matching. The shipped Sigma uses the API's casing throughout.

## Response levers

**Error strings:** `DeleteBackup` throws `BackupInUseException` (400) — "There is another ongoing conflicting
backup control plane operation on the table. The backup is either being created, deleted or
restored to a table" — `BackupNotFoundException` (400), `InternalServerError` (500) and
`LimitExceededException` (400). `UpdateContinuousBackups` throws
`ContinuousBackupsUnavailableException` (400), `InternalServerError` (500) and
`TableNotFoundException` (400); note that `InvalidRestoreTimeException` and
`PointInTimeRecoveryUnavailableException` belong to `RestoreTableToPointInTime` and **not** to
`UpdateContinuousBackups`. On top of those, the DynamoDB **Common Errors** set applies:
`AccessDeniedException` (403), `NotAuthorized` (401), `ExpiredTokenException` (403),
`IncompleteSignature` (403), `InternalFailure` (500), `MalformedHttpRequestException` (400),
`OptInRequired` (403), `RequestAbortedException` (400), `RequestEntityTooLargeException` (413),
`RequestTimeoutException` (408), `ServiceUnavailable` (503), `ThrottlingException` (400),
`UnknownOperationException` (404), `UnrecognizedClientException` (403) and `ValidationError`
(400). DynamoDB documents `ValidationError`, **not** `ValidationException`, and documents two
denial forms — match both and confirm against a real denied event.

**GuardDuty:** There is **no GuardDuty finding type specific to DynamoDB backup deletion or PITR
modification.** Identity-side findings such as `Impact:IAMUser/AnomalousBehavior` may fire on
the principal rather than on the resource. Do not build the response on one existing.

**MITRE:** The source rule maps this to **T1490 (Inhibit System Recovery)** under Impact, and that is
**correct** — one of the few mappings in this set that is. Destroying backups and disabling
point-in-time recovery is precisely what T1490 describes. It is worth saying so explicitly,
because the sibling rules in the same set map table deletion to T1490 (where T1485 belongs) and
item operations to a SQL-stored-procedure technique that has no DynamoDB analogue at all. The
tactic label is right too.

**Severity:** **High** for a non-pipeline backup deletion, **Critical** for the destruction of a `SYSTEM`
`$DeletedTableBackup`, and **High** for a PITR disable or window reduction. The source rates it
**P3**. That is too low: a backup deletion is not itself damaging, which is exactly why it is
the last moment at which the incident is still fully recoverable. Triaging it as a routine
change spends that window.

**Files here:**

- `sigma_t1490.yml` — four documents: the non-pipeline backup deletion (`high`), destruction of
  a `SYSTEM` `$DeletedTableBackup` (`critical`), the PITR disable-or-shorten rule (`high`, with
  the verification caveat above in its own comment block), and an `event_count` correlation
  firing `high` at three or more deletions in ten minutes by one principal.
- `kql_t1490.kql` — puts all three recovery-removal paths in one result set per principal, and
  carries the `DeleteTable` that followed, so "one backup pruned" and "PITR turned off an hour
  later" appear as one row instead of two unrelated alerts.

Related: `../../dynamodb.impact.multiple-tables-deleted/` is the destruction this prepares for,
and its Sigma carries the `temporal_ordered` backup-then-table correlation.
`../../dynamodb.stealth.deletion-protection-disabled/` is the other precondition.

Full response procedure is in `../PLAYBOOK.md`.
