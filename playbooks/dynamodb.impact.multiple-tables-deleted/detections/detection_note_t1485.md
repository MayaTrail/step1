# Detection Note — T1485 / T1490 (DynamoDB Table Destruction, single and at volume)

**Signal:** `DeleteTable` succeeding for a principal that does not own table lifecycle — once,
or five or more distinct tables inside ten minutes.

**The source set has no rule for one table.** This is the sharpest defect in the whole
DynamoDB set and it is worth stating plainly: the only table-deletion alert is a unique-count
rule that fires above five *distinct* table names. One production table destroyed produces
nothing. Six ephemeral test tables torn down by a pipeline produce a P3. AWS's own guidance is
that "Deleting a table is an unrecoverable operation" — irreversibility does not scale with
count, and the difference between one table and fifty is the size of the recovery work-list,
not the severity of the loss. `sigma_t1485.yml`'s first document is therefore per-event and
`high`; the volume case survives as a correlation at its own priority.

## Two threshold defects, both in the same direction

The alert's own description says **"More than 5 in 10 minutes"**. Its configured window is
**one minute**. Two separate ways to miss the technique follow:

- An actor who paces deletions at five tables per minute never trips it, because no single
  one-minute window ever contains six distinct names.
- The count is a *maximum*, so the rule fires at six. An actor who deletes exactly five falls
  through — the classic case of a threshold that does not fire on the baseline its own prose
  states (rule F6).

The correlation ships with `gte: 5` over a `10m` span, which is what the source's description
describes and its configuration does not. There is no emulation behind that number and none is
claimed: the tuning basis is the source's own stated intent, and a deployer who knows their
account should re-baseline. If engineers routinely destroy five-table development stacks under
their own identity, raise the threshold rather than mute the rule.

## What survives a deletion, and what does not

The `DeleteTable` API page and the Developer Guide together are explicit:

- The table goes `ACTIVE` → `DELETING`, and "when the `DeleteTable` operation concludes, the
  table no longer exists in DynamoDB".
- "When you delete a table, any indexes on that table are also deleted."
- "If you have DynamoDB Streams enabled on the table, then the corresponding stream on that
  table goes into the `DISABLED` state, and the stream is automatically deleted after 24
  hours." So the change-data-capture record of what the table *contained* has its own 24-hour
  clock, independent of your incident timeline.
- "DynamoDB might continue to accept data read and write operations, such as `GetItem` and
  `PutItem`, on a table in the `DELETING` state until the table deletion is complete" — so
  application writes keep succeeding briefly against a table that is being destroyed, and the
  application-side symptom is delayed.
- "If table is already in the `DELETING` state, no error is returned" — a repeat call is
  silent, which is why the correlation counts **distinct table names** and not events.

Recovery exists only if it was arranged in advance. If PITR was enabled, DynamoDB
"automatically creates a backup snapshot called a *system backup* and retains it for 35 days",
named `{{table-name}}$DeletedTableBackup`. That is a snapshot of the table immediately before
deletion — **a single instant, not the continuous range PITR offered while the table lived**.
If PITR was off and no on-demand backup exists, the data is gone. `ListBackups` defaults to
`USER` backups and **hides** the system snapshot; a check that does not pass backup type `ALL`
reports "no backups" over the only recovery point that exists.

Deletion protection — the property that would have refused the call outright — is **off by
default** on every table, "including global replicas, and tables restored from backups". The
deliberate-downgrade case has its own use case,
`../../dynamodb.stealth.deletion-protection-disabled/`, whose `temporal_ordered` correlation is
the other half of this one.

## The size of the loss is in the event, and the source rule never reads it

`DeleteTable` returns `responseElements.tableDescription` — a **wrapper object**, matching the
API's `TableDescription` response element, not a flat path — carrying `itemCount` and
`tableSizeBytes`. After the deletion there is nothing left to measure, so this is the only
surviving record of how much was destroyed. `itemCount` is an approximate figure DynamoDB
refreshes periodically rather than a live count; report it as approximate and never as an exact
loss. `kql_t1485.kql` sums both across the burst.

`requestParameters.tableName` may be a bare name **or a full table ARN** — the API documents
"You can also provide the Amazon Resource Name (ARN) of the table in this parameter" and caps
the field at 1024 characters for that reason. A distinct-count over the raw field therefore
counts one table twice if the actor mixed forms. Both the KQL and the playbook's queries
normalise to the bare name first.

## Denials are not deletions

`DeleteTable` denials must be counted apart from successes. A principal probing its boundary
across twenty tables produces the same event volume as twenty real destructions, and conflating
them puts reconnaissance and an outage in the same bucket (rule B6). Both the primary rule and
the base rule feeding the correlations carry `errorCode: null` for this reason, and the KQL
reports `DeniedAttempts` in its own column.

## Response levers

**Error strings:** `DeleteTable` throws exactly four operation-specific errors: `InternalServerError` (500),
`LimitExceededException` (400), `ResourceInUseException` (400) and `ResourceNotFoundException`
(400). Note that `ResourceInUseException` covers a table in `CREATING` or `UPDATING` state, and
that a table already in `DELETING` returns **no error at all**. On top of those, the DynamoDB
**Common Errors** set applies: `AccessDeniedException` (403), `NotAuthorized` (401),
`ExpiredTokenException` (403), `IncompleteSignature` (403), `InternalFailure` (500),
`MalformedHttpRequestException` (400), `OptInRequired` (403), `RequestAbortedException` (400),
`RequestEntityTooLargeException` (413), `RequestTimeoutException` (408), `ServiceUnavailable`
(503), `ThrottlingException` (400), `UnknownOperationException` (404),
`UnrecognizedClientException` (403), `ValidationError` (400). DynamoDB documents
**`ValidationError`**, not `ValidationException`, and documents **two** denial forms —
`AccessDeniedException` and `NotAuthorized`. Match both, and confirm against a real denied
event. AWS documents the *behaviour* of deletion protection but names **no error** for a
`DeleteTable` refused because of it — do not branch a script on one.

**GuardDuty:** There is **no GuardDuty finding type specific to DynamoDB table deletion.** Identity-side
findings such as `Impact:IAMUser/AnomalousBehavior` may fire on the principal rather than on
the table. Do not build the response on one existing.

**MITRE:** The source rule maps this to **T1490 (Inhibit System Recovery)**. That is the right technique
for the wrong event. T1490 covers destroying the mechanisms that make recovery possible —
backups, snapshots, shadow copies — which is `../../dynamodb.impact.backup-was-deleted/`, not
this. Deleting the table destroys the **primary data**, and the canonical mapping for that is
**T1485 (Data Destruction)**, whose platform list includes IaaS. T1490 is carried here as a
genuine secondary, but only on the `temporal_ordered` correlation, where a backup deletion
actually precedes the table deletion — because in that sequence the recovery mechanism really
was the target first.

**Severity:** **High** for a single non-pipeline deletion and **High** for the volume case, rising to
**Critical** when a backup deletion precedes it. The source rates the volume rule **P3** and
ships nothing at all for a single deletion. P3 is defensible for a burst of ephemeral tables in
a development account and is too low everywhere else; the absence of a per-event rule is not
defensible anywhere.

**Files here:**

- `sigma_t1485.yml` — four documents: the non-pipeline table deletion (`high`), a
  `DeleteBackup` base rule (`informational`, sequence component only, success-filtered), a
  `value_count` correlation firing `high` at five or more **distinct tables** in ten minutes by
  one principal, and a `temporal_ordered` correlation firing `critical` on backup-then-table
  deletion within 24 hours.
- `kql_t1485.kql` — sums the destroyed `itemCount` and `tableSizeBytes` from each deletion's
  response, expresses the volume condition as a rate rather than a boolean, folds in restores
  by the same principal (a restore after a deletion is a copy until proven a recovery), and
  separates denied attempts from successful destructions.

Full response procedure is in `../PLAYBOOK.md`.
