# Detection Note — T1685 / T1485 (DynamoDB Deletion Protection Disabled)

**Signal:** an `UpdateTable` call carrying `DeletionProtectionEnabled: false`, and the
`DeleteTable` that follows it.

**This is the one source rule in the DynamoDB set that inspects a parameter.** Its siblings
match an event name and stop. This one reaches into `requestParameters` for the field that
actually distinguishes the change, and that is why its defects are small and specific rather
than structural. Credit where it is due — and then fix the three things it still gets wrong.

## The event name cannot tell you what changed

`DeletionProtectionEnabled` is an optional **Boolean parameter of `UpdateTable`**, not an API
of its own — verified against the DynamoDB API Reference for `UpdateTable`, which lists it
alongside `ProvisionedThroughput`, `BillingMode`, `GlobalSecondaryIndexUpdates`,
`StreamSpecification`, `SSESpecification`, `ReplicaUpdates`, `TableClass`,
`OnDemandThroughput` and `WarmThroughput`. Every one of those emits the identical
`eventName: UpdateTable`. So a rule matching the event name fires on every autoscaling
adjustment in the account — AWS documents that "after auto scaling triggers, the `UpdateTable`
API is invoked" — and the parameter is the entire discriminator. The sibling use case
`../../dynamodb.defense-evasion.table-configuration-modified/` is exactly the rule that
does *not* read the parameter, and its trigger table is the demonstration of what that costs.

**Type trap.** The parameter is documented `Type: Boolean`. CloudTrail therefore carries a
JSON boolean `false`, not the string `"false"`. The source rule's query compares against a
quoted value, which is harmless in a search dialect that stringifies at index time and is
**silently wrong** in `jq`, in a JSON-typed Sigma backend, or in any reimplementation:
`.requestParameters.deletionProtectionEnabled == "false"` never matches. The shipped rule uses
a YAML boolean and the KQL uses `tobool()`, which accepts both forms.

## Why the disable is a precondition and not the incident

Deletion protection is **off by default** for every table, and the Developer Guide is explicit
that this "includes global replicas, and tables restored from backups". Two consequences the
source rule does not carry:

1. **The rule can only ever fire for tables someone deliberately protected.** Its silence
   says nothing about the tables that were never protected — which, in most accounts, is
   nearly all of them. A quiet week is not an all-clear.
2. **Turning it off changes nothing by itself.** No data moves, nothing becomes readable. The
   damage is the `DeleteTable` that follows, and the Developer Guide states plainly that
   "Deleting a table is an unrecoverable operation." The `temporal_ordered` correlation in
   `sigma_t1685.yml` is the rule that names the actual incident, and it fires `critical`.

AWS documents the *behaviour* of deletion protection — "When deletion protection is enabled
for a table, it cannot be deleted by anyone" — but **names no error code** for the refusal.
The `DeleteTable` page lists only `InternalServerError`, `LimitExceededException`,
`ResourceInUseException` and `ResourceNotFoundException`, and none of their descriptions
mention deletion protection. Do not branch a script on a documented exception name here;
there isn't one. Confirm against a real refused call in your own account.

## Field shape

AWS's published `UpdateTable` CloudTrail example carries **no `tableName` in
`requestParameters`** — the request object in that example is just
`{"provisionedThroughput": {...}}`, and the table is named only at
`responseElements.tableDescription.tableName`, nested under a wrapper object matching the
API's `TableDescription` response element. `DeleteTable` does carry
`requestParameters.tableName`, and returns `responseElements.tableDescription` with
`itemCount` and `tableSizeBytes` — the size of the loss, in the event itself, though
`itemCount` is an approximate figure DynamoDB refreshes periodically rather than a live count.

Because the two events name the table through different paths, the Sigma correlation groups
by `userIdentity.arn` and not by table. `kql_t1685.kql` does the join properly, normalising
both sides and additionally handling the case where `tableName` was supplied as a full ARN —
the API documents that "You can also provide the Amazon Resource Name (ARN) of the table in
this parameter", which is why an equality test against a bare name drops those calls.

## Recovery, and what survives a deletion

If PITR was enabled at the moment of deletion, DynamoDB "automatically creates a backup
snapshot called a *system backup* and retains it for 35 days", named
`{{table-name}}$DeletedTableBackup`. That is a snapshot of the table immediately before
deletion — a single point in time, not the continuous range PITR offered while the table
lived. `ListBackups` defaults to `USER` backups; a check that does not pass backup type `ALL`
reports "no backups" over a live recovery point. Any restore "always restores to a new
table", and the restored table does not carry over auto scaling policies, IAM policies,
CloudWatch metrics and alarms, tags, stream settings or TTL settings — nor deletion
protection, which is off on restored tables by default. Recovery is therefore not complete
when the table exists again.

## Response levers

**Error strings:** `UpdateTable` throws `InternalServerError` (500), `LimitExceededException` (400),
`ResourceInUseException` (400) and `ResourceNotFoundException` (400). `DeleteTable` throws the
same four. On top of those, the DynamoDB **Common Errors** set applies to both:
`AccessDeniedException` (403), `NotAuthorized` (401), `ExpiredTokenException` (403),
`IncompleteSignature` (403), `InternalFailure` (500), `MalformedHttpRequestException` (400),
`OptInRequired` (403), `RequestAbortedException` (400), `RequestEntityTooLargeException` (413),
`RequestTimeoutException` (408), `ServiceUnavailable` (503), `ThrottlingException` (400),
`UnknownOperationException` (404), `UnrecognizedClientException` (403) and `ValidationError`
(400). Note DynamoDB documents **`ValidationError`**, not `ValidationException`, and both
`AccessDeniedException` and `NotAuthorized` are documented denial forms — match both, and
confirm against a real denied event.

**GuardDuty:** There is **no GuardDuty finding type specific to DynamoDB deletion protection or table
deletion.** Identity-side findings such as `Impact:IAMUser/AnomalousBehavior` may fire on the
principal rather than on the table. Do not build the response on one existing.

**MITRE:** The extract in `../_source/original_rules.yml` quotes the source's label verbatim, per the
house convention that a de-identified extract records what the source actually said.

**T1685** is the defensible successor: deletion protection is a protective control on the
resource, and removing it is disabling a protective mechanism. It is not a perfect fit —
T1685 is written around security *tooling* — so the primary reading is carried alongside
**T1485 (Data Destruction)**, which is what the disable is *for*, and which is the mapping the
`critical` correlation carries. The source's tactic label is right; the technique is stale.

**Severity:** **High** for the disable alone, **Critical** for the disable-then-delete pair. The source
rates it **P3**. That is too low for a change whose only purpose is to make an unrecoverable
operation possible: deletion protection exists precisely because the operation it guards
cannot be undone, and a table that was explicitly protected is by definition one someone
judged worth protecting.

**Files here:**

- `sigma_t1685.yml` — three documents: the deletion-protection disable (`high`), a
  `DeleteTable` base rule (`informational`, sequence component only, success-filtered so a
  denied deletion cannot compose), and a `temporal_ordered` correlation firing `critical` on
  disable-then-delete by the same principal within 24 hours.
- `kql_t1685.kql` — joins the disable to the deletion **on the table name**, which the Sigma
  correlation cannot do, normalises ARN-form table names, reports the destroyed `itemCount`
  and `tableSizeBytes` from the deletion's response, and separates denied attempts from
  successful changes.

Full response procedure is in `../PLAYBOOK.md`.
