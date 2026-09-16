# Detection Note — T1485 / T1565.001 (Data Destruction / Stored Data Manipulation)

**Signal:** the control-plane preconditions for permanent data loss — because the item-level events
themselves are usually not being collected.

## Both source rules are inert in a default account

AWS splits DynamoDB's CloudTrail coverage explicitly. `DeleteItem`, `BatchWriteItem`, `UpdateItem`
and `TransactWriteItems` are **data-plane** events: *"you must enable logging of data plane API
activity in CloudTrail."* Data events are off by default and billable.

Neither source rule says so. That matters more than a normal gap, because it changes what "no
results" means: a responder querying for item deletions in a default account gets nothing, and
nothing is indistinguishable from a clean result.

## So the detections lead with the control plane

These are logged by default, fire in every account, and are the preconditions that decide whether
destruction is recoverable:

| Event | Why it matters |
|---|---|
| `UpdateContinuousBackups` disabling PITR | No point-in-time restore |
| `UpdateTable` removing deletion protection | The table itself can be deleted |
| `UpdateTimeToLive` | Bulk deletion on a schedule — see below |

The item rules ship alongside, rated lower, and state their precondition plainly.

## TTL deletions are never logged at all

> **DynamoDB Time to Live data plane actions are not logged by CloudTrail**

Not as a data event, not as a management event, not even with data events fully enabled. An actor
who sets a short TTL attribute causes DynamoDB to delete items in bulk on its own schedule, and
**no record of any deletion is ever produced**.

`UpdateTimeToLive` *is* logged. So the configuration change is the only opportunity, and the
response has to read the item population that would expire rather than wait for deletions.

## PartiQL bypasses any item-level rule

`ExecuteStatement`, `BatchExecuteStatement` and `ExecuteTransaction` reach the same writes under
different event names. AWS states CloudTrail captures calls *"using both PartiQL and the classic
API"*. A `DELETE FROM` through `ExecuteStatement` matches neither source rule and does exactly what
`DeleteItem` does.

## Response levers

**Check whether data events are enabled before believing a negative.**
`get-event-selectors` on the trail settles it, and it changes how the whole incident is written up.

**PITR is the recovery, and it must have been on beforehand.**
`RestoreTableToPointInTime` restores to any second in the retention window — but only if continuous
backups were enabled before the incident, which is why disabling them is rated critical.

**DynamoDB Streams is often the only record of previous values.** For a modification, CloudTrail
records that `UpdateItem` happened, not what the item held before. Streams carries `OLD_IMAGE` if the
view type was configured for it — and that decision, like PITR, was made long before.

**The cost objection to data events has a documented answer.** AWS notes internal `GetRecords` calls
inflate volume and gives the remedy: the *Exclude AWS service-initiated events* selector template, or
an advanced selector with `userIdentity.arn` `NotStartsWith` `AWSServiceRoleFor`.

**MITRE:** the source maps both rules to `T1505 — Server Software Component` under Persistence — a
technique about web shells and server modules, not about writing rows. `T1485 — Data Destruction`
and `T1565.001 — Stored Data Manipulation` are correct. Verified live 2026-08-30.

**GuardDuty:** no finding type covers DynamoDB. `Impact:S3/AnomalousBehavior.Delete` is the nearest
analogue for a different service and has no DynamoDB equivalent, so these rules are the only
coverage.

**Files here:**
- `sigma_t1485.yml` — five documents: `dynamodb_recovery_protection_disabled` (critical) and
  `dynamodb_ttl_configured` (high) are control-plane and fire in every account;
  `dynamodb_items_destroyed` and `dynamodb_items_modified` (medium) require data events and say so,
  and both include the PartiQL event names; plus a `temporal_ordered` correlation for
  recovery-removed-then-destroyed (critical).
- `kql_t1485.kql` — leads with the control-plane signals, separates PartiQL calls, and reports a
  `DataPlaneSeen` count so a reviewer can confirm from their own account whether the item rules
  could ever fire.

Full response procedure is in `../PLAYBOOK.md`.
