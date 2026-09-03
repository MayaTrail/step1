# IR Playbook: DynamoDB Backup Deleted — Removing the Way Back Before the Data Goes via `dynamodb:DeleteBackup`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Recovery capability destruction (a restore point is removed, converting a future table deletion from recoverable to permanent) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** for a non-pipeline deletion, **Critical** when the backup destroyed is the `SYSTEM` `$DeletedTableBackup` of a table that no longer exists. The source rates it **P3**. A backup deletion is not itself damaging — which is precisely why it is the last moment at which the incident is still fully recoverable, and triaging it as a routine change spends that window |
| MITRE Tactics | Impact (TA0040) |
| MITRE Techniques | T1490 — verified live 2026-08-29, and the source rule's own mapping, which is **correct** |
| Services in Scope | DynamoDB, AWS Backup, CloudTrail (management), CloudWatch (`AWS/DynamoDB`), IAM, Organizations (SCP), and every table whose recovery posture the deletions touched |

**What the technique does:** the actor calls `dynamodb:DeleteBackup` with a `BackupArn` — the only request
parameter the API takes. One recovery point disappears. Nothing in production changes, no
application errors, and no data is lost yet, which is exactly why it is easy to wave through.
Working through a table's recovery points one call at a time converts a future `DeleteTable`
from an inconvenience into a permanent loss, because AWS's position on the follow-up is
unambiguous: *"Deleting a table is an unrecoverable operation."* The sharpest variant deletes a
`SYSTEM` backup named `<table>$DeletedTableBackup` — the snapshot DynamoDB creates automatically
when a PITR-enabled table is deleted, retained 35 days. That snapshot is the last copy of a
table that no longer exists, and deleting it finishes a destruction that had already happened.

**Detection thesis.** The discriminator is **the calling principal together with what survives
the deletion** — a `DeleteBackup` is only meaningful relative to the recovery points still
standing, and that state is not in the event. The source rule excludes AWS Backup's own
scheduled expiries correctly and then stops: it applies no success filter, so a principal
*denied* on twenty backups raises the same twenty alerts as a real destruction of twenty; and it
covers the least destructive of the three ways to remove recovery, leaving both
`UpdateContinuousBackups` paths entirely uncovered.

> The destruction this prepares for is `../dynamodb.impact.multiple-tables-deleted/`, whose
> Sigma carries the backup-then-table correlation. The other precondition is
> `../dynamodb.stealth.deletion-protection-disabled/`. The enumeration that precedes both is
> `../dynamodb.impact.backup-was-listed/`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing DynamoDB **management** events. `DeleteBackup`,
  `CreateBackup`, `ListBackups`, `DescribeBackup`, `DescribeContinuousBackups`, `DeleteTable`,
  `RestoreTableFromBackup` and `RestoreTableToPointInTime` are logged **by default** — AWS's
  DynamoDB CloudTrail page enumerates them as control-plane events
- **`UpdateContinuousBackups` is absent from that enumerated list**, while
  `DescribeContinuousBackups` is present. It is a control-plane API and the omission is very
  probably a documentation gap, but it was **not verifiable against primary documentation**.
  Run `aws dynamodb update-continuous-backups` against a throwaway table and confirm the event
  reaches your trail before treating its silence as evidence that PITR was untouched
- **`DeleteBackup` field shape, derived rather than observed.** The request carries exactly one
  parameter, `backupArn`. The response is a `BackupDescription` **wrapper object** containing
  `BackupDetails` (`BackupArn`, `BackupName`, `BackupType`, `BackupSizeBytes`, `BackupStatus`,
  `BackupCreationDateTime`, `BackupExpiryDateTime`) and `SourceTableDetails`. AWS publishes **no
  `DeleteBackup` CloudTrail example**, so these event paths come from the documented API
  response shape plus CloudTrail's usual lowercasing of the leading character — confirm them
  against a real event before depending on the nested paths
- A standing, dated inventory of recovery points per table: `ListBackups` with **backup type
  `ALL`** (the default is `USER` and hides every `SYSTEM` snapshot) and
  `DescribeContinuousBackups` for PITR status, `RecoveryPeriodInDays` and
  `EarliestRestorableDateTime`. The log records what was removed; only this records what remains
- A baseline of which principals own backup lifecycle, and the AWS Backup service role, so
  scheduled expiry can be told apart from deletion
- `AWS/DynamoDB` CloudWatch metrics retained. These do not carry recovery state, but
  `ConsumedReadCapacityUnits` and `ConsumedWriteCapacityUnits` per `TableName` establish whether
  a table whose backups were deleted is still in production use — which decides urgency

**Alerting (must be pre-configured)**
- **`DeleteBackup` succeeding for a principal outside the backup-lifecycle allowlist and not invoked by AWS Backup → P0**
- **`DeleteBackup` succeeding on a `SYSTEM` backup or one named `$DeletedTableBackup` — the last copy of an already-deleted table → P0**
- **`UpdateContinuousBackups` turning PITR off, or setting `recoveryPeriodInDays` below the 35-day default → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteBackup` succeeding for a principal outside the backup-lifecycle allowlist and not invoked by AWS Backup | CloudTrail (management) | T1490 |
| P0 | `DeleteBackup` succeeding on a `SYSTEM` backup or one named `$DeletedTableBackup` — the last copy of an already-deleted table | CloudTrail (management) | T1490 |
| P1 | `UpdateContinuousBackups` turning PITR off, or setting `recoveryPeriodInDays` below the 35-day default | CloudTrail (management) — **subject to the logging caveat in §1** | T1490 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Three or more `DeleteBackup` successes by one non-pipeline principal within ten minutes | CloudTrail (management) | T1490 |
| P2 | `DeleteBackup` denied repeatedly (`AccessDeniedException` / `NotAuthorized` / `BackupNotFoundException`) — boundary mapping, not destruction | CloudTrail (management) | T1490 |
| P3 | A table reporting `PointInTimeRecoveryStatus: DISABLED` with zero backups in a periodic sweep — the state, regardless of which event produced it | `DescribeContinuousBackups` + `ListBackups` | T1490 |

### Detection Rule Quality Notes

The source rule excludes AWS Backup's scheduled expiries correctly, and then stops before
everything that matters: it never filters failures, never looks at who called, and covers the
least destructive of the three ways to remove recovery.

| Issue | Impact | Correction |
|-------|--------|-----------|
| No success filter at all | A principal **denied** on twenty backups raises the same twenty alerts as a real destruction of twenty. The denial case is often the more urgent finding, but it is not a destruction, and mixing them makes any volume judgement meaningless | `errorCode: null` on the alerting rule; report denials in their own column |
| No principal check | Fires identically for an operator pruning last quarter's backups and for a compromised session clearing a table's recovery points before destroying it | Allowlist the backup-lifecycle roles and the AWS Backup service role; alert on everyone else |
| Nothing distinguishes a `SYSTEM` `$DeletedTableBackup` from a routine nightly backup | The request carries only a `BackupArn`, so the two look identical. Deleting the system snapshot destroys **the last copy of a table that no longer exists**, and it is triaged as a P3 alongside ordinary pruning | Match `backupType: SYSTEM` **or** the documented `$DeletedTableBackup` name suffix, at `critical` |
| **`UpdateContinuousBackups` is not covered anywhere in the set** | Disabling PITR removes every restorable instant in one call and deletes no backup, so nothing fires. Reducing `recoveryPeriodInDays` from 35 to 1 destroys 34 days of recovery **while PITR still reports `ENABLED`** — passing every compliance check that asks only whether PITR is on | Ship the rule, with the logging caveat from §1 stated in the rule's own comment |
| `eventName` matched in lower case while sibling rules use the API's PascalCase | Whether the lower-case form matches is a property of the search platform's index mapping, not of the technique. On a case-sensitive field one casing in the same rule set is dead, and a port to another engine silently drops roughly half the rules | Use the API's casing (`DeleteBackup`) and normalise before porting |
| P3 priority | The one moment at which the incident is still fully recoverable is triaged as a routine change | P0 for a non-pipeline deletion; `critical` for the system-backup case |

**Recommended detection — a backup destroyed by a principal outside the lifecycle pipeline.**

```yaml
# DynamoDB Backup Deleted (T1490)
#
# THE SOURCE RULE COVERS THE LEAST DESTRUCTIVE OF THE THREE WAYS TO REMOVE RECOVERY. Deleting
# one on-demand backup removes one recovery point. The two it does not cover remove all of them
# at once, and neither produces a `DeleteBackup` event:
#
#   1. UpdateContinuousBackups with PointInTimeRecoveryEnabled:false turns PITR off. Every
#      restorable instant in the window is gone in one call.
#   2. UpdateContinuousBackups with a reduced RecoveryPeriodInDays. AWS: "If you change the
#      recovery period and decrease it to a value lower than previously set, your
#      EarliestRestorePoint will immediately decrease to match your recovery period, and any
#      continuous backups that fall outside of the new set value will not be recoverable."
#      The range is 1-35 days and the default is 35, so a single parameter change can destroy
#      34 days of recovery capability while PITR still reads as ENABLED on every dashboard.
#
# Rule 3 below covers both, WITH A CAVEAT STATED IN ITS OWN COMMENT that must be read before
# deploying it.
#
# NO SUCCESS FILTER. The source rule excludes service-initiated deletions and then matches
# everything else including failures, so a principal DENIED on twenty backups raises the same
# twenty alerts as a real destruction of twenty backups. The denial case is the more urgent
# finding operationally - it means someone is probing - but it is not a destruction, and
# putting the two in one bucket makes the volume meaningless.
#
# WHAT THE SOURCE RULE GETS RIGHT, AND IT IS NOT NOTHING. It excludes AWS Backup's own
# service-initiated deletions on BOTH the user agent and userIdentity.invokedBy, ANDed. That
# is the correct shape: an AND makes the exclusion narrower, so if only one of the two fields
# is populated the event is still alerted on. An exclusion that fails open in the direction of
# more alerts is the right way to fail.
#
# FIELD SHAPE, AND HOW MUCH OF IT IS DERIVED. DeleteBackup takes exactly one request parameter,
# BackupArn, and returns a BackupDescription wrapper object containing BackupDetails
# (BackupArn, BackupName, BackupSizeBytes, BackupStatus, BackupType, BackupCreationDateTime,
# BackupExpiryDateTime). AWS publishes no DeleteBackup CloudTrail example, so the event paths
# below are derived from that documented API response shape plus CloudTrail's usual
# lowercasing of the leading character - they are NOT read off a published event. Confirm
# against a real event in your own trail before depending on the nested paths.
title: DynamoDB backup deleted by a principal outside the backup-lifecycle pipeline
id: d92f471a-0c68-4e35-b8a7-5f31c9e2074b
name: dynamodb_backup_deleted_nonpipeline
status: experimental
description: >-
  An on-demand or system backup was deleted by a principal that does not own backup lifecycle,
  and not by AWS Backup acting on its own schedule. A backup is the only thing that makes an
  unrecoverable table deletion recoverable, so removing one is preparation as often as it is
  housekeeping.
references:
  - https://attack.mitre.org/techniques/T1490/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DeleteBackup.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1490
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'DeleteBackup'
  # AWS Backup expiring a recovery point on its own lifecycle schedule. Kept as a sibling
  # block on invokedBy alone: it is the field AWS populates for service-initiated calls, and
  # a user agent can look like anything.
  service_initiated:
    userIdentity.invokedBy: 'backup.amazonaws.com'
  # POPULATE BEFORE DEPLOYING. Unpopulated, this fires on every scheduled backup rotation.
  backup_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's backup-lifecycle role
      - ':role/BackupOperator'      # replace with this account's backup operator role
  success:
    errorCode: null
  condition: selection and success and not service_initiated and not backup_lifecycle_pipeline
falsepositives:
  - >-
    An operator pruning old on-demand backups by hand outside the pipeline. Distinguishable by
    the backup's age and by whether any recovery point survives it; if it is routine, the
    finding is that backup retention is being managed manually rather than by a lifecycle.
level: high
---
# THE SHARPEST CASE THE SOURCE RULE CANNOT SEE. When a table with PITR enabled is deleted,
# DynamoDB "automatically creates a backup snapshot called a system backup and retains it for
# 35 days", named <table-name>$DeletedTableBackup. That snapshot is the ONLY remaining copy of
# an already-destroyed table. Deleting it is categorically worse than deleting a routine
# on-demand backup, and DeleteBackup's request parameter is only a BackupArn, so the request
# side cannot distinguish them. The response side can: BackupType is SYSTEM and the name ends
# in the documented suffix. Both paths are derived from the API response shape - see the file
# header - so verify them against a real event before relying on this rule alone.
title: DynamoDB system backup of an already-deleted table destroyed
id: 4b8c05e1-6a2d-49f7-83b0-1c7e5d94af26
status: experimental
description: >-
  A DeleteBackup removed a SYSTEM backup - the automatic snapshot DynamoDB creates when a
  PITR-enabled table is deleted, retained 35 days. That snapshot is the last remaining copy of
  a table that no longer exists, so its deletion makes the earlier destruction permanent.
references:
  - https://attack.mitre.org/techniques/T1490/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1490
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'DeleteBackup'
  system_backup_type:
    responseElements.backupDescription.backupDetails.backupType: 'SYSTEM'
  system_backup_name:
    responseElements.backupDescription.backupDetails.backupName|contains: '$DeletedTableBackup'
  success:
    errorCode: null
  # Either signal alone is enough. They are ORed rather than ANDed because both paths are
  # derived rather than observed, and requiring both would mean a single wrong path silently
  # stops the rule firing (B4) on the most destructive case in this playbook.
  condition: selection and success and (system_backup_type or system_backup_name)
falsepositives:
  - >-
    Deliberate cleanup after a table was decommissioned on purpose and the 35-day system backup
    is no longer wanted. Should be traceable to the decommission change record.
level: critical
---
# UNVERIFIED AGAINST PRIMARY DOCUMENTATION - READ BEFORE DEPLOYING.
#
# This rule covers the two PITR paths described in the file header, and it is the most
# important rule in this file. But AWS's DynamoDB CloudTrail page enumerates the control-plane
# operations "logged by default" and UpdateContinuousBackups is NOT on that list, even though
# DescribeContinuousBackups IS. That is almost certainly a documentation omission - it is a
# control-plane API and there is no mechanism by which its sibling would be logged and it
# would not - but "almost certainly" is not verification, and shipping a rule that silently
# never fires is the failure this corpus exists to avoid.
#
# BEFORE RELYING ON THIS RULE: run `aws dynamodb update-continuous-backups` against a
# throwaway table and confirm the event appears in your own trail with this event name. If it
# does not, the PITR gap is worse than described here, because it would mean PITR can be
# turned off with no management-event record at all - and the only remaining detection is a
# periodic DescribeContinuousBackups sweep, which is what §5 of the playbook does anyway.
title: DynamoDB point-in-time recovery disabled or its window shortened
id: 7e35a06c-8d41-4b92-a5f3-2b60c8e179d4
status: experimental
description: >-
  UpdateContinuousBackups either turned point-in-time recovery off or reduced its recovery
  period. AWS documents that a reduction takes effect immediately and that continuous backups
  falling outside the new value are no longer recoverable, so one parameter change can destroy
  up to 34 days of recovery capability while PITR still reports as enabled.
references:
  - https://attack.mitre.org/techniques/T1490/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateContinuousBackups.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1490
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'UpdateContinuousBackups'
  # PointInTimeRecoveryEnabled is documented Type: Boolean - a quoted 'false' matches nothing
  # on a JSON-typed backend.
  pitr_off:
    requestParameters.pointInTimeRecoverySpecification.pointInTimeRecoveryEnabled: false
  # A shortened window. The parameter is optional and defaults to 35; any value below 35 is a
  # reduction relative to the default, and the analyst compares against the table's previous
  # value from DescribeContinuousBackups. Enumerated rather than ranged because Sigma has no
  # numeric comparison operator.
  window_shortened:
    requestParameters.pointInTimeRecoverySpecification.recoveryPeriodInDays:
      - 1
      - 2
      - 3
      - 4
      - 5
      - 6
      - 7
  success:
    errorCode: null
  condition: selection and success and (pitr_off or window_shortened)
falsepositives:
  - >-
    A deliberate cost reduction on a non-production table. PITR is billed on table size and not
    on the length of the window, so shortening the window saves nothing - a change made for
    cost reasons is a change made on a wrong premise, and is worth a conversation either way.
level: high
---
# Volume basis, stated so a deployer can change it knowingly. Three is not observed, it is
# derived: a single backup deletion is routine pruning and is already covered per-event by Rule
# 1, while backups are deleted one at a time by an actor working through a table's recovery
# points, and three inside ten minutes is faster than any human pruning workflow and slower
# than nothing. The base rule already excludes AWS Backup's own lifecycle expiries and the
# backup-lifecycle pipeline, so scheduled rotation does not reach this correlation.
title: DynamoDB backups deleted at volume by one principal
id: 2c0b7f39-4e18-4a6d-9b53-e7d1a0c86f42
status: experimental
description: >-
  One principal outside the backup-lifecycle pipeline deleted three or more backups inside ten
  minutes. Working through a table's recovery points is preparation for destroying the table.
references:
  - https://attack.mitre.org/techniques/T1490/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1490
correlation:
  type: event_count
  rules:
    - dynamodb_backup_deleted_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 3
level: high
```

The rule cannot say what survives the deletion, because the recovery posture of a table is
state and not an event — that is Query 2, and it must be run before the 35-day expiry on any
`$DeletedTableBackup`. It also cannot see a table that never had PITR or a backup in the first
place: such a table was never recoverable, produces no event at any point, and is invisible to
every rule in this file. `detections/kql_t1490.kql` puts all three recovery-removal paths in one
result set per principal so the sequence is visible as one row.

---

### Key Investigation Queries

> DynamoDB is regional and so are backups — run these in the affected region, and repeat per region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: who removed which recovery points, and what they did next

```bash
REGION="us-east-1"
RAW=$(for EV in DeleteBackup UpdateContinuousBackups DeleteTable CreateBackup; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no backup was deleted'."
else
  # DeleteBackup's request carries ONLY backupArn; the backup's name, type and source table
  # come from the backupDescription WRAPPER in the response - paths derived from the API
  # response shape, not from a published event (see §1). UpdateContinuousBackups nests its
  # parameters under pointInTimeRecoverySpecification.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "dynamodb.amazonaws.com") |
    (.responseElements.backupDescription.backupDetails // {}) as $bd |
    (.requestParameters.pointInTimeRecoverySpecification // {}) as $pitr |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     invoked_by: (.userIdentity.invokedBy // "direct"),
     access_key: .userIdentity.accessKeyId,
     table_name: ((.requestParameters.tableName //
                   .responseElements.backupDescription.sourceTableDetails.tableName // "")
                  | split("/") | last),
     backup_arn: (.requestParameters.backupArn // null),
     backup_name: ($bd.backupName // null),
     backup_type: ($bd.backupType // null),
     backup_bytes: ($bd.backupSizeBytes // null),
     pitr_enabled: ($pitr.pointInTimeRecoveryEnabled // null),
     pitr_window_days: ($pitr.recoveryPeriodInDays // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

`invoked_by` of `backup.amazonaws.com` is AWS Backup expiring a recovery point on its own
lifecycle — not an incident, and the reason the source rule's exclusion is worth keeping.
Anything else is a direct call. A `backup_type` of `SYSTEM`, or a `backup_name` ending
`$DeletedTableBackup`, is the **last copy of an already-deleted table** and outranks everything
else in the list. `pitr_enabled: false` is the whole recovery window gone in one call with no
backup deleted to show for it; `pitr_window_days` below 35 is the same destruction done quietly,
because PITR keeps reporting `ENABLED` afterwards. Count `error` values apart from successes:
repeated `AccessDeniedException`, `NotAuthorized` or `BackupNotFoundException` is boundary
mapping. Record `table_name`, `backup_arn`, `caller_arn` and `access_key` as IOCs.

#### Query 2 — Inspect: what recovery capability actually remains, per affected table

```bash
REGION="us-east-1"
AFFECTED_TABLES="<table-names-from-Query-1>"
for T in $AFFECTED_TABLES; do
  # backup-type ALL is mandatory: the default is USER and hides every SYSTEM snapshot,
  # including the <table>$DeletedTableBackup that is the only recovery point a deleted table
  # can still have.
  BKJSON=$(aws dynamodb list-backups --table-name "$T" --backup-type ALL \
             --region "$REGION" --output json)
  CBJSON=$(aws dynamodb describe-continuous-backups --table-name "$T" \
             --region "$REGION" --output json)
  if [ -z "$BKJSON" ]; then
    echo "[!] $T - list-backups returned nothing. The call failed. Recovery points are UNKNOWN,"
    echo "    not zero. Do not record this table as unrecoverable on this basis."
  else
    printf '%s' "$BKJSON" | jq -r --arg t "$T" '.BackupSummaries as $b |
      if ($b | length) == 0 then "[!] " + $t + ": NO backups of any type"
      else "[i] " + $t + ": \($b | length) backup(s)\n" +
           ($b | sort_by(.BackupCreationDateTime)
               | map("      \(.BackupName) type=\(.BackupType) created=\(.BackupCreationDateTime) expires=\(.BackupExpiryDateTime // "never") bytes=\(.BackupSizeBytes)")
               | join("\n")) end'
  fi
  if [ -z "$CBJSON" ]; then
    echo "    [!] describe-continuous-backups failed - PITR state UNKNOWN, not disabled."
    echo "        A table that no longer exists also fails here; check the backup list above."
  else
    printf '%s' "$CBJSON" | jq -r '.ContinuousBackupsDescription.PointInTimeRecoveryDescription |
      "      pitr=\(.PointInTimeRecoveryStatus) window_days=\(.RecoveryPeriodInDays // "n/a") earliest=\(.EarliestRestorableDateTime // "n/a") latest=\(.LatestRestorableDateTime // "n/a")"'
  fi
done
```

Read `earliest` as the real answer: it is the oldest instant this table can be restored to, and
it is what a reduced `recoveryPeriodInDays` moves forward immediately. A table reporting
`pitr=ENABLED` with `window_days=1` has had 34 days of recovery destroyed and will pass any
check that asks only whether PITR is on. A `SYSTEM` entry ending `$DeletedTableBackup` means the
table itself is **already gone** and its `expires` value — 35 days after the deletion — is the
hard deadline on this entire incident. `NO backups of any type` together with a
`describe-continuous-backups` failure is the case to escalate immediately: it usually means the
table no longer exists and nothing was left behind.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteBackup UpdateContinuousBackups"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "dynamodb.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Grouped by caller rather than by resource,
because the question eradication needs answered is *how much of this is one actor's work* — a
per-resource list cannot say. `access_key` is emitted because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` whether or not it happened; the preamble's caveat applies.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN: one credential is used across many sessions, and
the key identifies the credential. The per-service grouping answers what this playbook cannot —
whether this technique was the objective or one stop on a tour. A service in that list with no
business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID, so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Take a new backup before containing anyone. The recovery points that survived Query 2 are
already reduced, the actor still holds their credential while you work through IAM, and a fresh
on-demand backup is one call that cannot be undone by anything except another `DeleteBackup` —
which Step 2 then denies. Do not restore first: a restore consumes time and creates a new table
the actor can also reach.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Take a fresh recovery point on every surviving affected table

```bash
REGION="us-east-1"
AFFECTED_TABLES="<table-names-from-Query-1>"
STAMP=$(date -u +%Y%m%d-%H%M%S)
for T in $AFFECTED_TABLES; do
  # BackupName is constrained to [a-zA-Z0-9_.-]+ and 3-255 characters, so the stamp uses
  # no characters outside that set. A table that no longer exists cannot be backed up -
  # that branch is a finding, not an error to swallow.
  OUT=$(aws dynamodb create-backup --table-name "$T" \
          --backup-name "ir-${T}-${STAMP}" --region "$REGION" --output json 2>&1)
  case "$OUT" in
    *TableNotFoundException*)
      echo "[!] $T no longer exists - nothing to back up. Its only recovery point is whatever"
      echo "    Query 2 listed. Go to §5 and race the 35-day system-backup expiry.";;
    *ContinuousBackupsUnavailableException*)
      echo "[FAIL] $T - backups are not yet available for this table; retry shortly";;
    *TableInUseException*|*BackupInUseException*)
      echo "[!] $T is mid-operation (creating, deleting, or another backup in flight). Retry.";;
    *LimitExceededException*)
      echo "[FAIL] $T - concurrent table-operation limit hit; stagger the loop and retry";;
    *backupDetails*|*BackupDetails*)
      echo "[OK] $T - fresh recovery point created: $(printf '%s' "$OUT" | jq -r '.BackupDetails.BackupArn')";;
    *)
      echo "[!] INCONCLUSIVE - unexpected create-backup output for $T: $OUT";;
  esac
done
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["dynamodb:DeleteBackup","dynamodb:UpdateContinuousBackups","dynamodb:DeleteTable"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name is the LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyDdbRecoveryRemoval" --policy-document "$DENY"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name is the 2ND segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyDdbRecoveryRemoval" --policy-document "$DENY"
  echo "[OK] revoked pre-$CUTOFF sessions and denied recovery removal for role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
  echo "    service principal. Contain manually; neither branch above applies."
fi
```

The session-revocation policy denies only tokens issued **before** `$CUTOFF`. A credential
re-fetched afterwards gets a newer `aws:TokenIssueTime` and is not covered — it kills the leaked
session, it does not gate the role. `EmergencyDenyDdbRecoveryRemoval` deliberately omits
`dynamodb:CreateBackup`, so Step 1 can be re-run against the same principal's tables if more
are found.

---

## 4. Eradication

### Remove Attacker Access

- **Restore PITR wherever it was turned off or shortened**, on every table in Query 1's
  `table_name` list. Re-enabling starts a **new** window from that moment: the days between the
  change and the re-enable are not recoverable and never will be. Set
  `RecoveryPeriodInDays` explicitly rather than relying on the default, so the value is visible
  in configuration rather than implied.
- **Race the 35-day clock on any `$DeletedTableBackup`.** If Query 2 found one, its
  `BackupExpiryDateTime` is a hard deadline that keeps running through the investigation.
  Restore from it into a new table now and investigate the copy, rather than investigating first
  and restoring later.
- **Hunt the rest of the session.** Pull every DynamoDB call by the same `access_key` from
  Query 1's window. A `DeleteTable` in the same session is
  `../dynamodb.impact.multiple-tables-deleted/`; a protection disable beforehand is
  `../dynamodb.stealth.deletion-protection-disabled/`; a `ListBackups` sweep first is
  `../dynamodb.impact.backup-was-listed/` and tells you what the actor knew.
- **Right-size the permission.** `dynamodb:DeleteBackup` and
  `dynamodb:UpdateContinuousBackups` are needed by no workload at runtime — only by whatever
  owns backup lifecycle, plus the AWS Backup service role for scheduled expiry.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}'); K=role
  for P in EmergencyDenyDdbRecoveryRemoval EmergencyRevokeSessions; do
    aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
  LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text)
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}'); K=user
  aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyDdbRecoveryRemoval"
  LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text)
else K=none; LEFT=""; fi
case "$K:$LEFT" in
  none:*)      echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify every affected table has recovery capability again

```bash
REGION="us-east-1"
AFFECTED_TABLES="<table-names-from-Query-1>"
BAD=0; UNKNOWN=0
for T in $AFFECTED_TABLES; do
  BKJSON=$(aws dynamodb list-backups --table-name "$T" --backup-type ALL --region "$REGION" --output json)
  CB=$(aws dynamodb describe-continuous-backups --table-name "$T" --region "$REGION" \
         --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.[PointInTimeRecoveryStatus,RecoveryPeriodInDays]' \
         --output text)
  # list-backups ALWAYS returns a BackupSummaries array, so no output at all is a call that did
  # not run - never "zero backups". Test the captured text for emptiness before comparing.
  if [ -z "$BKJSON" ]; then NBK=""; else NBK=$(printf '%s' "$BKJSON" | jq '.BackupSummaries | length'); fi
  PITR=$(echo "$CB" | awk '{print $1}'); WIN=$(echo "$CB" | awk '{print $2}')
  if [ -z "$NBK" ] || [ -z "$PITR" ]; then
    echo "[!] $T INCONCLUSIVE - backups='$NBK' pitr='$PITR'. A blank field is a call that"
    echo "    failed, or a table that no longer exists. Either way it is not a clean result."
    UNKNOWN=$((UNKNOWN+1))
  elif [ "$PITR" != "ENABLED" ] && [ "$NBK" -eq 0 ]; then
    echo "[FAIL] $T has NO recovery capability at all - PITR $PITR and zero backups."
    BAD=$((BAD+1))
  elif [ "$PITR" = "ENABLED" ] && [ "$WIN" != "None" ] && [ "$WIN" -lt 35 ] 2>/dev/null; then
    echo "[FAIL] $T reports PITR ENABLED but the window is $WIN days, not 35. A shortened"
    echo "       window passes every check that asks only whether PITR is on. Restore it."
    BAD=$((BAD+1))
  elif [ "$NBK" -eq 0 ]; then
    echo "[FAIL] $T has PITR $PITR but zero on-demand backups - §3 Step 1 did not complete."
    BAD=$((BAD+1))
  else
    echo "[OK] $T - PITR=$PITR window=$WIN days, $NBK on-demand/system backup(s)"
  fi
done
echo "--- $BAD failing, $UNKNOWN inconclusive ---"
[ "$BAD" -eq 0 ] && [ "$UNKNOWN" -eq 0 ] && echo "[OK] every affected table has recovery capability" \
                                         || echo "[FAIL] do not close this incident"
```

Every branch is reachable after the remediation: Step 1 created backups and §4 re-enabled PITR,
so both signals still exist to be queried, and the two partial outcomes that actually happen —
PITR restored but with a short window, and PITR restored but no fresh backup taken — land on
`[FAIL]` rather than being certified clean. The `[!]` branch deliberately merges two different
unknowns, a failed call and a table that no longer exists, because from this check's position
they are indistinguishable and **neither is a pass**; Query 2's backup listing is what separates
them.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource dynamodb.amazonaws.com / eventName DeleteBackup / no"
echo "  errorCode / userIdentity.invokedBy NOT backup.amazonaws.com / userIdentity.arn NOT on"
echo "  the backup-lifecycle allowlist. Critical when backupType is SYSTEM or the backupName"
echo "  contains \$DeletedTableBackup. High on UpdateContinuousBackups with"
echo "  pointInTimeRecoveryEnabled false (JSON boolean) or recoveryPeriodInDays below 35."
echo "MUST NOT fire on: AWS Backup expiring a recovery point on its own lifecycle schedule,"
echo "  identified by userIdentity.invokedBy = backup.amazonaws.com; a DeleteBackup that"
echo "  returned AccessDeniedException, NotAuthorized, BackupNotFoundException or"
echo "  BackupInUseException; UpdateContinuousBackups ENABLING PITR, which is the remediation."
echo "EXPECTED FP, by design: an operator pruning old on-demand backups by hand outside the"
echo "  pipeline. If that is routine, the finding is that retention is managed manually."
echo "KNOWN COVERAGE LIMIT: a table that never had PITR or a backup produces no event here at"
echo "  any point. It was never recoverable, and no rule in this file can see it."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside backup lifecycle could delete recovery points | `dynamodb:DeleteBackup` granted to an identity that never needs it at runtime; no SCP confining it to the backup role and the AWS Backup service role |
| Denied attempts and successful destructions raised identical alerts | The source rule applies no success filter, so a boundary-mapping probe and a real destruction arrive with the same shape and volume |
| Nobody noticed the PITR window had been shortened | No rule covers `UpdateContinuousBackups`, and a shortened window leaves PITR reporting `ENABLED` — so every check that asks only whether PITR is on kept passing |
| The last copy of a destroyed table was deleted as a routine P3 | Nothing distinguished a `SYSTEM` `$DeletedTableBackup` from a nightly backup, because the request carries only a `BackupArn` |
| No one could say what recovery capability remained | Recovery posture is state, not an event; it was never inventoried, and after the deletions there is nothing left to reconstruct it from |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the values are wildcarded: Deny + StringNotEquals against
// a wildcarded ARN matches EVERY principal and blocks scheduled backup expiry outright - an
// outage, not a bypass. The AWS Backup service-linked role MUST be in the allowlist or
// lifecycle expiry starts failing silently and backups accumulate until a quota stops them.
{
  "Effect": "Deny",
  "Action": ["dynamodb:DeleteBackup", "dynamodb:UpdateContinuousBackups"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/BackupOperator",
        "arn:aws:iam::*:role/BreakGlassAdmin",
        "arn:aws:iam::*:role/aws-service-role/backup.amazonaws.com/*"
      ]
    }
  }
}
```

- The SCP reaches the caller because a DynamoDB control-plane call is always made by an
  in-organisation principal. Pair it with **PITR enabled at table creation in infrastructure
  code, with `RecoveryPeriodInDays` set explicitly**, and with a scheduled sweep that asserts
  `EarliestRestorableDateTime` rather than `PointInTimeRecoveryStatus` — the status field
  cannot distinguish a healthy 35-day window from a one-day one, and the difference between
  them is 34 days of recovery.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1490 — Inhibit System Recovery. The source rule's own mapping, and **correct**, which is worth noting in a set where table deletion is mapped to T1490 and item operations to a SQL-stored-procedure technique |
| Primary API | `dynamodb:DeleteBackup`; `dynamodb:UpdateContinuousBackups` for the two PITR paths the source rule does not cover |
| Event source | `dynamodb.amazonaws.com`, **management** plane, regional. `DeleteBackup`, `CreateBackup` and `ListBackups` are on AWS's enumerated control-plane list; **`UpdateContinuousBackups` is not**, while `DescribeContinuousBackups` is — an apparent documentation omission that must be confirmed empirically |
| Key discriminator | The calling principal, plus `responseElements.backupDescription.backupDetails.backupType`. `SYSTEM` means the backup is the automatic `$DeletedTableBackup` of a table that no longer exists — the last copy, not one of many |
| Field shape | Request: `backupArn` only. Response: `backupDescription` **wrapper** → `backupDetails` (`backupName`, `backupType`, `backupSizeBytes`, `backupStatus`, `backupExpiryDateTime`) and `sourceTableDetails`. **Derived from the API response shape** — AWS publishes no `DeleteBackup` event example |
| "Was it used" pivot | What survives, not what happened: `ListBackups --backup-type ALL` (the default `USER` hides `SYSTEM` snapshots) and `DescribeContinuousBackups`, whose `EarliestRestorableDateTime` is the only field that exposes a shortened window |
| Blast radius | Recovery capability, not live data. A `$DeletedTableBackup` deletion makes an earlier table destruction permanent. PITR disable removes the whole continuous window; a `RecoveryPeriodInDays` reduction removes up to 34 days of it and leaves the status reading `ENABLED` |
| Error strings | `DeleteBackup`: `BackupInUseException`, `BackupNotFoundException`, `InternalServerError`, `LimitExceededException`. `UpdateContinuousBackups`: `ContinuousBackupsUnavailableException`, `InternalServerError`, `TableNotFoundException` — note `InvalidRestoreTimeException` and `PointInTimeRecoveryUnavailableException` belong to `RestoreTableToPointInTime`, **not** here. Plus DynamoDB Common Errors: `AccessDeniedException`, `NotAuthorized`, `ExpiredTokenException`, `IncompleteSignature`, `InternalFailure`, `MalformedHttpRequestException`, `OptInRequired`, `RequestAbortedException`, `RequestEntityTooLargeException`, `RequestTimeoutException`, `ServiceUnavailable`, `ThrottlingException`, `UnknownOperationException`, `UnrecognizedClientException`, `ValidationError` (**not** `ValidationException`) |

### Residual Risk

A deleted backup does not come back. §3's fresh backup protects the table's state **as of the
response**, not as of any earlier point, so anything that was already corrupted or removed
before the recovery points were destroyed is now unrecoverable — and the item-level writes that
would show when that happened are CloudTrail **data** events, off by default, so there is
usually no record of it either. Re-enabling PITR starts a new window from that moment; the gap
between the disable and the re-enable is permanent no matter what else is done. If a
`$DeletedTableBackup` was destroyed, the table it belonged to is gone for good and no step in
this playbook changes that. Any table that never had PITR or a backup was never recoverable,
generated no event at any stage, and is still in that state — the rules in this file can only
see capability being removed, never capability that was never there. And if the actor read the
data before removing the recovery points, that read is invisible: `Scan`, `Query` and `GetItem`
are data events, off by default, so destruction and exfiltration-then-destruction look identical
in the management log.
