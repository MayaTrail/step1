# IR Playbook: DynamoDB Tables Deleted — Unrecoverable Destruction of the Primary Data Store via `dynamodb:DeleteTable`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data destruction / Availability (a table, its indexes and its stream are destroyed; recovery exists only if it was arranged beforehand) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** for a single deletion as much as for a mass one, rising to **Critical** when a backup deletion precedes it. AWS: *"Deleting a table is an unrecoverable operation."* Irreversibility does not scale with count — one production table destroyed is already unrecoverable, and the difference between one and fifty is the size of the recovery work-list. The source rates the volume case **P3** and ships **no rule at all** for a single deletion, which is the more serious of the two problems |
| MITRE Tactics | Impact (TA0040) |
| MITRE Techniques | T1485 (primary), T1490 (secondary, on the backup-then-table sequence) — both verified live 2026-08-29 |
| Services in Scope | DynamoDB, CloudTrail (management), CloudWatch (`AWS/DynamoDB`), IAM, Organizations (SCP), AWS Backup, and every application reading or writing the destroyed tables |

**What the technique does:** the actor calls `dynamodb:DeleteTable` with a table name — or a table ARN, which
the API accepts equally. The table moves from `ACTIVE` to `DELETING`; its indexes go with it,
and any stream on it goes `DISABLED` and is auto-deleted 24 hours later, taking the
change-data-capture record of the table's contents with it. During the transition "DynamoDB
might continue to accept data read and write operations, such as `GetItem` and `PutItem`, on a
table in the `DELETING` state until the table deletion is complete", so the application keeps
succeeding briefly against a table that is being destroyed and the outage surfaces late. When
the operation concludes, "the table no longer exists in DynamoDB". If point-in-time recovery
was enabled, DynamoDB leaves a single system snapshot named `<table>$DeletedTableBackup`,
retained 35 days. If it was not, and no on-demand backup exists, the data is gone. Deletion
protection, the property that would have refused the call, is **off by default** on every
table.

**Detection thesis.** The discriminator is **the calling principal**, because `DeleteTable`
carries no field that separates destruction from decommissioning — the same event, with the
same parameters, is what every stack teardown emits. The source rule looks at neither the
caller nor the loss recorded in `responseElements.tableDescription`, and its volume condition
never fires for a single table at all: it is a unique-count alert above five distinct names in a
one-minute window, while its own description claims ten minutes.

> The precondition is `../dynamodb.stealth.deletion-protection-disabled/`. Removing the
> recovery point instead of the data is `../dynamodb.impact.backup-was-deleted/`. Destroying
> rows without destroying the table is `../dynamodb.impact.table-items-modified-or-destroyed/`,
> and that one is a **data event**, invisible by default.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing DynamoDB **management** events. `DeleteTable`,
  `CreateTable`, `UpdateTable`, `CreateBackup`, `DeleteBackup`, `ListBackups`,
  `RestoreTableFromBackup` and `RestoreTableToPointInTime` are logged **by default** — AWS's
  DynamoDB CloudTrail page enumerates them as control-plane events
- **`DeleteTable` field shape, verified against AWS's published log example.**
  `requestParameters.tableName`, and `responseElements.tableDescription` — a **wrapper object**
  matching the API's `TableDescription` response element, not a flat path — carrying
  `itemCount`, `tableSizeBytes` and `tableStatus: DELETING`. That `itemCount` is the only
  surviving measure of what was destroyed, and it is an **approximate** figure DynamoDB
  refreshes periodically, not a live count
- **`tableName` may be a bare name or a full table ARN.** The API documents "You can also
  provide the Amazon Resource Name (ARN) of the table in this parameter" and caps the field at
  1024 characters for that reason. A distinct-count over the raw field counts one table twice
  if the actor mixes forms — normalise before counting
- A standing inventory of PITR state (`DescribeContinuousBackups`) and on-demand backups
  (`ListBackups`, **backup type `ALL`** — the default is `USER` and hides the
  `$DeletedTableBackup` system snapshots). This decides whether a deletion is recoverable and
  it must exist *before* the deletion; afterwards there is nothing left to ask
- Every table's key schema, indexes, TTL configuration, stream settings and tags **in
  infrastructure code**. A restore "always restores to a new table" and does not carry over
  auto scaling policies, IAM policies, CloudWatch metrics and alarms, tags, stream settings or
  TTL settings — those exist only where you put them
- A baseline of which principals own table lifecycle — in most accounts one deployment role
  and one break-glass role

**Alerting (must be pre-configured)**
- **`DeleteTable` succeeding for a principal outside the table-lifecycle allowlist → P0**
- **Five or more distinct tables deleted by one non-pipeline principal within ten minutes → P1**
- **A `DeleteBackup` followed by a `DeleteTable` from the same principal within 24 hours → P0**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- **The normal value for this measure, per resource, from a quiet week.** The rule compares against a resource's own history rather than a fleet average, so without the baseline the threshold is a guess.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteTable` succeeding for a principal outside the table-lifecycle allowlist | CloudTrail (management) | T1485 |
| P0 | A `DeleteBackup` followed by a `DeleteTable` from the same principal within 24 hours | CloudTrail (management) | T1490 |
| P1 | Five or more distinct tables deleted by one non-pipeline principal within ten minutes | CloudTrail (management) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DeleteTable` denied repeatedly across tables (`AccessDeniedException` / `NotAuthorized`) — boundary mapping, not destruction | CloudTrail (management) | T1485 |
| P2 | `RestoreTableFromBackup` or `RestoreTableToPointInTime` by the same principal after a deletion — a restore is a **copy** until proven a recovery, especially into another Region | CloudTrail (management) | T1485 |
| P3 | A table's `ConsumedReadCapacityUnits` and `ConsumedWriteCapacityUnits` stop emitting with no scheduled teardown | CloudWatch `AWS/DynamoDB` | T1485 |

### Detection Rule Quality Notes

The source rule counts distinct table names in a window and looks at nothing else — not the
caller, not the loss recorded in its own response, and not whether one table was destroyed at
all.

| Issue | Impact | Correction |
|-------|--------|-----------|
| No per-event rule anywhere in the set | **One production table destroyed produces no alert.** The only table-deletion rule requires more than five distinct names, so the single irreversible destruction — the common case — is invisible, while six ephemeral test tables torn down by a pipeline raise a P3 | Ship a per-event rule at `high`, gated on the principal; keep volume as a correlation on top of it |
| Configured window is one minute; the rule's own description says ten | An actor pacing five tables per minute never fills a one-minute window with six distinct names and never fires the rule at all | `10m` span, matching the described intent |
| Threshold is a maximum, so it fires at six | An actor who deletes exactly five falls through — a threshold that does not fire on the baseline stated in the text beside it | `gte: 5` at the baseline, with the tuning basis stated |
| No principal check | Fires identically for a scheduled stack teardown and for a compromised session. `DeleteTable` carries nothing else that separates the two, so the caller is the entire signal and it is unused | Allowlist the table-lifecycle roles; alert on everyone else |
| `responseElements.tableDescription.itemCount` and `.tableSizeBytes` are never read | The alert says a table was deleted and cannot say how much was in it. After the deletion there is nothing left to measure, so the number is lost permanently at the moment it was available for free | Emit both from the query and record them, flagged approximate |
| Mapped to T1490 (Inhibit System Recovery) | T1490 covers destroying the *recovery mechanism*. Deleting the table destroys the **primary data**, which is T1485; the mapping sends a responder to the backup story instead of the data-loss one | T1485 primary; T1490 retained only on the backup-then-table sequence, where a recovery mechanism genuinely was the first target |

**Recommended detection — a table destroyed by a principal outside the lifecycle pipeline.**

```yaml
# DynamoDB Table Destruction, single and at volume (T1485 / T1490)
#
# THE SOURCE RULE HAS NO ROW FOR ONE TABLE. It is a unique-count alert that fires when more
# than five DISTINCT table names are deleted inside its window, and there is no per-event
# companion anywhere in the set. So one production table destroyed — irreversibly, per AWS's
# own "Deleting a table is an unrecoverable operation" — produces no alert at all, while six
# ephemeral test tables torn down by a pipeline produce a P3. Irreversibility does not scale
# with count: the difference between one table and fifty is the size of the recovery work-list,
# not the severity of the loss. Rule 1 below is per-event and `high`; the volume case is the
# correlation, at its own priority.
#
# TWO THRESHOLD DEFECTS, BOTH IN THE SAME DIRECTION. The alert's own description says "More
# than 5 in 10 minutes"; the configured window is ONE minute. And the count is a maximum, so
# it fires at six — an actor deleting exactly five tables falls through, and an actor pacing
# five per minute never trips it at all. The correlation below uses `gte` at the baseline and a
# 10-minute span, which is what the source's own prose describes.
#
# WHAT SURVIVES A DELETION. AWS: the table goes ACTIVE -> DELETING, "any indexes on that table
# are also deleted", a stream on it "goes into the DISABLED state, and the stream is
# automatically deleted after 24 hours", and "when the DeleteTable operation concludes, the
# table no longer exists in DynamoDB". Recovery exists only if it was arranged beforehand:
# if point-in-time recovery was enabled, DynamoDB "automatically creates a backup snapshot
# called a system backup and retains it for 35 days", named <table>$DeletedTableBackup — a
# single instant, not the continuous range PITR offered while the table lived. If PITR was off
# and no on-demand backup exists, the data is gone. Deletion protection, the property that
# would have refused the call, is OFF BY DEFAULT on every table.
#
# THE LOSS IS IN THE EVENT. DeleteTable returns responseElements.tableDescription (a wrapper
# object, matching the API's TableDescription response element) carrying itemCount and
# tableSizeBytes. That is the only surviving measure of what was destroyed, and the source rule
# never reads it. itemCount is an approximate figure DynamoDB refreshes periodically rather
# than a live count — report it as approximate, never as an exact loss.
title: DynamoDB table deleted by a principal outside the table-lifecycle pipeline
id: 6e2a94b7-58c1-4d3f-a71e-c05b8f9e2d13
name: dynamodb_table_deleted_nonpipeline
status: experimental
description: >-
  A table was deleted by a principal that does not own table lifecycle. Deletion is
  unrecoverable unless point-in-time recovery or an on-demand backup existed at the moment of
  the call; the table's indexes go with it and any stream is auto-deleted after 24 hours.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DeleteTable.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'DeleteTable'
  # POPULATE BEFORE DEPLOYING. Unpopulated, this fires on every stack teardown. The allowlist
  # IS the discriminator - DeleteTable carries no field that separates destruction from
  # decommissioning, so the caller is the whole signal.
  table_lifecycle_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace with this account's deployment role
      - ':role/BreakGlassAdmin'     # replace with this account's break-glass role
  success:
    errorCode: null
  condition: selection and success and not table_lifecycle_pipeline
falsepositives:
  - >-
    An engineer tearing down a personal or ephemeral table outside the pipeline. Common in
    development accounts and rare in production ones; if it is common in production, the
    finding is that table lifecycle is not owned by the pipeline.
level: high
---
# Base rule — sequence component only, not for direct alerting. Success-filtered so a DENIED
# DeleteBackup cannot compose into the critical correlation below (D-f). Its own use case,
# with the full response procedure, is ../../dynamodb.impact.backup-was-deleted/; it ships
# here because a correlation can only resolve base rules that are in the same file.
title: DynamoDB backup deleted
id: 1a6f83c2-9e07-4b5d-8c24-3d7a1e6b90f5
name: dynamodb_backup_deleted_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DeleteBackup.html  # retrieved 2026-08-29
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
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# Threshold basis, stated so a deployer can change it knowingly. There is no emulation behind
# this number. The source's own description names five in ten minutes and its configuration
# says six in one minute; the ten-minute span here is the described intent, and `gte: 5` is the
# baseline the description states rather than one past it (F6 - a threshold that does not fire
# on the technique's own stated baseline contradicts the text next to it).
#
# Distinct TABLES, not events: DeleteTable on a table already in the DELETING state returns no
# error and would otherwise inflate an event count. Grouped by userIdentity.arn - the PRINCIPAL,
# not the account. The base rule already excludes the pipeline, so a legitimate multi-table
# teardown does not reach this correlation. Re-baseline against your own account: if engineers
# routinely destroy five-table dev stacks under their own identity, raise it rather than mute it.
title: DynamoDB tables deleted at volume by one principal
id: c48d1057-7b39-4e62-9f80-2a4c6d8e1b73
status: experimental
description: >-
  One non-pipeline principal deleted five or more distinct tables inside ten minutes. That is
  destruction at machine speed, and the recovery work-list is every table in the group.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: value_count
  rules:
    - dynamodb_table_deleted_nonpipeline
  group-by:
    - userIdentity.arn
  field: requestParameters.tableName
  timespan: 10m
  condition:
    gte: 5
level: high
---
# DESTROY THE RECOVERY POINT, THEN THE DATA. This is the sequence that turns a recoverable
# incident into an unrecoverable one, and neither half alerts above informational on its own in
# the source set. Ordered, because the reverse order is ordinary housekeeping: deleting a
# backup AFTER the table it belonged to is cleanup, while deleting it FIRST is preparation.
#
# 24h rather than minutes: there is no documented cooldown to anchor a short window on, and
# both halves are already rare and success-filtered, so the span costs nothing in false
# positives. Grouped by principal because a backup is named by BackupArn and a table by
# tableName - Sigma cannot join those two field shapes.
title: DynamoDB backup deleted and a table then deleted by the same principal
id: 9b70e2f4-3c85-41a9-b6d2-8e15c07af934
status: experimental
description: >-
  One principal deleted a backup and then deleted a table. If the backup belonged to that
  table, the recovery point was removed before the data was destroyed and the loss is final
  unless point-in-time recovery was independently enabled.
references:
  - https://attack.mitre.org/techniques/T1490/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1490
  - attack.t1485
correlation:
  type: temporal_ordered
  rules:
    - dynamodb_backup_deleted_bb
    - dynamodb_table_deleted_nonpipeline
  group-by:
    - userIdentity.arn
  timespan: 24h
level: critical
```

The rule cannot say whether any of it is recoverable: nothing about PITR or on-demand backups
appears in the `DeleteTable` event, and that state has to be read from
`DescribeContinuousBackups` and `ListBackups` — which is Query 2, and which must be run before
the 35-day system-backup clock expires. It also cannot join a backup deletion to a table
deletion on the resource, because a backup is named by `backupArn` and a table by `tableName`;
the `temporal_ordered` correlation therefore groups by principal, and
`detections/kql_t1485.kql` reports both sides in one row.

---

### Key Investigation Queries

> DynamoDB is regional and so is every table — run these in the affected region, and repeat per region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: who destroyed what, how much was in it, and what else they touched

```bash
REGION="us-east-1"
RAW=$(for EV in DeleteTable DeleteBackup RestoreTableFromBackup RestoreTableToPointInTime; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no table was destroyed'."
else
  # tableName may legally be a full ARN, so it is split to a bare name before anything counts
  # it - otherwise one table appears as two. DeleteTable's response carries the size of the
  # loss under a tableDescription WRAPPER object; the restore APIs name their target in
  # targetTableName instead.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "dynamodb.amazonaws.com") |
    ((.requestParameters.tableName // .requestParameters.targetTableName //
      .responseElements.tableDescription.tableName // "") | split("/") | last) as $tbl |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId, region: .awsRegion,
     table_name: $tbl,
     backup_arn: (.requestParameters.backupArn // null),
     items_lost: (.responseElements.tableDescription.itemCount // null),
     bytes_lost: (.responseElements.tableDescription.tableSizeBytes // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

Group by `caller_arn` and count **distinct `table_name`** values, not events: a repeat
`DeleteTable` against a table already in `DELETING` returns no error and would otherwise
inflate the count. `items_lost` and `bytes_lost` summed across the deletions are the size of
the incident and belong in the record, flagged approximate. A `DeleteBackup` with a
`backup_arn` *before* the deletions is the sequence that makes the loss final — treat it as the
first event, not a footnote. A `RestoreTableFromBackup` by the same `caller_arn`, especially
with a different `region`, is a **copy** until someone proves it was a recovery. Count `error`
values apart from successes: repeated `AccessDeniedException` or `NotAuthorized` across tables
is boundary mapping. Record `table_name`, `caller_arn` and `access_key` as IOCs.

#### Query 2 — Inspect: for every destroyed table, what recovery point still exists

```bash
REGION="us-east-1"
LOST_TABLES="<table-names-from-Query-1>"
for T in $LOST_TABLES; do
  # backup-type ALL is mandatory here. The default is USER, which HIDES the SYSTEM snapshot
  # named <table>$DeletedTableBackup that DynamoDB creates automatically on deletion IF PITR
  # was enabled - the one recovery point that can still exist after the table is gone.
  BKJSON=$(aws dynamodb list-backups --table-name "$T" --backup-type ALL \
             --region "$REGION" --output json)
  if [ -z "$BKJSON" ]; then
    echo "[!] $T - list-backups returned nothing. The call failed. Recovery points are"
    echo "    UNKNOWN, not zero. Do not report this table as unrecoverable on this basis."
    continue
  fi
  N=$(printf '%s' "$BKJSON" | jq '.BackupSummaries | length')
  if [ "$N" -eq 0 ]; then
    echo "[FAIL] $T - NO recovery point of any type. PITR was off at deletion and no on-demand"
    echo "       backup exists. This table is unrecoverable."
  else
    printf '%s' "$BKJSON" | jq -r --arg t "$T" '.BackupSummaries | sort_by(.BackupCreationDateTime) |
      map("  \(.BackupName) type=\(.BackupType) status=\(.BackupStatus) created=\(.BackupCreationDateTime) expires=\(.BackupExpiryDateTime // "none") bytes=\(.BackupSizeBytes)") |
      ["[OK] " + $t + " has \(length) recovery point(s):"] + . | .[]'
  fi
done
```

A `BackupType` of `SYSTEM` with a name ending `$DeletedTableBackup` is the automatic snapshot
DynamoDB took at the instant of deletion — it exists **only if PITR was enabled**, it is a
single point in time rather than the continuous range PITR offered while the table lived, and
its `BackupExpiryDateTime` is 35 days after the deletion. That expiry is the real deadline on
this incident: restore before it, or the table is gone regardless of anything else in this
playbook. `type=USER` entries are on-demand backups and do not expire. `[FAIL]` here is the
finding, not a script error, and every `[!]` is an unknown that must be recorded as unknown.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteBackup DeleteTable"
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

The destruction is already complete and cannot be undone, so containment is about the **next**
table. Stop the principal before restoring anything: a restore run while the actor still holds
`dynamodb:DeleteTable` invites a second deletion of the restored copy, and it also consumes the
`$DeletedTableBackup` window on a table that will simply be destroyed again.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Stop the principal destroying anything else

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["dynamodb:DeleteTable","dynamodb:DeleteBackup","dynamodb:UpdateContinuousBackups","dynamodb:UpdateTable"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name is the LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyDdbDestroy" --policy-document "$DENY"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name is the 2ND segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyDdbDestroy" --policy-document "$DENY"
  echo "[OK] revoked pre-$CUTOFF sessions and denied DynamoDB destruction for role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
  echo "    service principal. Contain manually; neither branch above applies."
fi
```

The session-revocation policy denies only tokens issued **before** `$CUTOFF`. A credential
re-fetched afterwards gets a newer `aws:TokenIssueTime` and is not covered — it kills the leaked
session, it does not gate the role. `EmergencyDenyDdbDestroy` includes `dynamodb:UpdateTable`,
which **breaks autoscaling on every table this principal manages**; that is acceptable for the
duration and is why §4 removes it explicitly.

#### Step 2 — Restore from the surviving recovery point, and protect the restored table

```bash
REGION="us-east-1"; T="<table-names-from-Query-1>"
ARN=$(aws dynamodb list-backups --table-name "$T" --backup-type ALL --region "$REGION" \
        --query 'BackupSummaries | sort_by(@, &BackupCreationDateTime) | [-1].BackupArn' \
        --output text)
if [ -z "$ARN" ] || [ "$ARN" = "None" ]; then
  echo "[!] no recovery point for $T - nothing to restore. Confirm against Query 2 before"
  echo "    concluding the data is unrecoverable; an empty result here can also be a failed call."
else
  # A restore ALWAYS creates a NEW table, so the target name is deliberately distinct: writing
  # over the original name would make the restored copy indistinguishable from the lost table
  # in every later audit. Rename after verification, not before.
  OUT=$(aws dynamodb restore-table-from-backup --backup-arn "$ARN" \
          --target-table-name "${T}-restored" --region "$REGION" --output json 2>&1)
  case "$OUT" in
    *TableAlreadyExistsException*) echo "[!] ${T}-restored already exists - investigate before overwriting";;
    *BackupNotFoundException*)     echo "[FAIL] the backup ARN no longer resolves: $ARN";;
    *tableDescription*|*TableDescription*) echo "[i] restore started into ${T}-restored";;
    *) echo "[!] INCONCLUSIVE - unexpected restore output: $OUT";;
  esac
  # AWS: "You must manually set up the following on the restored table: Auto scaling policies,
  # IAM policies, Amazon CloudWatch metrics and alarms, Tags, Stream settings, Time to Live
  # (TTL) settings." Deletion protection is off on restored tables too. Turn it on immediately.
  aws dynamodb update-table --table-name "${T}-restored" --deletion-protection-enabled \
    --region "$REGION" >/dev/null
  echo "[i] deletion protection requested on ${T}-restored - §5 verifies it landed"
fi
```

---

## 4. Eradication

### Remove Attacker Access

- **Work the whole deletion set, not the table that alerted.** Query 1's distinct
  `table_name` list is the work-list; the correlation's group is the same list.
- **Rebuild what the restore does not carry.** AWS states plainly that auto scaling policies,
  IAM policies, CloudWatch metrics and alarms, tags, stream settings and TTL settings must be
  set up manually on a restored table — and deletion protection and PITR come back **off**. A
  restored table that is serving traffic with no TTL and no PITR is a second incident waiting.
- **Re-enable PITR on every restored and surviving table.** Re-enabling starts a **new**
  recovery window from that moment; the days between the incident and the re-enable are not
  recoverable and never will be.
- **Hunt the rest of the session.** Pull every DynamoDB call by the same `access_key` from
  Query 1's window. `DeleteBackup` in the same session is
  `../dynamodb.impact.backup-was-deleted/`; a protection disable beforehand is
  `../dynamodb.stealth.deletion-protection-disabled/`; a restore into another Region is a data
  copy and belongs to `../dynamodb.impact.multiple-tables-created/`.
- **Right-size the permission.** `dynamodb:DeleteTable` is needed by no workload at runtime;
  only whatever owns table lifecycle needs it. The same applies to `dynamodb:DeleteBackup` and
  `dynamodb:UpdateContinuousBackups`.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either. Leaving `EmergencyDenyDdbDestroy` attached denies `UpdateTable`, so
  autoscaling stays broken and the next capacity event throttles production:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}'); K=role
  for P in EmergencyDenyDdbDestroy EmergencyRevokeSessions; do
    aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
  LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text)
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}'); K=user
  aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyDdbDestroy"
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

#### Verify the restored table exists, holds the data, and is protected

```bash
REGION="us-east-1"; T="<table-names-from-Query-1>"
DESC=$(aws dynamodb describe-table --table-name "${T}-restored" --region "$REGION" --output json)
if [ -z "$DESC" ]; then
  echo "[!] INCONCLUSIVE - describe-table returned nothing for ${T}-restored. The restore may"
  echo "    still be running, the call may have failed, or the table may not exist. Unknown."
else
  STATUS=$(printf '%s' "$DESC" | jq -r '.Table.TableStatus // empty')
  ITEMS=$(printf '%s'  "$DESC" | jq -r '.Table.ItemCount // empty')
  PROT=$(printf '%s'   "$DESC" | jq -r '.Table.DeletionProtectionEnabled // false')
  BASELINE="<items_lost-from-Query-1>"
  if [ -z "$STATUS" ] || [ -z "$ITEMS" ]; then
    echo "[!] INCONCLUSIVE - the table exists but ItemCount/TableStatus did not parse."
  elif [ "$STATUS" != "ACTIVE" ]; then
    echo "[FAIL] ${T}-restored is $STATUS, not ACTIVE - the restore has not finished"
  elif [ "$PROT" != "true" ]; then
    echo "[FAIL] ${T}-restored is ACTIVE with $ITEMS items but deletion protection is OFF."
    echo "       Restored tables come back unprotected. Re-run §3 Step 2's update-table."
  elif [ "$ITEMS" -eq 0 ]; then
    echo "[FAIL] ${T}-restored is ACTIVE and protected but holds ZERO items - the restore"
    echo "       produced an empty table. Do not re-point the application at it."
  else
    echo "[OK] ${T}-restored ACTIVE, protected, ItemCount=$ITEMS (baseline before deletion:"
    echo "     $BASELINE). Both figures are APPROXIMATE - DynamoDB refreshes ItemCount"
    echo "     periodically, so a mismatch of a few is not evidence of loss, and an exact"
    echo "     match is not evidence of integrity. Reconcile against the application."
  fi
fi
```

Every branch is reachable after the remediation: the restored table exists, so `DescribeTable`
has something to return, and the two partial outcomes that actually happen — a restore that
completes unprotected, and a restore that completes empty — land on `[FAIL]` instead of being
certified clean. Note the limit this check deliberately states rather than hides: matching
`ItemCount` is **not** proof the items are the right ones. `ItemCount` is approximate on both
sides, and a table restored to the instant before deletion contains none of the writes that
happened during the incident. Table presence is not data integrity.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource dynamodb.amazonaws.com / eventName DeleteTable / no"
echo "  errorCode / userIdentity.arn NOT on the table-lifecycle allowlist - on the FIRST"
echo "  table, not the sixth. The value_count correlation must fire at exactly five DISTINCT"
echo "  requestParameters.tableName values in ten minutes from one principal - gte, not gt."
echo "  The temporal correlation must fire critical on DeleteBackup then DeleteTable."
echo "MUST NOT fire on: DeleteTable by the pipeline role during a scheduled teardown; a"
echo "  DeleteTable that returned AccessDeniedException, NotAuthorized, ResourceInUseException"
echo "  or ResourceNotFoundException; a repeat DeleteTable against a table already DELETING,"
echo "  which returns no error and must not inflate the DISTINCT-TABLE count to five."
echo "EXPECTED FP, by design: an engineer tearing down a personal or ephemeral table outside"
echo "  the pipeline. If that is common in production, the finding is that table lifecycle is"
echo "  not owned by the pipeline."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the pipeline could destroy a production table | `dynamodb:DeleteTable` granted to an identity that never needs it at runtime; no SCP confining table lifecycle |
| The first table destroyed raised no alert | The only table-deletion rule is a unique-count above five distinct names — the single irreversible destruction is below the floor by design |
| Nobody could say how much was lost | `responseElements.tableDescription.itemCount` and `.tableSizeBytes` were in the event and were never read; after the deletion there is nothing left to measure |
| The table turned out to be unrecoverable | Deletion protection and PITR are both **off by default**, and neither was set at creation — so nothing refused the call and nothing was left behind |
| The restored table came back without TTL, tags or alarms | AWS requires those to be set up manually on a restored table; they lived only in the console, not in infrastructure code |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against a
// wildcarded ARN matches EVERY principal and denies table lifecycle outright - an outage, not
// a bypass. UpdateTable is deliberately absent: denying it would break autoscaling account-wide.
{
  "Effect": "Deny",
  "Action": ["dynamodb:DeleteTable", "dynamodb:DeleteBackup", "dynamodb:UpdateContinuousBackups"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the caller because a DynamoDB control-plane call is always made by an
  in-organisation principal. Pair it with **deletion protection and PITR set at table creation
  in infrastructure code** — both default to off, and a table protected only because someone
  remembered is a table that will be created unprotected next time. Keep key schema, indexes,
  TTL, stream settings and tags in that same code, because a restore carries none of them.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction (primary); T1490 — Inhibit System Recovery (secondary, only on the backup-then-table sequence) |
| Primary API | `dynamodb:DeleteTable`; `dynamodb:DeleteBackup` as the preceding half of the unrecoverable variant |
| Event source | `dynamodb.amazonaws.com`, **management** plane, regional — verified against AWS's DynamoDB CloudTrail control-plane list, which enumerates `DeleteTable` as logged by default |
| Key discriminator | The calling principal. `DeleteTable` carries no field separating destruction from decommissioning; volume raises urgency and the size of the work-list, not severity |
| Field shape | `requestParameters.tableName` (**may be a bare name or a full table ARN**); `responseElements.tableDescription` — a **wrapper object** — carrying `itemCount`, `tableSizeBytes`, `tableStatus: DELETING`. `itemCount` is approximate, refreshed periodically, not live |
| "Was it used" pivot | Not applicable in the usual sense — the deletion *is* the outcome. The measurable question is what survived, answered only by `ListBackups --backup-type ALL` (the default `USER` hides the `$DeletedTableBackup` system snapshot) and by `DescribeContinuousBackups` on the tables still standing |
| Blast radius | The table, all its indexes, and its stream (`DISABLED`, auto-deleted after 24 hours). Reads and writes keep succeeding briefly while the table is in `DELETING`. Recoverable only from a `$DeletedTableBackup` — created **only if PITR was on**, retained 35 days, a single instant rather than a range — or from a pre-existing on-demand backup |
| Error strings | `DeleteTable`: `InternalServerError`, `LimitExceededException`, `ResourceInUseException`, `ResourceNotFoundException`. A table already in `DELETING` returns **no error**. Plus DynamoDB Common Errors: `AccessDeniedException`, `NotAuthorized`, `ExpiredTokenException`, `IncompleteSignature`, `InternalFailure`, `MalformedHttpRequestException`, `OptInRequired`, `RequestAbortedException`, `RequestEntityTooLargeException`, `RequestTimeoutException`, `ServiceUnavailable`, `ThrottlingException`, `UnknownOperationException`, `UnrecognizedClientException`, `ValidationError` (**not** `ValidationException`). AWS names **no** error for a deletion refused by deletion protection |

### Residual Risk

The tables are gone and no step above changes that. A `$DeletedTableBackup` restores the table
as it stood at the instant of deletion and nothing later — every write the application made
during the incident is lost even after a successful restore, silently, with no error anywhere
to correlate against. The restore lands in a **new** table that does not carry over auto
scaling policies, IAM policies, CloudWatch metrics and alarms, tags, stream settings or TTL
settings, and comes back with deletion protection and PITR **off**; until those are rebuilt the
restored copy is less protected than the table that was destroyed. The 35-day expiry on the
system backup is a hard deadline that keeps running through the investigation. If PITR was off
at deletion there is no system backup at all, and the only copies are on-demand backups
predating the incident — reduced by whatever the same principal deleted first. Anything the
actor read before destroying is unrecorded: item-level reads are CloudTrail **data** events,
off by default, so there is no way to establish from the log whether this was destruction or
exfiltration followed by destruction.
