# IR Playbook: DynamoDB Backup Enumeration — reconnaissance of the recovery path via `dynamodb:ListBackups`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Discovery (a principal inventories the recovery points that exist, immediately before destroying or copying them) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Informational on its own; High to Critical for what it precedes. Enumeration is a read and is performed constantly by the console and by reporting jobs. It becomes an incident when the same principal then deletes a backup, restores one under a different name, or turns off point-in-time recovery. The source rule rates it P4 and fires on every occurrence, which is why nobody reads it. |
| MITRE Tactics | Discovery |
| MITRE Techniques | T1580 |
| Services in Scope | DynamoDB, IAM, CloudTrail, AWS Backup where used |

**What the technique does:** the actor calls `dynamodb:ListBackups` to learn which recovery points
exist and for which tables. It is a read — nothing changes, nothing breaks, no alarm has anything
to fire on. What it buys is a target list, and it is followed by one of two things. Either
`DeleteBackup`, removing the recovery path before destroying the table; or
`RestoreTableFromBackup` into a **new table name**, which produces a complete copy of the data
while leaving the original untouched and every application working normally.

**Why the usual reflexes miss it.** The reflex is to alert on the enumeration, which is what the
source rule does — and enumeration is routine, so the rule produces constant volume and is rated
down until it is effectively off. The second reflex is to watch for deletion, which misses the copy
path entirely: a restore is an ordinary recovery operation and looks like remediation. The third is
to check that backups still exist, which misses `UpdateContinuousBackups` disabling point-in-time
recovery — that removes a recovery path without touching a single backup object.

**Detection thesis:** the enumeration is a base rule and never an alert. The signal is the ordered
pair — enumerate then delete, or enumerate then restore under a different name — and in the second
case the discriminator is one field, whether `targetTableName` differs from `sourceTableName`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `dynamodb.amazonaws.com`.** `ListBackups`, `DescribeBackup`,
  `DeleteBackup`, `RestoreTableFromBackup`, `RestoreTableToPointInTime` and
  `UpdateContinuousBackups` are management events and on by default.
- **A record of which tables have point-in-time recovery enabled**, refreshed on a schedule.
  `UpdateContinuousBackups` disabling it removes a recovery path with no backup object involved,
  and nothing else records that the path used to exist.
- **The backup schedule and its owning principal**, so a `DeleteBackup` outside the retention
  policy is distinguishable from the policy doing its job.
- **Item-level data events where the data warrants it.** They are off by default and billable, and
  without them what was read from a restored copy is not recorded anywhere.

**Alerting (must be pre-configured)**
- **`ListBackups` followed by `DeleteBackup` by the same principal within 24 hours → P0**
- **`ListBackups` followed by a restore whose `targetTableName` differs from `sourceTableName` → P0**
- **`UpdateContinuousBackups` disabling point-in-time recovery → P1**
- **`ListBackups` followed by any restore by the same principal within 24 hours → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under
  investigation, and `jq`.
- The table's expected item count and size from monitoring, so a restored copy can be compared
  against what it claims to be.
- The retention policy and the backup schedule in writing, since the whole triage rests on whether
  a deletion was the policy or a person.

**Known IOC Baselines**
- **Which principals legitimately delete backups or perform restores.** In most estates this is a
  backup automation role and nobody else, which makes an unfamiliar caller a finding before the
  sequence is even considered.
- The set of table names that exist. A restore target that is not among them is a new object, and a
  new object holding a copy of production data is the finding.
- Which tables have PITR enabled today, so a disable is a diff rather than a discovery.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ListBackups` then `DeleteBackup` by the same principal within 24 hours | CloudTrail (management) | T1490 |
| P0 | `ListBackups` then a restore whose `targetTableName` differs from `sourceTableName` | CloudTrail (management) | T1530 |
| P1 | `UpdateContinuousBackups` with `pointInTimeRecoveryEnabled: false` | CloudTrail (management) | T1490 |
| P1 | `ListBackups` then any restore by the same principal within 24 hours | CloudTrail (management) | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | More than five refused backup or restore calls by one principal in an hour — mapping the recovery path | CloudTrail (management) | T1580 |
| P2 | `ListBackups` by a principal with no prior backup-related activity | CloudTrail (management) | T1580 |
| P3 | `ListBackups` on its own — routine, and the base rule the correlations are built over | CloudTrail (management) | T1580 |

### Detection Rule Quality Notes

The source rule is `eventSource:"dynamodb.amazonaws.com" AND eventName:"listbackups"`, immediate
and ungrouped, so every row below is auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Alerts immediately on a read-only enumeration | `ListBackups` is called by the console, by reporting jobs and by any recovery-point inventory. Firing on every occurrence produces constant volume from routine operation, which is why it is rated P4 and lands where nobody reads it | The enumeration becomes an **informational base rule**. The signal moves to ordered correlations built over it |
| No grouping and no principal filter | The rule cannot say who enumerated, so even when read it produces no actionable next step | Group by `userIdentity.arn`; the correlations key on the same principal performing both halves |
| Watches the reconnaissance and never what it was for | `ListBackups` before `DeleteBackup` is preparation for destruction; before a renamed restore it is preparation for a copy. Those are different incidents and the rule reports neither | Two `temporal_ordered` correlations, one per outcome, each carrying the technique that actually applies |
| Cannot distinguish a recovery from a copy | The restore API is identical for both. The one available discriminator — whether `targetTableName` differs from `sourceTableName` — is in the request and unused | A dedicated trigger on the renamed restore, and the KQL surfaces it as `RenamedRestores` rather than as a restore count |
| No coverage of point-in-time recovery | `UpdateContinuousBackups` removes a recovery path with no backup object involved. Nothing enumerable disappears, so a backup-focused rule sees nothing at all | Shipped as its own rule, and combined with deletion in the KQL verdict as the highest-severity shape |
| MITRE `T1490` on the enumeration | That technique is destroying the recovery path, which reading it is not | `T1580` for the enumeration; `T1490` retained where deletion follows; `T1530` where a copy follows |

**Recommended detection — the enumeration as a base rule, the sequence as the signal.**

```yaml
# DynamoDB Backup Enumeration (T1580)
#
# THE HONEST VERDICT ON THE SOURCE RULE: as a per-event alert it is noise, and it should be
# demoted rather than tuned. `ListBackups` is `readOnly: true` and is emitted by the DynamoDB
# console's Backups tab on every page load, by AWS Backup and third-party backup tooling
# polling for recovery points, by configuration and compliance scanners, by infrastructure-code
# plan runs, and by the responder running `aws dynamodb list-backups` while working an
# incident. The source rule matches the event name with no principal filter, no error filter
# and no threshold. Deployed as written it fires continuously, gets muted inside a week, and
# then contributes nothing - which is the single most common way a detection rule fails.
#
# The source rates it P4. That priority is CORRECT and is the rule's best feature; the defect
# is that it is an alert at all rather than a building block.
#
# THERE IS NO "EXCESSIVE" VERSION OF THIS, AND THAT IS WHY NO VOLUME RULE IS SHIPPED.
# ListBackups' TableName parameter is optional. Called without it, one request enumerates every
# backup in the account and Region, up to the documented Limit of 100 per page with
# LastEvaluatedBackupArn for the rest. A single call is therefore the complete enumeration, so
# a threshold on call count measures pagination, not intent. Compare
# ../../dynamodb.impact.multiple-tables-created/ where a fan-out threshold does mean something.
#
# WHY IT IS STILL WORTH SHIPPING AS A COMPONENT. ListBackups is one of the very few DynamoDB
# reconnaissance APIs that is a CloudTrail management event at all. Enumerating the DATA -
# Scan, Query, GetItem, BatchGetItem - is a DATA event, off by default, so in a default account
# it produces nothing forever. Enumerating the RECOVERY POINTS is visible by default. That
# asymmetry means the only reconnaissance you can reliably see is the reconnaissance of the
# things that would let you recover, which is exactly the reconnaissance that precedes
# destruction. It earns its place in a sequence, not on its own.
#
# CASING. The source rule matches `listbackups` in lower case while its siblings in the same
# set use the API's PascalCase. CloudTrail's eventName is `ListBackups`. Whether the lower-case
# form matches is a property of the search platform's index mapping, not of the technique, so a
# port to another engine must normalise casing first.
title: DynamoDB backups enumerated
id: 5a1e73b8-c204-4f96-8e7d-b3906c1af528
name: dynamodb_backups_listed_bb
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. ListBackups is readOnly and is
  emitted by console page loads, backup tooling, compliance scanners and responders; alerting on
  it per event produces noise that gets the rule muted. It carries signal only as the first half
  of the sequences below.
references:
  - https://attack.mitre.org/techniques/T1580/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ListBackups.html  # retrieved 2026-08-29
tags:
  - attack.discovery
  - attack.t1580
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'ListBackups'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# Base rule — sequence component only, not for direct alerting. Success-filtered so a DENIED
# DeleteBackup cannot compose into a high-severity correlation (D-f). Its own use case, with
# the full response procedure, is ../../dynamodb.impact.backup-was-deleted/; it is duplicated
# here because a Sigma correlation can only resolve base rules defined in the same file.
title: DynamoDB backup deleted
id: e7c48b20-95d3-4a17-bf62-08a1c5e73d94
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
# Base rule — sequence component only, not for direct alerting. Both restore APIs are matched:
# RestoreTableFromBackup takes a BackupArn, RestoreTableToPointInTime takes a source table and
# a timestamp, and both produce a NEW table containing a copy of the data. That is the point.
title: DynamoDB table restored from a backup or to a point in time
id: 90b2f4c7-1d85-4e63-a09f-6c47e28b5d13
name: dynamodb_table_restored_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_RestoreTableFromBackup.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_RestoreTableToPointInTime.html  # retrieved 2026-08-29
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName:
      - 'RestoreTableFromBackup'
      - 'RestoreTableToPointInTime'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# ENUMERATE, THEN DESTROY. This is the sequence the source rule's own description gestures at -
# "A threat actor can list the DynamoDB table backups to understand which tables have backups.
# They can then delete them" - and does not implement. Ordered, because the reverse is
# housekeeping: listing backups AFTER deleting one is verifying the deletion.
#
# One hour, not minutes: a single ListBackups returns the whole account inventory, so there is
# no pagination burst to wait out and no reason for an actor to hurry, while an hour is short
# enough that ordinary console browsing followed by unrelated scheduled pruning does not
# collide. The base rules are success-filtered, so a refused deletion cannot compose into this.
title: DynamoDB backups enumerated and then deleted by the same principal
id: 3d6a09e5-7b41-42fc-95a8-e0d17c4b6829
status: experimental
description: >-
  One principal listed the account's backups and then deleted one. Enumeration followed by
  destruction of recovery points is the preparation stage of an unrecoverable table deletion,
  and it is the last point at which the incident is still fully recoverable.
references:
  - https://attack.mitre.org/techniques/T1490/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1580/  # retrieved 2026-08-29
tags:
  - attack.discovery
  - attack.t1580
  - attack.impact
  - attack.t1490
correlation:
  type: temporal_ordered
  rules:
    - dynamodb_backups_listed_bb
    - dynamodb_backup_deleted_bb
  group-by:
    - userIdentity.arn
  timespan: 1h
level: high
---
# ENUMERATE, THEN COPY. The quieter half of this use case, and the one nothing in the source
# set covers. A restore ALWAYS creates a NEW table - AWS: "The point-in-time recovery process
# always restores to a new table" - and the restore APIs let the caller choose the target name
# and, for RestoreTableFromBackup, a different Region. So a principal who cannot read a
# production table in place, but can restore its backup into a table name their own IAM policy
# permits, obtains a complete copy of the data without a single item-level read.
#
# That path is entirely management-plane and therefore visible by default, which is unusual:
# the equivalent read of the live table is a DATA event and is invisible in a default account.
# Restoring is also legitimate and common, which is why this is a sequence rather than an alert
# on the restore alone - and why the analyst must check the TARGET name and Region.
title: DynamoDB backups enumerated and then restored into a new table by the same principal
id: c1847fa3-2e69-4d05-b7c1-9358e0a2df64
status: experimental
description: >-
  One principal listed the account's backups and then restored one into a new table. A restore
  always creates a new table, so this is a full copy of the source data under a name - and
  possibly in a Region - of the caller's choosing, obtained without any item-level read.
references:
  - https://attack.mitre.org/techniques/T1580/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1530/  # retrieved 2026-08-29
tags:
  - attack.discovery
  - attack.t1580
  - attack.collection
  - attack.t1530
correlation:
  type: temporal_ordered
  rules:
    - dynamodb_backups_listed_bb
    - dynamodb_table_restored_bb
  group-by:
    - userIdentity.arn
  timespan: 1h
level: high
```

What this set structurally cannot do: it cannot tell you what a restored copy contains, because
item-level operations are data events and are off by default — `lookup-events` returns zero for
them whether or not they happened. And it cannot establish that a restore was illegitimate; the API
is identical for a recovery, and the only evidence of intent is whether an incident record exists
outside AWS.

---

### Key Investigation Queries

> DynamoDB is regional and these are **management** events, on by default. Item-level operations
> are **data** events and are not returned by `lookup-events` at all. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events
> per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: the sequence this principal performed

```bash
REGION="us-east-1"
PRINCIPAL_KEY="<access-key-from-the-alert>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$PRINCIPAL_KEY" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "dynamodb.amazonaws.com") |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     table: (.requestParameters.tableName // .requestParameters.sourceTableName // "-"),
     target: (.requestParameters.targetTableName // "-"),
     backup: (.requestParameters.backupArn // "-"),
     pitr: (.requestParameters.pointInTimeRecoverySpecification.pointInTimeRecoveryEnabled // "-"),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read it in order. `ListBackups` then `DeleteBackup` is preparation for destruction, and the backup
is already gone by the time you are reading this — deletion is immediate and there is no recycle
bin. `ListBackups` then a restore where `target` differs from `table` is a **copy**: the original is
intact, nothing broke, and a full duplicate of the data now exists. `pitr` reading `false` on an
`UpdateContinuousBackups` is a third recovery path removed without any backup object involved.

#### Query 2 — Sweep: the same sequence anywhere else in the account

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in ListBackups DeleteBackup RestoreTableFromBackup RestoreTableToPointInTime UpdateContinuousBackups; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "dynamodb.amazonaws.com") |
      {event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId, time: .eventTime,
       error: (.errorCode // "SUCCESS")}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

A caller whose `events` array contains **both** an enumeration and a deletion or restore is the
shape the correlations detect; this finds the ones outside the alert window. A caller that appears
only with `ListBackups` is doing inventory, which is what most of this traffic is.

#### Query 3 — Inspect: what still exists, and what a restore produced

```bash
REGION="us-east-1"
TABLE="<table-from-Query-1>"
TARGET="<target-from-Query-1>"

echo "== recovery points that survive for the source table =="
aws dynamodb list-backups --table-name "$TABLE" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.BackupSummaries[]? | "\(.BackupCreationDateTime)  \(.BackupStatus)  \(.BackupType)  \(.BackupSizeBytes) bytes  \(.BackupArn)"' \
  || echo "[!] none listed — either none exist, or this principal cannot see them"

echo
echo "== is point-in-time recovery still enabled =="
aws dynamodb describe-continuous-backups --table-name "$TABLE" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.ContinuousBackupsDescription |
    "continuous=\(.ContinuousBackupsStatus)  pitr=\(.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus)  earliest=\(.PointInTimeRecoveryDescription.EarliestRestorableDateTime // "-")"'

echo
echo "== if a restore ran, what did it create =="
if [ -n "$TARGET" ] && [ "$TARGET" != "-" ]; then
  aws dynamodb describe-table --table-name "$TARGET" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Table | "target=\(.TableName)  items=\(.ItemCount)  bytes=\(.TableSizeBytes)  created=\(.CreationDateTime)  arn=\(.TableArn)"' \
    || echo "[i] target table not found — it may already have been deleted"
fi
```

`ItemCount` and `TableSizeBytes` are updated roughly every six hours, so a freshly restored table
may report zero for both — that is staleness, not an empty copy, and reading it as an empty copy is
the mistake this note exists to prevent. Compare the target's size against the source's once the
figures settle.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique)})'
```

Keyed on the access key rather than the ARN, since one credential spans many sessions. Look
particularly for S3 activity in the same window: a restored copy is most useful to an actor once
its contents leave, and an export or a scan-and-write is where that shows.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

What to contain depends entirely on which sequence Query 1 showed. Establish that first — the
deletion case and the copy case have almost nothing in common.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being investigated.

#### Step 1 — Establish which sequence occurred

```bash
SEQ="<from Query 1: delete | renamed-restore | pitr-off | enumeration-only>"

case "$SEQ" in
  delete)           echo "[i] Recovery path destroyed. Deletion is immediate and irreversible —"
                    echo "    Step 2 is about what SURVIVES, not about restoring what went." ;;
  renamed-restore)  echo "[i] A COPY exists. The original is intact and nothing is broken, which is"
                    echo "    why nothing alerted. Step 3 removes the copy and scopes the exposure." ;;
  pitr-off)         echo "[i] Point-in-time recovery disabled — a recovery path removed with no"
                    echo "    backup object involved. Re-enable it in Step 4; the window is lost." ;;
  enumeration-only) echo "[i] Reconnaissance only. Contain the principal and watch for the second"
                    echo "    half; nothing has been destroyed or copied yet." ;;
  *)                echo "[!] Sequence not determined — re-read Query 1 before acting." ;;
esac
```

#### Step 2 — Preserve what survives

```bash
REGION="us-east-1"
TABLE="<table-from-Query-1>"

REMAINING=$(aws dynamodb list-backups --table-name "$TABLE" --region "$REGION" \
            --output json 2>/dev/null | jq '[.BackupSummaries[]?] | length')
echo "[i] surviving on-demand backups for $TABLE: ${REMAINING:-0}"
if [ "${REMAINING:-0}" -eq 0 ]; then
  echo "[FAIL] no on-demand backup remains. Point-in-time recovery is the only path left —"
  echo "       confirm it is ENABLED before anything else touches this table."
else
  aws dynamodb create-backup --table-name "$TABLE" \
    --backup-name "ir-$(date -u +%Y%m%dT%H%M%SZ)" --region "$REGION" --output json | \
    jq -r '"[OK] protective backup created: \(.BackupDetails.BackupArn)"'
fi
```

A fresh backup taken now is cheap and pins the current state before any remediation touches the
table. Take it before deciding anything else.

#### Step 3 — Remove the unauthorised copy, after recording it

```bash
REGION="us-east-1"
TARGET="<target-from-Query-1>"

if [ -n "$TARGET" ] && [ "$TARGET" != "-" ]; then
  aws dynamodb describe-table --table-name "$TARGET" --region "$REGION" --output json 2>/dev/null | \
    jq '.Table | {TableName, TableArn, ItemCount, TableSizeBytes, CreationDateTime}' \
    | tee "./copy-${TARGET}.json"
  echo "[i] recorded above. Delete only after the incident record is written — the table IS the"
  echo "    evidence of what was copied, and its ARN is what any downstream grant would reference:"
  echo "    aws dynamodb delete-table --table-name $TARGET --region $REGION"
fi
```

#### Step 4 — Contain the principal and restore the recovery path

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
REGION="us-east-1"
TABLE="<table-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi

aws dynamodb update-continuous-backups --table-name "$TABLE" --region "$REGION" \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true --output json 2>/dev/null | \
  jq -r '"[OK] PITR: \(.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus)"' \
  || echo "[i] PITR already enabled, or not permitted from this principal"
```

Re-enabling point-in-time recovery restores the path going forward. **It does not restore the
window that was lost** — the earliest restorable time resets, so anything that happened while it
was off is unrecoverable.

---

## 4. Eradication

### Remove Attacker Access

#### Account for every copy

Query 2's caller list, filtered to restores, is the work-list. Each restored table is a full copy of
its source and carries none of the source's access controls unless they were reapplied — the
restore creates a new resource with default permissions.

#### Right-size backup and restore permissions

`dynamodb:DeleteBackup`, `dynamodb:RestoreTableFromBackup`, `dynamodb:RestoreTableToPointInTime`
and `dynamodb:UpdateContinuousBackups` belong to a backup automation role, not to application
credentials. Query 4's principal is the starting point.

#### Move the recovery path where the workload account cannot reach it

AWS Backup with a vault in a separate account, and vault lock where the retention requirement
justifies it, makes deletion require access the workload principal does not have. This is the only
control here that survives full compromise of the account.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or retired, and
remove the protective backup from Step 2 once a normal recovery point exists.

---

## 5. Recovery

### Restore Clean State

#### Verify a recovery path exists for every table that needs one

```bash
REGION="us-east-1"
BAD=0
for T in $(aws dynamodb list-tables --region "$REGION" --output json | jq -r '.TableNames[]'); do
  P=$(aws dynamodb describe-continuous-backups --table-name "$T" --region "$REGION" \
      --output text --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' 2>/dev/null)
  B=$(aws dynamodb list-backups --table-name "$T" --region "$REGION" --output json 2>/dev/null | \
      jq '[.BackupSummaries[]?] | length')
  if [ "$P" != "ENABLED" ] && [ "${B:-0}" -eq 0 ]; then
    echo "[FAIL] $T has neither PITR nor an on-demand backup"; BAD=$((BAD+1))
  fi
done
[ "$BAD" -eq 0 ] && echo "[OK] every table has at least one recovery path"
```

#### Verify no unaccounted-for copy remains

```bash
REGION="us-east-1"
KNOWN="<space-separated-list-of-expected-table-names>"
for T in $(aws dynamodb list-tables --region "$REGION" --output json | jq -r '.TableNames[]'); do
  echo "$KNOWN" | tr ' ' '\n' | grep -qx "$T" || echo "[!] $T is not on the expected-table list"
done
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  ListBackups then DeleteBackup by the same userIdentity.arn within 24 hours"
echo "and MUST fire on the case the source rule cannot represent at all:"
echo "  ListBackups then RestoreTableFromBackup with"
echo "  sourceTableName=orders targetTableName=orders-copy"
echo "  (a COPY — the original is untouched and nothing breaks)"
echo "The rule MUST NOT alert on:"
echo "  ListBackups alone by the backup automation role"
echo "  (the base rule records it at informational; that is the whole point)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could enumerate every recovery point | `dynamodb:ListBackups` granted broadly, and enumeration treated as harmless because it is a read |
| The enumeration alert was not read | It fired on every occurrence of a routine call, with no principal filter and no grouping, at P4 |
| A restore under a new name was not noticed | Nothing compared `targetTableName` against `sourceTableName`, and a copy breaks nothing |
| A recovery path was removed with no backup involved | `UpdateContinuousBackups` disabling PITR was not monitored |
| Backups were deletable by the same principal that could delete the table | The recovery path lived in the same account and under the same permission boundary as the data |

### Recommended Guardrails

**Keep the recovery path out of the workload's reach**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["dynamodb:DeleteBackup", "dynamodb:UpdateContinuousBackups",
             "dynamodb:RestoreTableFromBackup", "dynamodb:RestoreTableToPointInTime"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/BackupAutomation"] } }
}
```

**Structural controls**
- Use AWS Backup with a vault in a separate account, and vault lock where retention is a
  requirement. It is the only control here that survives compromise of the workload account.
- Enable point-in-time recovery on every table holding data worth recovering, and alert on it being
  disabled. It is a single boolean and it is the recovery path most often removed silently.
- Apply the source table's access controls to any restored table as part of the restore procedure.
  A restore creates a new resource with default permissions, which is how a copy ends up more
  readable than its original.

**Detection improvements**
- Do not alert on read-only enumeration. Make it a base rule and put the signal in what follows —
  otherwise the rule's volume guarantees it is rated down until it is off.
- Compare `targetTableName` against `sourceTableName` on every restore. One field separates a
  recovery from a copy, and nothing else in the event does.
- Watch `UpdateContinuousBackups` alongside `DeleteBackup`. They remove different recovery paths and
  a rule watching backups sees only one of them.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1580 — Cloud Infrastructure Discovery |
| MITRE tactic | Discovery (TA0007) |
| Primary API | `dynamodb:ListBackups`; `DeleteBackup`, `RestoreTableFromBackup` and `UpdateContinuousBackups` as the outcomes |
| Event source | dynamodb.amazonaws.com, management plane, on by default. Item-level operations are **data** events and are off by default |
| Key discriminator | The ordered pair — enumeration followed by deletion or by a restore whose `targetTableName` differs from `sourceTableName`. The enumeration alone carries no signal |
| Ground-truth signal | `list-backups` and `describe-continuous-backups` — live state, since deletion is immediate and leaves nothing behind |
| "Was it used" pivot | For the copy path, the restored table's existence and size. For the deletion path there is no pivot: the backup is gone |
| Blast radius | For deletion, the recovery window for that table. For a copy, every item in it, in a new resource carrying default permissions |
| Error strings | `BackupNotFoundException`, `TableNotFoundException`, `ContinuousBackupsUnavailableException`, `LimitExceededException`, plus `AccessDenied` / `AccessDeniedException` — match both forms |

**MITRE mapping note:** the source carries `T1490 — Inhibit System Recovery`, which describes
destroying the recovery path rather than reading it — the rule matches an enumeration.
`T1580 — Cloud Infrastructure Discovery` covers the enumeration; `T1490` is retained on the
enumerate-then-delete correlation, where it is exactly right; and `T1530 — Data from Cloud Storage`
on the enumerate-then-restore correlation, where the objective is the data rather than its
availability. All verified live 2026-08-30.

### Residual Risk

A deleted backup is gone: deletion is immediate, there is no recycle bin, and no support path
recovers it. Time spent looking for one is time not spent establishing what survives. If
point-in-time recovery was disabled, the window lost while it was off does not return when it is
re-enabled — the earliest restorable time simply resets. A restored copy that was deleted during
containment may already have been read, and item-level reads are data events that are off by
default, so what left it is not knowable from AWS unless a data-event trail existed beforehand. And
`ItemCount` and `TableSizeBytes` update roughly every six hours, so any size comparison made shortly
after a restore is comparing against a stale figure rather than an empty table.
