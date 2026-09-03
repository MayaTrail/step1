# IR Playbook: RDS Snapshot Exported to S3 — Database Contents Converted to Parquet Objects via `rds:StartExportTask`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data exfiltration (database contents leave RDS entirely and land in S3 as Apache Parquet, under a different service's access controls) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** for an export by a principal outside the analytics pipeline; **Critical** where the write role or the KMS key resolves to a foreign AWS account, because AWS supports a cross-account export only through the CLI and API and never through the console — it cannot be a mis-click. The source rates it **P2**, which under-rates a completed transfer that this account may not be able to observe the reading of |
| MITRE Tactics | Exfiltration, Collection |
| MITRE Techniques | T1567.002 (primary), T1530 (secondary) — both verified live 2026-08-29 |
| Services in Scope | RDS, S3 (destination bucket and its policy), KMS (the export key), IAM (the export role), CloudTrail (management, and S3 data events if configured), AWS Config, Organizations (SCP) |

**What the technique does:** the actor calls `rds:StartExportTask` with five required parameters — a task
identifier, a `sourceArn`, an `s3BucketName`, an `iamRoleArn` and a `kmsKeyId`. RDS assumes the
named role, encrypts under the named key, and writes the database out as compressed Apache Parquet
into the bucket. Optionally `exportOnly` narrows it to named databases, schemas or tables; without
it, everything goes. The source may be a snapshot of any kind — including an **automated system
snapshot**, which cannot be shared and can be exported — or, since `SourceType` admits `CLUSTER`, a
live DB cluster with no snapshot involved at all. The bucket must be in the same Region; it does
**not** have to be in the same account. From the moment the objects land, the data is governed by
that bucket's policy and Block Public Access settings, and reading it is an `s3:GetObject` data
event, which is off by default. In an account without data events on that bucket, the export is the
last thing anybody can see.

**Detection thesis.** The discriminator is the **destination**, in three fields — `s3BucketName`,
`iamRoleArn` and `kmsKeyId` — not the event name. An S3 bucket name carries no account, so the
foreign-destination test is a comparison between the account in those two ARNs and the account of
the trail record itself. The source rule matches only the event name and the absence of an error,
so it fires on every scheduled analytics export and is muted before the one that matters arrives.

> The same data can leave without ever becoming an S3 object, by
> `../rds.exfiltration.snapshot-made-public/` — a share keeps it inside RDS and hands out a restore
> right. Once it is in a bucket, `../_superseded/aws.exfiltration.s3-bucket-public-exposure/` owns it.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing RDS **management** events. `StartExportTask` carries
  `requestParameters.exportTaskIdentifier`, `.sourceArn`, `.s3BucketName`, `.s3Prefix`,
  `.iamRoleArn`, `.kmsKeyId` and `.exportOnly`. **The response renames the bucket to `s3Bucket`** —
  same value, same event, two field names — and is otherwise **flat**, because the API's output
  shape is the `ExportTask` object itself with no wrapper: `responseElements.status`,
  `.sourceType`, `.percentProgress`, `.totalExtractedDataInGB`
- **S3 data events on every bucket that is a legitimate export destination.** Without them,
  `s3:GetObject` against the exported Parquet is invisible and "was the data read" is unanswerable.
  This is the single most valuable preparation step for this technique and it is off by default
- A recorded list of **legitimate export destinations** — bucket, role and KMS key — held as data.
  All three are attacker-choosable, which is exactly why the known-good set has to exist in advance
- **KMS key policies** for the export keys, and an alarm on their modification. Every export runs
  through a symmetric key whose policy grants `kms:CreateGrant` and `kms:DescribeKey` to
  `export.rds.amazonaws.com`; an AWS-managed key's policy cannot be edited, so the key is always
  one somebody deliberately configured. That makes the key policy the tightest control point
- Object-level inventory or versioning on the destination buckets, so that deleting exported
  objects during eradication does not also delete the record of what was there

**Alerting (must be pre-configured)**
- **`StartExportTask` succeeding for a principal outside the export-pipeline allowlist → P0**
- **A snapshot created or copied and then exported by the same principal within two hours → P1**
- **A `StartExportTask` whose `iamRoleArn` or `kmsKeyId` resolves to an account other than this one → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- **The normal value for this measure, per resource, from a quiet week.** The rule compares against a resource's own history rather than a fleet average, so without the baseline the threshold is a guess.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `StartExportTask` succeeding for a principal not on the export-pipeline allowlist | CloudTrail (management) | T1567.002 |
| P1 | A snapshot created or copied, then exported by the same principal within two hours | CloudTrail (management) | T1567.002 |
| P1 | `iamRoleArn` or `kmsKeyId` on a `StartExportTask` resolving to an account other than the trail's own | CloudTrail (management) | T1567.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Three or more export tasks started by one non-pipeline principal within six hours | CloudTrail (management) | T1567.002 |
| P2 | `IamRoleMissingPermissions`, `KMSKeyNotAccessibleFault` or `InvalidS3BucketFault` in a run — the export path being assembled, before any data moves | CloudTrail (management) | T1567.002 |
| P2 | A KMS key policy gaining `kms:CreateGrant` for `export.rds.amazonaws.com` outside a change window | CloudTrail (management) | T1567.002 |
| P3 | `s3:GetObject` against an export prefix from an unexpected principal | CloudTrail (S3 data events) | T1530 |

### Detection Rule Quality Notes

The source rule matches an event name and a success filter, and never looks at where the data went.

| Issue | Impact | Correction |
|-------|--------|-----------|
| No destination check of any kind | Fires identically on the nightly analytics export and on an export into an attacker's bucket. In an account with a data pipeline it is muted within a week, and it is muted in the direction that hides a completed transfer | Allowlist the export-pipeline principal; score the destination by comparing the account in `iamRoleArn` and `kmsKeyId` against the trail's own |
| No principal check | The pipeline role is the one identity that legitimately exports, and it is the only field on the event the actor cannot choose. Bucket, role and key are all attacker-supplied | Allowlist the principal, never the bucket |
| Treats a snapshot export and a live-cluster export as one thing without noticing the second exists | `SourceType` admits `CLUSTER`, and `StartExportTask` lists `DBClusterNotFoundFault` among its errors. A control that watches snapshots misses an export that never made one | Carry `responseElements.sourceType` into the alert and triage on it |
| Nothing on the failure path | `IamRoleMissingPermissions` and `KMSKeyNotAccessibleFault` in a run are the export path being built. That is intent observed **before** the data moves, and it is the only early warning this technique offers | Ship a separate medium-priority view of the refusals |
| Nothing follows the data into S3 | The export's blast radius is the bucket's exposure as much as the database's contents, and the source set has no rule that crosses the service boundary | Hand off to the S3 exposure playbook; add data events on the destination buckets |

**Recommended detection — an export started by a principal outside the pipeline.**

```yaml
# RDS Snapshot Exported to S3 (T1567.002 / T1530)
#
# WHAT THE SOURCE RULE DOES. `eventName:"StartExportTask"` plus a success filter, grouped by
# caller. It fires on every scheduled analytics export, and it never looks at the one thing that
# separates a data pipeline from an exfiltration: THE DESTINATION.
#
# THE DESTINATION IS THE WHOLE SIGNAL, and it is three fields, not one:
#   * `s3BucketName` - and AWS supports exporting to a CROSS-ACCOUNT bucket. The console cannot
#     do it ("To export a DB snapshot to a cross-account Amazon S3 bucket, you must use the AWS
#     CLI or the RDS API"), which means a cross-account export is always scripted and never an
#     accident of the UI.
#   * `iamRoleArn` - the role RDS assumes to write the objects. A role created minutes before the
#     export is a role created FOR the export.
#   * `kmsKeyId` - REQUIRED on this API, and it must be a symmetric key whose policy grants
#     `kms:CreateGrant` and `kms:DescribeKey` to the service principal `export.rds.amazonaws.com`.
#     An AWS-managed key's policy cannot be edited, so this is a customer-managed key in
#     practice, and a key in another account is as strong a destination signal as the bucket.
#
# THE DATA LEAVES RDS ENTIRELY. The export writes Apache Parquet into S3, where a different
# service's access controls and a different service's logging govern it. Reading those objects is
# an S3 DATA event, off by default - so unless the destination bucket has data events configured,
# the export is the LAST thing you can see. The bucket's own exposure therefore becomes part of
# this incident's blast radius, and `../../_superseded/aws.exfiltration.s3-bucket-public-exposure/` is the
# playbook the response hands off to.
#
# TWO ASYMMETRIES WORTH KNOWING BEFORE YOU WRITE A QUERY. First, EXPORT WORKS ON AUTOMATED
# SNAPSHOTS: "You can export all types of DB snapshots - including manual snapshots, automated
# system snapshots, and snapshots created by the AWS Backup service." Sharing does not. So an
# actor who cannot share a system snapshot can still export it, and the create-then-act chain
# that gives away a deliberate share is often absent here. Second, `SourceArn` may be a live DB
# CLUSTER, not only a snapshot - `SourceType` is SNAPSHOT or CLUSTER - so an export can bypass
# the snapshot layer altogether.
#
# FIELD SHAPE, AND THE TRAP IN IT. The request names the destination `s3BucketName`; the
# RESPONSE names it `s3Bucket`. Those are different field names for the same value on the same
# event, and a rule that reads only one of them silently misses half the shape it is looking at.
# The response is otherwise FLAT - the API's output shape is the ExportTask object itself, with
# no wrapper - so `responseElements.status`, `.sourceType`, `.percentProgress` and
# `.totalExtractedDataInGB` sit at the top level.
title: RDS snapshot or cluster exported to S3 by a principal outside the export pipeline
id: c08b12b9-61ee-45f3-beee-34e88d868530
name: rds_export_task_started
status: experimental
description: >-
  An RDS snapshot or live cluster was exported to S3 as Parquet by a principal that does not own
  the analytics export pipeline. The data has left RDS; from here it is governed by the bucket's
  policy and visible only in S3 data events, which are off by default.
references:
  - https://attack.mitre.org/techniques/T1567/002/                                                # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1530/                                                    # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StartExportTask.html             # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ExportSnapshot.html                # retrieved 2026-08-29
tags:
  - attack.exfiltration
  - attack.collection
  - attack.t1567.002
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName: 'StartExportTask'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING - this allowlist IS the rule. Unpopulated it fires on every
  # scheduled analytics export, which is what the source rule does. Allowlist the PRINCIPAL that
  # owns the pipeline; the bucket and the role are attacker-choosable, the principal is not.
  export_pipeline:
    userIdentity.arn|contains:
      - ':role/analytics-export'    # replace with this account's export role
      - ':role/iac-deploy'          # replace with this account's deployment role
  condition: selection and success and not export_pipeline
falsepositives:
  - >-
    An analyst running a one-off export for a genuine reporting need. Common in data-heavy
    accounts; if it is common here, the finding is that exports are not owned by a pipeline.
level: high
---
# Base rule — sequence component only, not for direct alerting. Carries the success filter so a
# failed create cannot compose into the correlation below.
title: RDS manual snapshot created or copied
id: cb6d28e9-67e5-463c-8030-3f85613d6b66
name: rds_snapshot_created_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBSnapshot.html   # retrieved 2026-08-29
tags:
  - attack.defense-impairment
  - attack.t1578.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'rds.amazonaws.com'
    eventName:
      - 'CreateDBSnapshot'
      - 'CreateDBClusterSnapshot'
      - 'CopyDBSnapshot'
      - 'CopyDBClusterSnapshot'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# A snapshot taken and immediately exported is a snapshot taken IN ORDER TO export. A backup
# process creates snapshots and never exports them; an analytics pipeline exports on a schedule
# from snapshots it did not just create. Two hours covers snapshot completion on a large database.
#
# Weaker here than in the sharing case, and deliberately so: export works on AUTOMATED system
# snapshots, so an actor has no need to create one first. Absence of this correlation is not
# absence of exfiltration - it is the reason the single-event rule above is `high` on its own.
title: RDS snapshot created and exported to S3 by one principal
id: 9fd0efbd-7b20-4f5a-9554-5cba2795efdd
status: experimental
description: >-
  One principal created or copied a snapshot and then exported it to S3 within two hours. No
  backup process does this and no scheduled pipeline needs to.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ExportSnapshot.html   # retrieved 2026-08-29
tags:
  - attack.exfiltration
  - attack.t1567.002
correlation:
  type: temporal_ordered
  rules:
    - rds_snapshot_created_bb
    - rds_export_task_started
  group-by:
    - userIdentity.arn
  timespan: 2h
level: critical
---
# THRESHOLD BASIS, with no observed baseline to derive one from. AWS caps an account at five
# CONCURRENT export tasks, so an actor working through a fleet queues them in batches at that
# ceiling. Three distinct export tasks from one non-pipeline principal inside six hours is a
# sweep across databases rather than a reporting need. `gte` at the baseline, never `gt`, so a
# run that starts exactly three does not fall through. Re-baseline before deploying.
title: Multiple RDS export tasks started by one principal
id: a078c8c9-54db-4698-a17f-155b4ac37bba
status: experimental
description: >-
  One non-pipeline principal started three or more export tasks within six hours. The recovery
  work-list is every destination prefix in the group, not just the one that alerted.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ExportSnapshot.html   # retrieved 2026-08-29
tags:
  - attack.exfiltration
  - attack.t1567.002
correlation:
  type: value_count
  rules:
    - rds_export_task_started
  group-by:
    - userIdentity.arn
  field: requestParameters.exportTaskIdentifier
  timespan: 6h
  condition:
    gte: 3
level: high
```

The rule cannot tell a friendly bucket from a hostile one: S3 names are global and carry no
account, so the destination's ownership has to be derived by comparing two ARNs on the event to
each other — a field-to-field comparison Sigma has no way to express.
`detections/kql_t1567_002.kql` does it, and Query 2 below settles it with live state.

---

### Key Investigation Queries

> RDS is regional, and the destination bucket must be in the same Region as the snapshot — run these in that Region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: what was exported, where to, and under whose role and key

```bash
REGION="us-east-1"
RAW=$(for EV in StartExportTask CancelExportTask; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region, or"
  echo "    missing cloudtrail:LookupEvents. This is NOT 'nothing was exported'."
else
  # The request calls the bucket s3BucketName and the response calls it s3Bucket. Both are read.
  # The destination ACCOUNT is field 5 of the role and key ARNs; a bare key ID or an alias yields
  # an empty string, which is emitted as "unresolved" rather than defaulting to local.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "rds.amazonaws.com") |
    (.requestParameters.iamRoleArn // .responseElements.iamRoleArn // "") as $role |
    (.requestParameters.kmsKeyId   // .responseElements.kmsKeyId   // "") as $key |
    {time: .eventTime, event: .eventName, region: .awsRegion,
     caller_arn: .userIdentity.arn, access_key: .userIdentity.accessKeyId,
     task_id: (.requestParameters.exportTaskIdentifier // .responseElements.exportTaskIdentifier),
     source_arn: (.requestParameters.sourceArn // .responseElements.sourceArn),
     source_type: (.responseElements.sourceType // "unknown-at-start"),
     bucket: (.requestParameters.s3BucketName // .responseElements.s3Bucket),
     prefix: (.requestParameters.s3Prefix // .responseElements.s3Prefix // "(bucket root)"),
     role_arn: $role, kms_key: $key,
     role_account: (if ($role | startswith("arn:")) then ($role | split(":")[4]) else "unresolved" end),
     key_account:  (if ($key  | startswith("arn:")) then ($key  | split(":")[4]) else "unresolved" end),
     trail_account: .recipientAccountId,
     selection: (.requestParameters.exportOnly // "ENTIRE SNAPSHOT"),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

Compare `role_account` and `key_account` against `trail_account` on every row. Any difference is a
cross-account export, which AWS supports only through the CLI and API — it was scripted. An
`unresolved` value is unknown, not local; resolve it by hand. `selection` is the most precise
statement of **what** was taken that this account will ever hold: when it names tables, those are
the tables; when it reads `ENTIRE SNAPSHOT`, everything went. `source_type` of `CLUSTER` means no
snapshot was involved. Record `task_id`, `bucket`, `prefix`, `role_arn`, `kms_key` and `caller_arn`
as IOCs, and carry `bucket` and `prefix` into Query 2.

#### Query 2 — Inspect the destination: what is there, how exposed is it, and was it read

```bash
REGION="us-east-1"
BUCKET="<bucket-from-Query-1>"
PREFIX="<prefix-from-Query-1>"
ACCT=$(aws sts get-caller-identity --query Account --output text)

# Does this account even own the bucket? A cross-account destination fails here, and that failure
# is the finding - not an error to route around.
LOC=$(aws s3api get-bucket-location --bucket "$BUCKET" --output json 2>&1)
case "$LOC" in
  *AccessDenied*|*NoSuchBucket*|*AllAccessDisabled*)
    echo "[FAIL] $BUCKET is not readable from account $ACCT. If Query 1 showed a foreign"
    echo "       role_account or key_account, this is a COMPLETED CROSS-ACCOUNT TRANSFER."
    echo "       Nothing below can run; escalate and pursue the receiving account.";;
  *LocationConstraint*)
    echo "[OK] $BUCKET is readable from $ACCT";;
  *) echo "[!] INCONCLUSIVE - unexpected get-bucket-location output: $LOC";;
esac

# Block Public Access is the fastest read on exposure. get-public-access-block THROWS when no
# configuration exists, and "no configuration" means NOTHING IS BLOCKED - the inverse of the
# empty-means-safe reading. That error is routed to FAIL, never to OK.
PAB=$(aws s3api get-public-access-block --bucket "$BUCKET" --output json 2>&1)
case "$PAB" in
  *NoSuchPublicAccessBlockConfiguration*)
    echo "[FAIL] $BUCKET has NO public access block configuration - nothing is blocked";;
  *BlockPublicAcls*)
    ALL=$(printf '%s' "$PAB" | jq -r '[.PublicAccessBlockConfiguration | to_entries[] | .value] | all')
    if [ "$ALL" = "true" ]; then echo "[OK] $BUCKET blocks all public access"
    else echo "[FAIL] $BUCKET has a partial public access block: $(printf '%s' "$PAB" | jq -c '.PublicAccessBlockConfiguration')"; fi;;
  *) echo "[!] INCONCLUSIVE - could not read the public access block for $BUCKET: $PAB";;
esac

# What actually landed, and how much of it.
OBJ=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" --output json 2>&1)
case "$OBJ" in
  *KeyCount*)
    N=$(printf '%s' "$OBJ" | jq -r '.KeyCount')
    B=$(printf '%s' "$OBJ" | jq -r '[.Contents[]?.Size] | add // 0')
    if [ "$N" -eq 0 ]; then
      echo "[i] no objects under $BUCKET/$PREFIX. Either the export was cancelled before writing,"
      echo "    or somebody has already deleted them - check versioning before concluding."
    else
      echo "[FAIL] $N object(s), $B bytes of Parquet under $BUCKET/$PREFIX"
    fi;;
  *) echo "[!] INCONCLUSIVE - could not list $BUCKET/$PREFIX: $OBJ";;
esac

# The authoritative size and status of the transfer, while the task record survives.
TASK=$(aws rds describe-export-tasks --region "$REGION" --output json)
if [ -z "$TASK" ]; then
  echo "[!] INCONCLUSIVE - describe-export-tasks returned nothing; volume and status unknown"
else
  printf '%s' "$TASK" | jq -r '.ExportTasks[] |
    "\(.ExportTaskIdentifier)  status=\(.Status)  pct=\(.PercentProgress)  GB=\(.TotalExtractedDataInGB)  bucket=\(.S3Bucket)/\(.S3Prefix // "")  only=\(.ExportOnly // ["ALL"] | join(","))  failure=\(.FailureCause // "none")"'
fi
```

`TotalExtractedDataInGB` is the size of the transfer and belongs in the incident record; the
`StartExportTask` event does not carry it, because the task has barely begun when the event is
written. Whether anyone **read** the objects is a separate question this query cannot answer:
`s3:GetObject` is a data event and is off by default. If the destination bucket has no data-event
trail, record "unknown" rather than reporting the absence of reads as the absence of access.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CopyDBClusterSnapshot CopyDBSnapshot CreateDBClusterSnapshot CreateDBSnapshot"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "rds.amazonaws.com") |
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
elsewhere, and whether anyone else did it too. Group by caller rather than by resource: the
question the eradication phase needs answered is *how much of this is one actor's work*, and a
per-resource list cannot say. `access_key` is emitted here because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` regardless of whether it happened — see the caveat in the preamble.

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

Keyed on the access key rather than the ARN, because one credential is used across many
sessions and the key is what identifies the credential. The per-service grouping answers the
question this playbook cannot: whether this technique was the objective or one stop on a tour.
A service in that list with no business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID — so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Cancel the task before touching the principal only if it is still running — a cancelled task leaves
whatever was already written, so cancelling buys you the remainder and nothing more. If the
destination is a foreign account, the transfer is already complete in every sense that matters and
the order stops mattering: contain the principal and escalate.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Stop the transfer and cut the path it used

```bash
REGION="us-east-1"; TASK_ID="<task-id-from-Query-1>"; ROLE_ARN="<role-arn-from-Query-1>"

STATUS=$(aws rds describe-export-tasks --export-task-identifier "$TASK_ID" --region "$REGION" \
           --query 'ExportTasks[0].Status' --output text)
case "$STATUS" in
  ''|None)             echo "[!] INCONCLUSIVE - no status for $TASK_ID; the task record may have"
                       echo "    aged out or the call failed. Do not assume it is finished.";;
  STARTING|IN_PROGRESS)
    aws rds cancel-export-task --export-task-identifier "$TASK_ID" --region "$REGION" >/dev/null \
      && echo "[OK] cancelled $TASK_ID - objects already written REMAIN" \
      || echo "[FAIL] cancel-export-task did not succeed; the export is still running";;
  *)                   echo "[i] $TASK_ID is in state $STATUS - nothing to cancel, the data is written";;
esac

# The export role is the path. Denying it stops the NEXT task even if the principal survives.
case "$ROLE_ARN" in
  arn:aws:iam::*:role/*)
    R=$(echo "$ROLE_ARN" | awk -F'/' '{print $NF}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyExportWrites" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:PutObject","s3:AbortMultipartUpload"],"Resource":"*"}]}' \
      && echo "[OK] denied S3 writes to export role $R" \
      || echo "[FAIL] could not attach the deny to $R - the export path is still open";;
  *) echo "[!] INCONCLUSIVE - $ROLE_ARN is not an IAM role ARN in this account. If it belongs to"
     echo "    another account, you cannot deny it from here; revoke the KMS grant instead.";;
esac
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["rds:StartExportTask","rds:CreateDBSnapshot","rds:CreateDBClusterSnapshot","rds:CopyDBSnapshot","rds:CopyDBClusterSnapshot","rds:ModifyDBSnapshotAttribute"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case "$SUSPECT_ARN" in
  *:user/*)                                       # user ARN: name is the LAST segment
    U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$U" \
        --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
      echo "[OK] disabled key $K for $U"
    done
    aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyRdsExport" --policy-document "$DENY";;
  *:assumed-role/*)                               # role ARN: name is the 2ND segment
    R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
    aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyRdsExport" --policy-document "$DENY"
    echo "[OK] revoked pre-$CUTOFF sessions and denied RDS export for role $R";;
  *) echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
     echo "    service principal. Contain manually; neither branch above applies.";;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Inventory the destination prefix before deleting anything.** The Parquet objects are the
  evidence of what left, and deleting them destroys the only record of scope. Capture the
  `list-objects-v2` output from Query 2 to a file first, then delete.
- **Revoke the KMS grant, not just the IAM policy.** The export key's policy is what admits
  `export.rds.amazonaws.com`; while it stands, any principal that can call `StartExportTask` with
  that key can run the transfer again. `aws kms list-grants --key-id <key>` shows the grants RDS
  created, and `revoke-grant` removes them.
- **Treat the data as read if the bucket had no data events.** `s3:GetObject` is off by default,
  so the absence of read records is not evidence of no reads. Rotate every credential the exported
  tables contained and notify on the assumption of disclosure.
- **Right-size the permission.** `rds:StartExportTask` belongs to the analytics pipeline role and
  to nothing else. Pair it with an S3 bucket policy that accepts writes only from that role, so a
  stolen RDS permission has nowhere to write.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either:

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
case "$SUSPECT_ARN" in
  *:assumed-role/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')
    for P in EmergencyDenyRdsExport EmergencyRevokeSessions; do
      aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
    LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text);;
  *:user/*) N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
    aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyRdsExport"
    LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text);;
  *) N=""; LEFT="UNCHECKED";;
esac
case "$LEFT" in
  UNCHECKED)   echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify no export task is running and nothing owned by this account still holds the data

```bash
REGION="us-east-1"; BUCKET="<bucket-from-Query-1>"; PREFIX="<prefix-from-Query-1>"; VERDICT="clean"

# describe-export-tasks keeps returning every task record whatever its state, so this assertion
# stays able to fail after the cancellation in §3 - the cancelled task appears as CANCELED, not
# as an absence, and a task somebody started since appears as IN_PROGRESS.
T=$(aws rds describe-export-tasks --region "$REGION" --output json)
if [ -z "$T" ]; then
  echo "[!] INCONCLUSIVE - describe-export-tasks returned nothing at all; running tasks unknown"
  VERDICT="inconclusive"
else
  LIVE=$(printf '%s' "$T" | jq -r '[.ExportTasks[] | select(.Status == "STARTING" or .Status == "IN_PROGRESS")] | length')
  if [ "$LIVE" -gt 0 ]; then
    echo "[FAIL] $LIVE export task(s) still running:"
    printf '%s' "$T" | jq -r '.ExportTasks[] | select(.Status == "STARTING" or .Status == "IN_PROGRESS") |
      "        \(.ExportTaskIdentifier) -> \(.S3Bucket)/\(.S3Prefix // "")"'
    VERDICT="fail"
  else
    echo "[OK] no export task is in a running state in $REGION"
  fi
fi

# The objects. An empty listing here is meaningful ONLY because the bucket is known to be readable
# from Query 2 - a listing that errors is routed to INCONCLUSIVE, never to the clean branch.
OBJ=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" --output json 2>&1)
case "$OBJ" in
  *KeyCount*)
    N=$(printf '%s' "$OBJ" | jq -r '.KeyCount')
    if [ "$N" -eq 0 ]; then echo "[OK] no objects remain under $BUCKET/$PREFIX"
    else echo "[FAIL] $N exported object(s) still present under $BUCKET/$PREFIX"; VERDICT="fail"; fi;;
  *) echo "[!] INCONCLUSIVE - could not list $BUCKET/$PREFIX: $OBJ"; VERDICT="inconclusive";;
esac

case "$VERDICT" in
  clean)        echo "[OK] no running export and no exported objects remain in this account";;
  fail)         echo "[FAIL] recovery is not complete - see the lines above";;
  inconclusive) echo "[!] INCONCLUSIVE - at least one check could not run. Do not close on this.";;
esac
echo "[i] None of the above speaks to a CROSS-ACCOUNT destination. If Query 1 resolved the role or"
echo "    key to a foreign account, the data is in a bucket you cannot list and cannot delete."
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     StartExportTask / rds.amazonaws.com / no errorCode, where userIdentity.arn"
echo "  is NOT on the export-pipeline allowlist - including a sourceType of CLUSTER, where no"
echo "  snapshot was ever created, and including an export of an AUTOMATED system snapshot."
echo "MUST NOT fire on: the scheduled pipeline export by the allowlisted role; a StartExportTask"
echo "  returning IamRoleMissingPermissions, KMSKeyNotAccessibleFault, InvalidS3BucketFault or"
echo "  AccessDeniedException - those are the separate failure-path view, not a transfer."
echo "EXPECTED FP, by design: an analyst running a one-off export for a genuine reporting need."
echo "  If that is common here, the finding is that exports are not owned by a pipeline."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the analytics pipeline could move a whole database into S3 | `rds:StartExportTask` granted broadly; no bucket policy restricting writes to the pipeline role |
| The export was not distinguished from the nightly one | The deployed rule matched the event name and the success flag, and never read the destination — so the signal arrived inside a stream of legitimate exports |
| Nobody can say whether the objects were read | S3 data events were not enabled on the destination bucket, and `s3:GetObject` is off by default |
| The export key admitted the service principal to anyone who could name it | The KMS key policy granted `kms:CreateGrant` to `export.rds.amazonaws.com` without a condition confining which principals may use the key |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike, not StringNotEquals: the value is wildcarded, and * expands only in Resource and
// in the *Like operators. Deny + StringNotEquals against a wildcarded ARN matches every principal
// and denies exports outright - an outage, not a control.
{
  "Effect": "Deny",
  "Action": ["rds:StartExportTask"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/analytics-export"] }
  }
}
```

- The tightest control is not IAM at all — it is the **KMS key policy**. `StartExportTask` requires
  a symmetric key whose policy admits `export.rds.amazonaws.com`, and an AWS-managed key cannot be
  edited to do that. Confine the export key to the pipeline role with a `kms:ViaService` and a
  principal condition, and no other identity can complete an export regardless of its RDS
  permissions. Pair it with a destination bucket policy that accepts `s3:PutObject` only from the
  export role, and with S3 data events on that bucket so the read side is observable at all.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage (primary); T1530 — Data from Cloud Storage (secondary). Where the destination is a foreign account, **T1537 — Transfer Data to Cloud Account** is better scoped and is the mapping to cite: T1567/T1567.002 do not list IaaS among their platforms, while T1537 does |
| Primary API | `rds:StartExportTask`; `rds:CancelExportTask` and `rds:DescribeExportTasks` for the response |
| Event source | `rds.amazonaws.com`, **management** plane, regional — verified against AWS's RDS CloudTrail documentation. The destination bucket must be in the same Region as the source |
| Key discriminator | The destination, in three fields — `s3BucketName`, `iamRoleArn`, `kmsKeyId`. An S3 name carries no account, so ownership comes from comparing the ARNs' account to the trail's own |
| Field shape | Request: `exportTaskIdentifier`, `sourceArn`, `s3BucketName`, `iamRoleArn`, `kmsKeyId` (all **required**), `s3Prefix`, `exportOnly`. **Response renames the bucket to `s3Bucket`** and is otherwise **flat** — the output shape is the `ExportTask` object with no wrapper: `.status`, `.sourceType` (`SNAPSHOT` or `CLUSTER`), `.percentProgress`, `.totalExtractedDataInGB` |
| "Was it used" pivot | `s3:GetObject` on the destination prefix — a **data** event, off by default. With no data-event trail on that bucket, `StartExportTask` is the last observable step and the read side is unknowable. `describe-export-tasks` gives the transferred volume while the task record survives |
| Blast radius | Every row in the selected scope, as queryable Parquet, plus the destination bucket's own exposure. `exportOnly` names the databases, schemas or tables taken; when absent, the whole snapshot went. Export works on **automated system snapshots**, which cannot be shared — so a control built only on the sharing path does not cover this |
| Error strings | `StartExportTask`: `DBSnapshotNotFound`, `DBClusterSnapshotNotFoundFault`, `DBClusterNotFoundFault`, `ExportTaskAlreadyExists`, `IamRoleMissingPermissions`, `IamRoleNotFound`, `InvalidExportOnly`, `InvalidExportSourceState`, `InvalidS3BucketFault`, `KMSKeyNotAccessibleFault`. `CancelExportTask`: `ExportTaskNotFound`, `InvalidExportTaskStateFault`. Note the irregular suffixes — some codes carry `Fault` and some do not, and CloudTrail carries the **wire** code, not the SDK shape name. Denials: `AccessDeniedException` (403), `NotAuthorized` (401); the bare `AccessDenied` form is **not** documented for RDS. Common: `InvalidParameterValue`, `InvalidParameterCombination`, `ValidationError`, `ThrottlingException` |

**MITRE mapping note.** This is the only one of the five RDS rules in this batch whose source
mapping needed no correction on the merits — **T1567.002 / TA0010** is what an export to S3 is, and
it is retained as primary. **T1530** is added as a genuine second mapping for the read that the
export enables, and here S3 genuinely is cloud storage in ATT&CK's sense. The honest caveat is
platform scope: T1567 and T1567.002 do not list IaaS, while **T1537** does — so for a
foreign-account destination, cite T1537.

### Residual Risk

The objects are deleted and the task is cancelled, and neither tells you whether the Parquet was
read: `s3:GetObject` is a data event, off by default, so in most accounts the export is the last
observable step and "was it taken" closes as unknown. Credential rotation for everything the
exported tables held is therefore not precautionary — it is the only remediation that does not
depend on evidence you do not have. If the destination resolved to another account, nothing in §3
or §4 reached it at all: you cannot list that bucket, you cannot delete those objects, and the
transfer is complete. And the path stays open while the KMS key policy still admits
`export.rds.amazonaws.com` for any principal that can name the key — the IAM deny is a lock on one
door in a room with two.
