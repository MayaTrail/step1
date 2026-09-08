# Detection Note — T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage)

**Signal:** `StartExportTask` moved an RDS snapshot — or a live DB cluster — into an S3 bucket as
Apache Parquet.

**This is the only RDS exposure where the data physically leaves the service.** A public instance
is still your instance; a shared snapshot is still an RDS resource in RDS's control plane. An
export produces ordinary S3 objects, governed from that moment by a bucket policy, a Block Public
Access setting and an object ownership model that have nothing to do with RDS. The blast radius
therefore includes the destination bucket's own exposure, and the response has a phase none of its
neighbours has: an S3 review, handed off to
`../../_superseded/aws.exfiltration.s3-bucket-public-exposure/` when the bucket turns out to be reachable.

## What the original rule got wrong

It matches the event name and the absence of an error, and never looks at the destination — so it
fires on every scheduled analytics export in an account that has one, and gets muted. **The
destination is the entire signal, and it is three fields:**

- **`s3BucketName`.** AWS supports exporting to a **cross-account** bucket, and documents that the
  console cannot do it: *"To export a DB snapshot to a cross-account Amazon S3 bucket, you must use
  the AWS CLI or the RDS API."* A cross-account export is therefore always scripted, never a
  mis-click. The bucket must be in the **same Region** as the snapshot — *"The S3 bucket to export
  to must be in the same AWS Region as the snapshot"* — which is a useful narrowing, not a control.
- **`iamRoleArn`.** The role RDS assumes to write the objects. A role created shortly before the
  export is a role created for it.
- **`kmsKeyId`.** **Required** on this API. The key must be symmetric and its policy must grant
  `kms:CreateGrant` and `kms:DescribeKey` to the service principal `export.rds.amazonaws.com`.
  AWS never writes the sentence "a customer managed key is required" — but an AWS-managed key's
  policy cannot be edited, so a CMK is required *by implication*, and a key in another account is
  as strong a destination signal as the bucket.

An S3 bucket name carries no account, so the foreign-destination test has to come from the two
ARNs on the same event. That is a field-to-field comparison, which Sigma cannot express and
`kql_t1567_002.kql` does.

## Two asymmetries against the sharing case

**Export works on automated system snapshots.** *"You can export all types of DB snapshots —
including manual snapshots, automated system snapshots, and snapshots created by the AWS Backup
service."* Sharing does not: an automated snapshot must be copied to a manual one first. So the
create-then-act chain that betrays a deliberate share is frequently **absent** here, and its
absence proves nothing. That is why the single-event rule stands at `high` on its own and the
correlation is a bonus rather than the backbone.

**The source may be a live cluster.** `SourceType` is `SNAPSHOT` or `CLUSTER`, and `StartExportTask`
lists `DBClusterNotFoundFault` among its errors. An export can bypass the snapshot layer entirely,
so a control or a query that watches only snapshots misses it.

## Field shape, and the trap in it

`eventSource` `rds.amazonaws.com`, **management** plane, regional.

Request: `exportTaskIdentifier`, `sourceArn`, `s3BucketName`, `iamRoleArn`, `kmsKeyId` — all
required — plus optional `s3Prefix` and `exportOnly`.

**The request calls the destination `s3BucketName`; the response calls it `s3Bucket`.** Same value,
same event, two names. A rule or query reading only one of them is reading half the event.

`responseElements` is **flat** here, and for a different reason than elsewhere in RDS: the API's
output shape *is* the `ExportTask` object, with no wrapper at all. So
`responseElements.exportTaskIdentifier`, `.sourceArn`, `.s3Bucket`, `.s3Prefix`, `.iamRoleArn`,
`.kmsKeyId`, `.status`, `.sourceType`, `.exportOnly`, `.percentProgress` and
`.totalExtractedDataInGB` all sit at the top level. At start time `status` is an early value and
`totalExtractedDataInGB` is not yet meaningful — the completed size comes from
`describe-export-tasks` while the task record survives.

**`exportOnly` is the most precise statement of what was taken that this account will ever hold.**
It names the databases, schemas or tables selected. When it is absent the whole snapshot went.

## Error strings

`StartExportTask`, complete: `DBSnapshotNotFound` (404), `DBClusterSnapshotNotFoundFault` (404),
`DBClusterNotFoundFault` (404), `ExportTaskAlreadyExists` (400), `IamRoleMissingPermissions` (400),
`IamRoleNotFound` (404), `InvalidExportOnly` (400), `InvalidExportSourceState` (400),
`InvalidS3BucketFault` (400), `KMSKeyNotAccessibleFault` (400).
`CancelExportTask`: `ExportTaskNotFound` (404), `InvalidExportTaskStateFault` (400).

Note the irregularity: `DBSnapshotNotFound` drops the `Fault` suffix while
`DBClusterSnapshotNotFoundFault`, `InvalidS3BucketFault` and `KMSKeyNotAccessibleFault` keep it,
and `InvalidExportSourceState` drops it while `InvalidExportTaskStateFault` keeps it. CloudTrail
carries the **wire** code, not the SDK shape name; AWS's own export documentation shows the pair
in one line — *"ExportTaskAlreadyExistsFault: An error occurred (**ExportTaskAlreadyExists**) when
calling the StartExportTask operation"* — and the parenthesised value is what lands in
`errorCode`. Match on the stem.

`IamRoleMissingPermissions` and `KMSKeyNotAccessibleFault` in a run are somebody assembling the
export path and getting the plumbing wrong. That is intent, observed before the data moves, and it
is the best early warning this technique offers.

Denials: `AccessDeniedException` (403), `NotAuthorized` (401). The bare `AccessDenied` form is not
documented for RDS.

## GuardDuty and posture controls

**No GuardDuty coverage.** There is no `Policy:RDS/*` finding namespace, and the nine RDS finding
types are login-behaviour detectors. Nothing in GuardDuty's S3 set fires on an object being
written either.

There is **no AWS Config managed rule for snapshot export** — the RDS rules cover public access,
snapshot sharing and encryption, not export destinations. The nearest posture controls are on the
S3 side (`s3-bucket-public-read-prohibited`, `s3-bucket-level-public-access-prohibited`) and on the
KMS key policy, which is the tightest control point available: every export runs through a key
whose policy somebody deliberately edited to admit `export.rds.amazonaws.com`.

## Response levers

`CancelExportTask` stops a task in progress and leaves whatever was already written. Deleting the
objects is the only step that removes the data, and it removes the evidence with it — so inventory
the prefix first. Rotate the export role's trust and permissions, review the destination bucket's
policy, and if the bucket is in another account treat this as a completed transfer rather than an
interrupted one.

## MITRE mapping

The source maps **T1567.002 / TA0010**, and it is the only one of the five RDS rules in this batch
whose mapping needed no correction on the merits: exfiltration to a cloud storage service is
exactly what this is. It is retained as primary, with **T1530 — Data from Cloud Storage**
(Collection) as a genuine second mapping for the step the export enables — and here S3 *is* cloud
storage in ATT&CK's own sense, unlike the RDS-endpoint case next door.

One honest caveat: **T1567 and T1567.002 do not list IaaS among their platforms**, while T1537
(Transfer Data to Cloud Account) does. Where the destination bucket is in another account, T1537 is
the better-scoped mapping and the reference table in `../PLAYBOOK.md` says so. The primary is left
at T1567.002 because it names the behaviour precisely and because the same-account case — staging
into your own bucket before reading it out — is the more common shape.

## Severity

**High** for a non-pipeline export, **Critical** when the write role or the KMS key resolves to a
foreign account. The source rates it P2. High is right because the data has definitively left RDS
and, without S3 data events, the export is the last observable step. Critical for the cross-account
case because AWS supports it only through the CLI and API, which removes any reading of it as an
accident.

**MITRE:** `T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage`, which is the source's own mapping and is correct — an export writes the snapshot to S3. Verified live 2026-08-30.

**GuardDuty:** RDS Protection exists but covers **login activity** only — `CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin`, `.FailedLogin`, `.SuccessfulBruteForce`, and the `MaliciousIPCaller` / `TorIPCaller` variants, on supported Aurora and RDS databases. No finding type covers RDS **configuration** changes, so a control-plane technique like this one produces no GuardDuty signal.

**Files here:**

- `sigma_t1567_002.yml` — four documents: the primary rule at `high` (successes only,
  pipeline-allowlisted); an `informational` base rule for snapshot create and copy; a
  `temporal_ordered` correlation at `critical` for create-then-export; and a `value_count`
  correlation at `high` for three or more export tasks in six hours, sized against AWS's
  five-concurrent-task cap.
- `kql_t1567_002.kql` — resolves the **destination account** from the `iamRoleArn` and `kmsKeyId`
  on the event and compares it to the trail's own account, which is the field-to-field comparison
  Sigma cannot express; and reconciles the `s3BucketName` / `s3Bucket` request-response split.

Sibling notes: `../../rds.exfiltration.snapshot-made-public/detections/` covers the other way a
snapshot's contents leave — a share keeps the data in RDS and hands out a restore right, an export
converts it to objects — and `../../_superseded/aws.exfiltration.s3-bucket-public-exposure/detections/` owns
the destination bucket once the data is there.

Full response procedure is in `../PLAYBOOK.md`.
