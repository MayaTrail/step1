# IR Playbook: S3 Bucket Emptied One Object at a Time — `DeleteObject` Burst From a Single Principal

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data destruction (every object in a bucket deleted with one `DeleteObject` call each; in a real intrusion usually preceded by exfiltration and followed by a ransom note) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.impact.s3-ransomware-individual-deletion`) |
| Platform | aws |
| Severity | **Critical** (matches the emulation manifest), assuming no recovery copy. Critical when the bucket had no versioning, replica or backup. High when the data is recoverable; the principal with delete rights is still hostile |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 |
| Services in Scope | S3, IAM, STS, CloudTrail (S3 data events), CloudTrail Lake / Athena, GuardDuty S3 Protection, S3 server access logs, AWS Backup |

**What the technique does:** the actor lists a bucket and deletes each key with its own
`s3:DeleteObject` call. It is slower than `DeleteObjects` and far noisier — one log record per
object — which is exactly why some tooling uses it: per-object calls blend into application traffic
in environments that alert on the batch API, and a client can parallelise them across many
connections. In an unversioned bucket each delete is final.

**How this emulation runs it.** The stack creates `stratus-red-team-ransomware-individual-<account>`
with Block Public Access on, **no versioning**, and 100 synthetic objects
(`data/file-0000.txt` … `data/file-0099.txt`). The connected role assumes
`stratus-red-team-ransomware-individual-attacker-role` (session `atomic-t1485-s3-individual`), which
may only `s3:ListBucket` that bucket and `s3:DeleteObject` its objects. It lists the bucket and
issues 100 `DeleteObject` calls back to back. No reads, no ransom note, no version deletion.
Not reversible: redeploy the stack. Events: `AssumeRole` (management), `ListObjects`/`ListObjectsV2`
and 100 × `DeleteObject` (**data events**).

**Why the usual reflexes miss it.** `DeleteObject` is a **data event**: recorded only when the trail
selects S3 data events for the bucket, never in Event history, never returned by `lookup-events`.
Where data events are logged, every individual delete looks like an application deleting a
temporary file, so a per-event rule is either muted or ignored. The signal is the **rate per
principal per bucket**, and it has to be measured in distinct keys.

**Detection thesis:** count distinct keys deleted by one principal in one bucket over a short
window. Each `DeleteObject` record names its key (`requestParameters.key`), so — unlike the batch
variant — the count is a true object count. Corroborate with GuardDuty
`Impact:S3/AnomalousBehavior.Delete`, and separate destruction from churn by whether the same
principal is writing in the same window.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **S3 data events (at least write events) for every bucket whose loss would matter**, queryable in
  Athena or CloudTrail Lake. Without them §2 returns nothing, and nothing means "not logged".
- **S3 server access logs** as a second source (`REST.DELETE.OBJECT` per object).
- **GuardDuty S3 Protection** enabled.
- **A per-bucket delete baseline**: which principals delete, and at what peak rate. The shipped
  threshold (50 distinct keys / 5 min) is a starting point, not a measurement.

**Recoverability (decides the severity)**
- Versioning (delete markers are recoverable), Object Lock (locked versions cannot be deleted),
  replication or AWS Backup.

**Alerting (must be pre-configured)**
- **≥ 50 distinct keys deleted by one principal in one bucket within 5 minutes → P1** (shipped as a
  `value_count` correlation).
- **GuardDuty `Impact:S3/AnomalousBehavior.Delete` → P1.**

**Response Tooling**
- Break-glass credentials with `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetBucketVersioning`,
  `s3:PutBucketPolicy`, `iam:PutRolePolicy`; Athena access to the data-event table.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Delete burst emptying a bucket with no versioning / replica / backup | CloudTrail (S3 data events) + bucket state | T1485 |
| P1 | ≥ 50 distinct keys deleted by one principal in one bucket within 5m | CloudTrail (S3 data events), correlation | T1485 |
| P1 | GuardDuty `Impact:S3/AnomalousBehavior.Delete` | GuardDuty S3 Protection | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Delete burst preceded by `GetObject` on the same keys by the same principal (exfiltrate, then destroy) | CloudTrail (S3 data events) | T1485 |
| P2 | Delete burst followed by a single new object (ransom note) | CloudTrail (S3 data events) | T1485 |
| P2 | Many `AccessDenied` `DeleteObject` errors from one principal — a wipe hitting a guardrail | CloudTrail (S3 data events) | T1485 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| Only the low-level base rule shipped; the threshold lived in the KQL | A Sigma deployment alerted on nothing | `value_count` correlation on `requestParameters.key`, grouped by principal and bucket, `gte: 50` in 5m |
| Counting events rather than keys | Retries of one key inflate the count | Distinct keys, in Sigma and in the KQL |
| Data-event dependency | Silence read as clean | Stated in every rule and query |

### Key Investigation Queries

> **`lookup-events` cannot see `DeleteObject`.** Use Athena / CloudTrail Lake over the trail's data
> events. If the bucket was not covered, record the CloudTrail answer as **INCONCLUSIVE**.

#### Query 1 — Delete burst per principal (Athena)

```sql
SELECT useridentity.arn AS principal,
       count(DISTINCT json_extract_scalar(requestparameters, '$.key')) AS keys_deleted,
       min(eventtime) AS first_delete, max(eventtime) AS last_delete,
       array_agg(DISTINCT sourceipaddress) AS ips
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com' AND eventname = 'DeleteObject'
  AND json_extract_scalar(requestparameters, '$.bucketName') = '<bucket_name>'
  AND eventtime > '<start-of-window>'
GROUP BY 1
ORDER BY keys_deleted DESC;
```

The top row is the actor if it is not a known application. For this emulation: 100 keys from the
`atomic-t1485-s3-individual` session within seconds.

#### Query 2 — Did the principal read or write as well?

```sql
SELECT eventname, count(*) AS calls, min(eventtime) AS first_seen, max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND useridentity.arn = '<principal-from-Query-1>'
  AND eventtime > '<start-of-window>'
GROUP BY 1;
```

`GetObject` before the deletes is exfiltration — assume extortion and treat the data as disclosed.
`PutObject` of new keys after the deletes is a ransom note; `PutObject` of `<key>.<suffix>` before
each delete is encryption — go to the client-side encryption playbook.

#### Query 3 — Can it come back?

```bash
BUCKET="<bucket_name>"
aws s3api get-bucket-versioning --bucket "$BUCKET"
```

`Enabled` → deleted objects are non-current versions behind delete markers (recoverable, §5).
Empty or `Suspended` → objects deleted while unversioned are gone from this bucket.

#### Query 4 — What remains

```bash
BUCKET="<bucket_name>"
aws s3api list-objects-v2 --bucket "$BUCKET" --query 'KeyCount'
```

For a versioned bucket also list delete markers:
`aws s3api list-object-versions --bucket <bucket_name> --query 'DeleteMarkers[].Key'`.

#### Query 5 — The session's management events

```bash
SESSION="<session-name-from-Query-1-arn>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

The `AssumeRole` that started the session, and any `PutBucketVersioning`, `PutBucketLifecycle` or
`PutBucketPolicy` that prepared the wipe, are management events and are here.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Stop the principal

```bash
ROLE="<role-name-from-Query-1>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenyS3Destruction \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:DeleteObject","s3:DeleteObjectVersion","s3:PutBucketVersioning","s3:PutLifecycleConfiguration","s3:PutBucketPolicy"],"Resource":"*"}]}'
```

#### Step 2 — Deny deletes on the bucket to everyone but break-glass

A bucket policy statement denying `s3:DeleteObject` and `s3:DeleteObjectVersion` unless
`aws:PrincipalArn` is the break-glass role. A per-object wipe in progress from other credentials
stops at the next call.

#### Step 3 — Freeze recovery sources

Keep versioning enabled, disable any lifecycle rule expiring non-current versions, confirm backup
recovery points exist.

---

## 4. Eradication

### Remove Attacker Access

- Trace the session to its source identity and contain it; remove `s3:DeleteObject` from principals
  that do not delete.

### Prevent recurrence

- Versioning plus Object Lock (or MFA Delete) on critical buckets.
- The guardrail catalogue's **`S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects`** RCP
  denies `s3:DeleteObject` on named buckets.

### Remove the emergency policies once clean

```bash
ROLE="<role-name-from-Query-1>"
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyDenyS3Destruction
aws iam list-role-policies --role-name "$ROLE"
```

---

## 5. Recovery

### Restore Clean State

#### Versioned bucket: remove the delete markers

```bash
BUCKET="<bucket_name>"
aws s3api list-object-versions --bucket "$BUCKET" --query 'DeleteMarkers[?IsLatest==`true`].[Key,VersionId]' --output text
```

For each line, `aws s3api delete-object --bucket <bucket_name> --key <Key> --version-id <VersionId>`
removes the marker and restores the previous version.

#### Unversioned bucket

Restore from the replica or AWS Backup, or record the loss (Query 1 gives the exact key list —
an advantage of this variant over the batch one).

#### Confirm the corrected detection fires

```text
MUST fire on:     >= 50 distinct keys deleted by one principal in one bucket within 5m -> high.
MUST NOT fire on: a handful of DeleteObject calls from an application; DeleteObjects (batch
                  playbook); reads.
PRECONDITION:     the trail must log S3 data events for the bucket.
```

Running this emulation is the test, if data events cover the lab bucket: 100 `DeleteObject` calls
from session `atomic-t1485-s3-individual`.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal deleted a bucket's contents key by key | `s3:DeleteObject` granted beyond the workloads that delete |
| Data could not be restored | No versioning, Object Lock, replica or backup |
| The burst went unnoticed | No S3 data events, or a per-event rule nobody watched |

### Recommended Guardrails

- **Catalogue match:** `S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects` (RCP, named
  bucket, unconditional) denies `s3:DeleteObject`.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction |
| APIs (eventName) | `ListObjectsV2` (`ListObjects` / `ListObjectsV2`), `DeleteObject` per key |
| IAM actions | `s3:ListBucket`, `s3:DeleteObject` |
| Event category | **Data** — not in Event history, not in `lookup-events` |
| Key fields | `requestParameters.bucketName`, `requestParameters.key` |
| Other sources | S3 server access logs (`REST.DELETE.OBJECT`), GuardDuty `Impact:S3/AnomalousBehavior.Delete` |
| Lab identity | Role `stratus-red-team-ransomware-individual-attacker-role`, session `atomic-t1485-s3-individual` |

### Residual Risk

Unversioned objects deleted are unrecoverable from S3. If data events were not logged, the key list
and the read-before-delete question can only be answered from server access logs, if they exist.
