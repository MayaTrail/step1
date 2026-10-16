# IR Playbook: S3 Bucket Wiped With `DeleteObjects` — Batch-Deletion Stage of S3 Ransomware

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data destruction (every object in a bucket is removed in a few batch calls; in a real intrusion usually preceded by exfiltration and followed by a ransom note) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.impact.s3-ransomware-batch-deletion`) |
| Platform | aws |
| Severity | **Critical**, assuming no recovery copy. Critical when the bucket had no versioning, replica or backup — the data is gone. High when versioning or a replica makes it recoverable; the attacker still controls a principal with delete rights |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 |
| Services in Scope | S3, IAM, STS, CloudTrail (S3 data events), CloudTrail Lake / Athena, GuardDuty S3 Protection, CloudWatch storage metrics, AWS Backup |

**What the technique does:** the actor lists a bucket and passes the keys to `s3:DeleteObjects`,
up to 1,000 per call. A bucket of a million objects goes in a thousand requests, in minutes. In an
unversioned bucket a delete is final. Real S3 extortion adds two steps around it — download the data
first, upload a ransom note after — and Stratus Red Team's version of this technique also deletes
every object **version**, which is what defeats versioning.

**How this emulation runs it.** The stack creates `stratus-red-team-ransomware-batch-<account>`
with S3 Block Public Access on, **no versioning**, and 100 synthetic objects under `data/` — none of
the tenant's data. The connected role assumes `stratus-red-team-ransomware-batch-attacker-role`
(session `atomic-t1485-s3-batch`), which may only `s3:ListBucket` that bucket and `s3:DeleteObject`
its objects (IAM authorises each key of a `DeleteObjects` call with `s3:DeleteObject`). It lists the
bucket with `ListObjectsV2` and deletes all 100 objects in **one** `DeleteObjects` call. It does
not delete versions (there are none), upload a ransom note or read objects first. It is not
reversible: redeploy the stack to recreate the objects. Events: `AssumeRole` (management),
`ListObjects`/`ListObjectsV2` and `DeleteObjects` (**data events**).

**Why the usual reflexes miss it.** Three structural blind spots:

1. **S3 object calls are CloudTrail data events.** They are recorded only by a trail or event data
   store that selects S3 data events for the bucket. They are never in Event history and never
   returned by `aws cloudtrail lookup-events`. Most accounts do not log them for most buckets, and
   then this technique produces **no CloudTrail record at all** except the `AssumeRole`.
2. **One event, a thousand objects.** A `DeleteObjects` record names the bucket but not the keys or
   how many. Volume rules count calls; this emulation's entire wipe is one call.
3. **Destruction looks like housekeeping.** ETL and cleanup jobs batch-delete all day.

**Detection thesis:** where S3 data events exist, the shape is *enumerate, then batch-delete, as one
principal on one bucket* — that fires on a single call. GuardDuty S3 Protection
(`Impact:S3/AnomalousBehavior.Delete`) is the behavioural complement and reads the same data events.
Where data events do not exist, nothing in CloudTrail will catch this, and the playbook says so
instead of reporting "no activity".

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **S3 data events for every bucket whose loss would matter** — at minimum write events
  (`DeleteObject`, `DeleteObjects`, `PutObject`) — in a trail or CloudTrail Lake event data store,
  queryable with Athena or Lake SQL. Without them, §2's queries return nothing and that nothing
  means "not logged", not "did not happen".
- **S3 server access logs** as a cheaper second source; deletions appear with operation
  `REST.POST.MULTI_OBJECT_DELETE` for the batch call.
- **GuardDuty S3 Protection** enabled (it consumes S3 data events itself, even if your trail does not
  store them).
- **CloudWatch `NumberOfObjects`** storage metric — daily, but it needs no logging configuration.

**Recoverability (decides the severity)**
- **Versioning** turns a `DeleteObjects` without version IDs into delete markers; the data remains as
  non-current versions. **Object Lock** prevents deletion of locked versions even by a principal
  with delete rights. **Replication** or **AWS Backup** keeps a copy elsewhere.

**Alerting (must be pre-configured)**
- **`ListObjects` then `DeleteObjects` by one principal on one bucket within 15 minutes → P1.**
- **Three or more `DeleteObjects` calls on one bucket within 10 minutes → P1.**
- **GuardDuty `Impact:S3/AnomalousBehavior.Delete` → P1.**

**Response Tooling**
- Break-glass credentials with `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetBucketVersioning`,
  `s3:PutBucketPolicy`, `iam:PutRolePolicy`; Athena access to the trail's data-event table.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteObjects` emptying a bucket with no versioning / replica / backup | CloudTrail (S3 data events) + bucket state | T1485 |
| P1 | `ListObjects`/`ListObjectsV2` then `DeleteObjects` by one principal on one bucket within 15m | CloudTrail (S3 data events), correlation | T1485 |
| P1 | ≥ 3 `DeleteObjects` calls by one principal on one bucket within 10m | CloudTrail (S3 data events), correlation | T1485 |
| P1 | GuardDuty `Impact:S3/AnomalousBehavior.Delete` | GuardDuty S3 Protection | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Any `DeleteObjects` from a principal not on the cleanup-job allowlist | CloudTrail (S3 data events) | T1485 |
| P2 | `DeleteObjects` followed by one to three `PutObject` calls (ransom note) | CloudTrail (S3 data events) | T1485 |
| P2 | `PutBucketVersioning` `Suspended` or `PutBucketLifecycle` by the same principal (management events) | CloudTrail (management) | T1490 |
| P3 | `NumberOfObjects` falling sharply day over day | CloudWatch | T1485 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| The generated rule matched every `DeleteObjects` at medium, with no sequence or volume | Either too noisy to keep or, tuned by threshold, blind to a single-call wipe | Kept as the base; added list-then-delete (`temporal_ordered`, fires on one call) and ≥ 3 calls (`event_count`) |
| Call counts read as object counts | "1 event" understated a 1,000-object wipe | Documented in the rule and the KQL (`MaxObjectsRemoved = calls × 1000`) |
| Data-event dependency unstated | Empty results read as clean | Stated in every rule; §2 queries print INCONCLUSIVE guidance |

### Key Investigation Queries

> **`aws cloudtrail lookup-events` cannot answer any question in this playbook** — it returns
> management events only. Use the trail's data events through Athena or CloudTrail Lake. If the
> bucket was not covered by a data-event selector, record the CloudTrail answer as **INCONCLUSIVE**
> and go to Query 3 and the server access logs.

#### Query 1 — Who deleted, how many calls, and did they list first (Athena)

```sql
SELECT useridentity.arn AS principal, eventname, count(*) AS calls,
       min(eventtime) AS first_seen, max(eventtime) AS last_seen,
       array_agg(DISTINCT sourceipaddress) AS ips
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND json_extract_scalar(requestparameters, '$.bucketName') = '<bucket_name>'
  AND eventname IN ('ListObjects', 'ListObjectsV2', 'DeleteObjects', 'DeleteObject',
                    'GetObject', 'PutObject')
  AND eventtime > '<start-of-window>'
GROUP BY 1, 2
ORDER BY first_seen;
```

A principal with `ListObjects` then `DeleteObjects` and no business deleting is the actor. Each
`DeleteObjects` row is up to 1,000 objects. `GetObject` before the deletes is exfiltration — assume
extortion. A few `PutObject` after the deletes is the ransom note. **Zero rows:** check that the
table holds data events for this bucket before concluding anything.

#### Query 2 — What is left in the bucket, and can it come back

```bash
BUCKET="<bucket_name>"
aws s3api get-bucket-versioning --bucket "$BUCKET"
```

`Status: Enabled` → the deleted objects are non-current versions behind delete markers; go to §5.
Empty output (never versioned) or `Suspended` → objects deleted while unversioned are gone from this
bucket; only replication or a backup can restore them. For this emulation's bucket the output is
empty: by design, nothing comes back.

#### Query 3 — Count what remains

```bash
BUCKET="<bucket_name>"
aws s3api list-objects-v2 --bucket "$BUCKET" --query 'KeyCount'
```

Compare with the last known object count (inventory, `NumberOfObjects`, or 100 for this lab).
For a versioned bucket also run `aws s3api list-object-versions --bucket <bucket_name> --query 'DeleteMarkers[].Key'`
— those keys are recoverable.

#### Query 4 — The session behind the principal (management events)

```bash
SESSION="<session-name-from-Query-1-arn>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

Management events are in Event history: the `AssumeRole` that created the session (for this
emulation, session `atomic-t1485-s3-batch`), and any `PutBucketVersioning`, `PutBucketLifecycle`,
`PutBucketPolicy` or `DeleteBucketReplication` that prepared the wipe.

#### Query 5 — GuardDuty

```bash
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings --detector-id "$DETECTOR" \
  --finding-criteria '{"Criterion":{"type":{"Eq":["Impact:S3/AnomalousBehavior.Delete"]}}}'
```

A finding names the principal and bucket and is built from S3 data events GuardDuty collects
itself — useful corroboration when your trail does not store them.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

> Deletion runs at API speed. Contain the principal before anything else.

#### Step 1 — Stop the principal

```bash
ROLE="<role-name-from-Query-1>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenyS3Destruction \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:DeleteObject","s3:DeleteObjectVersion","s3:PutBucketVersioning","s3:PutLifecycleConfiguration","s3:PutBucketPolicy"],"Resource":"*"}]}'
```

For an IAM user, deactivate its access keys and attach the same deny as a user policy.

#### Step 2 — Protect the bucket from every principal while you recover

Add a bucket policy statement denying `s3:DeleteObject` and `s3:DeleteObjectVersion` to everyone
except the break-glass role (`"Condition":{"StringNotLike":{"aws:PrincipalArn":"arn:aws:iam::<account>:role/<break-glass>"}}`).
If other compromised principals exist, this stops them too.

#### Step 3 — Freeze the recovery sources

If the bucket is versioned, do **not** suspend versioning and do not touch lifecycle rules that
expire non-current versions — disable any such rule now so S3 does not finish the attacker's work.
Pause replication deletes and confirm AWS Backup recovery points exist.

---

## 4. Eradication

### Remove Attacker Access

- Trace the session to its source identity (`AssumeRole` caller in Query 4) and contain it.
- Remove `s3:DeleteObject` from principals that read or write but never delete.

### Prevent recurrence

- **Versioning + Object Lock** (or MFA Delete) on buckets whose loss is unacceptable.
- The guardrail catalogue's **`S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects`** (an RCP
  scoped to named buckets) denies `s3:DeleteObject` and `s3:DeleteObjectVersion` outright — the
  same action that authorises every key of a `DeleteObjects` call.
- S3 write data events on critical buckets, so the next one is in CloudTrail.

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

For each line run `aws s3api delete-object --bucket <bucket_name> --key <Key> --version-id <VersionId>`;
deleting the marker makes the previous version current again. Check that the attacker did not also
delete versions (`DeleteObjects` with version IDs) — Stratus's original technique does.

#### Unversioned bucket

Restore from the replica or AWS Backup. If neither exists, the objects are lost; record the key
range from inventory reports or the application's own records.

#### Confirm the corrected detection fires

```text
MUST fire on:     ListObjects(V2) then DeleteObjects by one principal on one bucket within 15m
                  -> high; >= 3 DeleteObjects in 10m -> high; any DeleteObjects -> medium.
MUST NOT fire on: single DeleteObject calls (see the individual-deletion playbook); list alone.
PRECONDITION:     the trail must log S3 data events for the bucket - otherwise nothing fires.
```

Running this emulation is the test, **if** your trail selects data events for the lab bucket: one
`ListObjects(V2)` and one `DeleteObjects` from session `atomic-t1485-s3-batch`.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A bucket was emptied in one call | `s3:DeleteObject` held by a principal that never needed it |
| The data could not be restored | No versioning, Object Lock, replica or backup |
| The wipe was not seen, or seen a day later | No S3 data events; only the daily storage metric |

### Recommended Guardrails

- **Catalogue match:** `S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects` (RCP, named
  bucket, unconditional) denies `s3:DeleteObject`.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction |
| APIs (eventName) | `ListObjectsV2` (`ListObjects` / `ListObjectsV2`), `DeleteObjects` |
| IAM actions | `s3:ListBucket`, `s3:DeleteObject` (per key) |
| Event category | **Data** — not in Event history, not in `lookup-events` |
| Key fields | `requestParameters.bucketName`; the record does not list deleted keys |
| Other sources | S3 server access logs, GuardDuty `Impact:S3/AnomalousBehavior.Delete`, CloudWatch `NumberOfObjects` |
| Lab identity | Role `stratus-red-team-ransomware-batch-attacker-role`, session `atomic-t1485-s3-batch` |

### Residual Risk

Without versioning or a copy, deleted objects cannot be recovered by any AWS mechanism. Without S3
data events, the incident's own record is the `AssumeRole` and whatever server access logs exist —
which may be enough to know it happened and not enough to know what was taken first.
