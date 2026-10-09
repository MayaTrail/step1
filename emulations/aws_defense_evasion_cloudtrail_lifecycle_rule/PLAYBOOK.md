# IR Playbook: CloudTrail Log Bucket Given a 1-Day Expiration — `PutBucketLifecycle` Makes S3 Delete the Audit Trail for You

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment with scheduled destruction (a lifecycle rule on the trail's log bucket makes S3 delete historical and future log files; no delete call is ever made by the actor) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.defense-evasion.cloudtrail-lifecycle-rule`) |
| Platform | aws |
| Severity | High while the rule is in place and nothing has expired yet — there is still a window to undo it. Critical once objects have expired from a bucket with no versioning, replica or Object Lock, because the history is then gone |
| MITRE Tactics | Defense Impairment, Impact |
| MITRE Techniques | T1685.002 (primary); T1485.001 (the lifecycle-triggered deletion it schedules) |
| Services in Scope | S3 (log bucket), CloudTrail, IAM, STS, S3 server access logs, S3 Event Notifications |

**What the technique does:** the actor calls `PutBucketLifecycleConfiguration` on the bucket a
trail delivers to, with a rule that expires every object after one day. The trail keeps logging,
`GetTrailStatus` stays healthy, and new log files keep arriving — then S3 removes them, along with
every older file, on its own schedule. The actor never calls `DeleteObject`, so every rule that
watches for log-file deletion stays silent.

**How this emulation runs it.** The connected role assumes `stratus-red-team-ct-lifecycle-attacker-role`
(session `atomic-t1685002-ct-lifecycle`). Its only permissions are `s3:GetLifecycleConfiguration`
and `s3:PutLifecycleConfiguration` on the lab trail's bucket `stratus-red-team-ct-lifecycle-bucket-<account>`.
It reads the current lifecycle (`GetBucketLifecycle`), applies rule `mayatrail-emulation-expire-all`
(`Status: Enabled`, empty prefix, `Expiration.Days: 1`, `NoncurrentVersionExpiration.NoncurrentDays: 1`),
waits 30 seconds, and calls `DeleteBucketLifecycle` from a `finally` block — authorised by the same
`s3:PutLifecycleConfiguration` action. S3 evaluates lifecycle rules asynchronously, so nothing
expires in a 30-second window. Events produced: `AssumeRole`, `GetBucketLifecycle`,
`PutBucketLifecycle`, `DeleteBucketLifecycle`.

**Why the usual reflexes miss it.** Three names for one call: the API is
`PutBucketLifecycleConfiguration`, the IAM action is `s3:PutLifecycleConfiguration`, and the
CloudTrail **eventName is `PutBucketLifecycle`**. A rule written with either of the first two
spellings never fires. The deletions themselves are not CloudTrail events at all: S3 records them
only in **server access logs** (operation `S3.EXPIRE.OBJECT`) and, if configured, as
`s3:LifecycleExpiration:*` event notifications. And lifecycle changes are routine — every
retention policy is one — so an eventName-only rule is tuned away.

**Detection thesis:** the `PutBucketLifecycle` management event is the only CloudTrail record of the
technique, and it is in Event history and every trail. The discriminators are the **expiration
length** (seven days or less is shorter than any audit retention requirement) and **whether the
bucket is a log destination**, which the KQL resolves from the trail inventory.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **The list of log destination buckets**, kept as data: every trail's `S3BucketName`, the Config
  delivery channel bucket, flow-log buckets. This is the join key that turns a routine lifecycle
  change into a critical one.
- `PutBucketLifecycle`, `GetBucketLifecycle` and `DeleteBucketLifecycle` are **management**
  events: logged by default and visible in Event history for 90 days.
- **S3 server access logging** on the log bucket (to a different bucket) is the only record of
  which objects expired. Security Hub control CloudTrail.7 checks for it.
- **Versioning, replication to a log-archive account, or Object Lock** on the log bucket. With
  versioning alone, the attacker's `NoncurrentVersionExpiration` removes old versions too; with
  Object Lock in compliance mode, locked versions cannot be expired.

**Alerting (must be pre-configured)**
- **`PutBucketLifecycle` with an expiration on a log destination bucket → P1**; **≤ 7 days → P0.**
- **`PutBucketLifecycle` with expiration ≤ 7 days on any bucket → P2.**

**Response Tooling**
- Break-glass credentials with `s3:PutLifecycleConfiguration`, `s3:GetLifecycleConfiguration`,
  `s3:ListBucket`, `s3:ListBucketVersions`, `cloudtrail:LookupEvents`, `iam:PutRolePolicy`.
- The approved lifecycle configuration for each log bucket, in IaC.

**Known IOC Baselines**
- Which principals change lifecycle on log buckets (normally one IaC role, rarely).

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `PutBucketLifecycle` with `Expiration`/`NoncurrentVersionExpiration` ≤ 7 days on a trail's bucket | CloudTrail (management) | T1685.002, T1485.001 |
| P1 | `PutBucketLifecycle` with any expiration on a log destination bucket, by a principal other than the log-admin role | CloudTrail (management) | T1685.002 |
| P1 | `S3.EXPIRE.OBJECT` entries for `AWSLogs/` keys younger than the approved retention | S3 server access logs | T1485.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutBucketLifecycle` with expiration ≤ 7 days on a bucket not known to hold logs | CloudTrail (management) | T1485.001 |
| P2 | `GetBucketLifecycle` / `DescribeTrails` from a principal that does not administer logging | CloudTrail (management) | T1685.002 |
| P3 | `PutBucketLifecycle` followed by `DeleteBucketLifecycle` from the same principal within minutes — an operator testing, or this emulation | CloudTrail (management) | T1685.002 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| The generated rule was a substring test (`Expiration`) on the whole flattened request | Behaviour depends on how the backend renders nested objects | Scoped to `requestParameters.LifecycleConfiguration` |
| Length of the expiration was ignored | A 365-day retention rule and a 1-day destruction rule scored the same | Second document: expiration ≤ 7 days, at high; numbers matched with or without quotes |
| Whether the bucket holds logs cannot be expressed in Sigma | The most important fact is outside the rule | KQL joins the bucket against `CreateTrail`/`UpdateTrail` `s3BucketName` and ranks a short expiry on a trail bucket as critical |
| The eventName spelling | `PutBucketLifecycleConfiguration` is not the CloudTrail name | Rules match `PutBucketLifecycle` |

### Key Investigation Queries

#### Query 1 — Which bucket does the trail deliver to?

```bash
TRAIL="<trail_name>"
aws cloudtrail describe-trails --trail-name-list "$TRAIL" \
  --query 'trailList[].[Name,S3BucketName,S3KeyPrefix,HomeRegion]' --output table
```

Run without `--trail-name-list` to get every trail's bucket; that set is the list of buckets this
playbook protects.

#### Query 2 — The lifecycle configuration on the log bucket now

```bash
BUCKET="<bucket_name>"
aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET"
```

`NoSuchLifecycleConfiguration` means no rule is in place (or it was already removed — Query 3
shows which). Any rule with `Expiration.Days` or `NoncurrentVersionExpiration.NoncurrentDays`
shorter than your retention requirement is the incident, regardless of its `ID`.

#### Query 3 — Every lifecycle change in the last 30 days

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketLifecycle \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' --output json
```

Read `requestParameters.bucketName`, `requestParameters.LifecycleConfiguration`,
`userIdentity.arn`, `sourceIPAddress` and `errorCode`. Repeat with
`AttributeValue=DeleteBucketLifecycle` to find the removal, if any. The time between the put and
the removal is the exposure window; if no removal exists and Query 2 still shows the rule, the
clock is running.

#### Query 4 — Has anything expired yet?

```bash
BUCKET="<bucket_name>"
aws s3api list-objects-v2 --bucket "$BUCKET" --prefix AWSLogs/ \
  --query '[KeyCount, Contents[0].LastModified]' --output json
```

The oldest surviving object's `LastModified` against your retention period tells you whether
history has already gone. A versioned bucket also needs `list-object-versions` (delete markers are
what expiration leaves behind in a versioned bucket). For the exact list of expired keys, query
the bucket's **server access logs** for `operation = S3.EXPIRE.OBJECT`; CloudTrail does not
record them.

#### Query 5 — The principal's session

```bash
SESSION="<session-name-or-user-from-Query-3>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

`DescribeTrails` or `GetTrail` before the lifecycle change is the actor finding the log bucket.
Look also for `PutBucketVersioning` (suspending versioning first), `PutBucketPolicy` on the log
bucket, and `StopLogging` / `PutEventSelectors` on the trail.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

> Run under the **break-glass responder credentials** from §1. Speed matters: S3 evaluates
> lifecycle rules roughly once a day, and every evaluation after the rule landed can remove files.

#### Step 1 — Remove the malicious rule (or restore the approved one)

```bash
BUCKET="<bucket_name>"
aws s3api delete-bucket-lifecycle --bucket "$BUCKET"
aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET"
```

The second call should return `NoSuchLifecycleConfiguration`. If the bucket had an approved
retention rule, re-apply it from IaC immediately afterwards: `PutBucketLifecycleConfiguration`
replaces the whole configuration, so the attacker's put already erased the approved rule.

#### Step 2 — Contain the principal

```bash
ROLE="<role-name-from-Query-3>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyDenyLogBucketTampering \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:PutLifecycleConfiguration","s3:PutBucketVersioning","s3:PutBucketPolicy","s3:DeleteObject","s3:DeleteObjectVersion"],"Resource":"*"}]}'
```

For an IAM user, deactivate its access keys and attach the same deny as a user policy.

#### Step 3 — Freeze the log bucket's history

If the bucket is versioned, objects expired after this point leave non-current versions or delete
markers you can still recover; do not suspend versioning. If it is not versioned, start a copy of
`AWSLogs/` to a separate bucket now (`aws s3 sync s3://<bucket_name>/AWSLogs/ s3://<archive-bucket>/AWSLogs/`)
so that a missed expiration cannot take the only copy.

---

## 4. Eradication

### Remove Attacker Access

- Trace the session to its source identity and contain it. Remove `s3:PutLifecycleConfiguration`
  on log buckets from every principal except the log-admin role.

### Prevent recurrence

- Add a **bucket policy statement on each log bucket** denying `s3:PutLifecycleConfiguration`,
  `s3:PutBucketVersioning` and `s3:DeleteObject*` to every principal except the log-admin role.
  The guardrail catalogue has no SCP for lifecycle changes; the bucket policy is the control.
- Enable **Object Lock** (compliance mode, retention ≥ your audit requirement) on new log buckets,
  or replicate to a log-archive account the workload account cannot write to.

### Remove the emergency policies once clean

```bash
ROLE="<role-name-from-Query-3>"
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyDenyLogBucketTampering
aws iam list-role-policies --role-name "$ROLE"
```

---

## 5. Recovery

### Restore Clean State

#### Confirm the lifecycle configuration is the approved one

```bash
BUCKET="<bucket_name>"
aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET"
```

Either `NoSuchLifecycleConfiguration` or exactly the approved rule from IaC.

#### Restore expired log files

From the versioned bucket's non-current versions, the log-archive replica, or AWS Backup. If none
exist, record which date range is gone (from the server access logs' `S3.EXPIRE.OBJECT` entries)
and recover that window's management events from Event history while they are still within 90 days.

#### Confirm the corrected detection fires

```text
MUST fire on:     PutBucketLifecycle with Expiration or NoncurrentVersionExpiration -> medium;
                  with Days / NoncurrentDays of 1-7 -> high (both fire on this emulation).
MUST NOT fire on: DeleteBucketLifecycle; GetBucketLifecycle; a Transition-only rule.
EXPECTED FP:      short-retention scratch buckets - allowlist by bucket name, never a log bucket.
```

Running this emulation is the test: `PutBucketLifecycle` with rule `mayatrail-emulation-expire-all`
from session `atomic-t1685002-ct-lifecycle` must fire both documents.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| The log bucket accepted a destructive lifecycle rule | No bucket policy restricting `s3:PutLifecycleConfiguration`; no Object Lock |
| The change was not alerted, or alerted at the same level as retention policy | Rule keyed on the wrong event name, or on eventName without expiration length and bucket role |
| Expired files could not be identified | No server access logging on the log bucket |

### Recommended Guardrails

- **Catalogue:** no catalogue policy denies `s3:PutLifecycleConfiguration` (the upstream AWS SCP
  examples contain none). The preventive control is a bucket policy on each log bucket, or Object
  Lock.
- **Structural:** organization trail delivering to a log-archive account, versioned and locked.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Cloud Log (primary); T1485.001 — Lifecycle-Triggered Deletion (the effect) |
| API / IAM action / CloudTrail eventName | `PutBucketLifecycleConfiguration` / `s3:PutLifecycleConfiguration` / **`PutBucketLifecycle`** |
| Revert | `DeleteBucketLifecycle` (authorised by `s3:PutLifecycleConfiguration`) |
| Event category | Management, `s3.amazonaws.com`, bucket Region |
| Key fields | `requestParameters.bucketName`, `requestParameters.LifecycleConfiguration.Rule[].Expiration.Days`, `.NoncurrentVersionExpiration.NoncurrentDays` |
| Where the deletions appear | S3 server access logs (`S3.EXPIRE.OBJECT`), S3 event notifications (`s3:LifecycleExpiration:*`) — never CloudTrail |
| Lab identity | Role `stratus-red-team-ct-lifecycle-attacker-role`, session `atomic-t1685002-ct-lifecycle`, rule ID `mayatrail-emulation-expire-all` |

### Residual Risk

If any object expired before the rule was removed and the bucket had no versioning, replica or
backup, those log files are gone, and with them every data event they held. Management events from
the last 90 days can be re-derived from Event history; older management events and all data events
from the lost files cannot.
