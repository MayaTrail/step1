# Detection Note: T1685.002 (Delete CloudTrail Logs Through an S3 Lifecycle Rule)

**Signal:** CloudTrail eventName **`PutBucketLifecycle`** (the API is `PutBucketLifecycleConfiguration`, the IAM action `s3:PutLifecycleConfiguration`) — a bucket-level **management** event — with an `Expiration` or `NoncurrentVersionExpiration` action, on a bucket that is a CloudTrail destination. `requestParameters.bucketName` names the bucket; `requestParameters.LifecycleConfiguration.Rule` carries the rules and their `Days`.

The object deletions the rule causes are performed by S3, not by the caller, and **never appear in CloudTrail** — only in S3 server access logs (`S3.EXPIRE.OBJECT`) or as `s3:LifecycleExpiration:*` event notifications. The `PutBucketLifecycle` event is the only CloudTrail record of the technique.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| Any Expiration / NoncurrentVersionExpiration lifecycle rule | medium | yes |
| Expiration of 7 days or less | high | yes (`Days: 1`) |

The KQL joins the bucket against every `CreateTrail`/`UpdateTrail` `s3BucketName` and ranks a short expiration on a trail bucket as critical. Sigma cannot know which buckets are log destinations.

## Coverage beyond the rule

- **S3 Object Lock** (compliance mode) on the log bucket makes expiration of locked versions impossible; **versioning** plus a log-archive replica keeps a copy.
- **Expiration is asynchronous** (S3 evaluates lifecycle rules roughly daily). There is a window to remove the rule before any object is deleted; act inside it.
- No GuardDuty finding type covers lifecycle changes. `Stealth:S3/ServerAccessLoggingDisabled` covers a different change.
- The guardrail catalogue has no policy denying `s3:PutLifecycleConfiguration`; a bucket policy on the log bucket denying it to everyone except the log-admin role is the preventive control.

## Response

1. `DeleteBucketLifecycle` on the log bucket, or restore the approved rule from IaC. Note that `PutBucketLifecycleConfiguration` replaces the whole configuration, so check what the approved rule was before the change.
2. List the bucket's objects (and versions) to confirm nothing has expired yet; if it has, restore from the replica.
3. Revoke the acting principal's sessions.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*); the deletion it schedules is T1485.001 (*Lifecycle-Triggered Deletion*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** session `atomic-t1685002-ct-lifecycle` on the lab role `stratus-red-team-ct-lifecycle-attacker-role`; `GetBucketLifecycle`, `PutBucketLifecycle` with rule ID `mayatrail-emulation-expire-all` (`Days: 1`), then `DeleteBucketLifecycle` 30 s later — before S3 can expire anything.
