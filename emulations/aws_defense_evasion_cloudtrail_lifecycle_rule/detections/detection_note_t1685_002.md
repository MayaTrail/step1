# Detection Note: T1685.002 (Delete CloudTrail Logs Through an S3 Lifecycle Rule)

**Signal:** `s3:PutBucketLifecycle` (bucket-level management event) with an `Expiration` action, on a bucket that is a CloudTrail destination. `requestParameters.bucketName` names the bucket; `requestParameters.LifecycleConfiguration` carries the rules and their `Days`.

## Coverage beyond the rule

- Keep a list of audit-log buckets (`DescribeTrails` → `S3BucketName`) and alert at high severity on any lifecycle change to them.
- **S3 Object Lock** (compliance mode) on log buckets makes expiration ineffective.
- Expiration is evaluated asynchronously; there is a window to remove the rule before objects go.

## Response

1. `DeleteBucketLifecycle` (or restore the approved rule) on the log bucket.
2. Check whether any log objects already expired; restore them from replication or backups.
3. Revoke the acting principal's sessions.

**MITRE:** T1685.002 (*Disable or Modify Tools: Disable or Modify Cloud Log*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-ct-lifecycle-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
