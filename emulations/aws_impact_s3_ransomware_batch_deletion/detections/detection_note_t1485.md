# Detection Note: T1485 (S3 Ransomware Through Batch Object Deletion)

**Signal:** `s3:DeleteObjects` — an S3 **data event** (`eventCategory: Data`) — preceded by `ListObjects`/`ListObjectsV2` on the same bucket by the same principal. Data events are recorded only when a trail (or CloudTrail Lake event data store) has an S3 data-event selector covering the bucket; **Event history and `lookup-events` never show them**.

**One event is up to 1,000 objects.** A `DeleteObjects` record names the bucket but not the keys or their number, so event counts are call counts. This emulation deletes 100 synthetic objects with **one** `DeleteObjects` call, after one paginated `ListObjectsV2`. A volume threshold alone would never fire on it.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `s3_delete_objects` - any DeleteObjects | medium | yes |
| `s3_list_objects_bb` - ListObjects / ListObjectsV2 (base rule) | informational | yes (sequence component only) |
| List then DeleteObjects by one principal on one bucket within 15m (`temporal_ordered`) | high | yes |
| 3 or more DeleteObjects calls by one principal on one bucket within 10m (`event_count`) | high | no (one call) |

The KQL reports call counts, an upper bound on objects removed (calls × 1,000), whether enumeration came first, and a ransom-note candidate (a few `PutObject` after the wipe).

## Coverage beyond the rule

- **GuardDuty S3 Protection** `Impact:S3/AnomalousBehavior.Delete` (default severity High) models anomalous delete behaviour from the same data events.
- **CloudWatch `NumberOfObjects`** (daily storage metric) shows the drop even without data events — a day late.
- **Versioning** turns a `DeleteObjects` without version IDs into delete markers, which are recoverable; **Object Lock** prevents deletion of locked versions. The lab bucket has neither, by design.
- The guardrail catalogue's `S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects` (RCP on a named bucket) denies `s3:DeleteObject`, which authorises every key in a `DeleteObjects` call.

## Response

1. Revoke the acting principal's sessions immediately; deletion is fast.
2. Recover from versions (remove delete markers), replication or AWS Backup.
3. Check for `GetObject` by the same principal before the delete (exfiltration for extortion) and for a ransom note after it.

**MITRE:** T1485 (*Data Destruction*).
**Severity:** manifest CRITICAL.
**Emulation fingerprint:** session `atomic-t1485-s3-batch` on `stratus-red-team-ransomware-batch-attacker-role`; bucket `stratus-red-team-ransomware-batch-<account>`; one `ListObjects(V2)` then one `DeleteObjects`. Not reversible: redeploy the stack to recreate the objects.
