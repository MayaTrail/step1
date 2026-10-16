# Detection Note: T1485 (S3 Ransomware Through Individual Object Deletion)

**Signal:** a burst of `s3:DeleteObject` **data events** (`eventCategory: Data`) from one principal against one bucket — 50 or more distinct `requestParameters.key` values in five minutes. Data events are recorded only when a trail (or event data store) selects S3 data events for the bucket; **Event history and `lookup-events` never show them**.

The emulation lists the lab bucket (`ListObjectsV2`) and deletes its 100 synthetic objects with 100 consecutive `DeleteObject` calls from one session — one data event per object, unlike the batch variant, where a single `DeleteObjects` record hides how many keys it removed.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `s3_delete_object` - every DeleteObject (base rule) | low | yes (100 times) |
| ≥ 50 distinct keys deleted by one principal in one bucket within 5m (`value_count`) | high | yes |

The generated package shipped only the low-level base rule and left the threshold to the KQL, so a Sigma deployment alerted on nothing; the threshold is now a Sigma correlation. The KQL adds the context that separates destruction from churn: writes in the same window, reads before the deletes, listing.

## Coverage beyond the rule

- **GuardDuty S3 Protection** `Impact:S3/AnomalousBehavior.Delete` models anomalous delete behaviour per principal from the same data events.
- **Versioning** turns each delete into a delete marker (recoverable); **Object Lock** prevents deletion of locked versions.
- The guardrail catalogue's `S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects` RCP denies `s3:DeleteObject` on named buckets.
- S3 server access logs record each delete as `REST.DELETE.OBJECT`.

## Response

1. Revoke the acting principal's sessions.
2. Recover from versions, replication or AWS Backup.
3. Look for `GetObject` by the same principal before the deletes.

**MITRE:** T1485 (*Data Destruction*).
**Severity:** manifest CRITICAL.
**Emulation fingerprint:** session `atomic-t1485-s3-individual` on `stratus-red-team-ransomware-individual-attacker-role`; bucket `stratus-red-team-ransomware-individual-<account>`; 100 `DeleteObject` calls on `data/file-0000.txt` … `data/file-0099.txt`. Not reversible: redeploy the stack.
