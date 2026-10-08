# Detection Note: T1485 (S3 Ransomware Through Batch Object Deletion)

**Signal:** `s3:DeleteObjects` (object-level **data event**). It is only in CloudTrail when the trail has an S3 data-event selector (`AWS::S3::Object`) covering the bucket; Event History never shows it.

## Coverage beyond the rule

- **Versioning + MFA delete or S3 Object Lock** turns deletion into a recoverable delete-marker.
- **GuardDuty S3 Protection** raises `Impact:S3/ObjectDeletion.Unusual`-style findings on anomalous delete volume.
- Without data events, the only trace is S3 server access logs or a falling `NumberOfObjects` CloudWatch metric.

## Response

1. Revoke the acting principal's sessions immediately; deletion is fast.
2. Recover from versioning, replication or AWS Backup.
3. Check for a ransom note object and for exfiltration (GetObject) before the delete.

**MITRE:** T1485 (*Data Destruction*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-ransomware-batch-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
