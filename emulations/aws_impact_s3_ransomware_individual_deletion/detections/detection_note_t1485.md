# Detection Note: T1485 (S3 Ransomware Through Individual Object Deletion)

**Signal:** A burst of `s3:DeleteObject` **data events** from one principal against one bucket (the KQL uses 50 in 5 minutes; tune per environment). Requires an S3 data-event selector on the trail.

## Coverage beyond the rule

- **Versioning + MFA delete or S3 Object Lock** makes this recoverable.
- **GuardDuty S3 Protection** models anomalous delete volume per principal.
- Correlate with the absence of `PutObject` from the same principal: churn has writes, destruction does not.

## Response

1. Revoke the acting principal's sessions.
2. Recover from versioning, replication or AWS Backup.
3. Look for exfiltration (`GetObject`) by the same principal before the deletes.

**MITRE:** T1485 (*Data Destruction*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-ransomware-individual-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
