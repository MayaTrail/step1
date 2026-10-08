# Detection Note: T1486 (S3 Ransomware Through Client-Side Encryption)

**Signal:** Per object: `GetObject` → `PutObject` of `<key>.encrypted` → `DeleteObject` of `<key>`, all **data events** from one principal. Requires an S3 data-event selector on the trail.

## Coverage beyond the rule

- **Versioning** keeps the deleted plaintext as a non-current version; with **Object Lock** the delete cannot remove it at all.
- The SSE-C variant (CODEFINGER) re-encrypts in place with a customer-provided key; watch for `x-amz-server-side-encryption-customer-algorithm` in `PutObject`/`CopyObject`.
- GuardDuty S3 Protection flags anomalous object rewrite and delete volume.

## Response

1. Revoke the acting principal's sessions.
2. Restore originals from non-current versions, replication or AWS Backup.
3. Look for a ransom note object and for GetObject exfiltration before encryption.

**MITRE:** T1486 (*Data Encrypted for Impact*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-ransomware-encrypt-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
