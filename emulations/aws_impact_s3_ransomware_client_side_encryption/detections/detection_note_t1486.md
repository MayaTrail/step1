# Detection Note: T1486 (S3 Ransomware Through Client-Side Encryption)

**Signal:** per object, `GetObject <key>` → `PutObject <key>.encrypted` → `DeleteObject <key>`, all **data events** from one principal on one bucket. Requires an S3 data-event selector on the trail; **Event history and `lookup-events` never show these calls**.

The emulation generates a key in memory (Fernet if `cryptography` is installed, XOR otherwise), and for each of the lab bucket's 50 synthetic objects reads it, uploads the ciphertext as `<key>.encrypted` and deletes the original. The key is discarded at the end of the run: the lab objects are unrecoverable by design (redeploy the stack). This differs from Stratus Red Team's own version of the technique, which re-encrypts objects in place with SSE-C (`CopyObject` with a customer-provided key) after a `PutBucketEncryption` that unblocks SSE-C; that variant is covered by the codefinger emulation.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `s3_put_encrypted_suffix` - PutObject of `*.encrypted` / `*.locked` / `*.crypted` | high | yes (50 times) |
| `s3_get_object_bb`, `s3_delete_object_bb` (base rules) | informational | yes (sequence components only) |
| Read → suffix write → delete by one principal on one bucket within 5m (`temporal_ordered`) | critical | yes |
| ≥ 10 suffix writes by one principal in one bucket within 10m (`event_count`) | critical | yes |

The KQL joins each suffixed `PutObject` back to the original key and its deletion — for any suffix, not just the listed ones — which Sigma cannot express.

## Coverage beyond the rule

- **Versioning** keeps each deleted original as a non-current version; **Object Lock** prevents its deletion. Either defeats this variant — the attacker's ciphertext is a new key and the plaintext is still there.
- **GuardDuty S3 Protection** `Impact:S3/AnomalousBehavior.Write` and `.Delete`, and `Exfiltration:S3/AnomalousBehavior` for the read phase.
- S3-side encryption settings and KMS do not help: the encryption happens on the client.

## Response

1. Revoke the acting principal's sessions.
2. Restore originals from non-current versions, replication or AWS Backup; delete the `*.encrypted` objects only after the originals are back.
3. Treat every object read as exfiltrated; look for a ransom note object.

**MITRE:** T1486 (*Data Encrypted for Impact*).
**Severity:** manifest CRITICAL.
**Emulation fingerprint:** session `atomic-t1486-s3-encrypt` on `stratus-red-team-ransomware-encrypt-attacker-role`; bucket `stratus-red-team-ransomware-encrypt-<account>`; 50 × (GetObject, PutObject `.encrypted`, DeleteObject).
