# Detection Note: T1537 (Exfiltrate RDS Snapshot by Sharing)

**Signal:** `rds:ModifyDBSnapshotAttribute` with `attributeName = restore` and an
account ID in `valuesToAdd` that is not one of your DR/partner accounts.
`valuesToAdd = ["all"]` makes the snapshot **public** — treat as P0.

**Why this beats every other control.** The attacker never touches the running
instance. No network ingress change, no security-group rule, no IAM policy on
the database. They share a point-in-time copy and restore it somewhere you
cannot see. Encryption at rest does not help unless the snapshot's KMS key is
also not shared (a shared snapshot encrypted with the default `aws/rds` key
**cannot** be shared cross-account — attackers copy it to a CMK they control
first, which is a second `CopyDBSnapshot` event worth correlating).

## Field shape

`requestParameters` carries:

```
attributeName        "restore"
dBSnapshotIdentifier  the snapshot
valuesToAdd          [ "<account-id>", ... ]   or [ "all" ]
valuesToRemove       [ ... ]
```

The Stratus technique adds then immediately removes the account (the revert
step), so you will see **two** `ModifyDBSnapshotAttribute` events seconds apart —
one with `valuesToAdd`, one with `valuesToRemove` for the same account. A real
attacker leaves the share in place; the paired add/remove is the emulation
fingerprint, not a reason to downgrade the alert.

## Coverage beyond CloudTrail

- **AWS Config** managed rule `rds-snapshots-public-prohibited` flags public
  snapshots on a schedule — catches shares that predate log collection.
- **Scheduled inventory:** `describe-db-snapshots --snapshot-type manual` then
  `describe-db-snapshot-attributes` per snapshot; alert on any restore value
  outside the org.
- **`rds:CopyDBSnapshot` to an unfamiliar KMS key** often precedes a
  cross-account share of an encrypted snapshot.

## Response

1. `ModifyDBSnapshotAttribute` with `valuesToRemove` to revoke the share
   immediately (or set `attributeValue` back to empty).
2. If the snapshot was made public, assume the data is compromised.
3. If the snapshot was copied to an attacker KMS key first, that copy is outside
   your control — rotate any credentials/secrets stored in the database.
4. Review the acting principal's other recent activity and revoke its sessions.

**MITRE:** T1537 (*Transfer Data to Cloud Account*).
**Severity:** manifest HIGH; IR view HIGH (public share → critical).
**GuardDuty:** no finding type specific to this technique.
