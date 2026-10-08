# Detection Note: T1537 (Exfiltrate an EBS Snapshot by Sharing It)

**Signal:** `ec2:ModifySnapshotAttribute` whose `requestParameters.createVolumePermission.add.items[]` carries a `userId` outside your organization, or `group: all`.

## Coverage beyond the rule

- **Block public access for EBS snapshots** (account setting) prevents public sharing.
- Snapshots encrypted with the AWS-managed `aws/ebs` key cannot be shared; attackers `CopySnapshot` to a CMK first. Correlate with `CopySnapshot` from the same principal.
- AWS Config rule `ebs-snapshot-public-restorable-check` covers the public case.

## Response

1. Remove the permission (`ModifySnapshotAttribute ... Remove`).
2. Assume the data is copied; rotate any secrets that lived on the disk.
3. Revoke the acting principal's sessions.

**MITRE:** T1537 (*Transfer Data to Cloud Account*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-share-snapshot-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
