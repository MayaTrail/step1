# Detection Note: T1537 (Exfiltrate an EBS Snapshot by Sharing It)

**Signal:** `ec2:ModifySnapshotAttribute` (`eventSource: ec2.amazonaws.com`, management event, snapshot Region, `requestParameters.attributeType: CREATE_VOLUME_PERMISSION`) whose `requestParameters.createVolumePermission.add.items[]` names a `userId` outside your organization, or `group: all`. The unshare carries `createVolumePermission.remove` and must not alert.

The emulation shares a snapshot of an **empty 1 GiB lab volume** with the Stratus Red Team dummy account `193672423079`, reads the permission back, and removes it 15 seconds later. **In a tenant with EBS encryption by default under the AWS-managed `aws/ebs` key, AWS refuses the share** (default-key snapshots cannot be shared); the run reports it and the refused attempt — with an `errorCode` — is the only event. That is why no rule here filters on `errorCode`.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `ebs_snapshot_shared_public` - `group: all` | critical | no |
| `ebs_snapshot_shared_cross_account` - unlisted account, any outcome | high | yes (not on the revert) |
| `SharedSnapshotCopyInitiated` / `SharedSnapshotVolumeCreated` - recipient used the share | high | no (the dummy account does not consume) |
| `ebs_snapshot_created_bb` - CreateSnapshot(s) / CopySnapshot (base rule) | informational | no |
| Create-or-copy then share by one principal within 1h (`temporal_ordered`) | high | no (the lab snapshot is created by the stack) |

The generated rule matched the literal substring `"createVolumePermission":{"add"`, which is serialisation-dependent and never matched in the in-process evaluator. The KQL expands recipients, measures the exposure window to the matching removal, and joins the consumption events.

## Coverage beyond the rule

- **AWS logs consumption in the owner's account:** `SharedSnapshotCopyInitiated` and `SharedSnapshotVolumeCreated`. This is the one snapshot-sharing technique where "was it used?" has an answer in your own CloudTrail.
- **Block public access for snapshots** (`block-all-sharing` / `block-new-sharing`) refuses only public sharing.
- AWS Config `ebs-snapshot-public-restorable-check` covers the public case on its evaluation schedule.
- Attackers `CopySnapshot` a default-key snapshot under a customer-managed key to make it shareable; the correlation covers that path.

## Response

1. Capture `describe-snapshot-attribute --attribute createVolumePermission`, then remove each unlisted recipient.
2. Search for `SharedSnapshotCopyInitiated` / `SharedSnapshotVolumeCreated` on the snapshot; if present, the data is in the recipient's account — rotate every secret that lived on the disk.
3. Revoke the acting principal's sessions.

**MITRE:** T1537 (*Transfer Data to Cloud Account*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** session `atomic-t1537-share-snapshot` on `stratus-red-team-share-snapshot-attacker-role`; snapshot tagged `Name=stratus-red-team-ebs-snapshot`; recipient `193672423079`.
