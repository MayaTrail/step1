# Detection Note: T1537 (Exfiltrate an AMI by Sharing It)

**Signal:** `ec2:ModifyImageAttribute` (`eventSource: ec2.amazonaws.com`, management event, image Region) whose `requestParameters.launchPermission.add.items[]` names a `userId`, `organizationArn` or `organizationalUnitArn` outside your organization, or `group: all` (public). The unshare carries `launchPermission.remove` instead and must not alert.

The emulation adds launch permission on a lab AMI (built from an empty 1 GiB volume) for the Stratus Red Team dummy account `193672423079`, reads it back with `DescribeImageAttribute`, and removes it 15 seconds later. If AWS refuses the share (for example an AMI backed by a snapshot under the default `aws/ebs` key), the attempt is still logged with an `errorCode`.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `ami_shared_public` - launch permission for `group: all` | critical | no |
| `ami_shared_cross_account` - any other recipient not on the allowlist | high | yes (not on the revert) |
| `ami_created_bb` - CreateImage / CopyImage / RegisterImage (base rule) | informational | no |
| Create-or-copy then share by one principal within 1h (`temporal_ordered`) | high | no (the lab AMI is created by the stack) |

The generated rule matched the literal substring `"launchPermission":{"add"`, which depends on how a backend serialises nested JSON and never matched in the in-process evaluator; the rules now address `requestParameters.launchPermission.add` directly. None filter on `errorCode`. The KQL expands each recipient, excludes your own account and allowlist, and measures the exposure window until the matching removal.

## Coverage beyond the rule

- **Block public access for AMIs** is enabled by default for new accounts and for accounts that have had no public AMI since July 15, 2023. It refuses `group: all`; it does **not** stop a share with a named account.
- No GuardDuty finding type covers an AMI share. The recipient's `CopyImage` / `RunInstances` happen in their account and leave no event in yours, unless the snapshots are encrypted with your customer-managed key (then their use of the key is a KMS event here).
- A scheduled inventory (`describe-images --owners self`, then `describe-image-attribute --attribute launchPermission`) catches shares that predate log collection.

## Response

1. Remove the launch permission (`modify-image-attribute ... --launch-permission "Remove=[{UserId=<id>}]"`), after recording the full current list.
2. Assume the recipient may already have copied the AMI; rotate any credential, key or secret baked into it.
3. Revoke the acting principal's sessions.

**MITRE:** T1537 (*Transfer Data to Cloud Account*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** session `atomic-t1537-share-ami` on `stratus-red-team-share-ami-attacker-role`; AMI `stratus-red-team-share-ami-ami`; recipient `193672423079`; add and remove 15 s apart.
