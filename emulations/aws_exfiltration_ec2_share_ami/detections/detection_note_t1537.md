# Detection Note: T1537 (Exfiltrate an AMI by Sharing It)

**Signal:** `ec2:ModifyImageAttribute` whose `requestParameters.launchPermission.add.items[]` carries a `userId` outside your organization, or `group: all` (public).

## Coverage beyond the rule

- **EC2 block public access for AMIs** (account setting) prevents public sharing outright.
- A scheduled inventory (`DescribeImages --owners self` then `DescribeImageAttribute launchPermission`) catches shares that predate log collection.
- Snapshots behind the AMI are shared implicitly for launch; also watch `ModifySnapshotAttribute`.

## Response

1. Remove the launch permission (`ModifyImageAttribute ... Remove`).
2. Assume the recipient may already have copied the AMI; rotate any secrets baked into it.
3. Revoke the acting principal's sessions.

**MITRE:** T1537 (*Transfer Data to Cloud Account*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-share-ami-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
