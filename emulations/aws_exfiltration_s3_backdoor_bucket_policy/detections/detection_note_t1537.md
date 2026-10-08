# Detection Note: T1537 (Backdoor an S3 Bucket Through Its Bucket Policy)

**Signal:** `s3:PutBucketPolicy` where `requestParameters.bucketPolicy.Statement[].Principal.AWS` names an account outside your organization, or `*`.

## Coverage beyond the rule

- **IAM Access Analyzer** raises a finding for a bucket shared outside the zone of trust within minutes. It is the authoritative check.
- **GuardDuty** raises `Policy:S3/BucketAnonymousAccessGranted` only for public (`*`) grants, not for a named external account.
- An SCP or `aws:PrincipalOrgID` condition in the policy itself limits blast radius.

## Response

1. Restore the approved bucket policy (or delete the malicious statement).
2. Check S3 server access logs / data events for `GetObject` by the external principal.
3. Revoke the acting principal's sessions.

**MITRE:** T1537 (*Transfer Data to Cloud Account*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-s3-backdoor-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
