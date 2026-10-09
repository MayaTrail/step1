# Detection Note: T1537 (Backdoor an S3 Bucket Through Its Bucket Policy)

**Signal:** `s3:PutBucketPolicy` (`eventSource: s3.amazonaws.com`, bucket-level **management** event) whose `requestParameters.bucketPolicy.Statement[]` contains an **Allow** for `Principal: "*"` or for an AWS principal (account root ARN, role/user ARN, or bare 12-digit ID) in an account other than the bucket owner's.

The emulation replaces the lab bucket's policy (three synthetic objects) with one statement, `Sid: BackdoorRead`, allowing `s3:GetObject` and `s3:ListBucket` to `arn:aws:iam::193672423079:root` (the Stratus Red Team dummy account), and deletes the policy 15 seconds later. The lab bucket has S3 Block Public Access fully enabled — which does **not** stop a grant to a named account.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `s3_bucket_policy_cross_account` - Allow to a named account not on the allowlist | high | yes (not on the `DeleteBucketPolicy` revert) |
| `s3_bucket_policy_public` - Allow to `*` without `aws:PrincipalOrgID` | high in the file (deploy at critical) | no |

The cross-account rule is the first document and the public rule is held at the same level, because the product displays and AI-validates the first highest-level document and that must be the rule this emulation fires.

The generated rule (`requestParameters|contains: ':root'`) fired on the owner's own account and on Deny statements, and missed bare account IDs and role ARNs. The new rules require an Allow and the principal in the same statement. **Populate the allowlist with your own account ID** before deploying, or same-account policies will alert. The KQL expands statements and compares each principal's account to `RecipientAccountId`, which Sigma cannot do.

## Coverage beyond the rule

- **IAM Access Analyzer** raises a finding for a bucket shared outside the zone of trust. It is the authoritative check.
- **GuardDuty** `Policy:S3/BucketAnonymousAccessGranted` and `Policy:S3/BucketPublicAccessGranted` cover public grants only; nothing fires for a named external account.
- **S3 Block Public Access** (`BlockPublicPolicy`) refuses public policies; it does not consider a named external account public.
- Reads by the external principal (`GetObject`, `ListObjects`) are **data events**: visible only if the trail logs S3 data events for the bucket, or in S3 server access logs.

## Response

1. Save the current policy (`get-bucket-policy`), then restore the approved one or remove the malicious statement.
2. Search data events / server access logs for requests from the external account during the window.
3. Revoke the acting principal's sessions.

**MITRE:** T1537 (*Transfer Data to Cloud Account*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** session `atomic-t1537-s3-backdoor` on `stratus-red-team-s3-backdoor-attacker-role`; `GetBucketPolicy`, `PutBucketPolicy` (Sid `BackdoorRead`), `DeleteBucketPolicy` 15 s later.
