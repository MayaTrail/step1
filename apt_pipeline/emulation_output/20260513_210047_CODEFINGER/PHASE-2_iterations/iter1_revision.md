```json
{
  "status": "PHASE_1_COMPLETE",
  "platform": "aws",
  "sandbox_vpc": null,
  "resources": [
    {
      "name": "codefinger-victim-iam-user",
      "pulumi_type": "aws.iam.User",
      "resource_category": "attack_surface",
      "purpose": "Victim IAM user representing a developer/service account whose long-term access keys were publicly exposed. Sole entry point for T1078.004.",
      "techniques_served": ["T1078.004"],
      "configuration_notes": "No console access — Codefinger is programmatic-only. Tags only at creation; access key is a separate resource. path='/' default.",
      "depends_on": [],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-victim-iam-access-key",
      "pulumi_type": "aws.iam.AccessKey",
      "resource_category": "attack_surface",
      "purpose": "Long-term programmatic access key for the victim user. Key ID and secret are written into the bait credential object at deploy time, simulating the T1552.001 public exposure that Codefinger exploits.",
      "techniques_served": ["T1078.004", "T1552.001"],
      "configuration_notes": "aws.iam.AccessKey with user = codefinger-victim-iam-user.name. Export id and secret as encrypted Pulumi stack outputs so the attack script and bait object can reference them. No rotation — mimics the real scenario where long-term keys are never cycled.",
      "depends_on": ["codefinger-victim-iam-user"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-victim-iam-policy",
      "pulumi_type": "aws.iam.UserPolicy",
      "resource_category": "attack_surface",
      "purpose": "Inline policy granting the victim user over-permissioned S3 access scoped only to the target bucket. Intentionally includes PutLifecycleConfiguration (T1490) and PutObject (T1486 SSE-C re-upload).",
      "techniques_served": ["T1530", "T1486", "T1485", "T1490"],
      "configuration_notes": "Inline UserPolicy (not managed) keeps blast radius narrow. Actions: s3:GetObject, s3:PutObject, s3:DeleteObject, s3:ListBucket, s3:GetBucketLocation, s3:PutLifecycleConfiguration, s3:GetLifecycleConfiguration. ISSUE-3 FIX: Resource ARNs must be built at deploy time via pulumi.interpolate from codefinger-target-s3-bucket.bucket output — never hardcode the bucket name string. E.g.: pulumi.interpolate`arn:aws:s3:::${targetBucket.bucket}` and pulumi.interpolate`arn:aws:s3:::${targetBucket.bucket}/*`.",
      "depends_on": ["codefinger-victim-iam-user", "codefinger-target-s3-bucket"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-target-s3-bucket",
      "pulumi_type": "aws.s3.BucketV2",
      "resource_category": "target",
      "purpose": "Isolated S3 bucket containing synthetic data objects. The attack script enumerates objects (T1530), re-uploads each with SSE-C and an attacker-held AES-256 key (T1486 simulation), sets a 7-day lifecycle deletion rule (T1490 simulation), then deletes originals (T1485 simulation).",
      "techniques_served": ["T1530", "T1486", "T1485", "T1490"],
      "configuration_notes": "ISSUE-3 FIX: Set bucket name to codefinger-target-${stackName} where stackName comes from pulumi.getStack() — guarantees global uniqueness across accounts. Block all public access. Do NOT set default SSE-KMS or a bucket key — SSE-C conflicts with mandatory SSE-KMS. Versioning DISABLED intentionally: Codefinger specifically targets unversioned buckets so lifecycle deletion is irrecoverable. forceDestroy=true for teardown.",
      "depends_on": [],
      "cleanup_method": "pulumi destroy (forceDestroy=true)",
      "estimated_cost_usd_hr": 0.001
    },
    {
      "name": "codefinger-synthetic-data-finance",
      "pulumi_type": "aws.s3.BucketObject",
      "resource_category": "target",
      "purpose": "Synthetic CSV files in a finance/ prefix simulating sensitive financial records. These are the pre-encryption originals the attack replaces with SSE-C ciphertext copies.",
      "techniques_served": ["T1530", "T1486", "T1485"],
      "configuration_notes": "Upload 3 objects: finance/Q4_2025_revenue.csv, finance/payroll_export_2025.csv, finance/accounts_receivable.csv. Content: fabricated tabular data only (e.g., random names, fake dollar amounts). No real PII. Standard AES256 at rest before the attack.",
      "depends_on": ["codefinger-target-s3-bucket"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-synthetic-data-hr",
      "pulumi_type": "aws.s3.BucketObject",
      "resource_category": "target",
      "purpose": "Synthetic HR records in an hr/ prefix. Separate prefix validates the attack loop correctly iterates across multiple S3 key namespaces.",
      "techniques_served": ["T1530", "T1486", "T1485"],
      "configuration_notes": "Upload 2 objects: hr/employee_roster_2025.csv, hr/compensation_bands.csv. Entirely fabricated content. Standard AES256 at rest before the attack.",
      "depends_on": ["codefinger-target-s3-bucket"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-bait-public-bucket",
      "pulumi_type": "aws.s3.BucketV2",
      "resource_category": "bait",
      "purpose": "Public-readable S3 bucket acting as the 'accidentally exposed' source where the victim's credentials are discoverable. Simulates a misconfigured IaC state bucket that Codefinger-style actors scan to harvest IAM keys (T1552.001 discovery vector).",
      "techniques_served": ["T1552.001"],
      "configuration_notes": "ISSUE-3 FIX: Set bucket name to acme-devops-tfstate-${stackName} (pulumi.getStack()) for global uniqueness. ISSUE-4 FIX: The realistic S3 name acme-devops-tfstate-${stackName} mimics an accidentally public Terraform state bucket — plausible scenario for credential exposure. forceDestroy=true. Public access is controlled exclusively via codefinger-bait-public-access-block; do not set any ACL flags on the bucket itself.",
      "depends_on": [],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-bait-public-access-block",
      "pulumi_type": "aws.s3.BucketPublicAccessBlock",
      "resource_category": "bait",
      "purpose": "ISSUE-1 FIX: Explicitly disables all four S3 Block Public Access flags on the bait bucket. Required since April 2023 S3 default — without this resource, the bucket policy granting Principal:'*' is rejected by S3 and T1552.001 silently fails.",
      "techniques_served": ["T1552.001"],
      "configuration_notes": "bucket = codefinger-bait-public-bucket.id. blockPublicAcls=false, blockPublicPolicy=false, ignorePublicAcls=false, restrictPublicBuckets=false. Must be deployed AFTER codefinger-bait-public-bucket and BEFORE codefinger-bait-public-bucket-policy. The bucket policy depends_on this resource.",
      "depends_on": ["codefinger-bait-public-bucket"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-bait-public-bucket-policy",
      "pulumi_type": "aws.s3.BucketPolicy",
      "resource_category": "bait",
      "purpose": "Grants public s3:GetObject on the bait credential file only, making it discoverable without exposing the full bucket listing.",
      "techniques_served": ["T1552.001"],
      "configuration_notes": "ISSUE-3 FIX: Resource ARN built via pulumi.interpolate from codefinger-bait-public-bucket.bucket output — e.g., pulumi.interpolate`arn:aws:s3:::${baitBucket.bucket}/terraform.tfvars`. Principal: '*'. Effect: Allow. Action: s3:GetObject. depends_on codefinger-bait-public-access-block to guarantee public access is unblocked before the policy is applied.",
      "depends_on": ["codefinger-bait-public-bucket", "codefinger-bait-public-access-block"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-exposed-credentials-object",
      "pulumi_type": "aws.s3.BucketObject",
      "resource_category": "bait",
      "purpose": "A terraform.tfvars file containing the victim IAM access key and secret, simulating an accidentally committed credential file discoverable on a public bucket — the exact initial access vector Codefinger uses (T1552.001).",
      "techniques_served": ["T1552.001", "T1078.004"],
      "configuration_notes": "Key: terraform.tfvars. Content rendered at deploy time via Pulumi interpolation of codefinger-victim-iam-access-key outputs: 'aws_access_key_id = \"<id>\"\\naws_secret_access_key = \"<secret>\"\\nregion = \"us-east-1\"'. ISSUE-2 FIX: Do NOT set acl='public-read' — BucketOwnerEnforced (S3 default since 2023) disables all ACLs and setting one throws AccessControlListNotSupported. Public read is already granted by codefinger-bait-public-bucket-policy; the ACL was redundant. The attack script sources credentials from this object or a local AWS profile populated from it.",
      "depends_on": ["codefinger-bait-public-bucket", "codefinger-bait-public-bucket-policy", "codefinger-victim-iam-access-key"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-cloudtrail-log-bucket",
      "pulumi_type": "aws.s3.BucketV2",
      "resource_category": "support",
      "purpose": "Receives CloudTrail events for the emulation. Key detection signals: SSE-C PutObject entries (HMAC only, no key logged), PutLifecycleConfiguration calls, and DeleteObject volume spikes.",
      "techniques_served": [],
      "configuration_notes": "ISSUE-3 FIX: Set bucket name to codefinger-cloudtrail-${stackName} (pulumi.getStack()). Private, forceDestroy=true. Bucket policy must allow cloudtrail.amazonaws.com s3:PutObject and s3:GetBucketAcl. Retrieve account ID via aws.getCallerIdentity() — never hardcode in the resource ARN or the deployment will fail.",
      "depends_on": [],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.001
    },
    {
      "name": "codefinger-cloudtrail-log-bucket-policy",
      "pulumi_type": "aws.s3.BucketPolicy",
      "resource_category": "support",
      "purpose": "Grants CloudTrail service principal write access to the log bucket.",
      "techniques_served": [],
      "configuration_notes": "Two statements: (1) s3:GetBucketAcl for cloudtrail.amazonaws.com; (2) s3:PutObject for cloudtrail.amazonaws.com with Condition StringEquals s3:x-amz-acl=bucket-owner-full-control. ISSUE-3 FIX: Use pulumi.interpolate for both the bucket ARN (from codefinger-cloudtrail-log-bucket.bucket) and the account ID (from aws.getCallerIdentity output) — no hardcoded strings.",
      "depends_on": ["codefinger-cloudtrail-log-bucket"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.0
    },
    {
      "name": "codefinger-cloudtrail",
      "pulumi_type": "aws.cloudtrail.Trail",
      "resource_category": "support",
      "purpose": "Captures management events and S3 data-plane events for the target bucket. Provides the detection artifact set for GuardDuty/SIEM validation after the emulation run.",
      "techniques_served": ["T1530", "T1486", "T1485", "T1490"],
      "configuration_notes": "enableLogFileValidation=true. isMultiRegionTrail=false (cost control). eventSelectors: [{readWriteType: 'All', includeManagementEvents: true, dataResources: [{type: 'AWS::S3::Object', values: [pulumi.interpolate`arn:aws:s3:::${targetBucket.bucket}/`]}]}]. s3BucketName = codefinger-cloudtrail-log-bucket.bucket (via interpolate). ISSUE-3 FIX: All ARN references use pulumi.interpolate from bucket output properties. Must deploy after bucket policy or CloudTrail validation will fail.",
      "depends_on": ["codefinger-cloudtrail-log-bucket", "codefinger-cloudtrail-log-bucket-policy"],
      "cleanup_method": "pulumi destroy",
      "estimated_cost_usd_hr": 0.02
    }
  ],
  "userdata_actions": [],
  "vulnerable_app": null,
  "iam_policies": [
    {
      "name": "codefinger-victim-inline-policy",
      "attached_to": "codefinger-victim-iam-user",
      "policy_type": "inline",
      "intentionally_overpermissioned": true,
      "reason": "Codefinger exploits broadly-scoped S3 policies found on compromised service accounts. PutLifecycleConfiguration is the critical over-permission enabling irrecoverable T1490 deletion scheduling; PutObject enables SSE-C re-encryption (T1486). Real-world victims had these permissions because the account was used for backup or ETL automation.",
      "policy_json_note": "ISSUE-3 FIX: Do not hardcode bucket ARNs. Build at deploy time: Resource[0] = pulumi.interpolate`arn:aws:s3:::${targetBucket.bucket}`, Resource[1] = pulumi.interpolate`arn:aws:s3:::${targetBucket.bucket}/*`. Pass as policyDocument via pulumi.all([...]).apply(...).",
      "policy_json_template": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Sid": "CodefingervictimS3Access",
            "Effect": "Allow",
            "Action": [
              "s3:GetObject",
              "s3:PutObject",
              "s3:DeleteObject",
              "s3:ListBucket",
              "s3:GetBucketLocation",
              "s3:PutLifecycleConfiguration",
              "s3:GetLifecycleConfiguration"
            ],
            "Resource": [
              "arn:aws:s3:::REPLACE_WITH_PULUMI_INTERPOLATE_targetBucket_bucket",
              "arn:aws:s3:::REPLACE_WITH_PULUMI_INTERPOLATE_targetBucket_bucket/*"
            ]
          }
        ]
      }
    }
  ],
  "permission_boundaries": [],
  "resource_dependency_order": [
    "codefinger-bait-public-bucket",
    "codefinger-target-s3-bucket",
    "codefinger-cloudtrail-log-bucket",
    "codefinger-cloudtrail-log-bucket-policy",
    "codefinger-cloudtrail",
    "codefinger-victim-iam-user",
    "codefinger-victim-iam-access-key",
    "codefinger-victim-iam-policy",
    "codefinger-synthetic-data-finance",
    "codefinger-synthetic-data-hr",
    "codefinger-bait-public-access-block",
    "codefinger-bait-public-bucket-policy",
    "codefinger-exposed-credentials-object"
  ],
  "naming_convention": "codefinger-{resource_name}",
  "estimated_total_cost_usd_hr": 0.022,
  "tags": {
    "MayaTrail": "true",
    "Purpose": "adversary-emulation",
    "ThreatActor": "Codefinger",
    "Environment": "isolated-lab"
  }
}
```

---

**Changes made per issue:**

| Issue | Fix Applied |
|---|---|
| ISSUE-1 (critical) | Added `codefinger-bait-public-access-block` (`aws.s3.BucketPublicAccessBlock`) with all four flags `false`; inserted between bait bucket and bucket policy in dependency order; bucket policy now `depends_on` this resource |
| ISSUE-2 (high) | Removed `acl='public-read'` from `codefinger-exposed-credentials-object`; configuration_notes explain why (BucketOwnerEnforced disables ACLs; bucket policy already grants public GetObject) |
| ISSUE-3 (high) | All three bucket names now use `${stackName}` suffix via `pulumi.getStack()`; IAM policy and CloudTrail ARNs explicitly call out `pulumi.interpolate` from `.bucket` output properties; `policy_json_template` uses `REPLACE_WITH_PULUMI_INTERPOLATE` sentinel strings to prevent hardcoding |
| ISSUE-4 (low) | Bait bucket S3 name changed to `acme-devops-tfstate-${stackName}` — realistic misconfigured Terraform state bucket scenario |