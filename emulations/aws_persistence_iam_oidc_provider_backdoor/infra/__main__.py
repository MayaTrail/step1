import json
import pathlib
import pulumi
import pulumi_aws as aws

# Load resource names - single source of truth
_NAMES = {'campaign': 'ATOMIC-iam-oidc-provider-backdoor',
 'csp': 'aws',
 'resources': {'exec_role_name': 'atomic-iam-oidc-provider-backdoor-exec-role',
               'bait_deploy_role_name': 'acme-prod-deploy-github',
               'trail_name': 'atomic-iam-oidc-provider-backdoor-trail',
               'github_oidc_url': 'https://token.actions.githubusercontent.com',
               'github_oidc_thumbprint': '6938fd4d98bab03faadb97b34396831e3780aea1',
               'bait_oidc_subject': 'repo:acme-corp/prod-deploy:ref:refs/heads/main'},
 'pulumi_export_keys': {'exec_role_arn': 'exec_role_arn',
                        'exec_role_name': 'exec_role_name',
                        'github_provider_arn': 'github_provider_arn',
                        'bait_provider_created': 'bait_provider_created',
                        'bait_deploy_role_arn': 'bait_deploy_role_arn',
                        'bait_deploy_role_name': 'bait_deploy_role_name',
                        'trail_name': 'trail_name',
                        'cloudtrail_bucket_name': 'cloudtrail_bucket_name'}}
_R = _NAMES["resources"]

# Resource name constants (constraint 10: all AWS names as module-level constants)
EXEC_ROLE_NAME = _R["exec_role_name"]
BAIT_DEPLOY_ROLE_NAME = _R["bait_deploy_role_name"]
TRAIL_NAME = _R["trail_name"]
GITHUB_OIDC_URL = _R["github_oidc_url"]
GITHUB_OIDC_THUMBPRINT = _R["github_oidc_thumbprint"]
BAIT_OIDC_SUBJECT = _R["bait_oidc_subject"]

TAGS = {
    "MayaTrail": "true",
    "Purpose": "adversary-emulation",
    "ThreatActor": "ATOMIC-iam-oidc-provider-backdoor",
    "Technique": "T1484.002",
}

# Account identity
caller = aws.get_caller_identity()
account_id = caller.account_id

# ── CloudTrail S3 Bucket ──────────────────────────────────────────────────────
trail_bucket = aws.s3.BucketV2(
    "cloudtrail-log-bucket",
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "cloudtrail-bucket-pab",
    bucket=trail_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "cloudtrail-bucket-sse",
    bucket=trail_bucket.id,
    rules=[
        aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256",
            ),
        )
    ],
)

aws.s3.BucketLifecycleConfigurationV2(
    "cloudtrail-bucket-lifecycle",
    bucket=trail_bucket.id,
    rules=[
        aws.s3.BucketLifecycleConfigurationV2RuleArgs(
            id="expire-30-days",
            status="Enabled",
            filter=aws.s3.BucketLifecycleConfigurationV2RuleFilterArgs(prefix=""),
            expiration=aws.s3.BucketLifecycleConfigurationV2RuleExpirationArgs(days=30),
        )
    ],
)

# Bucket policy for CloudTrail
# Constraint 6b: path must be /AWSLogs/{account_id}/* (not /CloudTrail/ suffix)
trail_bucket_policy = aws.s3.BucketPolicy(
    "cloudtrail-bucket-policy",
    bucket=trail_bucket.id,
    policy=trail_bucket.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": arn,
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"{arn}/AWSLogs/{account_id}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    },
                },
            ],
        })
    ),
)

# CloudTrail Trail
# Constraint 6: enable_logging=True
# Constraint 6b: depends_on bucket policy so CreateTrail validates the policy server-side
trail = aws.cloudtrail.Trail(
    "cloudtrail-trail",
    name=TRAIL_NAME,
    s3_bucket_name=trail_bucket.id,
    include_global_service_events=True,
    is_multi_region_trail=False,
    enable_logging=True,
    enable_log_file_validation=True,
    event_selectors=[
        aws.cloudtrail.TrailEventSelectorArgs(
            read_write_type="All",
            include_management_events=True,
        )
    ],
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[trail_bucket_policy]),
)

# ── Exec Role ─────────────────────────────────────────────────────────────────
# Constraint 3: use current account (self-trust), never a placeholder
exec_role = aws.iam.Role(
    "exec-role",
    name=EXEC_ROLE_NAME,
    description="Emulation exec role for OIDC provider backdoor T1484.002",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }),
    tags=TAGS,
)

aws.iam.RolePolicy(
    "exec-policy",
    role=exec_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OIDCBackdoorEmulation",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateOpenIDConnectProvider",
                    "iam:GetOpenIDConnectProvider",
                    "iam:ListOpenIDConnectProviders",
                    "iam:DeleteOpenIDConnectProvider",
                    "iam:TagOpenIDConnectProvider",
                    "iam:CreateRole",
                    "iam:GetRole",
                    "iam:DeleteRole",
                ],
                "Resource": "*",
            }
        ],
    }),
)

# ── OIDC Provider Lookup (conditional create) ─────────────────────────────────
# Probe for an existing GitHub Actions OIDC provider in this account.
# If one already exists, reuse its ARN; otherwise create the bait provider.
# Pulumi may need ListOpenIDConnectProviders + GetOpenIDConnectProvider to resolve by URL.
bait_provider_created: bool = False
github_provider_arn: pulumi.Output

try:
    _existing = aws.iam.get_open_id_connect_provider(url=GITHUB_OIDC_URL)
    github_provider_arn = pulumi.Output.from_input(_existing.arn)
    bait_provider_created = False
except Exception:
    _bait_provider = aws.iam.OpenIdConnectProvider(
        "legitimate-github-oidc-provider",
        url=GITHUB_OIDC_URL,
        client_id_lists=["sts.amazonaws.com"],
        thumbprint_lists=[GITHUB_OIDC_THUMBPRINT],
        tags=TAGS,
    )
    github_provider_arn = _bait_provider.arn
    bait_provider_created = True

# ── Bait Deployment Role ──────────────────────────────────────────────────────
# Realistic GitHub Actions deployment role an analyst would investigate.
# Trust references the resolved provider ARN (existing or newly created).
# Zero permissions attached - purely cosmetic bait with no blast radius.
_bait_trust_policy = github_provider_arn.apply(
    lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:sub": BAIT_OIDC_SUBJECT
                    }
                },
            }
        ],
    })
)

bait_deploy_role = aws.iam.Role(
    "acme-prod-deploy-github",
    name=BAIT_DEPLOY_ROLE_NAME,
    description="GitHub Actions deployment role for acme-corp/prod-deploy production",
    assume_role_policy=_bait_trust_policy,
    tags=TAGS,
)

# ── Pulumi Exports (constraint 10: export every static name + all dynamic values) ──
pulumi.export("exec_role_name", EXEC_ROLE_NAME)
pulumi.export("bait_deploy_role_name", BAIT_DEPLOY_ROLE_NAME)
pulumi.export("trail_name", TRAIL_NAME)
pulumi.export("exec_role_arn", exec_role.arn)
pulumi.export("github_provider_arn", github_provider_arn)
pulumi.export("bait_provider_created", bait_provider_created)
pulumi.export("bait_deploy_role_arn", bait_deploy_role.arn)
pulumi.export("cloudtrail_bucket_name", trail_bucket.bucket)
