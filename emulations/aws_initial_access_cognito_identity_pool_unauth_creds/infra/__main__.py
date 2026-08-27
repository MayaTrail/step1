import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import pathlib
import pulumi
import pulumi_aws as aws

# =========================================================================== #
# Resource Name Constants -- single source of truth via resource_names.json
# Load from file when present (local dev / pipeline); fall back to embedded
# defaults when the backend worker copies only Pulumi.yaml + __main__.py.
# =========================================================================== #
_DEFAULT_RESOURCES = {
    "identity_pool_name":        "prod-mobile-identities",
    "unauth_role_name":          "atomic-cognito-identity-pool-unauth-creds-unauth-role",
    "victim_role_name":          "atomic-cognito-identity-pool-unauth-creds-victim-role",
    "attacker_user_name":        "atomic-cognito-identity-pool-unauth-creds-attacker",
    "target_bucket_name_prefix": "atomic-cognito-unauth-assets",
}
_p = pathlib.Path(__file__).parent / "resource_names.json"
_R = json.loads(_p.read_text())["resources"] if _p.exists() else _DEFAULT_RESOURCES

IDENTITY_POOL_NAME       = _R["identity_pool_name"]
UNAUTH_ROLE_NAME         = _R["unauth_role_name"]
VICTIM_ROLE_NAME         = _R["victim_role_name"]
ATTACKER_USER_NAME       = _R["attacker_user_name"]
TARGET_BUCKET_PREFIX     = _R["target_bucket_name_prefix"]

# AWS identity resolved at deploy time (plain strings, not Outputs)
identity   = aws.get_caller_identity()
account_id = identity.account_id

# Target bucket name embeds account_id (resolved synchronously)
TARGET_BUCKET_NAME = f"{TARGET_BUCKET_PREFIX}-{account_id}"

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-cognito-identity-pool-unauth-creds",
    "Technique":   "T1078.004",
}

# =========================================================================== #
# S3 Target Bucket
# =========================================================================== #
target_bucket = aws.s3.BucketV2(
    "target-bucket",
    bucket=TARGET_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "target-bucket-sse",
    bucket=target_bucket.id,
    rules=[aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
        apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
            sse_algorithm="AES256",
        ),
    )],
)

aws.s3.BucketPublicAccessBlock(
    "target-bucket-pab",
    bucket=target_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# =========================================================================== #
# Bait S3 Objects
# =========================================================================== #
aws.s3.BucketObjectv2(
    "bait-app-config",
    bucket=target_bucket.id,
    key="config/app-backend-config.json",
    content_type="application/json",
    content=json.dumps({
        "api_endpoint":          "https://api.mobileapp.internal",
        "cognito_pool_id":       "us-east-1:00000000-0000-0000-0000-000000000000",
        "push_notification_key": "AAABBBCCC111",
        "analytics_write_key":   "wk-fake-1234567890abcdef",
        "feature_flags_url":     "https://flags.mobileapp.internal/v1",
    }),
)

aws.s3.BucketObjectv2(
    "bait-user-export",
    bucket=target_bucket.id,
    key="exports/registered-users-2026-07.csv",
    content_type="text/csv",
    content=(
        "user_id,email,signup_date,plan\n"
        "USR-00001,alice.mercer@fakemail.example,2025-11-03,premium\n"
        "USR-00002,brian.okonkwo@fakemail.example,2026-01-17,standard\n"
        "USR-00003,carmen.delgado@fakemail.example,2026-04-29,enterprise\n"
    ),
)

# =========================================================================== #
# Cognito Identity Pool (the misconfigured resource -- unauth access enabled)
# =========================================================================== #
identity_pool = aws.cognito.IdentityPool(
    "identity-pool",
    identity_pool_name=IDENTITY_POOL_NAME,
    allow_unauthenticated_identities=True,
    allow_classic_flow=False,
    tags=TAGS,
)

# =========================================================================== #
# Unauthenticated IAM Role
# Trust condition scoped to this specific pool -- requires pool ID from Output
# =========================================================================== #
unauth_role_trust_policy = identity_pool.id.apply(
    lambda pool_id: json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": pool_id,
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "unauthenticated",
                },
            },
        }],
    })
)

unauth_role = aws.iam.Role(
    "unauth-role",
    name=UNAUTH_ROLE_NAME,
    assume_role_policy=unauth_role_trust_policy,
    tags=TAGS,
)

# Intentionally over-permissioned: bucket-wide S3 read mirrors real-world mobile backend misconfiguration
aws.iam.RolePolicy(
    "unauth-role-policy",
    role=unauth_role.id,
    policy=target_bucket.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "UnauthS3Read",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [arn, f"{arn}/*"],
            }],
        })
    ),
)

# =========================================================================== #
# Identity Pool Role Attachment
# Required for enhanced flow -- GetCredentialsForIdentity resolves role from here
# =========================================================================== #
aws.cognito.IdentityPoolRoleAttachment(
    "role-attachment",
    identity_pool_id=identity_pool.id,
    roles={"unauthenticated": unauth_role.arn},
)

# =========================================================================== #
# Victim IAM Role (compromised credential entry point)
# Self-account root trust so any principal in the account with AssumeRole grant can use it
# =========================================================================== #
victim_role = aws.iam.Role(
    "victim-role",
    name=VICTIM_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

# Cognito discovery only -- no S3 or STS; data access comes via unauth pool credentials
aws.iam.RolePolicy(
    "victim-policy",
    role=victim_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "CognitoPoolDiscovery",
            "Effect": "Allow",
            "Action": [
                "cognito-identity:ListIdentityPools",
                "cognito-identity:DescribeIdentityPool",
            ],
            "Resource": "*",
        }],
    }),
)

# =========================================================================== #
# Attacker IAM User + Access Key
# Holds only sts:AssumeRole on victim-role; all technique permissions live in victim-role
# =========================================================================== #
attacker_user = aws.iam.User(
    "attacker-user",
    name=ATTACKER_USER_NAME,
    tags=TAGS,
)

aws.iam.UserPolicy(
    "attacker-user-policy",
    user=attacker_user.name,
    policy=victim_role.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AssumeVictimRole",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": arn,
            }],
        })
    ),
)

attacker_access_key = aws.iam.AccessKey(
    "attacker-access-key",
    user=attacker_user.name,
)

# =========================================================================== #
# Stack Outputs
# =========================================================================== #

# Static name constants (exported so attack.py can read names from stack output)
pulumi.export("identity_pool_name",       pulumi.Output.from_input(IDENTITY_POOL_NAME))
pulumi.export("unauth_role_name",         pulumi.Output.from_input(UNAUTH_ROLE_NAME))
pulumi.export("victim_role_name",         pulumi.Output.from_input(VICTIM_ROLE_NAME))
pulumi.export("attacker_user_name",       pulumi.Output.from_input(ATTACKER_USER_NAME))
pulumi.export("target_bucket_name_prefix", pulumi.Output.from_input(TARGET_BUCKET_PREFIX))

# Dynamic outputs (known only after pulumi up)
pulumi.export("identity_pool_id",           identity_pool.id)
pulumi.export("unauth_role_arn",            unauth_role.arn)
pulumi.export("victim_role_arn",            victim_role.arn)
pulumi.export("target_bucket_name",         target_bucket.bucket)
pulumi.export("attacker_access_key_id",     attacker_access_key.id)
pulumi.export("attacker_secret_access_key", attacker_access_key.secret)
