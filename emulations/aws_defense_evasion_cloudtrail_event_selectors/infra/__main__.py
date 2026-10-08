"""
Infrastructure for aws.defense-evasion.cloudtrail-event-selectors.

Provisions a single-region lab trail with its own log bucket, plus a scoped attacker role
that can only read and change that trail's event selectors.
"""

import json

import pulumi
import pulumi_aws as aws

account_id = aws.get_caller_identity().account_id
region = aws.get_region().id

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.defense-evasion.cloudtrail-event-selectors",
}


def make_attacker_role(name: str, statements):
    """
    Scoped attacker role. Trusts the account root so the tenant's cross-account
    role can assume it; the inline policy carries only what the technique needs.
    `statements` may contain pulumi Outputs (resource ARNs).
    """
    role = aws.iam.Role(
        "attacker-role",
        name=name,
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
    aws.iam.RolePolicy(
        "attacker-role-policy",
        name=f"{name}-policy",
        role=role.id,
        policy=pulumi.Output.all(*[pulumi.Output.from_input(s) for s in statements]).apply(
            lambda resolved: json.dumps({"Version": "2012-10-17", "Statement": list(resolved)})
        ),
    )
    return role

TRAIL_NAME = "stratus-red-team-ct-selectors-trail"
BUCKET_NAME = f"stratus-red-team-ct-selectors-bucket-{account_id}"
ATTACKER_ROLE_NAME = "stratus-red-team-ct-selectors-attacker-role"

# ── Log bucket for the lab trail ───────────────────────────────────────────────
bucket = aws.s3.BucketV2(
    "trail-bucket",
    bucket=BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "trail-bucket-pab",
    bucket=bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

bucket_policy = aws.s3.BucketPolicy(
    "trail-bucket-policy",
    bucket=bucket.id,
    policy=bucket.arn.apply(lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{arn}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceAccount": account_id,
                }},
            },
        ],
    })),
)

# ── Lab trail (single-region, management events) ───────────────────────────────
# Only this trail is touched by the attack; the tenant's own trails are out of
# the attacker role's reach because its policy is pinned to this trail's ARN.
trail = aws.cloudtrail.Trail(
    "lab-trail",
    name=TRAIL_NAME,
    s3_bucket_name=bucket.id,
    enable_logging=True,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[bucket_policy]),
)

attacker_role = make_attacker_role(ATTACKER_ROLE_NAME, [
    trail.arn.apply(lambda arn: {
        "Sid": "TamperLabTrailSelectors",
        "Effect": "Allow",
        "Action": ["cloudtrail:GetEventSelectors", "cloudtrail:PutEventSelectors"],
        "Resource": arn,
    }),
])

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("trail_name",         TRAIL_NAME)
pulumi.export("trail_arn",          trail.arn)
pulumi.export("bucket_name",        BUCKET_NAME)
pulumi.export("bucket_arn",         bucket.arn)
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", ATTACKER_ROLE_NAME)
