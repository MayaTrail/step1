"""
Infrastructure for aws.impact.s3-ransomware-client-side-encryption.

Provisions an unversioned lab bucket with 50 synthetic objects, plus a scoped attacker role that
can only list, read, write and delete objects in that bucket.
"""

import json

import pulumi
import pulumi_aws as aws

account_id = aws.get_caller_identity().account_id
region = aws.get_region().id

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.impact.s3-ransomware-client-side-encryption",
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

BUCKET_NAME = f"stratus-red-team-ransomware-encrypt-{account_id}"
ATTACKER_ROLE_NAME = "stratus-red-team-ransomware-encrypt-attacker-role"
OBJECT_COUNT = 50

bucket = aws.s3.BucketV2(
    "lab-bucket",
    bucket=BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

pab = aws.s3.BucketPublicAccessBlock(
    "lab-bucket-pab",
    bucket=bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# Synthetic objects only; nothing of the tenant's is ever in this bucket.
for i in range(OBJECT_COUNT):
    aws.s3.BucketObjectv2(
        f"lab-object-{i}",
        bucket=bucket.id,
        key=f"data/file-{i:04d}.txt",
        content=f"Synthetic sensitive data file {i} - MayaTrail emulation target\n",
        tags=TAGS,
        opts=pulumi.ResourceOptions(depends_on=[pab]),
    )

attacker_role = make_attacker_role(ATTACKER_ROLE_NAME, [
    bucket.arn.apply(lambda arn: {
        "Sid": "ListLabBucket",
        "Effect": "Allow",
        "Action": ["s3:ListBucket"],
        "Resource": arn,
    }),
    bucket.arn.apply(lambda arn: {
        "Sid": "RewriteLabObjects",
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        "Resource": f"{arn}/*",
    }),
])

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("bucket_name",        BUCKET_NAME)
pulumi.export("bucket_arn",         bucket.arn)
pulumi.export("object_count",       OBJECT_COUNT)
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", ATTACKER_ROLE_NAME)
