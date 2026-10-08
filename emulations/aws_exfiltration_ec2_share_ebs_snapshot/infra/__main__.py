"""
Infrastructure for aws.exfiltration.ec2-share-ebs-snapshot.

Provisions a snapshot of an empty 1 GiB volume (no tenant data), plus a scoped attacker role
that can change permissions on that one snapshot only.
"""

import json

import pulumi
import pulumi_aws as aws

account_id = aws.get_caller_identity().account_id
region = aws.get_region().id

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.exfiltration.ec2-share-ebs-snapshot",
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

ATTACKER_ROLE_NAME = "stratus-red-team-share-snapshot-attacker-role"

volume = aws.ebs.Volume(
    "stratus-red-team-ebs-volume",
    availability_zone=f"{region}a",
    size=1,
    tags={**TAGS, "Name": "stratus-red-team-ebs-volume"},
)

snapshot = aws.ebs.Snapshot(
    "stratus-red-team-ebs-snapshot",
    volume_id=volume.id,
    tags={**TAGS, "Name": "stratus-red-team-ebs-snapshot"},
)

# DescribeSnapshotAttribute does not support resource-level permissions.
attacker_role = make_attacker_role(ATTACKER_ROLE_NAME, [
    snapshot.id.apply(lambda snap_id: {
        "Sid": "ShareLabSnapshot",
        "Effect": "Allow",
        "Action": ["ec2:ModifySnapshotAttribute"],
        "Resource": f"arn:aws:ec2:{region}::snapshot/{snap_id}",
    }),
    {
        "Sid": "ReadSnapshotAttributes",
        "Effect": "Allow",
        "Action": ["ec2:DescribeSnapshotAttribute"],
        "Resource": "*",
    },
])

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("snapshot_id",        snapshot.id)
pulumi.export("volume_id",          volume.id)
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", ATTACKER_ROLE_NAME)
