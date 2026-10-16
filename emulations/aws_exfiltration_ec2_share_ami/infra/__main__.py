"""
Infrastructure for aws.exfiltration.ec2-share-ami.

Provisions an AMI backed by a snapshot of an empty 1 GiB volume (no tenant data), plus a
scoped attacker role that can change launch permissions on that one AMI only.
"""

import json

import pulumi
import pulumi_aws as aws

account_id = aws.get_caller_identity().account_id
region = aws.get_region().id

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.exfiltration.ec2-share-ami",
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

PREFIX = "stratus-red-team-share-ami"
ATTACKER_ROLE_NAME = "stratus-red-team-share-ami-attacker-role"

volume = aws.ebs.Volume(
    f"{PREFIX}-vol",
    availability_zone=f"{region}a",
    size=1,
    tags={**TAGS, "Name": f"{PREFIX}-vol"},
)

snapshot = aws.ebs.Snapshot(
    f"{PREFIX}-snap",
    volume_id=volume.id,
    tags={**TAGS, "Name": f"{PREFIX}-snap"},
)

ami = aws.ec2.Ami(
    f"{PREFIX}-ami",
    name=f"{PREFIX}-ami",
    description="MayaTrail emulation AMI (empty volume)",
    architecture="x86_64",
    virtualization_type="hvm",
    root_device_name="/dev/xvda",
    ebs_block_devices=[aws.ec2.AmiEbsBlockDeviceArgs(
        device_name="/dev/xvda",
        snapshot_id=snapshot.id,
        volume_size=1,
        volume_type="gp2",
        delete_on_termination=True,
    )],
    tags={**TAGS, "Name": f"{PREFIX}-ami"},
)

# DescribeImageAttribute does not support resource-level permissions.
attacker_role = make_attacker_role(ATTACKER_ROLE_NAME, [
    ami.id.apply(lambda ami_id: {
        "Sid": "ShareLabAmi",
        "Effect": "Allow",
        "Action": ["ec2:ModifyImageAttribute"],
        "Resource": f"arn:aws:ec2:{region}::image/{ami_id}",
    }),
    {
        "Sid": "ReadImageAttributes",
        "Effect": "Allow",
        "Action": ["ec2:DescribeImageAttribute"],
        "Resource": "*",
    },
])

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("ami_id",             ami.id)
pulumi.export("snapshot_id",        snapshot.id)
pulumi.export("volume_id",          volume.id)
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", ATTACKER_ROLE_NAME)
