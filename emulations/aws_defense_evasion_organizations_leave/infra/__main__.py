"""
Infrastructure for aws.defense-evasion.organizations-leave.

Provisions only a scoped attacker role. It may describe the organization, and it carries an
explicit Deny on organizations:LeaveOrganization so the attempt can never succeed: an explicit
Deny in the caller's identity policy wins over any Allow, in any account.
"""

import json

import pulumi
import pulumi_aws as aws

account_id = aws.get_caller_identity().account_id
region = aws.get_region().id

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.defense-evasion.organizations-leave",
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

ATTACKER_ROLE_NAME = "stratus-red-team-org-leave-attacker-role"

attacker_role = make_attacker_role(ATTACKER_ROLE_NAME, [
    {
        "Sid": "Recon",
        "Effect": "Allow",
        "Action": ["organizations:DescribeOrganization"],
        "Resource": "*",
    },
    {
        # Safety guard: the emulation makes the LeaveOrganization call so
        # CloudTrail records it, but this Deny guarantees AWS refuses it.
        "Sid": "GuardNeverLeave",
        "Effect": "Deny",
        "Action": ["organizations:LeaveOrganization"],
        "Resource": "*",
    },
])

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", ATTACKER_ROLE_NAME)
