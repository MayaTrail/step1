"""
Infrastructure for aws.defense-evasion.vpc-remove-flow-logs.

Provisions a VPC with flow logging enabled, plus a scoped attacker role holding
only ec2:DeleteFlowLogs and ec2:DescribeFlowLogs. The technique is destructive
(it removes network visibility), so the attack assumes that role rather than
running with the tenant's cross-account credentials. IAM, not the script, bounds
what the attack can reach.
"""

import json

import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
LOG_GROUP_NAME = "/stratus-red-team/vpc-flow-logs"
ATTACKER_ROLE_NAME = "stratus-red-team-flow-logs-attacker-role"
ATTACKER_POLICY_NAME = "stratus-red-team-flow-logs-attacker-policy"

account_id = aws.get_caller_identity().account_id

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.defense-evasion.vpc-remove-flow-logs",
}

# ── VPC ───────────────────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    "flow-logs-vpc",
    cidr_block="10.0.0.0/16",
    tags={**TAGS, "Name": "stratus-red-team-flow-logs-vpc"},
)

# ── CloudWatch Log Group for flow logs ────────────────────────────────────────
log_group = aws.cloudwatch.LogGroup(
    "flow-logs-log-group",
    name=LOG_GROUP_NAME,
    retention_in_days=7,
    tags=TAGS,
)

# ── IAM Role for flow logs delivery ───────────────────────────────────────────
flow_log_role = aws.iam.Role(
    "flow-log-role",
    name="stratus-red-team-flow-log-role",
    assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }""",
    tags=TAGS,
)

aws.iam.RolePolicy(
    "flow-log-role-policy",
    role=flow_log_role.name,
    policy="""{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        }]
    }""",
)

# ── VPC Flow Log ───────────────────────────────────────────────────────────────
flow_log = aws.ec2.FlowLog(
    "vpc-flow-log",
    vpc_id=vpc.id,
    traffic_type="ALL",
    iam_role_arn=flow_log_role.arn,
    log_destination=log_group.arn,
    tags=TAGS,
)

# ── Attacker role (scoped to the single destructive action) ───────────────────
# Trusts the account root so the tenant's cross-account role can assume it. The
# policy carries only what the technique needs; DeleteFlowLogs has no
# resource-level permission support, so Resource must be "*" and the bound is
# the action list itself.
attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
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
    name=ATTACKER_POLICY_NAME,
    role=attacker_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DeleteFlowLogs",
            "Effect": "Allow",
            "Action": [
                "ec2:DeleteFlowLogs",
                "ec2:DescribeFlowLogs",
            ],
            "Resource": "*",
        }],
    }),
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("vpc_id",        vpc.id)
pulumi.export("flow_log_id",   flow_log.id)
pulumi.export("log_group_name", LOG_GROUP_NAME)
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", ATTACKER_ROLE_NAME)
