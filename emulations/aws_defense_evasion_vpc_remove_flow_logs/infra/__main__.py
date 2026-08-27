import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
LOG_GROUP_NAME = "/stratus-red-team/vpc-flow-logs"

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

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("vpc_id",        vpc.id)
pulumi.export("flow_log_id",   flow_log.id)
pulumi.export("log_group_name", LOG_GROUP_NAME)
