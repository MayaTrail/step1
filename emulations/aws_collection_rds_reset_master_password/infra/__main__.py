import json
import pathlib
import sys

import pulumi
import pulumi_aws as aws
import secrets as _secrets
import string as _string


class _RandomPassword:
    """Shim for pulumi_random.RandomPassword (that provider is not in the backend
    worker image). Generated at deploy time with the stdlib `secrets` module and
    exposes `.result` so the call sites are unchanged. RDS rejects / @ " and space."""
    def __init__(self, _name, length=16, special=True, override_special=None, **_kw):
        specials = ""
        if special:
            specials = override_special if override_special is not None else "!#$%&*()-_=+[]<>:?"
            specials = "".join(c for c in specials if c not in '/@" ')
        pools = [_string.ascii_lowercase, _string.ascii_uppercase, _string.digits] + ([specials] if specials else [])
        chars = [_secrets.choice(p) for p in pools]
        allowed = "".join(pools)
        chars += [_secrets.choice(allowed) for _ in range(max(length - len(chars), 0))]
        _secrets.SystemRandom().shuffle(chars)
        self.result = "".join(chars)


class random:
    RandomPassword = _RandomPassword

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# --- Resource Name Constants (single source of truth: resource_names.json) ---
_NAMES = {'campaign': 'ATOMIC-rds-reset-master-password',
 'csp': 'aws',
 'resources': {'vpc_name': 'atomic-rds-reset-master-password-lab-vpc',
               'subnet_a_name': 'atomic-rds-reset-master-password-lab-subnet-a',
               'subnet_b_name': 'atomic-rds-reset-master-password-lab-subnet-b',
               'sg_name': 'atomic-rds-reset-master-password-rds-sg',
               'subnet_group_name': 'atomic-rds-reset-master-password-rds-subnet-group',
               'victim_role_name': 'atomic-rds-reset-master-password-victim-role',
               'rds_instance_identifier': 'atomic-rds-reset-master-password-lab-rds-instance',
               'db_name': 'labdb',
               'db_username': 'admin',
               'bait_secret_name': 'prod/database/master_credentials'},
 'pulumi_export_keys': {'victim_role_arn': 'victim_role_arn',
                        'rds_endpoint': 'rds_endpoint',
                        'rds_instance_arn': 'rds_instance_arn',
                        'bait_secret_arn': 'bait_secret_arn'}}
_R = _NAMES["resources"]

VPC_NAME                = _R["vpc_name"]
SUBNET_A_NAME           = _R["subnet_a_name"]
SUBNET_B_NAME           = _R["subnet_b_name"]
SG_NAME                 = _R["sg_name"]
SUBNET_GROUP_NAME       = _R["subnet_group_name"]
VICTIM_ROLE_NAME        = _R["victim_role_name"]
RDS_INSTANCE_IDENTIFIER = _R["rds_instance_identifier"]
DB_NAME                 = _R["db_name"]
DB_USERNAME             = _R["db_username"]
BAIT_SECRET_NAME        = _R["bait_secret_name"]

# Export static name constants so attack.py can read them via stack output
pulumi.export("vpc_name",                VPC_NAME)
pulumi.export("subnet_a_name",           SUBNET_A_NAME)
pulumi.export("subnet_b_name",           SUBNET_B_NAME)
pulumi.export("sg_name",                 SG_NAME)
pulumi.export("subnet_group_name",       SUBNET_GROUP_NAME)
pulumi.export("victim_role_name",        VICTIM_ROLE_NAME)
pulumi.export("rds_instance_identifier", RDS_INSTANCE_IDENTIFIER)
pulumi.export("db_name",                 DB_NAME)
pulumi.export("db_username",             DB_USERNAME)
pulumi.export("bait_secret_name",        BAIT_SECRET_NAME)

# Current account and region (synchronous, plain strings - not Outputs)
identity   = aws.get_caller_identity()
account_id = identity.account_id
region     = aws.get_region().id   # v7: use .id, not .name

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-rds-reset-master-password",
    "Technique":   "T1213",
}

# =============================================================================
# VPC + Network Infrastructure
# =============================================================================

lab_vpc = aws.ec2.Vpc(
    "lab-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": VPC_NAME},
)

# VPC Flow Logs (sandbox_vpc.flow_logs = true)
flow_log_group = aws.cloudwatch.LogGroup(
    "lab-vpc-flow-log-group",
    name=f"/aws/vpc/flowlogs/{VPC_NAME}",
    retention_in_days=1,
    tags=TAGS,
)

flow_log_role = aws.iam.Role(
    "lab-vpc-flow-log-role",
    name=f"{VPC_NAME}-flow-log-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicy(
    "lab-vpc-flow-log-role-policy",
    role=flow_log_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
            ],
            "Resource": "*",
        }],
    }),
)

aws.ec2.FlowLog(
    "lab-vpc-flow-log",
    iam_role_arn=flow_log_role.arn,
    log_destination=flow_log_group.arn,
    traffic_type="ALL",
    vpc_id=lab_vpc.id,
    tags=TAGS,
)

# Private subnets in two AZs (RDS SubnetGroup requires minimum two AZs)
lab_subnet_a = aws.ec2.Subnet(
    "lab-subnet-a",
    vpc_id=lab_vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone=f"{region}a",
    map_public_ip_on_launch=False,
    tags={**TAGS, "Name": SUBNET_A_NAME},
)

lab_subnet_b = aws.ec2.Subnet(
    "lab-subnet-b",
    vpc_id=lab_vpc.id,
    cidr_block="10.99.2.0/24",
    availability_zone=f"{region}b",
    map_public_ip_on_launch=False,
    tags={**TAGS, "Name": SUBNET_B_NAME},
)

# Security Group - no ingress (password reset is a control-plane API call only)
rds_sg = aws.ec2.SecurityGroup(
    "rds-sg",
    name=SG_NAME,
    description="RDS lab security group - no ingress - control-plane attack only",
    vpc_id=lab_vpc.id,
    ingress=[],
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0,
        to_port=0,
        protocol="-1",
        cidr_blocks=["0.0.0.0/0"],
        description="Allow all egress",
    )],
    tags={**TAGS, "Name": SG_NAME},
)

# RDS Subnet Group spanning two AZs
rds_subnet_group = aws.rds.SubnetGroup(
    "rds-subnet-group",
    name=SUBNET_GROUP_NAME,
    description="Lab DB subnet group spanning two availability zones",
    subnet_ids=[lab_subnet_a.id, lab_subnet_b.id],
    tags=TAGS,
)

# =============================================================================
# Victim IAM Role (attack_surface)
# =============================================================================

victim_role = aws.iam.Role(
    "victim-role",
    name=VICTIM_ROLE_NAME,
    description="Over-privileged DB management role for adversary emulation",
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

# =============================================================================
# RDS MySQL Instance (target)
# =============================================================================

db_master_password = random.RandomPassword(
    "db-master-password",
    length=32,
    special=False,
)

lab_rds_instance = aws.rds.Instance(
    "lab-rds-instance",
    identifier=RDS_INSTANCE_IDENTIFIER,
    engine="mysql",
    engine_version="8.0",
    instance_class="db.t3.micro",
    allocated_storage=20,
    db_name=DB_NAME,
    username=DB_USERNAME,
    password=db_master_password.result,
    publicly_accessible=False,
    db_subnet_group_name=rds_subnet_group.name,
    vpc_security_group_ids=[rds_sg.id],
    skip_final_snapshot=True,
    deletion_protection=False,
    multi_az=False,
    apply_immediately=True,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[rds_subnet_group, rds_sg]),
)

# =============================================================================
# Victim Role Inline Policy - scoped to lab RDS instance ARN
# All components are known at program start so no Output.apply needed
# =============================================================================

rds_instance_arn = f"arn:aws:rds:{region}:{account_id}:db:{RDS_INSTANCE_IDENTIFIER}"

victim_role_policy = aws.iam.RolePolicy(
    "victim-role-policy",
    name="rds-password-reset-policy",
    role=victim_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "RDSPasswordReset",
            "Effect": "Allow",
            "Action": [
                "rds:ModifyDBInstance",
                "rds:DescribeDBInstances",
            ],
            "Resource": rds_instance_arn,
        }],
    }),
    opts=pulumi.ResourceOptions(depends_on=[victim_role, lab_rds_instance]),
)

# =============================================================================
# Bait Secret (bait) - prod/database/master_credentials
# =============================================================================

bait_master_credentials = aws.secretsmanager.Secret(
    "bait-master-credentials",
    name=BAIT_SECRET_NAME,
    description="RDS master credentials for production MySQL cluster",
    recovery_window_in_days=0,
    tags=TAGS,
)

bait_master_credentials_version = aws.secretsmanager.SecretVersion(
    "bait-master-credentials-version",
    secret_id=bait_master_credentials.id,
    secret_string=lab_rds_instance.address.apply(
        lambda addr: json.dumps({
            "username": DB_USERNAME,
            "password": "InitialSeedCredential-ChangeAfterDeploy",
            "host":     addr,
            "dbname":   DB_NAME,
            "port":     3306,
            "engine":   "mysql",
        })
    ),
    opts=pulumi.ResourceOptions(depends_on=[bait_master_credentials, lab_rds_instance]),
)

# =============================================================================
# Dynamic Outputs (known only after pulumi up)
# =============================================================================

pulumi.export("victim_role_arn",  victim_role.arn)
pulumi.export("rds_endpoint",     lab_rds_instance.address)
pulumi.export("rds_instance_arn", lab_rds_instance.arn)
pulumi.export("bait_secret_arn",  bait_master_credentials.arn)
