import json
import pathlib
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

_NAMES = {'campaign': 'ATOMIC-rds-delete-instance-and-backups',
 'csp': 'aws',
 'resources': {'sg_name': 'atomic-rds-delete-sg',
               'subnet_group_name': 'atomic-rds-delete-subnet-group',
               'attacker_role_name': 'atomic-rds-delete-attacker-role',
               'attacker_policy_name': 'atomic-rds-delete-attacker-policy',
               'db_instance_identifier': 'atomic-rds-delete-db-instance',
               'db_snapshot_identifier': 'proddb-backup-weekly-2026-10-05',
               'flow_log_bucket_prefix': 'atomic-rds-delete-flogs'},
 'pulumi_export_keys': {'attacker_role_arn': 'attacker_role_arn',
                        'attacker_role_name': 'attacker_role_name',
                        'db_instance_arn': 'db_instance_arn',
                        'db_instance_identifier': 'db_instance_identifier',
                        'db_snapshot_arn': 'db_snapshot_arn',
                        'db_snapshot_identifier': 'db_snapshot_identifier',
                        'flow_log_bucket_name': 'flow_log_bucket_name',
                        'vpc_id': 'vpc_id'}}
_R = _NAMES["resources"]

# Resource name constants -- all names passed to AWS APIs come from resource_names.json
SG_NAME                = _R["sg_name"]
SUBNET_GROUP_NAME      = _R["subnet_group_name"]
ATTACKER_ROLE_NAME     = _R["attacker_role_name"]
ATTACKER_POLICY_NAME   = _R["attacker_policy_name"]
DB_INSTANCE_IDENTIFIER = _R["db_instance_identifier"]
DB_SNAPSHOT_IDENTIFIER = _R["db_snapshot_identifier"]
FLOW_LOG_BUCKET_PREFIX = _R["flow_log_bucket_prefix"]

caller     = aws.get_caller_identity()
account_id = caller.account_id
region     = aws.get_region().id

tags = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-rds-delete-instance-and-backups",
    "Technique":   "T1485",
}

# ---------------------------------------------------------------------------
# S3 bucket for VPC flow logs
# ---------------------------------------------------------------------------
flow_log_bucket = aws.s3.BucketV2(
    "flow-log-bucket",
    bucket=f"{FLOW_LOG_BUCKET_PREFIX}-{account_id}",
    force_destroy=True,
    tags=tags,
)

flow_log_bucket_policy = aws.s3.BucketPolicy(
    "flow-log-bucket-policy",
    bucket=flow_log_bucket.id,
    policy=flow_log_bucket.arn.apply(lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FlowLogsPutObject",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{arn}/AWSLogs/{account_id}/vpcflowlogs/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id,
                    }
                },
            },
            {
                "Sid": "FlowLogsAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": arn,
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id}
                },
            },
        ],
    })),
)

# ---------------------------------------------------------------------------
# VPC -- no internet gateway; isolation by omission
# ---------------------------------------------------------------------------
vpc = aws.ec2.Vpc(
    "rds-delete-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**tags, "Name": "atomic-rds-delete-vpc"},
)

# VPC flow log -- depends on the bucket policy being in place first
flow_log = aws.ec2.FlowLog(
    "vpc-flow-log",
    vpc_id=vpc.id,
    traffic_type="ALL",
    log_destination_type="s3",
    log_destination=flow_log_bucket.arn,
    tags=tags,
    opts=pulumi.ResourceOptions(depends_on=[flow_log_bucket_policy]),
)

# ---------------------------------------------------------------------------
# Private subnets -- two AZs required by RDS SubnetGroup
# ---------------------------------------------------------------------------
subnet_a = aws.ec2.Subnet(
    "rds-delete-subnet-a",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone=f"{region}a",
    map_public_ip_on_launch=False,
    tags={**tags, "Name": "atomic-rds-delete-subnet-a"},
)

subnet_b = aws.ec2.Subnet(
    "rds-delete-subnet-b",
    vpc_id=vpc.id,
    cidr_block="10.99.2.0/24",
    availability_zone=f"{region}b",
    map_public_ip_on_launch=False,
    tags={**tags, "Name": "atomic-rds-delete-subnet-b"},
)

# ---------------------------------------------------------------------------
# Security group -- no inbound, allow outbound for RDS health checks
# ---------------------------------------------------------------------------
sg = aws.ec2.SecurityGroup(
    "rds-delete-sg",
    vpc_id=vpc.id,
    name=SG_NAME,
    description="Atomic RDS delete emulation - no inbound rules",
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0,
        to_port=0,
        protocol="-1",
        cidr_blocks=["0.0.0.0/0"],
        description="Allow all outbound",
    )],
    tags={**tags, "Name": SG_NAME},
)

# ---------------------------------------------------------------------------
# DB subnet group
# ---------------------------------------------------------------------------
db_subnet_group = aws.rds.SubnetGroup(
    "rds-delete-subnet-group",
    name=SUBNET_GROUP_NAME,
    subnet_ids=[subnet_a.id, subnet_b.id],
    description="DB subnet group for atomic RDS delete emulation",
    tags=tags,
)

# ---------------------------------------------------------------------------
# Attacker IAM role (over-permissioned credential seeded in the lab)
# Trust: current account root so AssumeRole from the lab operator works.
# ---------------------------------------------------------------------------
attacker_role = aws.iam.Role(
    "rds-delete-attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=tags,
)

attacker_policy = aws.iam.RolePolicy(
    "rds-delete-attacker-policy",
    name=ATTACKER_POLICY_NAME,
    role=attacker_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "RDSDataDestruction",
            "Effect": "Allow",
            "Action": [
                "rds:DeleteDBInstance",
                "rds:DeleteDBSnapshot",
                "rds:DeleteDBClusterSnapshot",
                "rds:DescribeDBInstances",
                "rds:DescribeDBSnapshots",
                "rds:ListTagsForResource",
            ],
            "Resource": f"arn:aws:rds:*:{account_id}:*",
        }],
    }),
)

# ---------------------------------------------------------------------------
# RDS instance -- the T1485 destruction target
# ---------------------------------------------------------------------------
db_password = random.RandomPassword(
    "db-password",
    length=20,
    special=True,
    override_special="!#$%&()-_=+[]<>:?",
)

db_password_param = aws.ssm.Parameter(
    "db-password-param",
    name=f"/atomic-rds-delete/{DB_INSTANCE_IDENTIFIER}/master-password",
    type="SecureString",
    value=db_password.result,
    tags=tags,
)

db_instance = aws.rds.Instance(
    "rds-delete-db-instance",
    identifier=DB_INSTANCE_IDENTIFIER,
    engine="mysql",
    engine_version="8.0",
    instance_class="db.t3.micro",
    allocated_storage=20,
    db_name="proddb",
    username="admin",
    password=db_password.result,
    db_subnet_group_name=db_subnet_group.name,
    vpc_security_group_ids=[sg.id],
    backup_retention_period=1,
    deletion_protection=False,
    skip_final_snapshot=True,
    publicly_accessible=False,
    multi_az=False,
    apply_immediately=True,
    tags=tags,
)

# ---------------------------------------------------------------------------
# Manual snapshot -- bait named to look like a production weekly backup
# ---------------------------------------------------------------------------
manual_snapshot = aws.rds.Snapshot(
    "rds-delete-manual-snapshot",
    db_instance_identifier=db_instance.identifier,
    db_snapshot_identifier=DB_SNAPSHOT_IDENTIFIER,
    tags=tags,
)

# ---------------------------------------------------------------------------
# Exports -- attack.py reads these via pulumi stack output
# ---------------------------------------------------------------------------
pulumi.export("attacker_role_arn",       attacker_role.arn)
pulumi.export("attacker_role_name",      attacker_role.name)
pulumi.export("db_instance_arn",         db_instance.arn)
pulumi.export("db_instance_identifier",  db_instance.identifier)
pulumi.export("db_snapshot_arn",         manual_snapshot.db_snapshot_arn)
pulumi.export("db_snapshot_identifier",  manual_snapshot.db_snapshot_identifier)
pulumi.export("flow_log_bucket_name",    flow_log_bucket.bucket)
pulumi.export("vpc_id",                  vpc.id)
