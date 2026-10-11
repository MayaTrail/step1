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

_NAMES = {'campaign': 'ATOMIC-rds-ransomware-kms',
 'csp': 'aws',
 'resources': {'victim_kms_alias': 'alias/rds-ransomware-kms-victim',
               'attacker_kms_alias': 'alias/rds-ransomware-kms-attacker',
               'attacker_role_name': 'rds-ransomware-kms-attacker-role',
               'db_identifier': 'rds-ransomware-kms-prod-customer-db',
               'snapshot_identifier': 'rds-ransomware-kms-prod-orders-2026-q3',
               'secret_name': 'prod/rds/orders/master',
               'db_subnet_group_name': 'rds-ransomware-kms-subnet-group',
               'db_sg_name': 'rds-ransomware-kms-db-sg',
               'flow_log_role_name': 'rds-ransomware-kms-flow-log-role',
               'flow_log_group_name': '/rds-ransomware-kms/vpc-flow-logs'},
 'pulumi_export_keys': {'attacker_role_arn': 'attacker_role_arn',
                        'attacker_role_name': 'attacker_role_name',
                        'victim_kms_key_arn': 'victim_kms_key_arn',
                        'victim_kms_key_id': 'victim_kms_key_id',
                        'attacker_kms_key_arn': 'attacker_kms_key_arn',
                        'attacker_kms_key_id': 'attacker_kms_key_id',
                        'db_instance_identifier': 'db_instance_identifier',
                        'db_instance_arn': 'db_instance_arn',
                        'snapshot_identifier': 'snapshot_identifier',
                        'snapshot_arn': 'snapshot_arn',
                        'secret_arn': 'secret_arn',
                        'region': 'region',
                        'account_id': 'account_id'}}
_R = _NAMES["resources"]

# ---------------------------------------------------------------------------
# Resource Name Constants
# ---------------------------------------------------------------------------
VICTIM_KMS_ALIAS     = _R["victim_kms_alias"]
ATTACKER_KMS_ALIAS   = _R["attacker_kms_alias"]
ATTACKER_ROLE_NAME   = _R["attacker_role_name"]
DB_IDENTIFIER        = _R["db_identifier"]
SNAPSHOT_IDENTIFIER  = _R["snapshot_identifier"]
SECRET_NAME          = _R["secret_name"]
DB_SUBNET_GROUP_NAME = _R["db_subnet_group_name"]
DB_SG_NAME           = _R["db_sg_name"]
FLOW_LOG_ROLE_NAME   = _R["flow_log_role_name"]
FLOW_LOG_GROUP_NAME  = _R["flow_log_group_name"]

# Account and region (synchronous in pulumi-aws v7)
account_id = aws.get_caller_identity().account_id
region     = aws.get_region().id

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-rds-ransomware-kms",
    "Technique":   "T1486",
}

# ---------------------------------------------------------------------------
# VPC and networking
# ---------------------------------------------------------------------------
vpc = aws.ec2.Vpc(
    "sandbox-vpc",
    cidr_block=          "10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=  True,
    tags={**TAGS, "Name": "rds-ransomware-kms-vpc"},
)

subnet_1a = aws.ec2.Subnet(
    "private-subnet-1a",
    vpc_id=             vpc.id,
    cidr_block=         "10.99.1.0/24",
    availability_zone=  f"{region}a",
    map_public_ip_on_launch=False,
    tags={**TAGS, "Name": "rds-ransomware-kms-subnet-1a"},
)

subnet_1b = aws.ec2.Subnet(
    "private-subnet-1b",
    vpc_id=             vpc.id,
    cidr_block=         "10.99.2.0/24",
    availability_zone=  f"{region}b",
    map_public_ip_on_launch=False,
    tags={**TAGS, "Name": "rds-ransomware-kms-subnet-1b"},
)

db_sg = aws.ec2.SecurityGroup(
    "db-security-group",
    name=       DB_SG_NAME,
    description="RDS ransomware KMS lab DB security group - no inbound",
    vpc_id=     vpc.id,
    ingress=    [],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            from_port=  0,
            to_port=    0,
            protocol=   "-1",
            cidr_blocks=["0.0.0.0/0"],
            description="Allow all outbound",
        )
    ],
    tags={**TAGS, "Name": DB_SG_NAME},
)

db_subnet_group = aws.rds.SubnetGroup(
    "rds-subnet-group",
    name=       DB_SUBNET_GROUP_NAME,
    subnet_ids= [subnet_1a.id, subnet_1b.id],
    description="RDS ransomware KMS lab subnet group",
    tags={**TAGS, "Name": DB_SUBNET_GROUP_NAME},
)

# VPC flow logs (CloudWatch Logs destination)
flow_log_group = aws.cloudwatch.LogGroup(
    "vpc-flow-log-group",
    name=             FLOW_LOG_GROUP_NAME,
    retention_in_days=7,
    tags={**TAGS, "Name": "rds-ransomware-kms-flow-logs"},
)

flow_log_role = aws.iam.Role(
    "vpc-flow-log-role",
    name=              FLOW_LOG_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags={**TAGS, "Name": FLOW_LOG_ROLE_NAME},
)

aws.iam.RolePolicy(
    "vpc-flow-log-role-policy",
    name=  "vpc-flow-log-policy",
    role=  flow_log_role.id,
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
    "vpc-flow-log",
    vpc_id=              vpc.id,
    iam_role_arn=        flow_log_role.arn,
    log_destination=     flow_log_group.arn,
    log_destination_type="cloud-watch-logs",
    traffic_type=        "ALL",
    tags={**TAGS, "Name": "rds-ransomware-kms-flow-log"},
)

# ---------------------------------------------------------------------------
# KMS keys
# ---------------------------------------------------------------------------
_account_root_arn = f"arn:aws:iam::{account_id}:root"

_victim_key_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":       "EnableIAMUserPermissions",
            "Effect":    "Allow",
            "Principal": {"AWS": _account_root_arn},
            "Action":    "kms:*",
            "Resource":  "*",
        },
    ],
})

victim_kms_key = aws.kms.Key(
    "victim-kms-key",
    description=             "RDS production encryption key",
    enable_key_rotation=     True,
    deletion_window_in_days= 7,
    policy=                  _victim_key_policy,
    tags={**TAGS, "Name": "rds-ransomware-kms-victim-key"},
)

aws.kms.Alias(
    "victim-kms-alias",
    name=         VICTIM_KMS_ALIAS,
    target_key_id=victim_kms_key.id,
)

_attacker_key_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":       "EnableIAMUserPermissions",
            "Effect":    "Allow",
            "Principal": {"AWS": _account_root_arn},
            "Action":    "kms:*",
            "Resource":  "*",
        },
    ],
})

attacker_kms_key = aws.kms.Key(
    "attacker-kms-key",
    description=             "Attacker-controlled re-encryption key",
    enable_key_rotation=     False,
    deletion_window_in_days= 7,
    policy=                  _attacker_key_policy,
    tags={**TAGS, "Name": "rds-ransomware-kms-attacker-key"},
)

aws.kms.Alias(
    "attacker-kms-alias",
    name=         ATTACKER_KMS_ALIAS,
    target_key_id=attacker_kms_key.id,
)

# ---------------------------------------------------------------------------
# Attacker IAM role + inline policies
# ---------------------------------------------------------------------------
attacker_role = aws.iam.Role(
    "attacker-role",
    name=              ATTACKER_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"AWS": _account_root_arn},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags={**TAGS, "Name": ATTACKER_ROLE_NAME},
)

# Allow policy: RDS snapshot ops + KMS re-encrypt on the two lab keys only
aws.iam.RolePolicy(
    "attacker-allow-policy",
    name=  "attacker-allow-policy",
    role=  attacker_role.id,
    policy=pulumi.Output.all(victim_kms_key.arn, attacker_kms_key.arn).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid":      "RDSSnapshotOperations",
                    "Effect":   "Allow",
                    "Action":   [
                        "rds:CreateDBSnapshot",
                        "rds:CopyDBSnapshot",
                        "rds:DescribeDBInstances",
                        "rds:DescribeDBSnapshots",
                        "rds:ListTagsForResource",
                        "rds:ModifyDBSnapshotAttribute",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid":      "KMSReencryptOperations",
                    "Effect":   "Allow",
                    "Action":   [
                        "kms:DescribeKey",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:CreateGrant",
                        "kms:ReEncrypt*",
                    ],
                    "Resource": [args[0], args[1]],
                },
            ],
        })
    ),
)

# Deny guard: explicit Deny on all irreversible RDS operations
# Deny semantics override any Allow regardless of attachment order
aws.iam.RolePolicy(
    "deny-guard-policy",
    name=  "deny-guard-policy",
    role=  attacker_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid":      "DenyGuardIrreversibleRDS",
            "Effect":   "Deny",
            "Action":   [
                "rds:DeleteDBInstance",
                "rds:DeleteDBSnapshot",
                "rds:DeleteDBCluster",
                "rds:DeleteDBClusterSnapshot",
                "rds:ModifyDBInstance",
            ],
            "Resource": "*",
        }],
    }),
)

# ---------------------------------------------------------------------------
# RDS instance (victim - encrypted under victim KMS key)
# ---------------------------------------------------------------------------
db_password = random.RandomPassword(
    "db-password",
    length=           20,
    special=          True,
    override_special= "!#$%",
)

prod_customer_db = aws.rds.Instance(
    "prod-customer-db",
    identifier=            DB_IDENTIFIER,
    engine=                "mysql",
    engine_version=        "8.0",
    instance_class=        "db.t3.micro",
    allocated_storage=     20,
    storage_encrypted=     True,
    kms_key_id=            victim_kms_key.arn,
    db_name=               "orders",
    username=              "admin",
    password=              db_password.result,
    db_subnet_group_name=  db_subnet_group.name,
    vpc_security_group_ids=[db_sg.id],
    publicly_accessible=   False,
    multi_az=              False,
    skip_final_snapshot=   True,
    tags={**TAGS, "Name": DB_IDENTIFIER},
)

# ---------------------------------------------------------------------------
# Pre-seeded manual RDS snapshot (primary T1486 target)
# ---------------------------------------------------------------------------
prod_orders_snapshot = aws.rds.Snapshot(
    "prod-orders-snapshot",
    db_instance_identifier=prod_customer_db.id,
    db_snapshot_identifier=SNAPSHOT_IDENTIFIER,
    tags={**TAGS, "Name": SNAPSHOT_IDENTIFIER},
)

# ---------------------------------------------------------------------------
# Bait Secrets Manager secret
# ---------------------------------------------------------------------------
prod_rds_secret = aws.secretsmanager.Secret(
    "prod-rds-master-secret",
    name=                   SECRET_NAME,
    recovery_window_in_days=0,
    description=            "RDS orders database master credentials",
    tags={**TAGS, "Name": SECRET_NAME},
)

aws.secretsmanager.SecretVersion(
    "prod-rds-master-secret-version",
    secret_id=    prod_rds_secret.id,
    secret_string=prod_customer_db.address.apply(lambda addr: json.dumps({
        "username": "admin",
        "password": "Wh3at-Harvest-2026!",
        "engine":   "mysql",
        "host":     addr,
        "port":     3306,
        "dbname":   "orders",
    })),
)

# ---------------------------------------------------------------------------
# Pulumi exports (attack.py reads these via pulumi stack output)
# ---------------------------------------------------------------------------
# Static name constants
pulumi.export("victim_kms_alias",    VICTIM_KMS_ALIAS)
pulumi.export("attacker_kms_alias",  ATTACKER_KMS_ALIAS)
pulumi.export("attacker_role_name",  ATTACKER_ROLE_NAME)
pulumi.export("db_identifier",       DB_IDENTIFIER)
pulumi.export("snapshot_identifier", SNAPSHOT_IDENTIFIER)
pulumi.export("secret_name",         SECRET_NAME)
pulumi.export("region",              region)
pulumi.export("account_id",          account_id)

# Dynamic outputs (ARNs and IDs resolved after deploy)
pulumi.export("attacker_role_arn",      attacker_role.arn)
pulumi.export("victim_kms_key_arn",     victim_kms_key.arn)
pulumi.export("victim_kms_key_id",      victim_kms_key.id)
pulumi.export("attacker_kms_key_arn",   attacker_kms_key.arn)
pulumi.export("attacker_kms_key_id",    attacker_kms_key.id)
pulumi.export("db_instance_identifier", DB_IDENTIFIER)
pulumi.export("db_instance_arn",        prod_customer_db.arn)
pulumi.export("snapshot_arn",           prod_orders_snapshot.db_snapshot_arn)
pulumi.export("secret_arn",             prod_rds_secret.arn)
