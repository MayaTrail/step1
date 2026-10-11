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

# ── Resource name constants (loaded from single source of truth) ───────────────
_NAMES = {'campaign': 'ATOMIC-rds-data-api-query',
 'csp': 'aws',
 'resources': {'vpc_name': 'atomic-rds-data-api-query-sandbox-vpc',
               'subnet_a_name': 'atomic-rds-data-api-query-sandbox-subnet-a',
               'subnet_b_name': 'atomic-rds-data-api-query-sandbox-subnet-b',
               'subnet_group_name': 'atomic-rds-data-api-query-aurora-subnet-group',
               'security_group_name': 'atomic-rds-data-api-query-aurora-sg',
               'secret_name': 'prod/labcorp/aurora-master-creds',
               'cluster_id': 'atomic-rds-data-api-query-aurora-cluster',
               'cluster_instance_id': 'atomic-rds-data-api-query-aurora-instance',
               'seed_function_name': 'atomic-rds-data-api-query-seeder',
               'seed_lambda_role_name': 'atomic-rds-data-api-query-seeder-role',
               'vpc_flow_log_role_name': 'atomic-rds-data-api-query-flow-log-role',
               'victim_role_name': 'atomic-rds-data-api-query-victim-role'},
 'pulumi_export_keys': {'vpc_id': 'vpc_id',
                        'cluster_arn': 'cluster_arn',
                        'cluster_endpoint': 'cluster_endpoint',
                        'secret_arn': 'secret_arn',
                        'victim_role_arn': 'victim_role_arn',
                        'region': 'region',
                        'account_id': 'account_id',
                        'vpc_name': 'vpc_name',
                        'secret_name': 'secret_name',
                        'cluster_id': 'cluster_id',
                        'seed_function_name': 'seed_function_name',
                        'victim_role_name': 'victim_role_name'}}
_R = _NAMES["resources"]

VPC_NAME              = _R["vpc_name"]
SUBNET_A_NAME         = _R["subnet_a_name"]
SUBNET_B_NAME         = _R["subnet_b_name"]
SUBNET_GROUP_NAME     = _R["subnet_group_name"]
SECURITY_GROUP_NAME   = _R["security_group_name"]
SECRET_NAME           = _R["secret_name"]
CLUSTER_ID            = _R["cluster_id"]
CLUSTER_INSTANCE_ID   = _R["cluster_instance_id"]
SEED_FUNCTION_NAME    = _R["seed_function_name"]
SEED_LAMBDA_ROLE_NAME = _R["seed_lambda_role_name"]
VPC_FLOW_ROLE_NAME    = _R["vpc_flow_log_role_name"]
VICTIM_ROLE_NAME      = _R["victim_role_name"]

TAGS = {
    "MayaTrail": "true",
    "Purpose": "adversary-emulation",
    "ThreatActor": "ATOMIC-rds-data-api-query",
    "Technique": "T1213",
}

# Export name constants so attack.py can read them from stack outputs
pulumi.export("vpc_name",           VPC_NAME)
pulumi.export("secret_name",        SECRET_NAME)
pulumi.export("cluster_id",         CLUSTER_ID)
pulumi.export("seed_function_name", SEED_FUNCTION_NAME)
pulumi.export("victim_role_name",   VICTIM_ROLE_NAME)

# Account and region -- plain strings in pulumi-aws v7 (.id not .name)
account_id = aws.get_caller_identity().account_id
region     = aws.get_region().id

pulumi.export("account_id", account_id)
pulumi.export("region",     region)

# ── VPC ────────────────────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    VPC_NAME,
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": VPC_NAME},
)

_flow_log_group = aws.cloudwatch.LogGroup(
    f"{VPC_NAME}-flow-lg",
    name=f"/aws/vpc/flow-logs/{VPC_NAME}",
    retention_in_days=7,
    tags=TAGS,
)

_flow_log_role = aws.iam.Role(
    VPC_FLOW_ROLE_NAME,
    name=VPC_FLOW_ROLE_NAME,
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
    f"{VPC_FLOW_ROLE_NAME}-inline",
    role=_flow_log_role.name,
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
    f"{VPC_NAME}-flowlog",
    vpc_id=vpc.id,
    traffic_type="ALL",
    iam_role_arn=_flow_log_role.arn,
    log_destination=_flow_log_group.arn,
    tags=TAGS,
)

# ── Subnets ────────────────────────────────────────────────────────────────────
subnet_a = aws.ec2.Subnet(
    SUBNET_A_NAME,
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone=f"{region}a",
    map_public_ip_on_launch=False,
    tags={**TAGS, "Name": SUBNET_A_NAME},
)

subnet_b = aws.ec2.Subnet(
    SUBNET_B_NAME,
    vpc_id=vpc.id,
    cidr_block="10.99.2.0/24",
    availability_zone=f"{region}b",
    map_public_ip_on_launch=False,
    tags={**TAGS, "Name": SUBNET_B_NAME},
)

# ── RDS Subnet Group ───────────────────────────────────────────────────────────
subnet_group = aws.rds.SubnetGroup(
    SUBNET_GROUP_NAME,
    name=SUBNET_GROUP_NAME,
    subnet_ids=[subnet_a.id, subnet_b.id],
    description="Aurora subnet group for atomic-rds-data-api-query lab",
    tags=TAGS,
)

# ── Security Group (no internet inbound; Data API traffic never enters VPC) ────
aurora_sg = aws.ec2.SecurityGroup(
    SECURITY_GROUP_NAME,
    name=SECURITY_GROUP_NAME,
    description="Aurora SG for atomic-rds-data-api-query - Data API bypasses this SG",
    vpc_id=vpc.id,
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0,
        to_port=0,
        protocol="-1",
        cidr_blocks=["0.0.0.0/0"],
        description="Allow all egress for Aurora internal communication",
    )],
    tags={**TAGS, "Name": SECURITY_GROUP_NAME},
)

# ── Master password (random; embedded in secret after cluster endpoint known) ──
db_password = random.RandomPassword(
    "aurora-master-pw",
    length=32,
    special=False,
)

# ── Aurora Serverless v2 Cluster ───────────────────────────────────────────────
# enable_http_endpoint=True is the ATTACK SURFACE for T1213 via rds-data:ExecuteStatement
cluster = aws.rds.Cluster(
    CLUSTER_ID,
    cluster_identifier=CLUSTER_ID,
    engine="aurora-postgresql",
    engine_version="15.4",
    engine_mode="provisioned",
    database_name="labcorp_hr",
    master_username="admin",
    master_password=db_password.result,
    db_subnet_group_name=subnet_group.name,
    vpc_security_group_ids=[aurora_sg.id],
    enable_http_endpoint=True,
    skip_final_snapshot=True,
    deletion_protection=False,
    serverlessv2_scaling_configuration=aws.rds.ClusterServerlessv2ScalingConfigurationArgs(
        min_capacity=0.5,
        max_capacity=2.0,
    ),
    tags=TAGS,
)

# ── Writer instance (required for Serverless v2; db.serverless activates scaling)
cluster_instance = aws.rds.ClusterInstance(
    CLUSTER_INSTANCE_ID,
    identifier=CLUSTER_INSTANCE_ID,
    cluster_identifier=cluster.id,
    instance_class="db.serverless",
    engine="aurora-postgresql",
    publicly_accessible=False,
    tags=TAGS,
)

# ── SecretsManager secret -- created after cluster to embed real endpoint ──────
# recovery_window_in_days=0 prevents deletion-schedule conflicts on re-runs
_secret_string = pulumi.Output.all(db_password.result, cluster.endpoint).apply(
    lambda args: json.dumps({
        "username": "admin",
        "password": args[0],
        "engine": "postgres",
        "host": args[1],
        "port": 5432,
        "dbname": "labcorp_hr",
    })
)

db_secret = aws.secretsmanager.Secret(
    "prod-labcorp-aurora-master-creds",
    name=SECRET_NAME,
    description="Aurora master credentials for atomic-rds-data-api-query lab",
    recovery_window_in_days=0,
    tags=TAGS,
)

db_secret_version = aws.secretsmanager.SecretVersion(
    "prod-labcorp-aurora-master-creds-ver",
    secret_id=db_secret.id,
    secret_string=_secret_string,
)

# ── Lambda seeder -- inline code (backend copies only Pulumi.yaml + __main__.py)
_SEED_SRC = """\
import boto3
import json
import os
import time


def handler(event, context):
    cluster_arn = event["cluster_arn"]
    secret_arn = event["secret_arn"]
    db = "labcorp_hr"
    client = boto3.client("rds-data", region_name=os.environ.get("AWS_REGION", "us-east-1"))

    def run_sql(sql, max_attempts=8):
        for attempt in range(max_attempts):
            try:
                return client.execute_statement(
                    resourceArn=cluster_arn,
                    secretArn=secret_arn,
                    database=db,
                    sql=sql,
                )
            except Exception:
                if attempt == max_attempts - 1:
                    raise
                time.sleep(15)

    run_sql(
        "CREATE TABLE IF NOT EXISTS employees ("
        "id SERIAL PRIMARY KEY, "
        "full_name VARCHAR(100), "
        "email VARCHAR(100), "
        "ssn CHAR(11), "
        "salary INT, "
        "department VARCHAR(50))"
    )

    count_result = run_sql("SELECT COUNT(*) FROM employees")
    if count_result["records"][0][0].get("longValue", 0) > 0:
        return {"status": "already_seeded"}

    depts  = ["Engineering", "HR", "Finance", "Legal", "Operations"]
    fnames = ["Alice", "Bob", "Carol", "David", "Eve", "Frank", "Grace", "Hank", "Iris", "Jack"]
    lnames = ["Smith", "Jones", "Williams", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor", "Anderson"]
    for i in range(50):
        fn   = fnames[i % len(fnames)]
        ln   = lnames[(i // len(fnames)) % len(lnames)]
        name = "{} {}".format(fn, ln)
        email = "{}.{}{}@labcorp.internal".format(fn.lower(), ln.lower(), i)
        ssn   = "{:03d}-{:02d}-{:04d}".format(
            100 + (i * 7) % 900,
            10  + (i * 3) % 90,
            1000 + (i * 13) % 9000,
        )
        salary = 55000 + (i * 1973) % 95000
        dept   = depts[i % len(depts)]
        run_sql(
            "INSERT INTO employees (full_name, email, ssn, salary, department) "
            "VALUES ('{}', '{}', '{}', {}, '{}')".format(name, email, ssn, salary, dept)
        )

    return {"status": "seeded", "rows": 50}
"""

seed_role = aws.iam.Role(
    SEED_LAMBDA_ROLE_NAME,
    name=SEED_LAMBDA_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    f"{SEED_LAMBDA_ROLE_NAME}-basic-exec",
    role=seed_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

aws.iam.RolePolicy(
    f"{SEED_LAMBDA_ROLE_NAME}-data-api",
    role=seed_role.name,
    policy=pulumi.Output.all(cluster.arn, db_secret.arn).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DataAPI",
                    "Effect": "Allow",
                    "Action": [
                        "rds-data:ExecuteStatement",
                        "rds-data:BatchExecuteStatement",
                        "rds-data:BeginTransaction",
                        "rds-data:CommitTransaction",
                        "rds-data:RollbackTransaction",
                    ],
                    "Resource": args[0],
                },
                {
                    "Sid": "SecretRead",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": args[1],
                },
            ],
        })
    ),
)

seed_fn = aws.lambda_.Function(
    SEED_FUNCTION_NAME,
    name=SEED_FUNCTION_NAME,
    runtime="python3.12",
    handler="index.handler",
    role=seed_role.arn,
    timeout=300,
    code=pulumi.AssetArchive({"index.py": pulumi.StringAsset(_SEED_SRC)}),
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[cluster_instance, db_secret_version]),
)

aws.lambda_.Invocation(
    f"{SEED_FUNCTION_NAME}-invoke",
    function_name=seed_fn.name,
    input=pulumi.Output.all(cluster.arn, db_secret.arn).apply(
        lambda args: json.dumps({"cluster_arn": args[0], "secret_arn": args[1]})
    ),
    opts=pulumi.ResourceOptions(depends_on=[seed_fn]),
)

# ── Victim IAM role ────────────────────────────────────────────────────────────
# Trust: self-account root (real account_id -- never a placeholder)
victim_role = aws.iam.Role(
    VICTIM_ROLE_NAME,
    name=VICTIM_ROLE_NAME,
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
    f"{VICTIM_ROLE_NAME}-data-api-policy",
    role=victim_role.name,
    policy=pulumi.Output.all(cluster.arn, db_secret.arn).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DataAPIAccess",
                    "Effect": "Allow",
                    "Action": [
                        "rds-data:ExecuteStatement",
                        "rds-data:BatchExecuteStatement",
                        "rds-data:BeginTransaction",
                        "rds-data:CommitTransaction",
                        "rds-data:RollbackTransaction",
                    ],
                    "Resource": args[0],
                },
                {
                    "Sid": "SecretReadForDataAPI",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": args[1],
                },
            ],
        })
    ),
)

# ── Stack outputs (attack.py reads these via pulumi stack output) ──────────────
pulumi.export("vpc_id",           vpc.id)
pulumi.export("cluster_arn",      cluster.arn)
pulumi.export("cluster_endpoint", cluster.endpoint)
pulumi.export("secret_arn",       db_secret.arn)
pulumi.export("victim_role_arn",  victim_role.arn)
