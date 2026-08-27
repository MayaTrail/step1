import json
import pathlib
import secrets
import string

import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ─────────────────────────────────────────────────
# Loaded from resource_names.json when present (local dev); falls back to inline
# literals so the backend — which copies only Pulumi.yaml + __main__.py into the
# run dir — can still deploy without the sibling file.
_P = pathlib.Path(__file__).parent / "resource_names.json"
if _P.exists():
    _R = json.loads(_P.read_text())["resources"]
else:
    _R = {
        "db_instance_identifier": "customer-billing",
        "attacker_role_name":     "atomic-rds-modify-public-access-attacker-role",
        "rds_subnet_group_name":  "atomic-rds-modify-public-access-subnet-group",
        "secret_name":            "prod/rds/master_credentials",
    }

DB_INSTANCE_IDENTIFIER = _R["db_instance_identifier"]
ATTACKER_ROLE_NAME     = _R["attacker_role_name"]
RDS_SUBNET_GROUP_NAME  = _R["rds_subnet_group_name"]
SECRET_NAME            = _R["secret_name"]

# ── Caller Identity and Region ────────────────────────────────────────────────
identity   = aws.get_caller_identity()
account_id = identity.account_id
region     = aws.get_region().id  # .id not .name per pulumi-aws v7 compat

TAGS = {
    "MayaTrail":          "true",
    "Purpose":            "adversary-emulation",
    "ThreatActor":        "ATOMIC-rds-modify-public-access",
    "Technique":          "T1562.007",
    "DataClassification": "SandboxOnly",
}

# ── VPC ───────────────────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    "sandbox-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": "atomic-rds-modify-public-access-vpc"},
)

subnet_a = aws.ec2.Subnet(
    "subnet-a",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone=f"{region}a",
    tags={**TAGS, "Name": "atomic-rds-modify-public-access-subnet-a"},
)

subnet_b = aws.ec2.Subnet(
    "subnet-b",
    vpc_id=vpc.id,
    cidr_block="10.99.2.0/24",
    availability_zone=f"{region}b",
    tags={**TAGS, "Name": "atomic-rds-modify-public-access-subnet-b"},
)

igw = aws.ec2.InternetGateway(
    "igw",
    vpc_id=vpc.id,
    tags={**TAGS, "Name": "atomic-rds-modify-public-access-igw"},
)

route_table = aws.ec2.RouteTable(
    "route-table",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(
        cidr_block="0.0.0.0/0",
        gateway_id=igw.id,
    )],
    tags={**TAGS, "Name": "atomic-rds-modify-public-access-rt"},
)

aws.ec2.RouteTableAssociation(
    "rta-a",
    subnet_id=subnet_a.id,
    route_table_id=route_table.id,
)

aws.ec2.RouteTableAssociation(
    "rta-b",
    subnet_id=subnet_b.id,
    route_table_id=route_table.id,
)

# ── Security Group (empty ingress at deploy; emulation adds 3306 via API) ────
# Pre-destroy: call ec2:RevokeSecurityGroupIngress for any emulation-added rules first.
rds_sg = aws.ec2.SecurityGroup(
    "rds-security-group",
    vpc_id=vpc.id,
    description="RDS emulation lab SG - T1562.007 - no inbound at deploy",
    ingress=[],
    egress=[aws.ec2.SecurityGroupEgressArgs(
        protocol="-1",
        from_port=0,
        to_port=0,
        cidr_blocks=["0.0.0.0/0"],
        description="Allow all outbound",
    )],
    tags={**TAGS, "Name": "atomic-rds-modify-public-access-rds-sg"},
)

# ── RDS Subnet Group ──────────────────────────────────────────────────────────
rds_subnet_group = aws.rds.SubnetGroup(
    "rds-subnet-group",
    name=RDS_SUBNET_GROUP_NAME,
    subnet_ids=[subnet_a.id, subnet_b.id],
    description="RDS subnet group for T1562.007 emulation",
    tags=TAGS,
)

# ── RDS Master Password ───────────────────────────────────────────────────────
# Generated at deploy time with the stdlib `secrets` module (pulumi-random is not
# in the backend worker image). Restricted charset: alphanumeric + a subset of
# specials RDS accepts (RDS rejects /, @, ", space).
def _gen_db_password() -> str:
    specials = "!#$%^&*()-_"
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, specials]
    # Guarantee at least 2 lower / 2 upper / 2 digit / 1 special, pad to 20.
    chars = [secrets.choice(string.ascii_lowercase) for _ in range(2)]
    chars += [secrets.choice(string.ascii_uppercase) for _ in range(2)]
    chars += [secrets.choice(string.digits) for _ in range(2)]
    chars += [secrets.choice(specials) for _ in range(1)]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(20 - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class _Pw:
    """Minimal shim so downstream `db_password.result` keeps working."""
    result = _gen_db_password()


db_password = _Pw()

# ── RDS Instance ──────────────────────────────────────────────────────────────
# Deployed with publiclyAccessible=False; emulation calls ModifyDBInstance to flip it.
# READINESS GATE: attack.py must poll DescribeDBInstances until status == available (5-15 min).
# Pre-destroy: if emulation ran, call ModifyDBInstance publiclyAccessible=False first.
rds_instance = aws.rds.Instance(
    "rds-instance",
    identifier=DB_INSTANCE_IDENTIFIER,
    engine="mysql",
    engine_version="8.0",
    instance_class="db.t3.micro",
    allocated_storage=20,
    storage_type="gp2",
    username="admin",
    password=db_password.result,
    db_subnet_group_name=rds_subnet_group.name,
    vpc_security_group_ids=[rds_sg.id],
    publicly_accessible=False,
    multi_az=False,
    skip_final_snapshot=True,
    deletion_protection=False,
    tags=TAGS,
)

# ── IAM Attacker Role ─────────────────────────────────────────────────────────
# Trusts the current lab account root — self-trust avoids placeholder account IDs.
attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

# ── Attacker Role Inline Policy ───────────────────────────────────────────────
# Scoped to the sandbox RDS instance and security group; Describe* uses Resource:*
# because EC2/RDS Describe actions do not support resource-level conditions.
def _build_attacker_policy(args):
    acct, sg_id = args
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":    "MutatingRDSAndSG",
                "Effect": "Allow",
                "Action": [
                    "rds:ModifyDBInstance",
                    "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupIngress",
                ],
                "Resource": [
                    f"arn:aws:rds:{region}:{acct}:db:{DB_INSTANCE_IDENTIFIER}",
                    f"arn:aws:ec2:{region}:{acct}:security-group/{sg_id}",
                ],
            },
            {
                "Sid":     "ReadOnlyDescribes",
                "Effect":  "Allow",
                "Action":  ["rds:DescribeDBInstances", "ec2:DescribeSecurityGroups"],
                "Resource": "*",
            },
        ],
    })

aws.iam.RolePolicy(
    "attacker-role-policy",
    role=attacker_role.id,
    policy=pulumi.Output.all(account_id, rds_sg.id).apply(_build_attacker_policy),
)

# ── Bait Secret ───────────────────────────────────────────────────────────────
# Realistic name and structure; GetSecretValue calls generate CloudTrail events.
bait_secret = aws.secretsmanager.Secret(
    "prod-rds-master-secret",
    name=SECRET_NAME,
    description="Production RDS master credentials - DataClassification: Confidential",
    recovery_window_in_days=0,
    tags={**TAGS, "DataClassification": "Confidential"},
)

aws.secretsmanager.SecretVersion(
    "prod-rds-master-secret-version",
    secret_id=bait_secret.id,
    secret_string=rds_instance.address.apply(lambda host: json.dumps({
        "host":     host,
        "port":     3306,
        "username": "admin",
        "password": "Fa!ke_P@ssw0rd_D0_N0t_Use",
        "database": "billing",
    })),
)

# ── Pulumi Exports ────────────────────────────────────────────────────────────
# attack.py reads these keys from `pulumi stack output`
pulumi.export("attacker_role_arn",      attacker_role.arn)
pulumi.export("db_instance_id",         rds_instance.id)
pulumi.export("db_endpoint",            rds_instance.endpoint)
pulumi.export("rds_security_group_id",  rds_sg.id)
pulumi.export("db_instance_identifier", DB_INSTANCE_IDENTIFIER)
pulumi.export("attacker_role_name",     ATTACKER_ROLE_NAME)
pulumi.export("rds_subnet_group_name",  RDS_SUBNET_GROUP_NAME)
pulumi.export("secret_name",            SECRET_NAME)
pulumi.export("db_master_password",     db_password.result)
pulumi.export("rds_instance_id",        DB_INSTANCE_IDENTIFIER)
pulumi.export("prod_rds_master_secret_arn", bait_secret.arn)
