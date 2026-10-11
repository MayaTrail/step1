import json
import pathlib
import pulumi
import pulumi_aws as aws

# ---------------------------------------------------------------------------
# Resource name constants -- single source of truth
# ---------------------------------------------------------------------------
_NAMES = {'campaign': 'ATOMIC_EC2_MASS_TERMINATE',
 'csp': 'aws',
 'resources': {'vpc_name': 'atomic-ec2-mass-terminate-vpc',
               'subnet_name': 'atomic-ec2-mass-terminate-subnet',
               'sg_name': 'atomic-ec2-mass-terminate-sg',
               'role_name': 'atomic-ec2-mass-terminate-prod-ops-role',
               'role_policy_name': 'atomic-ec2-mass-terminate-prod-ops-policy',
               'scenario_tag_value': 'atomic-ec2-mass-terminate',
               'instance_web_name_tag': 'prod-web-01',
               'instance_app_name_tag': 'prod-app-01',
               'instance_db_name_tag': 'prod-db-01',
               'instance_bastion_name_tag': 'prod-bastion-01'},
 'pulumi_export_keys': {'prod_ops_role_arn': 'prod_ops_role_arn',
                        'target_web_01_instance_id': 'target_web_01_instance_id',
                        'target_app_01_instance_id': 'target_app_01_instance_id',
                        'target_db_01_instance_id': 'target_db_01_instance_id',
                        'bait_bastion_01_instance_id': 'bait_bastion_01_instance_id'}}
_R = _NAMES["resources"]

VPC_NAME                = _R["vpc_name"]
SUBNET_NAME             = _R["subnet_name"]
SG_NAME                 = _R["sg_name"]
ROLE_NAME               = _R["role_name"]
ROLE_POLICY_NAME        = _R["role_policy_name"]
SCENARIO_TAG_VALUE      = _R["scenario_tag_value"]
INSTANCE_WEB_NAME_TAG   = _R["instance_web_name_tag"]
INSTANCE_APP_NAME_TAG   = _R["instance_app_name_tag"]
INSTANCE_DB_NAME_TAG    = _R["instance_db_name_tag"]
INSTANCE_BASTION_NAME_TAG = _R["instance_bastion_name_tag"]

# ---------------------------------------------------------------------------
# Account / region / AZ -- derived at deploy time, never hardcoded
# ---------------------------------------------------------------------------
caller     = aws.get_caller_identity()
account_id = caller.account_id
region     = aws.get_region().id
azs        = aws.get_availability_zones(state="available")

# AL2023 AMI via SSM (AL2 is EOL as of 2026)
ami_param = aws.ssm.get_parameter(
    name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
)
AMI_ID = ami_param.value

# Tags applied to every lab resource
COMMON_TAGS = {
    "MayaTrail": "true",
    "Purpose":   "adversary-emulation",
}

# ---------------------------------------------------------------------------
# 1. Sandbox VPC
# ---------------------------------------------------------------------------
vpc = aws.ec2.Vpc(
    VPC_NAME,
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**COMMON_TAGS, "Name": VPC_NAME},
)

# ---------------------------------------------------------------------------
# 2. Private subnet (AZ derived at deploy time)
# ---------------------------------------------------------------------------
subnet = aws.ec2.Subnet(
    SUBNET_NAME,
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone=azs.names[0],
    map_public_ip_on_launch=False,
    tags={**COMMON_TAGS, "Name": SUBNET_NAME},
)

# ---------------------------------------------------------------------------
# 3. Security group -- no inbound; instances are control-plane targets only
# ---------------------------------------------------------------------------
sg = aws.ec2.SecurityGroup(
    SG_NAME,
    vpc_id=vpc.id,
    description="Lab SG - no inbound - control-plane targets only",
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            from_port=0,
            to_port=0,
            protocol="-1",
            cidr_blocks=["0.0.0.0/0"],
        )
    ],
    tags={**COMMON_TAGS, "Name": SG_NAME},
)

# ---------------------------------------------------------------------------
# 4. Victim role -- trust = current account root (no placeholder IDs)
# ---------------------------------------------------------------------------
prod_ops_role = aws.iam.Role(
    ROLE_NAME,
    name=ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags={**COMMON_TAGS},
)

# ---------------------------------------------------------------------------
# 5. Inline policy
#    Allow TerminateInstances where MayaTrailScenario tag matches.
#    Deny  TerminateInstances where it does not (StringNotEquals fires for
#    missing tags too, so untagged instances are denied -- client-account safety).
#    DescribeInstances is unrestricted to model realistic pre-terminate discovery;
#    attack.py applies a tag filter on Describe to avoid enumerating client fleet.
# ---------------------------------------------------------------------------
prod_ops_policy = aws.iam.RolePolicy(
    ROLE_POLICY_NAME,
    role=prod_ops_role.name,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":      "TerminateScenarioInstances",
                "Effect":   "Allow",
                "Action":   "ec2:TerminateInstances",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:ResourceTag/MayaTrailScenario": SCENARIO_TAG_VALUE
                    }
                },
            },
            {
                "Sid":      "DenyNonScenarioTerminate",
                "Effect":   "Deny",
                "Action":   "ec2:TerminateInstances",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:ResourceTag/MayaTrailScenario": SCENARIO_TAG_VALUE
                    }
                },
            },
            {
                "Sid":      "DescribeInstances",
                "Effect":   "Allow",
                "Action":   "ec2:DescribeInstances",
                "Resource": "*",
            },
        ],
    }),
)

# ---------------------------------------------------------------------------
# Helper: provision a lab EC2 instance
# ---------------------------------------------------------------------------
def lab_instance(pulumi_name, name_tag, extra_tags):
    return aws.ec2.Instance(
        pulumi_name,
        instance_type="t3.nano",
        ami=AMI_ID,
        subnet_id=subnet.id,
        vpc_security_group_ids=[sg.id],
        associate_public_ip_address=False,
        tags={
            **COMMON_TAGS,
            "Name":        name_tag,
            "Environment": "production",
            **extra_tags,
        },
    )

# ---------------------------------------------------------------------------
# 6-8. Target instances (carry MayaTrailScenario tag -> Allow fires)
# ---------------------------------------------------------------------------
scenario_tag = {"MayaTrailScenario": SCENARIO_TAG_VALUE}

target_web = lab_instance("target-web-01", INSTANCE_WEB_NAME_TAG, scenario_tag)
target_app = lab_instance("target-app-01", INSTANCE_APP_NAME_TAG, scenario_tag)
target_db  = lab_instance("target-db-01",  INSTANCE_DB_NAME_TAG,  scenario_tag)

# ---------------------------------------------------------------------------
# 9. Bait instance -- MayaTrailScenario tag deliberately absent.
#    attack.py terminates this in a SEPARATE API call so the Deny fires and
#    generates an AccessDenied CloudTrail event without disrupting the
#    successful terminates on the three targets above.
# ---------------------------------------------------------------------------
bait_bastion = lab_instance("bait-bastion-01", INSTANCE_BASTION_NAME_TAG, {})

# ---------------------------------------------------------------------------
# Stack outputs (attack.py reads all of these by exact key)
# ---------------------------------------------------------------------------
pulumi.export("vpc_name",                    VPC_NAME)
pulumi.export("sandbox_vpc_id",              vpc.id)
pulumi.export("subnet_name",                 SUBNET_NAME)
pulumi.export("sg_name",                     SG_NAME)
pulumi.export("role_name",                   ROLE_NAME)
pulumi.export("prod_ops_role_arn",           prod_ops_role.arn)
pulumi.export("target_web_01_instance_id",   target_web.id)
pulumi.export("target_app_01_instance_id",   target_app.id)
pulumi.export("target_db_01_instance_id",    target_db.id)
pulumi.export("bait_bastion_01_instance_id", bait_bastion.id)
