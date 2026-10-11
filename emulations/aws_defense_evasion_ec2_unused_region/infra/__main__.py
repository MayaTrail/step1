import json
import pathlib
import pulumi
import pulumi_aws as aws

# Load resource names - single source of truth
_NAMES = {'campaign': 'ATOMIC_EC2_UNUSED_REGION',
 'csp': 'aws',
 'resources': {'attacker_role_name': 'atomic-ec2-unused-region-attacker-role',
               'decoy_secret_name': 'prod/database/master_credentials',
               'vpc_name': 'atomic-ec2-unused-region-vpc',
               'subnet_name': 'atomic-ec2-unused-region-subnet',
               'sg_name': 'atomic-ec2-unused-region-sg'},
 'pulumi_export_keys': {'attacker_role_arn': 'attacker_role_arn',
                        'attacker_role_name': 'attacker_role_name',
                        'vpc_id': 'vpc_id',
                        'subnet_id': 'subnet_id',
                        'sg_id': 'sg_id',
                        'decoy_secret_arn': 'decoy_secret_arn',
                        'target_region': 'target_region'}}
_R = _NAMES["resources"]

# Resource Name Constants
ATTACKER_ROLE_NAME = _R["attacker_role_name"]
DECOY_SECRET_NAME  = _R["decoy_secret_name"]
VPC_NAME           = _R["vpc_name"]
SUBNET_NAME        = _R["subnet_name"]
SG_NAME            = _R["sg_name"]

TARGET_REGION = "eu-north-1"

TAGS = {
    "MayaTrail": "true",
    "Purpose":   "adversary-emulation",
}

# Current account identity - used for self-trust in IAM role (AWS validates account IDs)
caller     = aws.get_caller_identity()
account_id = caller.account_id

# ---------------------------------------------------------------------------
# Regional provider for eu-north-1 (low-visibility, typically unmonitored)
# All VPC / subnet / SG / bait resources below declare opts=provider=this
# ---------------------------------------------------------------------------
unused_region_provider = aws.Provider(
    "unused-region-provider",
    region=TARGET_REGION,
)

# ---------------------------------------------------------------------------
# Attacker IAM role (global - no regional provider)
# Self-account trust: attack.py assumes this role to emulate T1535 discovery
# and ec2:RunInstances in eu-north-1. EnableRegion/DisableRegion are Deny-guarded.
# ---------------------------------------------------------------------------
attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "AWS": f"arn:aws:iam::{account_id}:root"
            },
            "Action": "sts:AssumeRole"
        }]
    }),
    tags=TAGS,
)

aws.iam.RolePolicy(
    "attacker-role-inline-policy",
    role=attacker_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RegionAndMonitoringDiscovery",
                "Effect": "Allow",
                "Action": [
                    "account:ListRegions",
                    "account:GetRegionOptStatus",
                    "ec2:DescribeRegions",
                    "ec2:DescribeAvailabilityZones",
                    "ec2:DescribeImages",
                    "ec2:DescribeInstances",
                    "ec2:DescribeInstanceStatus",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeSecurityGroups",
                    "guardduty:ListDetectors",
                    "cloudtrail:DescribeTrails"
                ],
                "Resource": "*"
            },
            {
                "Sid": "EC2LaunchScopedToTarget",
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "ec2:InstanceType": "t3.nano",
                        "aws:RequestedRegion": "eu-north-1"
                    }
                }
            },
            {
                "Sid": "EC2TagOnLaunchOnly",
                "Effect": "Allow",
                "Action": "ec2:CreateTags",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "ec2:CreateAction": "RunInstances"
                    }
                }
            },
            {
                "Sid": "EC2TerminateTaggedOnly",
                "Effect": "Allow",
                "Action": "ec2:TerminateInstances",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "ec2:ResourceTag/MayaTrail": "true"
                    }
                }
            },
            {
                # Deny-guard: records AccessDenied in CloudTrail without modifying region state
                "Sid": "DenyRegionOptInOut",
                "Effect": "Deny",
                "Action": [
                    "account:EnableRegion",
                    "account:DisableRegion"
                ],
                "Resource": "*"
            }
        ]
    }),
)

# ---------------------------------------------------------------------------
# Target VPC in eu-north-1 - isolated, no IGW, no NAT
# ---------------------------------------------------------------------------
target_vpc = aws.ec2.Vpc(
    "target-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_support=True,
    enable_dns_hostnames=True,
    tags={**TAGS, "Name": VPC_NAME},
    opts=pulumi.ResourceOptions(provider=unused_region_provider),
)

# Private subnet - no public IP, no internet gateway
target_subnet = aws.ec2.Subnet(
    "target-subnet",
    vpc_id=target_vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone=f"{TARGET_REGION}a",
    map_public_ip_on_launch=False,
    tags={**TAGS, "Name": SUBNET_NAME},
    opts=pulumi.ResourceOptions(provider=unused_region_provider),
)

# Security group: no inbound rules, allow all outbound
target_sg = aws.ec2.SecurityGroup(
    "target-sg",
    name=SG_NAME,
    description="ec2-unused-region lab sg",
    vpc_id=target_vpc.id,
    ingress=[],
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0,
        to_port=0,
        protocol="-1",
        cidr_blocks=["0.0.0.0/0"],
        description="allow all outbound",
    )],
    tags={**TAGS, "Name": SG_NAME},
    opts=pulumi.ResourceOptions(provider=unused_region_provider),
)

# ---------------------------------------------------------------------------
# Decoy secret - realistic prod credential in eu-north-1 to model adversary
# motivation for establishing a foothold in an unmonitored region
# recovery_window_in_days=0 required: avoids deletion-schedule collision on redeploy
# ---------------------------------------------------------------------------
decoy_secret = aws.secretsmanager.Secret(
    "decoy-secret",
    name=DECOY_SECRET_NAME,
    recovery_window_in_days=0,
    tags=TAGS,
    opts=pulumi.ResourceOptions(provider=unused_region_provider),
)

aws.secretsmanager.SecretVersion(
    "decoy-secret-version",
    secret_id=decoy_secret.id,
    secret_string=json.dumps({
        "db_host": "prod-aurora-cluster.cluster-cxyz1234abc.eu-north-1.rds.amazonaws.com",
        "db_user": "admin",
        "db_pass": "Pr0d#Secr3t!2024"
    }),
    opts=pulumi.ResourceOptions(
        provider=unused_region_provider,
        depends_on=[decoy_secret],
    ),
)

# ---------------------------------------------------------------------------
# Stack outputs - attack.py reads these via pulumi stack output
# Keys must match pulumi_export_keys in resource_names.json exactly
# ---------------------------------------------------------------------------
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", attacker_role.name)
pulumi.export("vpc_id",             target_vpc.id)
pulumi.export("subnet_id",          target_subnet.id)
pulumi.export("sg_id",              target_sg.id)
pulumi.export("decoy_secret_arn",   decoy_secret.arn)
pulumi.export("target_region",      TARGET_REGION)
