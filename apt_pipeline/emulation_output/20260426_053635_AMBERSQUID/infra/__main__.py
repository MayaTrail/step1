import json
import os
import subprocess
import sys

import pulumi
import pulumi_aws as aws

# Cross-platform UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Account / Region ──────────────────────────────────────────────────────────
# aws.get_caller_identity() / aws.get_region() return sync values at module level
account_id = aws.get_caller_identity().account_id
region = aws.get_region().id  # .id not .name (pulumi-aws v7)

TAGS = {
    "MayaTrail": "true",
    "Purpose": "adversary-emulation",
    "ThreatActor": "AMBERSQUID",
    "Platform": "aws",
}

# ── Resource Name Constants (single source of truth) ──────────────────────────
CLUSTER_NAME         = "ambersquid-cluster"
TRAIL_NAME           = "ambersquid-trail"
TASK_FAMILY          = "ambersquid-miner"
LOG_GROUP_NAME       = "/ecs/ambersquid"
VICTIM_USER_NAME     = "ambersquid-victim"
HONEY_USER_NAME      = "prod-deploy-svc"
CODECOMMIT_REPO_NAME = "test"
ECS_EXEC_ROLE_NAME   = "ambersquid-ecs-execution-role"
CANARY_SECRET_NAME   = "prod/database/master_credentials"

# ── VPC ───────────────────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    "ambersquid-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={"Name": "ambersquid-vpc", **TAGS},
)

# ── Internet Gateway + routing ────────────────────────────────────────────────
igw = aws.ec2.InternetGateway(
    "ambersquid-igw",
    vpc_id=vpc.id,
    tags={"Name": "ambersquid-igw", **TAGS},
)

route_table = aws.ec2.RouteTable(
    "ambersquid-rt",
    vpc_id=vpc.id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            gateway_id=igw.id,
        )
    ],
    tags={"Name": "ambersquid-rt", **TAGS},
)

subnet = aws.ec2.Subnet(
    "ambersquid-public-subnet",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone="us-east-1a",
    map_public_ip_on_launch=True,
    tags={"Name": "ambersquid-public-subnet", **TAGS},
)

aws.ec2.RouteTableAssociation(
    "ambersquid-rt-assoc",
    subnet_id=subnet.id,
    route_table_id=route_table.id,
)

# ── Security Group (HTTPS egress only; all mining pool ports implicitly denied) ─
task_sg = aws.ec2.SecurityGroup(
    "ambersquid-task-sg",
    vpc_id=vpc.id,
    description="ECS task SG - HTTPS egress only for AWS API calls",
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            from_port=443,
            to_port=443,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
            description="AWS API endpoint access",
        )
    ],
    tags={"Name": "ambersquid-task-sg", **TAGS},
)

# ── CloudWatch Log Group ──────────────────────────────────────────────────────
log_group = aws.cloudwatch.LogGroup(
    "ambersquid-log-group",
    name=LOG_GROUP_NAME,
    retention_in_days=7,
    tags=TAGS,
)

# ── CloudTrail S3 Bucket (T1070 target — no s3:DeleteObject Deny per plan) ───
ct_bucket = aws.s3.BucketV2(
    "ambersquid-cloudtrail-bucket",
    bucket=f"ambersquid-cloudtrail-logs-{account_id}",
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketVersioningV2(
    "ambersquid-ct-versioning",
    bucket=ct_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled"
    ),
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "ambersquid-ct-encryption",
    bucket=ct_bucket.id,
    rules=[
        aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256"
            )
        )
    ],
)

# CloudTrail bucket policy — GetBucketAcl + PutObject with x-amz-acl condition
ct_bucket_policy_doc = ct_bucket.arn.apply(
    lambda bucket_arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": bucket_arn,
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{bucket_arn}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
        ],
    })
)

ct_bucket_policy = aws.s3.BucketPolicy(
    "ambersquid-ct-bucket-policy",
    bucket=ct_bucket.id,
    policy=ct_bucket_policy_doc,
)

# ── CloudTrail (detection + T1070 target) ────────────────────────────────────
trail = aws.cloudtrail.Trail(
    "ambersquid-cloudtrail",
    name=TRAIL_NAME,
    s3_bucket_name=ct_bucket.id,
    is_multi_region_trail=True,
    include_global_service_events=True,
    enable_log_file_validation=True,
    enable_logging=True,
    event_selectors=[
        aws.cloudtrail.TrailEventSelectorArgs(
            read_write_type="All",
            include_management_events=True,
        )
    ],
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[ct_bucket_policy]),
)

# ── Terraform State Bait Bucket (T1580 opportunistic discovery) ───────────────
tfstate_bucket = aws.s3.BucketV2(
    "ambersquid-terraform-state-bucket",
    bucket=f"prod-infra-terraform-state-{account_id}",
    force_destroy=True,
    tags={**TAGS, "Environment": "production", "ManagedBy": "terraform"},
)

# ── Canary Secret (T1580 enumeration bait) ────────────────────────────────────
canary_secret = aws.secretsmanager.Secret(
    "ambersquid-canary-secret",
    name=CANARY_SECRET_NAME,
    description="RDS master credentials for production cluster",
    recovery_window_in_days=0,
    tags={**TAGS, "Environment": "production", "Team": "data"},
)

aws.secretsmanager.SecretVersion(
    "ambersquid-canary-secret-version",
    secret_id=canary_secret.id,
    secret_string=json.dumps({
        "username": "dbadmin",
        "password": "Pr0dMasterKey#2024!zQ",
        "host": "prod-db-cluster.cluster-cxyz1234abcd.us-east-1.rds.amazonaws.com",
        "port": 5432,
        "dbname": "production",
    }),
)

# ── Victim IAM User (over-permissioned; creds injected into ECS task env) ─────
victim_user = aws.iam.User(
    "ambersquid-victim-iam-user",
    name=VICTIM_USER_NAME,
    tags=TAGS,
)

aws.iam.UserPolicy(
    "ambersquid-victim-policy",
    name="ambersquid-victim-policy",
    user=victim_user.name,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "IAMRoleAndCredentialManipulation",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateRole",
                    "iam:DeleteRole",
                    "iam:AttachRolePolicy",
                    "iam:DetachRolePolicy",
                    "iam:PutRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:PassRole",
                    "iam:CreateUser",
                    "iam:CreateAccessKey",
                    "iam:ListRoles",
                    "iam:ListUsers",
                    "iam:GetRole",
                    "iam:GetUser",
                    "iam:ListAttachedRolePolicies",
                    "sts:AssumeRole",
                ],
                "Resource": "*",
            },
            {
                "Sid": "MinerDeploymentServices",
                "Effect": "Allow",
                "Action": [
                    "ecs:*",
                    "sagemaker:*",
                    "codebuild:*",
                    "amplify:*",
                    "imagebuilder:*",
                    "autoscaling:*",
                    "glue:*",
                    "ec2:DescribeInstances",
                    "ec2:DescribeRegions",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeVpcs",
                    "ec2:CreateLaunchTemplate",
                    "ec2:DescribeLaunchTemplates",
                ],
                "Resource": "*",
            },
            {
                "Sid": "CodeAndInfraServices",
                "Effect": "Allow",
                "Action": ["codecommit:*", "cloudformation:*"],
                "Resource": "*",
            },
            {
                "Sid": "ContainerRegistry",
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchGetImage",
                    "ecr:DescribeRepositories",
                    "ecr:ListImages",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DiscoveryAndIndicatorRemoval",
                "Effect": "Allow",
                "Action": [
                    "logs:*",
                    "cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail",
                    "cloudtrail:UpdateTrail",
                    "cloudtrail:DescribeTrails",
                    "cloudtrail:GetTrailStatus",
                    "s3:ListAllMyBuckets",
                    "s3:ListBucket",
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "secretsmanager:ListSecrets",
                    "secretsmanager:GetSecretValue",
                ],
                "Resource": "*",
            },
        ],
    }),
)

victim_key = aws.iam.AccessKey(
    "ambersquid-victim-access-key",
    user=victim_user.name,
    status="Active",
)

# ── Honey IAM User (no policy; any use generates AuthFailure CloudTrail event) ─
honey_user = aws.iam.User(
    "ambersquid-honey-iam-user",
    name=HONEY_USER_NAME,
    tags={
        **TAGS,
        "Environment": "production",
        "Team": "platform",
        "ManagedBy": "terraform",
    },
)

honey_key = aws.iam.AccessKey(
    "ambersquid-honey-access-key",
    user=honey_user.name,
    status="Active",
)

# ── Bait terraform.tfstate — real honey key embedded to complete bait chain ───
tfstate_content = pulumi.Output.all(honey_key.id, honey_key.secret).apply(
    lambda args: json.dumps(
        {
            "version": 4,
            "terraform_version": "1.5.7",
            "serial": 42,
            "lineage": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "outputs": {
                "deploy_access_key_id": {"value": args[0], "type": "string"},
                "deploy_secret_access_key": {
                    "value": args[1],
                    "type": "string",
                    "sensitive": True,
                },
            },
            "resources": [
                {
                    "module": "module.iam",
                    "mode": "managed",
                    "type": "aws_iam_access_key",
                    "name": "deploy_svc",
                    "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                    "instances": [
                        {
                            "schema_version": 0,
                            "attributes": {
                                "id": args[0],
                                "secret": args[1],
                                "user": HONEY_USER_NAME,
                                "status": "Active",
                            },
                        }
                    ],
                },
                {
                    "module": "module.rds",
                    "mode": "managed",
                    "type": "aws_db_instance",
                    "name": "prod_primary",
                    "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                    "instances": [
                        {
                            "schema_version": 0,
                            "attributes": {
                                "id": "prod-db-cluster",
                                "endpoint": "prod-db-cluster.cluster-cxyz1234abcd.us-east-1.rds.amazonaws.com",
                                "username": "admin",
                                "password": "Sup3rS3cr3tProd2024!",
                            },
                        }
                    ],
                },
            ],
        },
        indent=2,
    )
)

aws.s3.BucketObject(
    "ambersquid-tfstate-object",
    bucket=tfstate_bucket.id,
    key="terraform.tfstate",
    content=tfstate_content,
    content_type="application/json",
)

# Bucket policy: victim user can read the bait tfstate (T1580 discovery path)
tfstate_bucket_policy_doc = pulumi.Output.all(
    tfstate_bucket.arn, victim_user.arn
).apply(
    lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VictimReadBait",
                "Effect": "Allow",
                "Principal": {"AWS": args[1]},
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [args[0], f"{args[0]}/*"],
            }
        ],
    })
)

aws.s3.BucketPolicy(
    "ambersquid-tfstate-bucket-policy",
    bucket=tfstate_bucket.id,
    policy=tfstate_bucket_policy_doc,
)

# ── ECS Task Execution Role (infra role; attacker ecsTaskExecutionRole with
#    AdministratorAccess is created at runtime by attack.py via iam:CreateRole) ─
ecs_exec_role = aws.iam.Role(
    "ambersquid-ecs-execution-role",
    name=ECS_EXEC_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    "ambersquid-ecs-exec-policy-attach",
    role=ecs_exec_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
)

# ── ECS Cluster ───────────────────────────────────────────────────────────────
ecs_cluster = aws.ecs.Cluster(
    "ambersquid-ecs-cluster",
    name=CLUSTER_NAME,
    settings=[
        aws.ecs.ClusterSettingArgs(name="containerInsights", value="enabled")
    ],
    tags=TAGS,
)

# ── ECS Task Definition (no service — T1610 simulated, desiredCount=0) ────────
# ubuntu:22.04 is benign stand-in for T1608.001-staged miner image
# sleep infinity simulates T1496 without any actual compute cost
container_defs = pulumi.Output.all(victim_key.id, victim_key.secret).apply(
    lambda args: json.dumps([
        {
            "name": "miner-container",
            "image": "ubuntu:22.04",
            "command": ["sleep", "infinity"],
            "environment": [
                {"name": "AWS_ACCESS_KEY_ID", "value": args[0]},
                {"name": "AWS_SECRET_ACCESS_KEY", "value": args[1]},
                {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": LOG_GROUP_NAME,
                    "awslogs-region": "us-east-1",
                    "awslogs-stream-prefix": "miner",
                },
            },
        }
    ])
)

task_def = aws.ecs.TaskDefinition(
    "ambersquid-task-definition",
    family=TASK_FAMILY,
    network_mode="awsvpc",
    requires_compatibilities=["FARGATE"],
    cpu="256",
    memory="512",
    execution_role_arn=ecs_exec_role.arn,
    container_definitions=container_defs,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[log_group]),
)

# ── CodeCommit Repo (empty — T1525 simulated; no malicious binaries pushed) ───
codecommit_repo = aws.codecommit.Repository(
    "ambersquid-codecommit-repo",
    repository_name=CODECOMMIT_REPO_NAME,
    description="Internal build artifacts",
    tags=TAGS,
)

# ── Stack Exports ─────────────────────────────────────────────────────────────
pulumi.export("victim_access_key_id", pulumi.Output.secret(victim_key.id))
pulumi.export("victim_secret_access_key", pulumi.Output.secret(victim_key.secret))
pulumi.export("honey_access_key_id", pulumi.Output.secret(honey_key.id))
pulumi.export("ecs_cluster_name", ecs_cluster.name)
pulumi.export("task_definition_arn", task_def.arn)
pulumi.export("cloudtrail_trail_name", trail.name)
pulumi.export("cloudtrail_bucket_name", ct_bucket.id)
pulumi.export("tfstate_bucket_name", tfstate_bucket.id)
pulumi.export("canary_secret_arn", canary_secret.arn)
pulumi.export("codecommit_repo_name", codecommit_repo.repository_name)
pulumi.export("subnet_id", subnet.id)
pulumi.export("task_sg_id", task_sg.id)
# Clean-key exports for constants pattern (attack.py reads these first)
pulumi.export("cluster_name",       CLUSTER_NAME)
pulumi.export("trail_name",         TRAIL_NAME)
pulumi.export("task_family",        TASK_FAMILY)
pulumi.export("log_group_name",     LOG_GROUP_NAME)
pulumi.export("honey_user_name",    HONEY_USER_NAME)
pulumi.export("canary_secret_name", CANARY_SECRET_NAME)

# ── Auto-Trigger Attack Script ────────────────────────────────────────────────
def _launch_attack(args):
    (
        victim_key_id,
        victim_secret,
        trail_name,
        ct_bucket_name,
        tf_bucket_name,
        repo_name,
        cluster_name,
        subnet_id_val,
        sg_id_val,
        secret_arn_val,
        task_def_arn_val,
    ) = args

    if not victim_key_id or not victim_secret:
        pulumi.log.warn("Victim credentials not resolved — skipping attack auto-trigger")
        return None

    attack_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "emulation_scripts", "attack.py"
    )
    if not os.path.exists(attack_script):
        pulumi.log.warn(f"attack.py not found at {attack_script} - skipping auto-trigger")
        return None

    env = {**os.environ}
    env["AWS_VICTIM_ACCESS_KEY_ID"] = victim_key_id
    env["AWS_VICTIM_SECRET_ACCESS_KEY"] = victim_secret
    env["CLOUDTRAIL_TRAIL_NAME"] = trail_name
    env["CLOUDTRAIL_BUCKET_NAME"] = ct_bucket_name
    env["TFSTATE_BUCKET_NAME"] = tf_bucket_name
    env["CODECOMMIT_REPO_NAME"] = repo_name
    env["ECS_CLUSTER_NAME"] = cluster_name
    env["ECS_SUBNET_ID"] = subnet_id_val
    env["ECS_SECURITY_GROUP_ID"] = sg_id_val
    env["CANARY_SECRET_ARN"] = secret_arn_val
    env["TASK_DEFINITION_ARN"] = task_def_arn_val
    env["AWS_ACCOUNT_ID"] = account_id
    env["AWS_DEFAULT_REGION"] = region

    pulumi.log.info("Launching attack.py emulation script ...")
    subprocess.Popen([sys.executable, attack_script], env=env)
    return None


pulumi.Output.all(
    victim_key.id,
    victim_key.secret,
    trail.name,
    ct_bucket.id,
    tfstate_bucket.id,
    codecommit_repo.repository_name,
    ecs_cluster.name,
    subnet.id,
    task_sg.id,
    canary_secret.arn,
    task_def.arn,
).apply(_launch_attack)
