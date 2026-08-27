"""
ECScape prerequisites — ECS-on-EC2 cluster with co-resident victim tasks.
Ported from naorhaziz/ecscape terraform/main.tf to Pulumi (pulumi-aws v7).

Stands up one t3.small container instance running three tasks in HOST network
mode (so the attacker container can reach IMDS 169.254.169.254 and the ECS agent
introspection port 51678):

  * ecscape-attacker  — deny-all task role (RunTask-launched by attack.py)
  * s3-control        — victim task role with S3 read-only  (loot #1)
  * database          — victim whose *execution* role reads a Secrets Manager
                        secret                              (loot #2)

The instance role carries the AWS-managed AmazonEC2ContainerServiceforEC2Role,
which grants ecs:Poll + ecs:DiscoverPollEndpoint by default — that default is
exactly what makes ECScape possible; it is deliberately NOT trimmed.

No CloudTrail/S3 is provisioned here — detections are documented under
detections/ and fire off the account's existing trail.
"""
import json

import pulumi
import pulumi_aws as aws

PREFIX = "ecscape"
INSTANCE_TYPE = "t3.small"          # 2 GB — fits 3 co-resident 512 MB tasks + agent
TASK_MEMORY = 512
TASK_CPU = 256

_region_info = aws.get_region()
region = getattr(_region_info, "region", None) or _region_info.name  # v7 renamed .name -> .region
account_id = aws.get_caller_identity().account_id
az = f"{region}a"

TAGS = {
    "Purpose": "adversary-emulation",
    "Technique": "aws.credential-access.ecscape",
}

# ── Network (dedicated VPC + public subnet for deterministic teardown) ───────
vpc = aws.ec2.Vpc(
    f"{PREFIX}-vpc",
    cidr_block="10.20.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={"Name": f"{PREFIX}-vpc", **TAGS},
)
igw = aws.ec2.InternetGateway(f"{PREFIX}-igw", vpc_id=vpc.id, tags={"Name": f"{PREFIX}-igw", **TAGS})
subnet = aws.ec2.Subnet(
    f"{PREFIX}-subnet",
    vpc_id=vpc.id,
    cidr_block="10.20.1.0/24",
    availability_zone=az,
    map_public_ip_on_launch=True,
    tags={"Name": f"{PREFIX}-subnet", **TAGS},
)
rt = aws.ec2.RouteTable(
    f"{PREFIX}-rt",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)],
    tags={"Name": f"{PREFIX}-rt", **TAGS},
)
aws.ec2.RouteTableAssociation(f"{PREFIX}-rta", subnet_id=subnet.id, route_table_id=rt.id)

# Egress-only SG (instance needs outbound for the ECS agent, ACS, and pip).
sg = aws.ec2.SecurityGroup(
    f"{PREFIX}-sg",
    vpc_id=vpc.id,
    description="ECScape ECS instance — egress only",
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0, to_port=0, protocol="-1", cidr_blocks=["0.0.0.0/0"],
    )],
    tags={"Name": f"{PREFIX}-sg", **TAGS},
)

# ── Instance role (managed ECS-for-EC2 policy is the enabling default) ───────
instance_role = aws.iam.Role(
    f"{PREFIX}-instance-role",
    name=f"{PREFIX}-instance-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }),
    tags=TAGS,
)
aws.iam.RolePolicyAttachment(
    f"{PREFIX}-instance-ecs",
    role=instance_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
)
aws.iam.RolePolicyAttachment(
    f"{PREFIX}-instance-ssm",
    role=instance_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
)
instance_profile = aws.iam.InstanceProfile(
    f"{PREFIX}-instance-profile", name=f"{PREFIX}-instance-profile", role=instance_role.name,
)

# ── Task roles ───────────────────────────────────────────────────────────────
ECS_TASKS_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Attacker: deny-all task role — proves the escalation (a zero-permission task
# harvests other tasks' credentials).
attacker_role = aws.iam.Role(
    f"{PREFIX}-attacker-role", name=f"{PREFIX}-attacker-role", assume_role_policy=ECS_TASKS_TRUST, tags=TAGS,
)
aws.iam.RolePolicy(
    f"{PREFIX}-attacker-deny-all",
    role=attacker_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }),
)

# Victim #1: real S3 read permissions (loot from a stolen task role).
s3_control_role = aws.iam.Role(
    f"{PREFIX}-s3-control-role", name=f"{PREFIX}-s3-control-role", assume_role_policy=ECS_TASKS_TRUST, tags=TAGS,
)
aws.iam.RolePolicyAttachment(
    f"{PREFIX}-s3-control-attach",
    role=s3_control_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
)

# Victim #2: a Secrets Manager secret + an *execution* role that reads it.
secret = aws.secretsmanager.Secret(
    f"{PREFIX}-db-secret",
    name=f"{PREFIX}-db-secret",
    description="ECScape demo database secret",
    recovery_window_in_days=0,   # allow immediate delete on pulumi destroy
    tags=TAGS,
)
aws.secretsmanager.SecretVersion(
    f"{PREFIX}-db-secret-version", secret_id=secret.id, secret_string="SuperSecretPassword",
)
secret_execution_role = aws.iam.Role(
    f"{PREFIX}-secret-execution-role", name=f"{PREFIX}-secret-execution-role",
    assume_role_policy=ECS_TASKS_TRUST, tags=TAGS,
)
aws.iam.RolePolicyAttachment(
    f"{PREFIX}-exec-base",
    role=secret_execution_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
)
aws.iam.RolePolicy(
    f"{PREFIX}-exec-read-secret",
    role=secret_execution_role.id,
    policy=secret.arn.apply(lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": arn}],
    })),
)

# ── ECS cluster + EC2 capacity provider (ASG) ────────────────────────────────
ami_id = aws.ssm.get_parameter(
    name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
).value

cluster = aws.ecs.Cluster(f"{PREFIX}-cluster", name=PREFIX, tags=TAGS)

launch_template = aws.ec2.LaunchTemplate(
    f"{PREFIX}-lt",
    name_prefix=f"{PREFIX}-lt-",
    image_id=ami_id,
    instance_type=INSTANCE_TYPE,
    vpc_security_group_ids=[sg.id],
    iam_instance_profile=aws.ec2.LaunchTemplateIamInstanceProfileArgs(name=instance_profile.name),
    metadata_options=aws.ec2.LaunchTemplateMetadataOptionsArgs(
        http_endpoint="enabled", http_tokens="optional",  # IMDSv1+v2 (host-mode task reads IMDS)
    ),
    user_data=pulumi.Output.all(cluster.name).apply(
        lambda a: __import__("base64").b64encode(
            f"#!/bin/bash\necho ECS_CLUSTER={a[0]} >> /etc/ecs/ecs.config\n".encode()
        ).decode()
    ),
    tags=TAGS,
)

asg = aws.autoscaling.Group(
    f"{PREFIX}-asg",
    name=f"{PREFIX}-asg",
    vpc_zone_identifiers=[subnet.id],
    min_size=1, max_size=1, desired_capacity=1,
    launch_template=aws.autoscaling.GroupLaunchTemplateArgs(id=launch_template.id, version="$Latest"),
    tags=[aws.autoscaling.GroupTagArgs(key="AmazonECSManaged", value="true", propagate_at_launch=True)],
    # depends_on cluster => on destroy the ASG (and its container instance) tears
    # down BEFORE the cluster, so DeleteCluster never hits a registered instance.
    opts=pulumi.ResourceOptions(depends_on=[cluster]),
)

capacity_provider = aws.ecs.CapacityProvider(
    f"{PREFIX}-cp",
    name=f"{PREFIX}-cp",
    auto_scaling_group_provider=aws.ecs.CapacityProviderAutoScalingGroupProviderArgs(
        auto_scaling_group_arn=asg.arn,
        managed_termination_protection="DISABLED",
        managed_scaling=aws.ecs.CapacityProviderAutoScalingGroupProviderManagedScalingArgs(
            status="ENABLED", target_capacity=100,
            minimum_scaling_step_size=1, maximum_scaling_step_size=1,
        ),
    ),
    tags=TAGS,
)

cluster_cp = aws.ecs.ClusterCapacityProviders(
    f"{PREFIX}-cluster-cp",
    cluster_name=cluster.name,
    capacity_providers=[capacity_provider.name],
    default_capacity_provider_strategies=[aws.ecs.ClusterCapacityProvidersDefaultCapacityProviderStrategyArgs(
        base=1, weight=100, capacity_provider=capacity_provider.name,
    )],
)

# ── Log group for the attacker container (attack.py reads its harvest here) ──
log_group = aws.cloudwatch.LogGroup(f"{PREFIX}-attacker-logs", name=f"/ecs/{PREFIX}-attacker", retention_in_days=1, tags=TAGS)

# ── Task definitions ─────────────────────────────────────────────────────────
def _log_config(stream_prefix: str):
    return {
        "logDriver": "awslogs",
        "options": {
            "awslogs-group": f"/ecs/{PREFIX}-attacker",
            "awslogs-region": region,
            "awslogs-stream-prefix": stream_prefix,
        },
    }

# Attacker task def — command is overridden by attack.py's RunTask with the
# base64 ECScape payload; base command just idles if launched bare.
attacker_container = "ecscape"
attacker_task = aws.ecs.TaskDefinition(
    f"{PREFIX}-attacker-task",
    family=f"{PREFIX}-attacker",
    network_mode="host",
    requires_compatibilities=["EC2"],
    task_role_arn=attacker_role.arn,
    container_definitions=pulumi.Output.json_dumps([{
        "name": attacker_container,
        "image": "public.ecr.aws/docker/library/python:3.12-slim",
        "essential": True,
        "memory": TASK_MEMORY,
        "cpu": TASK_CPU,
        "entryPoint": ["sleep", "3600"],
        "logConfiguration": _log_config("attacker"),
    }]),
    tags=TAGS,
)

s3_control_task = aws.ecs.TaskDefinition(
    f"{PREFIX}-s3-control-task",
    family=f"{PREFIX}-s3-control",
    network_mode="host",
    requires_compatibilities=["EC2"],
    task_role_arn=s3_control_role.arn,
    container_definitions=json.dumps([{
        "name": "s3-control",
        "image": "public.ecr.aws/docker/library/ubuntu:latest",
        "essential": True,
        "memory": TASK_MEMORY,
        "cpu": TASK_CPU,
        "entryPoint": ["sleep", "infinity"],
    }]),
    tags=TAGS,
)

database_task = aws.ecs.TaskDefinition(
    f"{PREFIX}-database-task",
    family=f"{PREFIX}-database",
    network_mode="host",
    requires_compatibilities=["EC2"],
    execution_role_arn=secret_execution_role.arn,
    container_definitions=pulumi.Output.all(secret.arn).apply(lambda a: json.dumps([{
        "name": "database-app",
        "image": "public.ecr.aws/docker/library/ubuntu:latest",
        "essential": True,
        "memory": TASK_MEMORY,
        "cpu": TASK_CPU,
        "entryPoint": ["sleep", "infinity"],
        "secrets": [{"name": "DB_SECRET", "valueFrom": a[0]}],
    }])),
    tags=TAGS,
)

# ── Victim services (attacker task is launched on demand by attack.py) ───────
_common_strategy = [aws.ecs.ServiceCapacityProviderStrategyArgs(
    capacity_provider=capacity_provider.name, weight=100, base=1,
)]

aws.ecs.Service(
    f"{PREFIX}-s3-control-svc",
    name=f"{PREFIX}-s3-control-service",
    cluster=cluster.id,
    task_definition=s3_control_task.arn,
    desired_count=1,
    capacity_provider_strategies=_common_strategy,
    opts=pulumi.ResourceOptions(depends_on=[asg, cluster_cp]),
)
aws.ecs.Service(
    f"{PREFIX}-database-svc",
    name=f"{PREFIX}-database-service",
    cluster=cluster.id,
    task_definition=database_task.arn,
    desired_count=1,
    capacity_provider_strategies=_common_strategy,
    opts=pulumi.ResourceOptions(depends_on=[asg, cluster_cp]),
)

# ── Outputs (consumed by attack.py::run) ─────────────────────────────────────
pulumi.export("region", region)
pulumi.export("cluster_name", cluster.name)
pulumi.export("capacity_provider_name", capacity_provider.name)
pulumi.export("subnet_id", subnet.id)
pulumi.export("attacker_task_family", attacker_task.family)
pulumi.export("attacker_container_name", attacker_container)
pulumi.export("attacker_log_group", log_group.name)
pulumi.export("instance_role_name", instance_role.name)
pulumi.export("attacker_role_arn", attacker_role.arn)
pulumi.export("s3_control_role_arn", s3_control_role.arn)
pulumi.export("secret_execution_role_arn", secret_execution_role.arn)
pulumi.export("secret_arn", secret.arn)
