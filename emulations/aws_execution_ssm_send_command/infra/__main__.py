import json
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
PREFIX         = "stratus-red-team-ssm-send-command"
INSTANCE_COUNT = 3
INSTANCE_TYPE  = "t3.micro"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.execution.ssm-send-command",
}

# ── Latest Amazon Linux 2 AMI ─────────────────────────────────────────────────
ami = aws.ec2.get_ami(
    most_recent=True,
    owners=["amazon"],
    filters=[
        aws.ec2.GetAmiFilterArgs(name="name",                values=["amzn2-ami-hvm-*-x86_64-gp2"]),
        aws.ec2.GetAmiFilterArgs(name="virtualization-type", values=["hvm"]),
        aws.ec2.GetAmiFilterArgs(name="state",               values=["available"]),
    ],
)

# ── VPC + Subnet ──────────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    f"{PREFIX}-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={"Name": f"{PREFIX}-vpc", **TAGS},
)

igw = aws.ec2.InternetGateway(
    f"{PREFIX}-igw",
    vpc_id=vpc.id,
    tags={"Name": f"{PREFIX}-igw", **TAGS},
)

subnet = aws.ec2.Subnet(
    f"{PREFIX}-subnet",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone="us-east-1a",
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

# ── IAM role for SSM ──────────────────────────────────────────────────────────
role = aws.iam.Role(
    f"{PREFIX}-role",
    name=f"{PREFIX}-instance-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    f"{PREFIX}-ssm-policy",
    role=role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
)

instance_profile = aws.iam.InstanceProfile(
    f"{PREFIX}-profile",
    name=f"{PREFIX}-profile",
    role=role.name,
)

# ── EC2 Instances (3) ──────────────────────────────────────────────────────────
instances = []
for i in range(INSTANCE_COUNT):
    inst = aws.ec2.Instance(
        f"{PREFIX}-instance-{i}",
        ami=ami.id,
        instance_type=INSTANCE_TYPE,
        subnet_id=subnet.id,
        iam_instance_profile=instance_profile.name,
        tags={"Name": f"{PREFIX}-instance-{i}", **TAGS},
    )
    instances.append(inst)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("instance_ids",  pulumi.Output.all(*[i.id for i in instances]).apply(list))
pulumi.export("instance_count", INSTANCE_COUNT)
pulumi.export("tag_key",   "StratusRedTeam")
pulumi.export("tag_value", "true")
