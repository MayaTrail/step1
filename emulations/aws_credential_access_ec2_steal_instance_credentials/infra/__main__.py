import json
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
PREFIX        = "stratus-red-team-steal-creds"
INSTANCE_TYPE = "t3.micro"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.credential-access.ec2-steal-instance-credentials",
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
    cidr_block="10.10.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={"Name": f"{PREFIX}-vpc", **TAGS},
)

igw = aws.ec2.InternetGateway(f"{PREFIX}-igw", vpc_id=vpc.id, tags={"Name": f"{PREFIX}-igw", **TAGS})

subnet = aws.ec2.Subnet(
    f"{PREFIX}-subnet",
    vpc_id=vpc.id,
    cidr_block="10.10.1.0/24",
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

# ── IAM role with SSM + DescribeInstances ─────────────────────────────────────
role = aws.iam.Role(
    f"{PREFIX}-role",
    name=f"{PREFIX}-role",
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

aws.iam.RolePolicyAttachment(f"{PREFIX}-ssm", role=role.name, policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
aws.iam.RolePolicyAttachment(f"{PREFIX}-ec2-ro", role=role.name, policy_arn="arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess")

instance_profile = aws.iam.InstanceProfile(f"{PREFIX}-profile", name=f"{PREFIX}-profile", role=role.name)

# ── EC2 Instance ──────────────────────────────────────────────────────────────
instance = aws.ec2.Instance(
    f"{PREFIX}-instance",
    ami=ami.id,
    instance_type=INSTANCE_TYPE,
    subnet_id=subnet.id,
    iam_instance_profile=instance_profile.name,
    tags={"Name": f"{PREFIX}-instance", **TAGS},
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("instance_id",   instance.id)
pulumi.export("role_name",     role.name)
pulumi.export("instance_profile_name", instance_profile.name)
