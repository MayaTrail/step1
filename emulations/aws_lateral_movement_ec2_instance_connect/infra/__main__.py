import json
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
PREFIX        = "stratus-red-team-ic"
INSTANCE_TYPE = "t3.micro"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.lateral-movement.ec2-instance-connect",
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

# ── VPC + Networking ──────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    f"{PREFIX}-vpc",
    cidr_block="10.14.0.0/16",
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
    cidr_block="10.14.1.0/24",
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

# ── Security Group (SSH open — required for EC2 Instance Connect) ─────────────
sg = aws.ec2.SecurityGroup(
    f"{PREFIX}-sg",
    vpc_id=vpc.id,
    description="Allow SSH for EC2 Instance Connect",
    ingress=[aws.ec2.SecurityGroupIngressArgs(
        from_port=22, to_port=22, protocol="tcp",
        cidr_blocks=["0.0.0.0/0"],
        description="SSH via EC2 Instance Connect",
    )],
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0, to_port=0, protocol="-1",
        cidr_blocks=["0.0.0.0/0"],
    )],
    tags={"Name": f"{PREFIX}-sg", **TAGS},
)

# ── IAM Role (minimal — EC2 Instance Connect uses IAM permissions on caller) ──
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

instance_profile = aws.iam.InstanceProfile(
    f"{PREFIX}-profile",
    name=f"{PREFIX}-profile",
    role=role.name,
)

# ── EC2 Instance ──────────────────────────────────────────────────────────────
instance = aws.ec2.Instance(
    f"{PREFIX}-instance",
    ami=ami.id,
    instance_type=INSTANCE_TYPE,
    subnet_id=subnet.id,
    vpc_security_group_ids=[sg.id],
    iam_instance_profile=instance_profile.name,
    associate_public_ip_address=True,
    tags={"Name": f"{PREFIX}-instance", **TAGS},
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("instance_id",        instance.id)
pulumi.export("public_ip",          instance.public_ip)
pulumi.export("availability_zone",  instance.availability_zone)
pulumi.export("ec2_username",       "ec2-user")
