import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
SG_NAME = "stratus-red-team-sg-port22"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.exfiltration.ec2-security-group-open-port-22-ingress",
}

# ── VPC + Security Group ───────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    "port22-vpc",
    cidr_block="10.0.0.0/16",
    tags={**TAGS, "Name": "stratus-red-team-port22-vpc"},
)

sg = aws.ec2.SecurityGroup(
    "port22-sg",
    name=SG_NAME,
    description="Stratus Red Team - target security group for port 22 ingress technique",
    vpc_id=vpc.id,
    # No ingress rules — attack will add port 22 open to world
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            from_port=0,
            to_port=0,
            protocol="-1",
            cidr_blocks=["0.0.0.0/0"],
        )
    ],
    tags=TAGS,
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("security_group_id",   sg.id)
pulumi.export("security_group_name", SG_NAME)
pulumi.export("vpc_id",              vpc.id)
