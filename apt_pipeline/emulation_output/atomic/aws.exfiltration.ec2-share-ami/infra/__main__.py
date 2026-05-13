import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
PREFIX = "stratus-red-team-share-ami"
region = aws.get_region().id

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.exfiltration.ec2-share-ami",
}

# ── EBS Volume + Snapshot (required to register a custom AMI) ─────────────────
volume = aws.ebs.Volume(
    f"{PREFIX}-vol",
    availability_zone=f"{region}a",
    size=1,
    tags={"Name": f"{PREFIX}-vol", **TAGS},
)

snapshot = aws.ebs.Snapshot(
    f"{PREFIX}-snap",
    volume_id=volume.id,
    tags={"Name": f"{PREFIX}-snap", **TAGS},
)

# ── Register a minimal AMI backed by the snapshot ─────────────────────────────
# This creates an AMI owned by the current account that can be shared.
ami = aws.ec2.Ami(
    f"{PREFIX}-ami",
    name=f"{PREFIX}-ami",
    description="Stratus Red Team AMI for exfiltration emulation",
    architecture="x86_64",
    virtualization_type="hvm",
    root_device_name="/dev/xvda",
    ebs_block_devices=[aws.ec2.AmiEbsBlockDeviceArgs(
        device_name="/dev/xvda",
        snapshot_id=snapshot.id,
        volume_size=1,
        volume_type="gp2",
        delete_on_termination=True,
    )],
    tags={**TAGS, "Name": f"{PREFIX}-ami"},
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("ami_id",      ami.id)
pulumi.export("snapshot_id", snapshot.id)
pulumi.export("volume_id",   volume.id)
