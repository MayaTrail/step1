import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
region = aws.get_region().id

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.exfiltration.ec2-share-ebs-snapshot",
}

# ── EBS Volume (1 GB) ─────────────────────────────────────────────────────────
volume = aws.ebs.Volume(
    "stratus-red-team-ebs-volume",
    availability_zone=f"{region}a",
    size=1,
    tags={"Name": "stratus-red-team-ebs-volume", **TAGS},
)

# ── EBS Snapshot ──────────────────────────────────────────────────────────────
snapshot = aws.ebs.Snapshot(
    "stratus-red-team-ebs-snapshot",
    volume_id=volume.id,
    tags={"Name": "stratus-red-team-ebs-snapshot", **TAGS},
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("snapshot_id", snapshot.id)
pulumi.export("volume_id",   volume.id)
