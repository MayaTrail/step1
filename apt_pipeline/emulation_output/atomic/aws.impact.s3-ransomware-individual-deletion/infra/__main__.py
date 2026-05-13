import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
account_id   = aws.get_caller_identity().account_id
BUCKET_NAME  = f"stratus-red-team-ransomware-individual-{account_id}"
OBJECT_COUNT = 100   # Exported so attack.py knows how many to seed

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.impact.s3-ransomware-individual-deletion",
}

# ── S3 bucket (objects seeded by attack.py to avoid DNS propagation race) ─────
bucket = aws.s3.BucketV2(
    "ransomware-individual-bucket",
    bucket=BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "ransomware-individual-pab",
    bucket=bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("bucket_name",  BUCKET_NAME)
pulumi.export("bucket_arn",   bucket.arn)
pulumi.export("object_count", OBJECT_COUNT)
