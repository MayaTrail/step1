import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
account_id  = aws.get_caller_identity().account_id
BUCKET_NAME = f"stratus-red-team-ransomware-batch-{account_id}"
OBJECT_COUNT = 100

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.impact.s3-ransomware-batch-deletion",
}

# ── S3 bucket with sample objects ─────────────────────────────────────────────
bucket = aws.s3.BucketV2(
    "ransomware-batch-bucket",
    bucket=BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

# Block public access
aws.s3.BucketPublicAccessBlock(
    "ransomware-batch-pab",
    bucket=bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# Seed with sample objects
for i in range(OBJECT_COUNT):
    aws.s3.BucketObjectv2(
        f"ransomware-batch-object-{i}",
        bucket=bucket.id,
        key=f"data/file-{i:04d}.txt",
        content=f"Sensitive data file {i} - target for ransomware batch deletion",
        tags=TAGS,
    )

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("bucket_name",   BUCKET_NAME)
pulumi.export("bucket_arn",    bucket.arn)
pulumi.export("object_count",  OBJECT_COUNT)
