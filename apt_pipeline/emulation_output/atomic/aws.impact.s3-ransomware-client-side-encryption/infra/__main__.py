import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
account_id   = aws.get_caller_identity().account_id
BUCKET_NAME  = f"stratus-red-team-ransomware-encrypt-{account_id}"
OBJECT_COUNT = 50     # Fewer objects — each requires download+encrypt+upload+delete

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.impact.s3-ransomware-client-side-encryption",
}

# ── S3 bucket with sample objects ─────────────────────────────────────────────
bucket = aws.s3.BucketV2(
    "ransomware-encrypt-bucket",
    bucket=BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "ransomware-encrypt-pab",
    bucket=bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

for i in range(OBJECT_COUNT):
    aws.s3.BucketObjectv2(
        f"ransomware-encrypt-object-{i}",
        bucket=bucket.id,
        key=f"data/file-{i:04d}.txt",
        content=f"Confidential document {i} - target for client-side ransomware encryption",
        tags=TAGS,
    )

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("bucket_name",  BUCKET_NAME)
pulumi.export("bucket_arn",   bucket.arn)
pulumi.export("object_count", OBJECT_COUNT)
