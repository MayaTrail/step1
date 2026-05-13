import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
account_id  = aws.get_caller_identity().account_id
BUCKET_NAME = f"stratus-red-team-s3-backdoor-{account_id}"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.exfiltration.s3-backdoor-bucket-policy",
}

# ── S3 bucket ─────────────────────────────────────────────────────────────────
bucket = aws.s3.BucketV2(
    "backdoor-bucket",
    bucket=BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

# Block all public access (attack will override via bucket policy)
aws.s3.BucketPublicAccessBlock(
    "backdoor-bucket-pab",
    bucket=bucket.id,
    block_public_acls=False,
    block_public_policy=False,
    ignore_public_acls=False,
    restrict_public_buckets=False,
)

# Sample objects (simulates a real data bucket)
for i, content in enumerate(["confidential-data-1", "confidential-data-2", "api-keys"]):
    aws.s3.BucketObjectv2(
        f"sample-object-{i}",
        bucket=bucket.id,
        key=f"data/{content}.txt",
        content=f"Simulated sensitive content: {content}\n",
    )

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("bucket_name", BUCKET_NAME)
pulumi.export("bucket_arn",  bucket.arn)
