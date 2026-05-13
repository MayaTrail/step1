import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
account_id = aws.get_caller_identity().account_id

TRAIL_NAME  = "stratus-red-team-ct-lifecycle-trail"
BUCKET_NAME = f"stratus-red-team-ct-lifecycle-bucket-{account_id}"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.defense-evasion.cloudtrail-lifecycle-rule",
}

# ── S3 bucket for CloudTrail logs ─────────────────────────────────────────────
bucket = aws.s3.BucketV2(
    "ct-lifecycle-bucket",
    bucket=BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

bucket_policy = aws.s3.BucketPolicy(
    "ct-lifecycle-bucket-policy",
    bucket=bucket.id,
    policy=pulumi.Output.all(bucket.bucket, account_id).apply(
        lambda args: f"""{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::{args[0]}",
      "Condition": {{"StringEquals": {{"aws:SourceAccount": "{args[1]}"}}}}
    }},
    {{
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::{args[0]}/AWSLogs/{args[1]}/*",
      "Condition": {{
        "StringEquals": {{"s3:x-amz-acl": "bucket-owner-full-control"}},
        "StringEquals": {{"aws:SourceAccount": "{args[1]}"}}
      }}
    }}
  ]
}}"""
    ),
)

# ── CloudTrail trail ──────────────────────────────────────────────────────────
trail = aws.cloudtrail.Trail(
    "ct-lifecycle-trail",
    name=TRAIL_NAME,
    s3_bucket_name=bucket.id,
    enable_logging=True,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[bucket_policy]),
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("trail_name",  TRAIL_NAME)
pulumi.export("bucket_name", BUCKET_NAME)
pulumi.export("trail_arn",   trail.arn)
