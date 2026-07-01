import json

import boto3
import pulumi
import pulumi_aws as aws

# -----------------------------------------------------------------------
# Resource Name Constants
# -----------------------------------------------------------------------
STACK_NAME = pulumi.get_stack()

# S3 bucket names share one global namespace across all AWS accounts, so they are
# scoped by account id to guarantee uniqueness; the stack name still disambiguates
# multiple stacks within a single account. IAM user and CloudTrail trail names are
# account-local, so the stack name alone is enough for them.
ACCOUNT_ID = aws.get_caller_identity().account_id

BAIT_BUCKET_NAME       = f"acme-devops-tfstate-{STACK_NAME}-{ACCOUNT_ID}"
TARGET_BUCKET_NAME     = f"codefinger-target-{STACK_NAME}-{ACCOUNT_ID}"
CLOUDTRAIL_BUCKET_NAME = f"codefinger-cloudtrail-{STACK_NAME}-{ACCOUNT_ID}"
VICTIM_USER_NAME       = f"codefinger-victim-{STACK_NAME}"
TRAIL_NAME             = f"codefinger-trail-{STACK_NAME}"

# Export constants so attack.py can reference them
pulumi.export("bait_bucket_name",       BAIT_BUCKET_NAME)
pulumi.export("target_bucket_name",     TARGET_BUCKET_NAME)
pulumi.export("cloudtrail_bucket_name", CLOUDTRAIL_BUCKET_NAME)
pulumi.export("victim_user_name",       VICTIM_USER_NAME)
pulumi.export("trail_name",             TRAIL_NAME)
pulumi.export("aws_region",             aws.config.region or "us-east-1")

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "Codefinger",
    "Environment": "isolated-lab",
}

# -----------------------------------------------------------------------
# 1. codefinger-bait-public-bucket
#    Simulates an accidentally-public Terraform state bucket (T1552.001)
# -----------------------------------------------------------------------
bait_bucket = aws.s3.BucketV2(
    "codefinger-bait-public-bucket",
    bucket=BAIT_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

# -----------------------------------------------------------------------
# 2. codefinger-target-s3-bucket
#    Unversioned, no default SSE-KMS (SSE-C conflicts with KMS)
# -----------------------------------------------------------------------
target_bucket = aws.s3.BucketV2(
    "codefinger-target-s3-bucket",
    bucket=TARGET_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

# Block public access on target bucket (private data store)
aws.s3.BucketPublicAccessBlock(
    "codefinger-target-public-access-block",
    bucket=target_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# Enable versioning on target bucket so T1490 phase5_inhibit_recovery can
# demonstrate suspending versioning and purging version history.
aws.s3.BucketVersioningV2(
    "codefinger-target-versioning",
    bucket=target_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
)


# -----------------------------------------------------------------------
# Override account-level SSE-C block on target bucket.
# AWS accounts created after Dec 2024 automatically apply
# BlockedEncryptionTypes=SSE-C to new buckets. We override this by
# explicitly setting BlockedEncryptionTypes=NONE (block only unencrypted
# uploads), which allows victim IAM key to perform SSE-C PutObject as
# Codefinger does in the wild. This mirrors a victim org that has NOT
# deployed the recommended "Block SSE-C" defense.
# -----------------------------------------------------------------------
def _unlock_ssec(bucket_id: str) -> None:
    if pulumi.runtime.is_dry_run():
        pulumi.log.info("[DRYRUN] Skipping SSE-C unlock during preview.")
        return
    try:
        s3_admin = boto3.client("s3")
        s3_admin.put_bucket_encryption(
            Bucket=bucket_id,
            ServerSideEncryptionConfiguration={
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                    "BucketKeyEnabled": False,
                    "BlockedEncryptionTypes": {"EncryptionType": ["NONE"]},
                }]
            },
        )
        pulumi.log.info(f"[INFO] SSE-C unlocked on {bucket_id} (BlockedEncryptionTypes=NONE)")
    except Exception as exc:
        pulumi.log.warn(f"[WARN] SSE-C unlock failed on {bucket_id}: {exc}")


target_bucket.id.apply(_unlock_ssec)

# -----------------------------------------------------------------------
# 3. codefinger-cloudtrail-log-bucket
# -----------------------------------------------------------------------
ct_log_bucket = aws.s3.BucketV2(
    "codefinger-cloudtrail-log-bucket",
    bucket=CLOUDTRAIL_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

# -----------------------------------------------------------------------
# 4. codefinger-cloudtrail-log-bucket-policy
# -----------------------------------------------------------------------
ct_log_bucket_policy = aws.s3.BucketPolicy(
    "codefinger-cloudtrail-log-bucket-policy",
    bucket=ct_log_bucket.id,
    policy=ct_log_bucket.bucket.apply(
        lambda name: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{name}",
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{name}/AWSLogs/{ACCOUNT_ID}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    },
                },
            ],
        })
    ),
)

# -----------------------------------------------------------------------
# 5. codefinger-cloudtrail
#    Captures management events + S3 data-plane events on target bucket
# -----------------------------------------------------------------------
cloudtrail = aws.cloudtrail.Trail(
    "codefinger-cloudtrail",
    name=TRAIL_NAME,
    s3_bucket_name=ct_log_bucket.bucket,
    enable_log_file_validation=True,
    is_multi_region_trail=False,
    enable_logging=True,
    event_selectors=[
        aws.cloudtrail.TrailEventSelectorArgs(
            read_write_type="All",
            include_management_events=True,
            data_resources=[
                aws.cloudtrail.TrailEventSelectorDataResourceArgs(
                    type="AWS::S3::Object",
                    values=[
                        pulumi.Output.concat(
                            "arn:aws:s3:::", target_bucket.bucket, "/"
                        )
                    ],
                )
            ],
        )
    ],
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[ct_log_bucket_policy]),
)

# -----------------------------------------------------------------------
# 6. codefinger-victim-iam-user
#    Programmatic-only; no console access
# -----------------------------------------------------------------------
victim_user = aws.iam.User(
    "codefinger-victim-iam-user",
    name=VICTIM_USER_NAME,
    path="/",
    tags=TAGS,
)

# -----------------------------------------------------------------------
# 7. codefinger-victim-iam-access-key
#    Long-term key; no rotation (mimics real exposed-key scenario)
# -----------------------------------------------------------------------
victim_access_key = aws.iam.AccessKey(
    "codefinger-victim-iam-access-key",
    user=victim_user.name,
)

pulumi.export("victim_access_key_id",     victim_access_key.id)
# Wrap the secret key so deploy does not persist it plaintext into Stack.outputs.
# The attack still receives it: the worker fetches the full (decrypted) output set
# live from Pulumi state at run time.
pulumi.export("victim_secret_access_key", pulumi.Output.secret(victim_access_key.secret))

# -----------------------------------------------------------------------
# 8. codefinger-victim-iam-policy (inline)
#    Over-permissioned: includes PutLifecycleConfiguration + PutObject
#    enabling T1490 deletion scheduling and T1486 SSE-C re-encryption.
#    Also includes versioning + list-all actions used in the full attack chain.
# -----------------------------------------------------------------------
victim_policy = aws.iam.UserPolicy(
    "codefinger-victim-iam-policy",
    name="CodefingervictimS3Access",
    user=victim_user.name,
    policy=target_bucket.bucket.apply(
        lambda name: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CodefingervictimS3BucketAccess",
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:GetBucketVersioning",
                        "s3:PutBucketVersioning",
                        "s3:ListBucketVersions",
                        "s3:GetLifecycleConfiguration",
                        "s3:PutLifecycleConfiguration",
                        "s3:DeleteBucketLifecycle",
                    ],
                    "Resource": f"arn:aws:s3:::{name}",
                },
                {
                    "Sid": "CodefingervictimS3ObjectAccess",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:DeleteObjectVersion",
                    ],
                    "Resource": f"arn:aws:s3:::{name}/*",
                },
                {
                    "Sid": "CodefingervictimS3Global",
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListAllMyBuckets",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "CodefingervictimSTS",
                    "Effect": "Allow",
                    "Action": [
                        "sts:GetCallerIdentity",
                    ],
                    "Resource": "*",
                },
            ],
        })
    ),
)

# -----------------------------------------------------------------------
# 9. codefinger-synthetic-data-finance
#    3 CSV objects in finance/ prefix; fabricated data only
# -----------------------------------------------------------------------
_finance_objects = {
    "finance/Q4_2025_revenue.csv": (
        "quarter,product,region,revenue_usd\n"
        "Q4,Widget-A,AMER,1250000\n"
        "Q4,Widget-B,EMEA,874500\n"
        "Q4,Widget-C,APAC,2100000\n"
        "Q4,Widget-D,AMER,430000\n"
    ),
    "finance/payroll_export_2025.csv": (
        "employee_id,first_name,last_name,department,annual_salary_usd\n"
        "E0021,James,Anderson,Engineering,120000\n"
        "E0047,Maria,Gonzalez,Marketing,95000\n"
        "E0083,Robert,Kim,Finance,110000\n"
        "E0112,Sarah,Patel,Operations,88000\n"
    ),
    "finance/accounts_receivable.csv": (
        "invoice_id,client_name,amount_usd,currency,due_date,status\n"
        "INV-2025-001,Acme Corp,45000,USD,2026-01-15,OPEN\n"
        "INV-2025-002,Beta Industries,22500,USD,2026-01-20,OPEN\n"
        "INV-2025-003,Gamma Solutions,67800,USD,2026-02-01,OPEN\n"
        "INV-2025-004,Delta Group,15200,USD,2026-02-14,PAID\n"
    ),
}

for _obj_key, _obj_content in _finance_objects.items():
    _resource_id = "codefinger-finance-" + _obj_key.split("/")[-1].replace(".", "-")
    aws.s3.BucketObject(
        _resource_id,
        bucket=target_bucket.id,
        key=_obj_key,
        content=_obj_content,
        content_type="text/csv",
        server_side_encryption="AES256",
    )

# -----------------------------------------------------------------------
# 10. codefinger-synthetic-data-hr
#     2 CSV objects in hr/ prefix; entirely fabricated content
# -----------------------------------------------------------------------
_hr_objects = {
    "hr/employee_roster_2025.csv": (
        "employee_id,first_name,last_name,department,title,start_date,location\n"
        "E0021,James,Anderson,Engineering,Senior Engineer,2020-03-15,New York\n"
        "E0047,Maria,Gonzalez,Marketing,Marketing Manager,2019-07-01,Austin\n"
        "E0083,Robert,Kim,Finance,Financial Analyst,2021-11-20,Chicago\n"
        "E0112,Sarah,Patel,Operations,Operations Lead,2022-05-10,Seattle\n"
        "E0134,David,Okafor,Engineering,Staff Engineer,2018-01-08,New York\n"
    ),
    "hr/compensation_bands.csv": (
        "level,title,min_usd,midpoint_usd,max_usd,bonus_target_pct\n"
        "L1,Associate Engineer,75000,85000,95000,5\n"
        "L2,Engineer,95000,110000,125000,8\n"
        "L3,Senior Engineer,125000,140000,160000,12\n"
        "L4,Staff Engineer,155000,175000,200000,15\n"
        "L5,Principal Engineer,190000,215000,250000,20\n"
    ),
}

for _obj_key, _obj_content in _hr_objects.items():
    _resource_id = "codefinger-hr-" + _obj_key.split("/")[-1].replace(".", "-")
    aws.s3.BucketObject(
        _resource_id,
        bucket=target_bucket.id,
        key=_obj_key,
        content=_obj_content,
        content_type="text/csv",
        server_side_encryption="AES256",
    )

# -----------------------------------------------------------------------
# 11. codefinger-bait-public-access-block
#     Disables all four Block Public Access flags so the bucket policy
#     granting Principal:'*' is accepted (required since S3 April 2023 default)
# -----------------------------------------------------------------------
bait_public_access_block = aws.s3.BucketPublicAccessBlock(
    "codefinger-bait-public-access-block",
    bucket=bait_bucket.id,
    block_public_acls=False,
    block_public_policy=False,
    ignore_public_acls=False,
    restrict_public_buckets=False,
)

# -----------------------------------------------------------------------
# 12. codefinger-bait-public-bucket-policy
#     Grants anonymous s3:GetObject on terraform.tfvars only
# -----------------------------------------------------------------------
bait_bucket_policy = aws.s3.BucketPolicy(
    "codefinger-bait-public-bucket-policy",
    bucket=bait_bucket.id,
    policy=bait_bucket.bucket.apply(
        lambda name: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadCredentialFile",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{name}/terraform.tfvars",
                }
            ],
        })
    ),
    opts=pulumi.ResourceOptions(depends_on=[bait_public_access_block]),
)

# -----------------------------------------------------------------------
# 13. codefinger-exposed-credentials-object
#     terraform.tfvars containing real victim IAM key/secret rendered
#     at deploy time via Pulumi interpolation (T1552.001 simulation)
#     No ACL set -- BucketOwnerEnforced rejects ACL calls; public read
#     is already granted by codefinger-bait-public-bucket-policy.
# -----------------------------------------------------------------------
exposed_credentials = aws.s3.BucketObject(
    "codefinger-exposed-credentials-object",
    bucket=bait_bucket.id,
    key="terraform.tfvars",
    content=pulumi.Output.all(
        victim_access_key.id, victim_access_key.secret
    ).apply(
        lambda args: (
            f'# Terraform variable overrides\n'
            f'aws_access_key_id     = "{args[0]}"\n'
            f'aws_secret_access_key = "{args[1]}"\n'
            f'region                = "us-east-1"\n'
        )
    ),
    content_type="text/plain",
    opts=pulumi.ResourceOptions(depends_on=[bait_bucket_policy]),
)

pulumi.export("exposed_credentials_key", "terraform.tfvars")
