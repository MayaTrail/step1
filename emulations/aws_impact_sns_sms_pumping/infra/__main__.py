import json
import pathlib
import sys

import pulumi
import pulumi_aws as aws

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# --- Load resource names ---
_NAMES = {'campaign': 'ATOMIC-sns-sms-pumping',
 'csp': 'aws',
 'resources': {'attacker_role_name': 'atomic-sns-sms-pumping-attacker-role',
               'sns_topic_name': 'atomic-sns-sms-pumping-prod-customer-notifications',
               'cloudtrail_trail_name': 'atomic-sns-sms-pumping-trail'},
 'pulumi_export_keys': {'attacker_role_arn': 'attacker_role_arn',
                        'attacker_role_name': 'attacker_role_name',
                        'sns_topic_arn': 'sns_topic_arn',
                        'cloudtrail_bucket_name': 'cloudtrail_bucket_name',
                        'cloudtrail_trail_arn': 'cloudtrail_trail_arn',
                        'cloudtrail_trail_name': 'cloudtrail_trail_name'}}
_R = _NAMES["resources"]

# --- Resource Name Constants ---
ATTACKER_ROLE_NAME   = _R["attacker_role_name"]
SNS_TOPIC_NAME       = _R["sns_topic_name"]
CT_TRAIL_NAME        = _R["cloudtrail_trail_name"]

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-sns-sms-pumping",
    "Technique":   "T1496.003",
}

# --- Identity / region (sync, available at preview time) ---
caller_identity = aws.get_caller_identity()
account_id      = caller_identity.account_id
region          = aws.get_region().id  # .id not .name (pulumi-aws v7)

# =========================================================================
# CloudTrail logs bucket  (BucketV2 + standalone sub-resources per v7 API)
# =========================================================================
ct_bucket = aws.s3.BucketV2(
    "cloudtrail-logs-bucket",
    tags=TAGS,
)

# Block all public access
aws.s3.BucketPublicAccessBlock(
    "ct-bucket-pab",
    bucket=ct_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# Server-side encryption: AES256
aws.s3.BucketServerSideEncryptionConfigurationV2(
    "ct-bucket-sse",
    bucket=ct_bucket.id,
    rules=[
        aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256",
            ),
            bucket_key_enabled=False,
        )
    ],
)

# Lifecycle: expire log objects after 30 days to contain cost
aws.s3.BucketLifecycleConfigurationV2(
    "ct-bucket-lifecycle",
    bucket=ct_bucket.id,
    rules=[
        aws.s3.BucketLifecycleConfigurationV2RuleArgs(
            id="expire-ct-logs",
            status="Enabled",
            filter=aws.s3.BucketLifecycleConfigurationV2RuleFilterArgs(prefix=""),
            expiration=aws.s3.BucketLifecycleConfigurationV2RuleExpirationArgs(
                days=30,
            ),
        )
    ],
)

# Bucket policy: grant CloudTrail GetBucketAcl + PutObject
# s3:PutObject MUST target /AWSLogs/{account_id}/* (not /CloudTrail/*) per AWS validation rules
ct_bucket_policy_doc = ct_bucket.arn.apply(
    lambda bucket_arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": bucket_arn,
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{bucket_arn}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                },
            },
        ],
    })
)

ct_bucket_policy_resource = aws.s3.BucketPolicy(
    "ct-bucket-policy",
    bucket=ct_bucket.id,
    policy=ct_bucket_policy_doc,
)

# =========================================================================
# SNS Topic - bait resource (realistic production-named)
# =========================================================================
sns_topic = aws.sns.Topic(
    "prod-customer-notifications",
    name=SNS_TOPIC_NAME,
    display_name="Customer Alerts",
    kms_master_key_id="alias/aws/sns",
    tags={**TAGS, "Environment": "production"},
)

# =========================================================================
# Attacker IAM Role
# Trust policy: self-account root so lab operator can assume it via sts:AssumeRole
# =========================================================================
attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
    description="Pre-compromised attacker role for SNS SMS pumping emulation",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }),
    max_session_duration=3600,
    tags=TAGS,
)

# Inline policy: Allow Publish + read ops; Deny billable/irreversible SMS ops
# The explicit Deny on SetSMSAttributes/OptInPhoneNumber causes CloudTrail to
# record errorCode=AccessDenied, which is the detection signal for this technique.
attacker_role_policy = aws.iam.RolePolicy(  # noqa: F841
    "attacker-role-policy",
    name="sns-sms-pumping-inline-policy",
    role=attacker_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSNSPublishAndRead",
                "Effect": "Allow",
                "Action": [
                    "sns:Publish",
                    "sns:GetSMSAttributes",
                    "sns:GetSMSSandboxAccountStatus",
                    "sns:ListTopics",
                    "sns:ListPhoneNumbersOptedOut",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DenyBillableOrIrreversibleSMSOps",
                "Effect": "Deny",
                "Action": [
                    "sns:SetSMSAttributes",
                    "sns:OptInPhoneNumber",
                ],
                "Resource": "*",
            },
        ],
    }),
)

# =========================================================================
# CloudTrail Trail
# depends_on ct_bucket_policy_resource - CreateTrail validates the policy server-side
# =========================================================================
ct_trail = aws.cloudtrail.Trail(
    "cloudtrail-trail",
    name=CT_TRAIL_NAME,
    s3_bucket_name=ct_bucket.id,
    is_multi_region_trail=True,
    include_global_service_events=True,
    enable_log_file_validation=True,
    enable_logging=True,
    event_selectors=[
        aws.cloudtrail.TrailEventSelectorArgs(
            read_write_type="All",
            include_management_events=True,
        )
    ],
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[ct_bucket_policy_resource]),
)

# =========================================================================
# Exports  (keys match pulumi_export_keys in resource_names.json)
# =========================================================================
pulumi.export("attacker_role_name",      attacker_role.name)
pulumi.export("attacker_role_arn",       attacker_role.arn)
pulumi.export("sns_topic_arn",           sns_topic.arn)
pulumi.export("cloudtrail_bucket_name",  ct_bucket.bucket)
pulumi.export("cloudtrail_trail_name",   ct_trail.name)
pulumi.export("cloudtrail_trail_arn",    ct_trail.arn)
