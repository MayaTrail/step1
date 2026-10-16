import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import pathlib
import boto3
import pulumi
import pulumi_aws as aws

# ===== Resource Name Constants =====
_NAMES = {'campaign': 'ATOMIC-guardduty-impair',
 'csp': 'aws',
 'resources': {'attacker_role_name': 'atomic-guardduty-impair-attacker-role',
               'attacker_allow_policy_name': 'atomic-guardduty-impair-attacker-allow',
               'attacker_deny_policy_name': 'atomic-guardduty-impair-attacker-deny',
               'trail_name': 'atomic-guardduty-impair-trail',
               'cw_log_group_name': '/mayatrail/atomic-guardduty-impair/trail',
               'cw_delivery_role_name': 'atomic-guardduty-impair-cw-delivery'},
 'pulumi_export_keys': {'detector_id': 'detector_id',
                        'detector_is_lab_owned': 'detector_is_lab_owned',
                        'attacker_role_arn': 'attacker_role_arn',
                        'attacker_role_name': 'attacker_role_name',
                        'trusted_ip_bucket_name': 'trusted_ip_bucket_name',
                        'trail_name': 'trail_name',
                        'trail_bucket_name': 'trail_bucket_name',
                        'account_id': 'account_id',
                        'region': 'region'}}
_R = _NAMES["resources"]

ATTACKER_ROLE_NAME       = _R["attacker_role_name"]
ATTACKER_ALLOW_POLICY    = _R["attacker_allow_policy_name"]
ATTACKER_DENY_POLICY     = _R["attacker_deny_policy_name"]
TRAIL_NAME               = _R["trail_name"]
CW_LOG_GROUP_NAME        = _R["cw_log_group_name"]
CW_DELIVERY_ROLE_NAME    = _R["cw_delivery_role_name"]

# ===== Runtime Identity =====
_caller    = aws.get_caller_identity()
account_id = _caller.account_id
region     = aws.get_region().id

TRUSTED_IP_BUCKET_NAME = f"prod-guardduty-trusted-ips-{account_id}"
TRAIL_BUCKET_NAME      = f"atomic-guardduty-impair-trail-bkt-{account_id}"

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-guardduty-impair",
    "LabOwned":    "true",
}

# Export static/computed names for attack.py
pulumi.export("attacker_role_name",    ATTACKER_ROLE_NAME)
pulumi.export("trail_name",            TRAIL_NAME)
pulumi.export("trusted_ip_bucket_name", TRUSTED_IP_BUCKET_NAME)
pulumi.export("trail_bucket_name",     TRAIL_BUCKET_NAME)
pulumi.export("account_id",            account_id)
pulumi.export("region",                region)

# =============================================================
# 1. CloudTrail S3 Bucket
# =============================================================
trail_bucket = aws.s3.BucketV2(
    "atomic-guardduty-impair-trail-bucket",
    bucket=TRAIL_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketOwnershipControls(
    "atomic-guardduty-impair-trail-bucket-ownership",
    bucket=trail_bucket.id,
    rule=aws.s3.BucketOwnershipControlsRuleArgs(
        object_ownership="BucketOwnerPreferred",
    ),
)

aws.s3.BucketPublicAccessBlock(
    "atomic-guardduty-impair-trail-bucket-pab",
    bucket=trail_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# Constraint 6b: PutObject path MUST be /AWSLogs/{account_id}/* not /CloudTrail/*
trail_bucket_policy = aws.s3.BucketPolicy(
    "atomic-guardduty-impair-trail-bucket-policy",
    bucket=trail_bucket.id,
    policy=trail_bucket.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CloudTrailGetBucketAcl",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": arn,
                },
                {
                    "Sid": "CloudTrailPutObject",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"{arn}/AWSLogs/{account_id}/*",
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

aws.s3.BucketLifecycleConfigurationV2(
    "atomic-guardduty-impair-trail-bucket-lifecycle",
    bucket=trail_bucket.id,
    rules=[
        aws.s3.BucketLifecycleConfigurationV2RuleArgs(
            id="expire-logs-30d",
            status="Enabled",
            expiration=aws.s3.BucketLifecycleConfigurationV2RuleExpirationArgs(
                days=30,
            ),
        )
    ],
)

# =============================================================
# 2. Trusted-IP S3 Bucket
# =============================================================
trusted_ip_bucket = aws.s3.BucketV2(
    "atomic-guardduty-impair-trusted-ip-bucket",
    bucket=TRUSTED_IP_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketOwnershipControls(
    "atomic-guardduty-impair-trusted-ip-bucket-ownership",
    bucket=trusted_ip_bucket.id,
    rule=aws.s3.BucketOwnershipControlsRuleArgs(
        object_ownership="BucketOwnerPreferred",
    ),
)

aws.s3.BucketPublicAccessBlock(
    "atomic-guardduty-impair-trusted-ip-bucket-pab",
    bucket=trusted_ip_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketPolicy(
    "atomic-guardduty-impair-trusted-ip-bucket-policy",
    bucket=trusted_ip_bucket.id,
    policy=trusted_ip_bucket.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "GuardDutyReadTrustedIPs",
                    "Effect": "Allow",
                    "Principal": {"Service": "guardduty.amazonaws.com"},
                    "Action": "s3:GetObject",
                    "Resource": f"{arn}/*",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": account_id
                        }
                    },
                },
            ],
        })
    ),
)

# Seed the RFC-5737 TEST-NET-1 list (non-routable, safe for real accounts)
aws.s3.BucketObjectv2(
    "atomic-guardduty-impair-trusted-ip-list",
    bucket=trusted_ip_bucket.id,
    key="trusted_ip_list.txt",
    content="192.0.2.0/24\n",
    content_type="text/plain",
    tags=TAGS,
)

# =============================================================
# 3. GuardDuty Detector - region singleton guard (constraint 15b)
# =============================================================
_gd_client = boto3.client("guardduty", region_name=region)
try:
    _existing_detector_ids = _gd_client.list_detectors().get("DetectorIds", [])
except Exception:
    _existing_detector_ids = []

_detector_resource = None
if _existing_detector_ids:
    _existing_detector_id = _existing_detector_ids[0]
    pulumi.export("detector_id",           _existing_detector_id)
    pulumi.export("detector_is_lab_owned", False)
else:
    _detector_resource = aws.guardduty.Detector(
        "atomic-guardduty-impair-detector",
        enable=True,
        finding_publishing_frequency="ONE_HOUR",
        tags=TAGS,
    )
    pulumi.export("detector_id",           _detector_resource.id)
    pulumi.export("detector_is_lab_owned", True)

# =============================================================
# 4. CloudWatch Logs group + delivery role for CloudTrail
# =============================================================
cw_log_group = aws.cloudwatch.LogGroup(
    "atomic-guardduty-impair-trail-logs",
    name=CW_LOG_GROUP_NAME,
    retention_in_days=30,
    tags=TAGS,
)

cw_delivery_role = aws.iam.Role(
    "atomic-guardduty-impair-cw-delivery-role",
    name=CW_DELIVERY_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    inline_policies=[
        aws.iam.RoleInlinePolicyArgs(
            name="CloudWatchDelivery",
            policy=cw_log_group.arn.apply(
                lambda arn: json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": f"{arn}:*",
                    }],
                })
            ),
        ),
    ],
    tags=TAGS,
)

# =============================================================
# 5. CloudTrail Trail
# Constraint 6b: bind policy via depends_on; enable_logging=True
# =============================================================
trail = aws.cloudtrail.Trail(
    "atomic-guardduty-impair-trail",
    name=TRAIL_NAME,
    s3_bucket_name=trail_bucket.id,
    is_multi_region_trail=False,
    include_global_service_events=True,
    enable_log_file_validation=True,
    enable_logging=True,
    cloud_watch_logs_group_arn=cw_log_group.arn.apply(lambda arn: f"{arn}:*"),
    cloud_watch_logs_role_arn=cw_delivery_role.arn,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[trail_bucket_policy]),
)

# =============================================================
# 6. Attacker IAM Role (compromised-credential seed)
# Trust: current account root - self-trust per constraint 3
# Allow policy: pinned to lab bucket ARN (constraint 15c)
# Deny policy: blocks destructive GD actions (deny-guard)
# =============================================================
_attacker_deps = [trusted_ip_bucket, trail]
if _detector_resource:
    _attacker_deps.append(_detector_resource)

attacker_role = aws.iam.Role(
    "atomic-guardduty-impair-attacker-role",
    name=ATTACKER_ROLE_NAME,
    description="Lab attacker role for GuardDuty impair emulation - deny-guarded",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }),
    inline_policies=[
        aws.iam.RoleInlinePolicyArgs(
            name=ATTACKER_ALLOW_POLICY,
            policy=trusted_ip_bucket.arn.apply(
                lambda bucket_arn: json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowGuardDutyModify",
                            "Effect": "Allow",
                            "Action": [
                                "guardduty:GetDetector",
                                "guardduty:ListDetectors",
                                "guardduty:UpdateDetector",
                                "guardduty:DeleteDetector",
                                "guardduty:CreateThreatIntelSet",
                                "guardduty:UpdateThreatIntelSet",
                                "guardduty:GetThreatIntelSet",
                                "guardduty:ListThreatIntelSets",
                                "guardduty:DeleteThreatIntelSet",
                                "guardduty:CreateFilter",
                                "guardduty:UpdateFilter",
                                "guardduty:GetFilter",
                                "guardduty:ListFilters",
                                "guardduty:DeleteFilter",
                            ],
                            "Resource": "*",
                        },
                        {
                            "Sid": "AllowThreatIntelS3",
                            "Effect": "Allow",
                            "Action": [
                                "s3:PutObject",
                                "s3:GetObject",
                                "s3:ListBucket",
                            ],
                            "Resource": [
                                bucket_arn,
                                f"{bucket_arn}/*",
                            ],
                        },
                    ],
                })
            ),
        ),
        aws.iam.RoleInlinePolicyArgs(
            name=ATTACKER_DENY_POLICY,
            policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DenyGuardDutyDestruction",
                    "Effect": "Deny",
                    "Action": [
                        "guardduty:DeleteDetector",
                        "guardduty:DisassociateFromMasterAccount",
                        "guardduty:DisassociateMembers",
                        "guardduty:StopMonitoringMembers",
                    ],
                    "Resource": "*",
                }],
            }),
        ),
    ],
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=_attacker_deps),
)

pulumi.export("attacker_role_arn", attacker_role.arn)
