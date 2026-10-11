import json
import pathlib
import sys

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import pulumi
import pulumi_aws as aws

# Load resource names from single source of truth
_NAMES = {'campaign': 'ATOMIC-EBS-RANSOMWARE-KMS',
 'csp': 'aws',
 'resources': {'lab_kms_key_description': 'atomic-ebs-ransomware-kms lab data CMK',
               'attacker_kms_key_description': 'atomic-ebs-ransomware-kms attacker ransom CMK',
               'victim_ebs_volume_name': 'atomic-ebs-ransomware-kms-victim-data',
               'victim_ebs_snapshot_name': 'prod-database-backup',
               'victim_ebs_snapshot_description': 'prod-database-backup-2026-10-10',
               'attacker_role_name': 'atomic-ebs-ransomware-kms-attacker-role',
               'attacker_allow_policy_name': 'atomic-ebs-ransomware-kms-attacker-allow',
               'deny_guard_policy_name': 'atomic-ebs-ransomware-kms-deny-guard',
               'cloudtrail_bucket_name_prefix': 'atomic-ebs-ransomware-kms-ct',
               'cloudtrail_trail_name': 'atomic-ebs-ransomware-kms-trail'},
 'pulumi_export_keys': {'lab_kms_key_arn': 'lab_kms_key_arn',
                        'attacker_kms_key_arn': 'attacker_kms_key_arn',
                        'victim_ebs_volume_id': 'victim_ebs_volume_id',
                        'victim_ebs_snapshot_id': 'victim_ebs_snapshot_id',
                        'attacker_role_arn': 'attacker_role_arn',
                        'attacker_role_name': 'attacker_role_name',
                        'cloudtrail_bucket_name': 'cloudtrail_bucket_name',
                        'trail_name': 'trail_name',
                        'region': 'region'}}
_R = _NAMES["resources"]

# ── Resource Name Constants ──────────────────────────────────────────────────
LAB_KMS_DESCRIPTION          = _R["lab_kms_key_description"]
ATTACKER_KMS_DESCRIPTION     = _R["attacker_kms_key_description"]
VICTIM_VOLUME_NAME           = _R["victim_ebs_volume_name"]
VICTIM_SNAPSHOT_NAME         = _R["victim_ebs_snapshot_name"]
VICTIM_SNAPSHOT_DESCRIPTION  = _R["victim_ebs_snapshot_description"]
ATTACKER_ROLE_NAME           = _R["attacker_role_name"]
ATTACKER_ALLOW_POLICY_NAME   = _R["attacker_allow_policy_name"]
DENY_GUARD_POLICY_NAME       = _R["deny_guard_policy_name"]
CT_BUCKET_PREFIX             = _R["cloudtrail_bucket_name_prefix"]
TRAIL_NAME                   = _R["cloudtrail_trail_name"]

COMMON_TAGS = {
    "MayaTrail": "true",
    "Purpose": "adversary-emulation",
    "ThreatActor": "ATOMIC-ebs-ransomware-kms",
}

# ── AWS Identity ─────────────────────────────────────────────────────────────
caller     = aws.get_caller_identity()
account_id = caller.account_id
region     = aws.get_region().id
az         = f"{region}a"

ct_bucket_name = f"{CT_BUCKET_PREFIX}-{account_id}"

# Export static name constants so attack.py can resolve them from stack outputs
pulumi.export("trail_name", TRAIL_NAME)
pulumi.export("region", region)

# ── CloudTrail Log Bucket ─────────────────────────────────────────────────────
ct_bucket = aws.s3.BucketV2(
    "cloudtrail-log-bucket",
    bucket=ct_bucket_name,
    force_destroy=True,
    tags={**COMMON_TAGS},
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "cloudtrail-log-bucket-sse",
    bucket=ct_bucket.id,
    rules=[
        aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256",
            ),
        )
    ],
)

# Constraint 6b: PutObject path must be /AWSLogs/{account_id}/* (NOT /CloudTrail/).
# Bind to variable and pass via depends_on to the Trail.
ct_bucket_policy = aws.s3.BucketPolicy(
    "cloudtrail-log-bucket-policy",
    bucket=ct_bucket.id,
    policy=ct_bucket.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": arn,
                },
                {
                    "Sid": "AWSCloudTrailWrite",
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

pulumi.export("cloudtrail_bucket_name", ct_bucket.id)

# ── Lab KMS Key (victim data CMK) ─────────────────────────────────────────────
lab_kms_key = aws.kms.Key(
    "lab-kms-key",
    description=LAB_KMS_DESCRIPTION,
    enable_key_rotation=True,
    deletion_window_in_days=7,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }),
    tags={**COMMON_TAGS},
)

pulumi.export("lab_kms_key_arn", lab_kms_key.arn)

# ── Attacker KMS Key (ransom CMK) ─────────────────────────────────────────────
# Key policy uses account-root trust delegation to IAM; attacker role gets per-action
# KMS access via attacker-allow-policy. This avoids a circular dependency (the key
# references a role that doesn't exist yet at key-creation time).
attacker_kms_key = aws.kms.Key(
    "attacker-kms-key",
    description=ATTACKER_KMS_DESCRIPTION,
    enable_key_rotation=False,
    deletion_window_in_days=7,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }),
    tags={**COMMON_TAGS},
)

pulumi.export("attacker_kms_key_arn", attacker_kms_key.arn)

# ── Victim EBS Volume ─────────────────────────────────────────────────────────
victim_ebs_volume = aws.ebs.Volume(
    "victim-ebs-volume",
    availability_zone=az,
    size=1,
    type="gp3",
    encrypted=True,
    kms_key_id=lab_kms_key.arn,
    tags={**COMMON_TAGS, "Name": VICTIM_VOLUME_NAME},
)

pulumi.export("victim_ebs_volume_id", victim_ebs_volume.id)

# ── Victim EBS Snapshot (pre-existing backup bait) ────────────────────────────
victim_ebs_snapshot = aws.ebs.Snapshot(
    "victim-ebs-snapshot",
    volume_id=victim_ebs_volume.id,
    description=VICTIM_SNAPSHOT_DESCRIPTION,
    tags={**COMMON_TAGS, "Name": VICTIM_SNAPSHOT_NAME},
)

pulumi.export("victim_ebs_snapshot_id", victim_ebs_snapshot.id)

# ── Attacker Allow Policy ─────────────────────────────────────────────────────
# ec2:DescribeVolumes and ec2:DescribeSnapshots are account-level list operations that
# do not support resource-level tag conditions in IAM. Separating them into their own
# unconditioned statement ensures the attack chain can enumerate resources. Allowed per
# constraint 15c: wildcard Resource is permitted for actions AWS cannot scope.
attacker_allow_policy = aws.iam.Policy(
    "attacker-allow-policy",
    name=ATTACKER_ALLOW_POLICY_NAME,
    policy=pulumi.Output.all(attacker_kms_key.arn, lab_kms_key.arn).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EBSWriteOpsTagScoped",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateSnapshot",
                        "ec2:CopySnapshot",
                        "ec2:CreateVolume",
                        "ec2:DeleteVolume",
                        "ec2:DeleteSnapshot",
                        "ec2:CreateTags",
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:ResourceTag/MayaTrail": "true"}
                    },
                },
                {
                    "Sid": "EBSDescribeOps",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeVolumes",
                        "ec2:DescribeSnapshots",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "KMSReEncryptKeyARNScoped",
                    "Effect": "Allow",
                    "Action": [
                        "kms:DescribeKey",
                        "kms:CreateGrant",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:ReEncryptFrom",
                        "kms:ReEncryptTo",
                        "kms:ScheduleKeyDeletion",
                        "kms:CancelKeyDeletion",
                    ],
                    "Resource": [args[0], args[1]],
                },
                {
                    "Sid": "KMSCreateKeyAccountScoped",
                    "Effect": "Allow",
                    "Action": "kms:CreateKey",
                    "Resource": "*",
                },
            ],
        })
    ),
    tags={**COMMON_TAGS},
)

# ── Deny Guard Policy ─────────────────────────────────────────────────────────
# Explicit Deny on kms:PutKeyPolicy prevents account-level key policy lockout.
# attack.py still calls PutKeyPolicy -> CloudTrail records errorCode=AccessDenied.
# Detection rules MUST NOT filter errorCode IS NULL.
deny_guard_policy = aws.iam.Policy(
    "deny-guard-policy",
    name=DENY_GUARD_POLICY_NAME,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyPutKeyPolicy",
                "Effect": "Deny",
                "Action": "kms:PutKeyPolicy",
                "Resource": "*",
            }
        ],
    }),
    tags={**COMMON_TAGS},
)

# ── Attacker Role ─────────────────────────────────────────────────────────────
attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
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
    tags={**COMMON_TAGS},
)

pulumi.export("attacker_role_arn", attacker_role.arn)
pulumi.export("attacker_role_name", attacker_role.name)

# ── Policy Attachments ────────────────────────────────────────────────────────
# Both attachments deploy atomically -- role never exists with Allow but without Deny.
aws.iam.RolePolicyAttachment(
    "attacker-allow-policy-attachment",
    role=attacker_role.name,
    policy_arn=attacker_allow_policy.arn,
)

aws.iam.RolePolicyAttachment(
    "deny-guard-policy-attachment",
    role=attacker_role.name,
    policy_arn=deny_guard_policy.arn,
)

# ── CloudTrail Trail ──────────────────────────────────────────────────────────
aws.cloudtrail.Trail(
    "cloudtrail-trail",
    name=TRAIL_NAME,
    s3_bucket_name=ct_bucket.id,
    include_global_service_events=True,
    is_multi_region_trail=True,
    enable_log_file_validation=True,
    enable_logging=True,
    event_selectors=[
        aws.cloudtrail.TrailEventSelectorArgs(
            read_write_type="WriteOnly",
            include_management_events=True,
        )
    ],
    tags={**COMMON_TAGS},
    opts=pulumi.ResourceOptions(depends_on=[ct_bucket_policy]),
)
