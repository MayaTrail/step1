import json
import pathlib
import pulumi
import pulumi_aws as aws

# ---------------------------------------------------------------------------
# Resource name constants - single source of truth loaded from resource_names.json
# ---------------------------------------------------------------------------
_NAMES = {'campaign': 'ATOMIC_EC2_DEREGISTER_AMI',
 'csp': 'aws',
 'resources': {'trail_bucket_prefix': 'atomic-ec2-deregister-ami-trail',
               'trail_name': 'atomic-ec2-deregister-ami-trail',
               'victim_role_name': 'atomic-ec2-deregister-ami-victim-role',
               'victim_policy_name': 'atomic-ec2-deregister-ami-victim-policy',
               'golden_ami_name': 'prod-golden-image-2024',
               'bait_ami_name': 'prod-database-backup-ami-v3',
               'source_volume_tag_name': 'atomic-ec2-deregister-ami-source-volume',
               'source_snapshot_description': 'lab-snapshot-for-ami-deregister-emulation'},
 'pulumi_export_keys': {'trail_name': 'trail_name',
                        'trail_bucket_name': 'trail_bucket_name',
                        'victim_role_arn': 'victim_role_arn',
                        'victim_role_name': 'victim_role_name',
                        'source_volume_id': 'source_volume_id',
                        'source_snapshot_id': 'source_snapshot_id',
                        'golden_ami_id': 'golden_ami_id',
                        'bait_ami_id': 'bait_ami_id',
                        'account_id': 'account_id',
                        'region': 'region'}}
_R = _NAMES["resources"]

TRAIL_BUCKET_PREFIX        = _R["trail_bucket_prefix"]
TRAIL_NAME                 = _R["trail_name"]
VICTIM_ROLE_NAME           = _R["victim_role_name"]
VICTIM_POLICY_NAME         = _R["victim_policy_name"]
GOLDEN_AMI_NAME            = _R["golden_ami_name"]
BAIT_AMI_NAME              = _R["bait_ami_name"]
SOURCE_VOLUME_TAG_NAME     = _R["source_volume_tag_name"]
SOURCE_SNAPSHOT_DESCRIPTION = _R["source_snapshot_description"]

# ---------------------------------------------------------------------------
# Account / region resolution
# ---------------------------------------------------------------------------
caller_identity = aws.get_caller_identity()
account_id      = caller_identity.account_id

region_info = aws.get_region()
region      = region_info.id   # .name is deprecated in pulumi-aws v7

# ---------------------------------------------------------------------------
# S3 trail bucket (BucketV2 + standalone config resources per pulumi-aws v7)
# ---------------------------------------------------------------------------
trail_bucket = aws.s3.BucketV2(
    "trail-bucket",
    bucket_prefix=TRAIL_BUCKET_PREFIX,
    force_destroy=True,
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

aws.s3.BucketPublicAccessBlock(
    "trail-bucket-pab",
    bucket=trail_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "trail-bucket-sse",
    bucket=trail_bucket.id,
    rules=[
        aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256",
            ),
        )
    ],
)

# Bucket policy for CloudTrail - path must be /AWSLogs/{account_id}/* (not /CloudTrail/)
trail_bucket_policy = aws.s3.BucketPolicy(
    "trail-bucket-policy",
    bucket=trail_bucket.id,
    policy=pulumi.Output.all(trail_bucket.arn, account_id).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": args[0],
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"{args[0]}/AWSLogs/{args[1]}/*",
                    "Condition": {
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                    },
                },
            ],
        })
    ),
)

# ---------------------------------------------------------------------------
# CloudTrail - WriteOnly management events capturing DeregisterImage
# depends_on trail_bucket_policy so CreateTrail validates the policy correctly
# ---------------------------------------------------------------------------
trail = aws.cloudtrail.Trail(
    "trail",
    name=TRAIL_NAME,
    s3_bucket_name=trail_bucket.id,
    is_multi_region_trail=False,
    include_global_service_events=True,
    enable_log_file_validation=True,
    enable_logging=True,
    event_selectors=[
        aws.cloudtrail.TrailEventSelectorArgs(
            read_write_type="WriteOnly",
            include_management_events=True,
        )
    ],
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
    opts=pulumi.ResourceOptions(depends_on=[trail_bucket_policy]),
)

# ---------------------------------------------------------------------------
# Victim IAM role - trust principal is the current account (self-trust)
# Attack script assumes this role to obtain temporary credentials
# ---------------------------------------------------------------------------
victim_role = aws.iam.Role(
    "victim-role",
    name=VICTIM_ROLE_NAME,
    assume_role_policy=pulumi.Output.from_input(account_id).apply(
        lambda aid: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{aid}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        })
    ),
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

# Inline policy - tag-conditioned to MayaTrail=true resources only
victim_policy = aws.iam.RolePolicy(
    "victim-policy",
    name=VICTIM_POLICY_NAME,
    role=victim_role.name,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DeregisterTaggedAMIs",
                "Effect": "Allow",
                "Action": ["ec2:DeregisterImage"],
                "Resource": "arn:aws:ec2:*::image/*",
                "Condition": {
                    "StringEquals": {"ec2:ResourceTag/MayaTrail": "true"}
                },
            },
            {
                "Sid": "DeleteTaggedSnapshots",
                "Effect": "Allow",
                "Action": ["ec2:DeleteSnapshot"],
                "Resource": "arn:aws:ec2:*::snapshot/*",
                "Condition": {
                    "StringEquals": {"ec2:ResourceTag/MayaTrail": "true"}
                },
            },
            {
                "Sid": "DescribeForDiscovery",
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeImages",
                    "ec2:DescribeSnapshots",
                ],
                "Resource": "*",
            },
        ],
    }),
)

# ---------------------------------------------------------------------------
# EBS source volume - minimal 1 GiB gp3, unencrypted for public AMI registration
# ---------------------------------------------------------------------------
source_volume = aws.ebs.Volume(
    "source-volume",
    size=1,
    type="gp3",
    availability_zone=f"{region}a",
    encrypted=False,
    tags={
        "MayaTrail": "true",
        "Purpose": "adversary-emulation",
        "Name": SOURCE_VOLUME_TAG_NAME,
    },
)

# ---------------------------------------------------------------------------
# EBS snapshot of the source volume - backing store for both lab AMIs
# ---------------------------------------------------------------------------
source_snapshot = aws.ebs.Snapshot(
    "source-snapshot",
    volume_id=source_volume.id,
    description=SOURCE_SNAPSHOT_DESCRIPTION,
    tags={
        "MayaTrail": "true",
        "Purpose": "adversary-emulation",
        "Name": "atomic-ec2-deregister-ami-source-snapshot",
    },
)

# ---------------------------------------------------------------------------
# Golden AMI - primary T1485 target representing a production golden image
# ---------------------------------------------------------------------------
golden_ami = aws.ec2.Ami(
    "golden-ami",
    name=GOLDEN_AMI_NAME,
    virtualization_type="hvm",
    root_device_name="/dev/xvda",
    ebs_block_devices=[
        aws.ec2.AmiEbsBlockDeviceArgs(
            device_name="/dev/xvda",
            snapshot_id=source_snapshot.id,
            volume_size=1,
            volume_type="gp3",
            delete_on_termination=True,
        )
    ],
    tags={
        "MayaTrail": "true",
        "Purpose": "adversary-emulation",
        "Name": GOLDEN_AMI_NAME,
    },
)

# ---------------------------------------------------------------------------
# Bait AMI - decoy with prod-database-backup name for multi-AMI destruction runs
# ---------------------------------------------------------------------------
bait_ami = aws.ec2.Ami(
    "bait-ami",
    name=BAIT_AMI_NAME,
    virtualization_type="hvm",
    root_device_name="/dev/xvda",
    ebs_block_devices=[
        aws.ec2.AmiEbsBlockDeviceArgs(
            device_name="/dev/xvda",
            snapshot_id=source_snapshot.id,
            volume_size=1,
            volume_type="gp3",
            delete_on_termination=True,
        )
    ],
    tags={
        "MayaTrail": "true",
        "Purpose": "adversary-emulation",
        "Name": BAIT_AMI_NAME,
    },
)

# ---------------------------------------------------------------------------
# Pulumi exports - keys must match pulumi_export_keys in resource_names.json
# ---------------------------------------------------------------------------
pulumi.export("trail_name",          TRAIL_NAME)
pulumi.export("trail_bucket_name",   trail_bucket.id)
pulumi.export("victim_role_arn",     victim_role.arn)
pulumi.export("victim_role_name",    victim_role.name)
pulumi.export("source_volume_id",    source_volume.id)
pulumi.export("source_snapshot_id",  source_snapshot.id)
pulumi.export("golden_ami_id",       golden_ami.id)
pulumi.export("bait_ami_id",         bait_ami.id)
pulumi.export("account_id",          account_id)
pulumi.export("region",              region)
