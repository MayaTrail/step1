import json
import pathlib
import pulumi
import pulumi_aws as aws

# Load resource names from single source of truth
_NAMES = {'campaign': 'ATOMIC_IAM_ACCOUNT_ACCESS_REMOVAL',
 'csp': 'aws',
 'resources': {'attacker_role': 'atomic-iam-account-access-removal-attacker-role',
               'attacker_policy': 'atomic-iam-account-access-removal-attacker-policy',
               'lab_user_1': 'atomic-iam-account-access-removal-lab-user-1',
               'lab_user_2': 'atomic-iam-account-access-removal-lab-user-2',
               'lab_user_1_mfa': 'atomic-iam-account-access-removal-lab-user-1-mfa',
               'lab_group': 'prod-engineers',
               'lab_policy': 'EngineeringReadOnly',
               'trail_name': 'atomic-iam-account-access-removal-trail'},
 'pulumi_export_keys': {'trail_name': 'trail_name',
                        'lab_user_1_name': 'lab_user_1_name',
                        'lab_user_2_name': 'lab_user_2_name',
                        'lab_group_name': 'lab_group_name',
                        'lab_policy_name': 'lab_policy_name',
                        'attacker_role_arn': 'attacker_role_arn',
                        'lab_user_1_arn': 'lab_user_1_arn',
                        'lab_user_2_arn': 'lab_user_2_arn',
                        'lab_user_1_access_key_id': 'lab_user_1_access_key_id',
                        'lab_user_2_access_key_id': 'lab_user_2_access_key_id',
                        'lab_user_1_mfa_serial': 'lab_user_1_mfa_serial',
                        'lab_policy_arn': 'lab_policy_arn',
                        'log_bucket_name': 'log_bucket_name'}}
_R = _NAMES["resources"]

# ── Resource Name Constants ───────────────────────────────────────────────────
ATTACKER_ROLE_NAME   = _R["attacker_role"]
ATTACKER_POLICY_NAME = _R["attacker_policy"]
LAB_USER_1_NAME      = _R["lab_user_1"]
LAB_USER_2_NAME      = _R["lab_user_2"]
LAB_USER_1_MFA_NAME  = _R["lab_user_1_mfa"]
LAB_GROUP_NAME       = _R["lab_group"]
LAB_POLICY_NAME      = _R["lab_policy"]
TRAIL_NAME           = _R["trail_name"]

# Export static names so attack.py can read them from stack outputs
pulumi.export("trail_name",      TRAIL_NAME)
pulumi.export("lab_user_1_name", LAB_USER_1_NAME)
pulumi.export("lab_user_2_name", LAB_USER_2_NAME)
pulumi.export("lab_group_name",  LAB_GROUP_NAME)
pulumi.export("lab_policy_name", LAB_POLICY_NAME)

# ── Identity ──────────────────────────────────────────────────────────────────
caller     = aws.get_caller_identity()
account_id = caller.account_id
region     = aws.get_region().id

LOG_BUCKET_NAME = f"atomic-iam-account-access-removal-logs-{account_id}"

# ── S3 Log Bucket ─────────────────────────────────────────────────────────────
log_bucket = aws.s3.BucketV2(
    "log-bucket",
    force_destroy=True,  # lab bucket: CloudTrail/log objects must not block destroy
    bucket=LOG_BUCKET_NAME,
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

aws.s3.BucketPublicAccessBlock(
    "log-bucket-pab",
    bucket=log_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketVersioningV2(
    "log-bucket-versioning",
    bucket=log_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
)

aws.s3.BucketLifecycleConfigurationV2(
    "log-bucket-lifecycle",
    bucket=log_bucket.id,
    rules=[
        aws.s3.BucketLifecycleConfigurationV2RuleArgs(
            id="expire-7-days",
            status="Enabled",
            expiration=aws.s3.BucketLifecycleConfigurationV2RuleExpirationArgs(
                days=7,
            ),
        )
    ],
)

# CloudTrail bucket policy:
#   - s3:GetBucketAcl on the bucket ARN (CloudTrail requires this, not GetBucketLocation)
#   - s3:PutObject on /AWSLogs/{account_id}/* (NOT /CloudTrail/ - CreateTrail validates literally)
log_bucket_policy = aws.s3.BucketPolicy(
    "log-bucket-policy",
    bucket=log_bucket.id,
    policy=log_bucket.arn.apply(
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
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                    },
                },
            ],
        })
    ),
)

# ── CloudTrail (depends_on bucket policy - CreateTrail validates policy server-side) ──
trail = aws.cloudtrail.Trail(
    "cloudtrail",
    name=TRAIL_NAME,
    s3_bucket_name=log_bucket.id,
    include_global_service_events=True,  # required: IAM is a global service
    is_multi_region_trail=False,
    enable_log_file_validation=True,
    enable_logging=True,
    event_selectors=[
        aws.cloudtrail.TrailEventSelectorArgs(
            read_write_type="WriteOnly",
            include_management_events=True,
        )
    ],
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
    opts=pulumi.ResourceOptions(depends_on=[log_bucket_policy]),
)

# ── IAM Group (bait: realistic engineering group name, zero blast radius) ─────
lab_group = aws.iam.Group(
    "lab-group",
    name=LAB_GROUP_NAME,
    path="/",
)

# ── IAM Managed Policy (bait: realistic name, read-only content) ──────────────
lab_policy = aws.iam.Policy(
    "lab-policy",
    name=LAB_POLICY_NAME,
    description="Engineering read-only access",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:Describe*", "s3:ListBucket"],
                "Resource": "*",
            }
        ],
    }),
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

# ── Attacker Role ─────────────────────────────────────────────────────────────
# Trust: current account root only - self-trust so deploy is repeatable.
# Never a placeholder account ID; never a real external/adversary account.
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
    description="T1531 lab attacker role - account access removal emulation",
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

# Inline attacker policy - scoped to lab user / group / policy ARNs only.
# Split into four SIDs to satisfy AWS multi-resource-type requirements:
#   DeactivateMFADevice requires both user ARN and mfa ARN.
#   DetachUserPolicy    requires both user ARN and policy ARN.
#   RemoveUserFromGroup requires group ARN only.
aws.iam.RolePolicy(
    "attacker-inline-policy",
    name=ATTACKER_POLICY_NAME,
    role=attacker_role.id,
    policy=lab_policy.arn.apply(
        lambda policy_arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "T1531UserScope",
                    "Effect": "Allow",
                    "Action": [
                        "iam:DeleteAccessKey",
                        "iam:DeleteLoginProfile",
                        "iam:DeactivateMFADevice",
                        "iam:DetachUserPolicy",
                        "iam:DeleteUserPolicy",
                        "iam:DeleteUser",
                        "iam:ListAccessKeys",
                        "iam:ListMFADevices",
                        "iam:ListGroupsForUser",
                        "iam:ListAttachedUserPolicies",
                        "iam:ListUserPolicies",
                        "iam:GetUser",
                    ],
                    "Resource": [
                        f"arn:aws:iam::{account_id}:user/{LAB_USER_1_NAME}",
                        f"arn:aws:iam::{account_id}:user/{LAB_USER_2_NAME}",
                    ],
                },
                {
                    # DeactivateMFADevice also checks the MFA device ARN as a resource
                    "Sid": "T1531MFAScope",
                    "Effect": "Allow",
                    "Action": ["iam:DeactivateMFADevice"],
                    "Resource": f"arn:aws:iam::{account_id}:mfa/{LAB_USER_1_MFA_NAME}",
                },
                {
                    # DetachUserPolicy also checks the policy ARN as a resource
                    "Sid": "T1531PolicyScope",
                    "Effect": "Allow",
                    "Action": ["iam:DetachUserPolicy"],
                    "Resource": policy_arn,
                },
                {
                    # RemoveUserFromGroup is scoped to the group ARN
                    "Sid": "T1531GroupScope",
                    "Effect": "Allow",
                    "Action": ["iam:RemoveUserFromGroup"],
                    "Resource": f"arn:aws:iam::{account_id}:group/{LAB_GROUP_NAME}",
                },
            ],
        })
    ),
)

# ── Lab Victim Users ──────────────────────────────────────────────────────────
lab_user_1 = aws.iam.User(
    "lab-user-1",
    name=LAB_USER_1_NAME,
    force_destroy=True,
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

lab_user_2 = aws.iam.User(
    "lab-user-2",
    name=LAB_USER_2_NAME,
    force_destroy=True,
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

# ── Login Profiles ────────────────────────────────────────────────────────────
# pulumi-aws v7: no `password` arg; use password_length + password_reset_required.
# Throwaway password generated internally - not logged or exported.
aws.iam.UserLoginProfile(
    "lab-user-1-login",
    user=lab_user_1.name,
    password_length=20,
    password_reset_required=True,
)

aws.iam.UserLoginProfile(
    "lab-user-2-login",
    user=lab_user_2.name,
    password_length=20,
    password_reset_required=True,
)

# ── Access Keys ───────────────────────────────────────────────────────────────
# Export key IDs only (not secrets) so attack.py can reference targets.
lab_user_1_key = aws.iam.AccessKey(
    "lab-user-1-key",
    user=lab_user_1.name,
    status="Active",
)

lab_user_2_key = aws.iam.AccessKey(
    "lab-user-2-key",
    user=lab_user_2.name,
    status="Active",
)

# ── Virtual MFA Device for user-1 ────────────────────────────────────────────
# Pulumi creates the device object; activation requires a live TOTP code and
# must be completed manually before the attack phase. The attack script
# calls iam:ListMFADevices and skips DeactivateMFADevice when not activated.
lab_user_1_mfa = aws.iam.VirtualMfaDevice(
    "lab-user-1-mfa",
    virtual_mfa_device_name=LAB_USER_1_MFA_NAME,
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

# ── Group Memberships ─────────────────────────────────────────────────────────
aws.iam.UserGroupMembership(
    "lab-user-1-membership",
    user=lab_user_1.name,
    groups=[lab_group.name],
)

aws.iam.UserGroupMembership(
    "lab-user-2-membership",
    user=lab_user_2.name,
    groups=[lab_group.name],
)

# ── Policy Attachments ────────────────────────────────────────────────────────
aws.iam.UserPolicyAttachment(
    "lab-user-1-policy-attach",
    user=lab_user_1.name,
    policy_arn=lab_policy.arn,
)

aws.iam.UserPolicyAttachment(
    "lab-user-2-policy-attach",
    user=lab_user_2.name,
    policy_arn=lab_policy.arn,
)

# ── Stack Exports (attack.py reads these via pulumi stack output) ─────────────
pulumi.export("attacker_role_arn",        attacker_role.arn)
pulumi.export("lab_user_1_arn",           lab_user_1.arn)
pulumi.export("lab_user_2_arn",           lab_user_2.arn)
pulumi.export("lab_user_1_access_key_id", lab_user_1_key.id)
pulumi.export("lab_user_2_access_key_id", lab_user_2_key.id)
pulumi.export("lab_user_1_mfa_serial",    lab_user_1_mfa.arn)
pulumi.export("lab_policy_arn",           lab_policy.arn)
pulumi.export("log_bucket_name",          log_bucket.id)
