"""
DangerDev Adversary Emulation Lab — Pulumi Infrastructure
Provisions all attack surface, bait, target, and support resources.
Auto-triggers attack.py with credential outputs after stack is ready.
"""
import json
import os
import subprocess

import pulumi
import pulumi_aws as aws
import pulumi_tls as tls

# ============================================================
# Config and account context
# ============================================================
config = pulumi.Config()
adversary_account_id = config.get("adversaryAccountId") or "111111111111"
ses_email = config.get("sesEmail") or "noreply@emulation-lab.internal"
lab_operator_email = config.get("labOperatorEmail") or "security-team@example.com"

identity = aws.get_caller_identity()
account_id = identity.account_id
region = aws.get_region().name

TAGS = {
    "MayaTrail": "true",
    "Purpose": "adversary-emulation",
    "ThreatActor": "DangerDev",
    "EmulationPhase": "lab",
    "Owner": "security-team",
    "AutoDestroy": "true",
}

# ============================================================
# 1. dangerdev-log-bucket — central sink for all lab telemetry
# ============================================================
log_bucket = aws.s3.Bucket(
    "dangerdev-log-bucket",
    bucket=f"dangerdev-lab-logs-{account_id}",
    force_destroy=True,
    server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
        rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="aws:kms",
            ),
        ),
    ),
    versioning=aws.s3.BucketVersioningArgs(enabled=True),
    lifecycle_rules=[
        aws.s3.BucketLifecycleRuleArgs(
            enabled=True,
            expiration=aws.s3.BucketLifecycleRuleExpirationArgs(days=90),
        )
    ],
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "dangerdev-log-bucket-pab",
    bucket=log_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketPolicy(
    "dangerdev-log-bucket-policy",
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
                    "Resource": f"{arn}/cloudtrail/AWSLogs/{account_id}/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
                {
                    "Sid": "AWSGuardDutyGetBucketLocation",
                    "Effect": "Allow",
                    "Principal": {"Service": "guardduty.amazonaws.com"},
                    "Action": "s3:GetBucketLocation",
                    "Resource": arn,
                    "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
                },
                {
                    "Sid": "AWSGuardDutyWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "guardduty.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"{arn}/AWSLogs/{account_id}/GuardDuty/*",
                    "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
                },
                {
                    "Sid": "VPCFlowLogsAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "delivery.logs.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": arn,
                },
                {
                    "Sid": "VPCFlowLogsWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "delivery.logs.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"{arn}/flow-logs/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
                {
                    "Sid": "S3AccessLogging",
                    "Effect": "Allow",
                    "Principal": {"Service": "logging.s3.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"{arn}/s3-access/*",
                    "Condition": {
                        "ArnLike": {"aws:SourceArn": f"arn:aws:s3:::dangerdev-*-{account_id}"}
                    },
                },
            ],
        })
    ),
)

# ============================================================
# 2. dangerdev-sandbox-vpc — isolated VPC with flow logs
# ============================================================
vpc = aws.ec2.Vpc(
    "dangerdev-sandbox-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": "dangerdev-sandbox-vpc"},
)

aws.ec2.FlowLog(
    "dangerdev-vpc-flow-log",
    vpc_id=vpc.id,
    traffic_type="ALL",
    log_destination_type="s3",
    log_destination=log_bucket.arn.apply(lambda arn: f"{arn}/flow-logs/"),
    tags=TAGS,
)

# ============================================================
# 3. dangerdev-internet-gateway + public route table
# ============================================================
igw = aws.ec2.InternetGateway(
    "dangerdev-internet-gateway",
    vpc_id=vpc.id,
    tags={**TAGS, "Name": "dangerdev-internet-gateway"},
)

public_rt = aws.ec2.RouteTable(
    "dangerdev-public-rt",
    vpc_id=vpc.id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            gateway_id=igw.id,
        )
    ],
    tags={**TAGS, "Name": "dangerdev-public-rt"},
)

# ============================================================
# 4. dangerdev-public-subnet
# ============================================================
public_subnet = aws.ec2.Subnet(
    "dangerdev-public-subnet",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone="us-east-1a",
    map_public_ip_on_launch=True,
    tags={**TAGS, "Name": "dangerdev-public-subnet"},
)

aws.ec2.RouteTableAssociation(
    "dangerdev-public-subnet-rta",
    subnet_id=public_subnet.id,
    route_table_id=public_rt.id,
)

# ============================================================
# 5. dangerdev-open-sg — RDP+SSH open to 0.0.0.0/0 (T1021.001 surface)
# ============================================================
open_sg = aws.ec2.SecurityGroup(
    "dangerdev-open-sg",
    name="dangerdev-open-sg",
    description="Lab attack surface: RDP/SSH open to 0.0.0.0/0 (T1021.001, T1578.002)",
    vpc_id=vpc.id,
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            from_port=3389,
            to_port=3389,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
            description="RDP open to 0.0.0.0/0 - T1021.001 attack surface",
        ),
        aws.ec2.SecurityGroupIngressArgs(
            from_port=22,
            to_port=22,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
            description="SSH open to 0.0.0.0/0 - T1021.001 attack surface",
        ),
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            from_port=0,
            to_port=0,
            protocol="-1",
            cidr_blocks=["0.0.0.0/0"],
            description="All outbound - simulated mining pool traffic in flow logs",
        )
    ],
    tags={**TAGS, "Name": "dangerdev-open-sg"},
)

# ============================================================
# 6. dangerdev-ec2-keypair — RSA key generated and imported
# ============================================================
lab_private_key = tls.PrivateKey(
    "dangerdev-lab-private-key",
    algorithm="RSA",
    rsa_bits=4096,
)

ec2_keypair = aws.ec2.KeyPair(
    "dangerdev-ec2-keypair",
    key_name="dangerdev-lab-key",
    public_key=lab_private_key.public_key_openssh,
    tags=TAGS,
)

# ============================================================
# 7. dangerdev-ssm-instance-role — minimal SSM-only host access
# ============================================================
ssm_role = aws.iam.Role(
    "dangerdev-ssm-instance-role",
    name="dangerdev-ssm-instance-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    "dangerdev-ssm-instance-role-policy",
    role=ssm_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
)

# ============================================================
# 8. dangerdev-ec2-instance-profile
# ============================================================
ec2_instance_profile = aws.iam.InstanceProfile(
    "dangerdev-ec2-instance-profile",
    name="dangerdev-ec2-instance-profile",
    role=ssm_role.name,
    tags=TAGS,
)

# ============================================================
# 9. dangerdev-exposed-admin-user — T1078.004 initial access vector
#    AdministratorAccess, key-only, no MFA, no console login
# ============================================================
admin_user = aws.iam.User(
    "dangerdev-exposed-admin-user",
    name="lab-infra-admin",
    tags=TAGS,
)

aws.iam.UserPolicyAttachment(
    "dangerdev-exposed-admin-user-policy",
    user=admin_user.name,
    policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
)

admin_access_key = aws.iam.AccessKey(
    "dangerdev-exposed-admin-access-key",
    user=admin_user.name,
)

# ============================================================
# 10. dangerdev-leaked-creds-bucket — bait tfstate with embedded creds
# ============================================================
leaked_creds_bucket = aws.s3.Bucket(
    "dangerdev-leaked-creds-bucket",
    bucket=f"dangerdev-infra-state-{account_id}",
    force_destroy=True,
    versioning=aws.s3.BucketVersioningArgs(enabled=True),
    logging=aws.s3.BucketLoggingArgs(
        target_bucket=log_bucket.id,
        target_prefix="s3-access/",
    ),
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "dangerdev-leaked-creds-bucket-pab",
    bucket=leaked_creds_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)


def _build_tfstate(key_id: str, secret: str) -> str:
    """Construct a realistic terraform.tfstate JSON with real lab credentials embedded."""
    return json.dumps(
        {
            "version": 4,
            "terraform_version": "1.6.0",
            "serial": 12,
            "lineage": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "outputs": {},
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_iam_user",
                    "name": "lab_admin",
                    "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                    "instances": [
                        {
                            "schema_version": 0,
                            "attributes": {
                                "arn": f"arn:aws:iam::{account_id}:user/lab-infra-admin",
                                "force_destroy": False,
                                "id": "lab-infra-admin",
                                "name": "lab-infra-admin",
                                "path": "/",
                                "permissions_boundary": None,
                                "tags": {"Environment": "prod"},
                                "unique_id": "AIDA000000000000000AB",
                            },
                        }
                    ],
                },
                {
                    "mode": "managed",
                    "type": "aws_iam_access_key",
                    "name": "lab_admin",
                    "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                    "instances": [
                        {
                            "schema_version": 0,
                            "attributes": {
                                "create_date": "2024-01-15T09:23:11Z",
                                "encrypted_secret": None,
                                "id": key_id,
                                "key_fingerprint": None,
                                "pgp_key": None,
                                "secret": secret,
                                "ses_smtp_password_v4": None,
                                "status": "Active",
                                "user": "lab-infra-admin",
                            },
                        }
                    ],
                },
            ],
        },
        indent=2,
    )


tfstate_content = pulumi.Output.all(
    admin_access_key.id,
    admin_access_key.secret,
).apply(lambda args: _build_tfstate(args[0], args[1]))

aws.s3.BucketObject(
    "dangerdev-tfstate-object",
    bucket=leaked_creds_bucket.id,
    key="infra/prod/terraform.tfstate",
    content=tfstate_content,
    content_type="application/json",
)

# ============================================================
# 11. dangerdev-decoy-user-alice — T1087.004 discovery target,
#     T1098 account manipulation target (second key + password reset)
# ============================================================
alice_user = aws.iam.User(
    "dangerdev-decoy-user-alice",
    name="alice.chen",
    tags=TAGS,
)

aws.iam.UserPolicyAttachment(
    "dangerdev-alice-policy",
    user=alice_user.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
)

aws.iam.UserPolicyAttachment(
    "dangerdev-alice-ses-policy",
    user=alice_user.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSESFullAccess",
)

aws.iam.UserLoginProfile(
    "dangerdev-alice-login-profile",
    user=alice_user.name,
    password_reset_required=False,
)

alice_access_key = aws.iam.AccessKey(
    "dangerdev-alice-access-key",
    user=alice_user.name,
)

# ============================================================
# 12. dangerdev-decoy-user-ops + ses-smtp-user masquerade decoy
#     Populates ListUsers to inform DangerDev's 'ses' username choice (T1036.005)
# ============================================================
ops_user = aws.iam.User(
    "dangerdev-decoy-user-ops",
    name="ops-automation",
    tags=TAGS,
)

aws.iam.UserPolicyAttachment(
    "dangerdev-ops-policy",
    user=ops_user.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
)

aws.iam.AccessKey(
    "dangerdev-ops-access-key",
    user=ops_user.name,
)

# SES auto-generated SMTP credential username pattern DangerDev's 'ses' account mimics
ses_smtp_decoy = aws.iam.User(
    "dangerdev-ses-smtp-decoy",
    name="ses-smtp-user.20231105-091212",
    tags=TAGS,
)

aws.iam.AccessKey(
    "dangerdev-ses-smtp-decoy-key",
    user=ses_smtp_decoy.name,
)

# ============================================================
# 13. dangerdev-honey-iam-user — canary credential (T1087.004)
#     Any API call using this key fires an EventBridge → SNS alert
# ============================================================
honey_user = aws.iam.User(
    "dangerdev-honey-iam-user",
    name="backup-restore-svc",
    tags=TAGS,
)

honey_access_key = aws.iam.AccessKey(
    "dangerdev-honey-access-key",
    user=honey_user.name,
)

honey_alert_topic = aws.sns.Topic(
    "dangerdev-honey-alert-topic",
    name="dangerdev-honey-user-alert",
    tags=TAGS,
)

aws.sns.TopicPolicy(
    "dangerdev-honey-alert-topic-policy",
    arn=honey_alert_topic.arn,
    policy=honey_alert_topic.arn.apply(
        lambda topic_arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
                "Condition": {
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:events:{region}:{account_id}:rule/dangerdev-*"
                    }
                },
            }],
        })
    ),
)

honey_event_rule = aws.cloudwatch.EventRule(
    "dangerdev-honey-event-rule",
    name="dangerdev-honey-iam-user-access",
    description="CANARY: fires on any API call made using backup-restore-svc credentials",
    event_pattern=json.dumps({
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "userIdentity": {
                "userName": ["backup-restore-svc"]
            }
        },
    }),
    tags=TAGS,
)

aws.cloudwatch.EventTarget(
    "dangerdev-honey-event-target",
    rule=honey_event_rule.name,
    arn=honey_alert_topic.arn,
)

# ============================================================
# 14. dangerdev-ses-email-identity — T1526 discovery + T1566.002 logging
#     SES sandbox mode: CloudTrail logs SendEmail but zero external delivery
# ============================================================
ses_identity = aws.ses.EmailIdentity(
    "dangerdev-ses-email-identity",
    email=ses_email,
)

# ============================================================
# 15. dangerdev-cross-account-backdoor-role — T1199 + T1036.005
#     AWSeservedSSO_AdminAccess: one-char typosquat of AWSReservedSSO_*
# ============================================================
backdoor_role_1 = aws.iam.Role(
    "dangerdev-cross-account-backdoor-role",
    name="AWSeservedSSO_AdminAccess",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{adversary_account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    "dangerdev-cross-account-backdoor-role-policy",
    role=backdoor_role_1.name,
    policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
)

# ============================================================
# 16. dangerdev-configrecorder-backdoor-role — T1199 + T1036.005
#     Mimics legitimate AWS Config service role naming in Organizations landing zones
# ============================================================
backdoor_role_2 = aws.iam.Role(
    "dangerdev-configrecorder-backdoor-role",
    name="AWSLanding-Zones-ConfigRecorderRoles",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{adversary_account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    "dangerdev-configrecorder-backdoor-role-policy",
    role=backdoor_role_2.name,
    policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
)

# ============================================================
# 17. dangerdev-sensitive-s3-bucket — T1530 collection target
#     Realistic objects; CloudTrail data events enabled
# ============================================================
sensitive_bucket = aws.s3.Bucket(
    "dangerdev-sensitive-s3-bucket",
    bucket=f"dangerdev-prod-data-archive-{account_id}",
    force_destroy=True,
    versioning=aws.s3.BucketVersioningArgs(enabled=True),
    server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
        rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256",
            ),
        ),
    ),
    logging=aws.s3.BucketLoggingArgs(
        target_bucket=log_bucket.id,
        target_prefix="s3-access/",
    ),
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "dangerdev-sensitive-bucket-pab",
    bucket=sensitive_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

_bait_objects = {
    "customers-export": (
        "customers/export_2024_q4.csv",
        "id,name,email,revenue\n1,Acme Corp,billing@acme.com,142000\n2,Globex,ar@globex.com,98500\n",
        "text/csv",
    ),
    "backups-db-dump": (
        "backups/db_dump_prod.sql.gz",
        "-- DangerDev Lab placeholder SQL dump\n-- NOT real data\n",
        "application/gzip",
    ),
    "reports-financial": (
        "reports/financial_summary_2024.xlsx",
        "placeholder-xlsx-content",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
}

for resource_name, (obj_key, obj_content, content_type) in _bait_objects.items():
    aws.s3.BucketObject(
        f"dangerdev-sensitive-obj-{resource_name}",
        bucket=sensitive_bucket.id,
        key=obj_key,
        content=obj_content,
        content_type=content_type,
    )

# ============================================================
# 18. dangerdev-secretsmanager-secret — T1518.001 SimulatePrincipalPolicy target
#     Deny GetSecretValue to everyone except lab-operator role
# ============================================================
db_secret = aws.secretsmanager.Secret(
    "dangerdev-secretsmanager-secret",
    name="prod/database/master_credentials",
    recovery_window_in_days=0,
    tags=TAGS,
)

aws.secretsmanager.SecretVersion(
    "dangerdev-secretsmanager-secret-version",
    secret_id=db_secret.id,
    secret_string=json.dumps({
        "username": "admin",
        "password": "Sup3rS3cr3t!",
        "host": "prod-mysql.us-east-1.rds.amazonaws.com",
        "port": 3306,
    }),
)

# SecretPolicy removed — attack.py uses SimulatePrincipalPolicy only,
# never calls GetSecretValue. Deny policy blocks Pulumi state refresh.

# ============================================================
# 19. dangerdev-guardduty-detector — T1518.001 detection target
#     Findings exported to log bucket; no suppression rules
# ============================================================
guardduty_detector = aws.guardduty.Detector(
    "dangerdev-guardduty-detector",
    enable=True,
    finding_publishing_frequency="FIFTEEN_MINUTES",
    datasources=aws.guardduty.DetectorDatasourcesArgs(
        s3_logs=aws.guardduty.DetectorDatasourcesS3LogsArgs(enable=True),
    ),
    tags=TAGS,
)

gd_kms_key = aws.kms.Key(
    "dangerdev-guardduty-kms-key",
    description="KMS key for GuardDuty findings S3 export - lab use only",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowGuardDutyEncrypt",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": ["kms:GenerateDataKey", "kms:Encrypt"],
                "Resource": "*",
            },
        ],
    }),
    tags=TAGS,
)

# GuardDuty S3 export skipped — KMS cross-service permission requires
# manual bucket policy propagation; detector itself is active for findings.
# aws.guardduty.PublishingDestination(
#     "dangerdev-guardduty-publishing-dest",
#     detector_id=guardduty_detector.id,
#     destination_type="S3",
#     destination_arn=log_bucket.arn,
#     kms_key_arn=gd_kms_key.arn,
# )

# ============================================================
# 20. dangerdev-ec2-windows-instance — T1578.002 + T1021.001 + T1496
#     t2.micro, Windows Server 2022, RDP enabled, IMDSv1, public IP
# ============================================================
windows_ami = aws.ec2.get_ami(
    most_recent=True,
    owners=["amazon"],
    filters=[
        aws.ec2.GetAmiFilterArgs(
            name="name",
            values=["Windows_Server-2022-English-Full-Base-*"],
        ),
        aws.ec2.GetAmiFilterArgs(name="state", values=["available"]),
    ],
)

# UserData: PowerShell — no Clear-History equivalent to set -e, use Clear-History per stage
_windows_userdata = """<powershell>
# [EMULATED] T1578.002: Enable RDP at the Windows OS level
# Matches the open security group (port 3389/0.0.0.0/0); without this Windows Firewall blocks inbound RDP
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
netsh advfirewall firewall set rule group='remote desktop' new enable=yes
Clear-History

# [SIMULATED] T1496: Benign CPU-bound workload approximating GPU cryptomining lifecycle
# Runs for 5 minutes; produces CloudWatch CPU spike and VPC flow log outbound traffic patterns
# p3.16xlarge excluded per cannot_safely_emulate; t2.micro used for lifecycle testing only
$end = (Get-Date).AddMinutes(5)
while ((Get-Date) -lt $end) {
  [Math]::Sqrt([Math]::PI * (Get-Random -Minimum 1 -Maximum 1000000)) | Out-Null
}
Write-EventLog -LogName Application -Source 'Application' -EventId 9999 -Message 'T1496-simulation: benign CPU workload complete'
Clear-History
</powershell>"""

ec2_instance = aws.ec2.Instance(
    "dangerdev-ec2-windows-instance",
    ami=windows_ami.id,
    instance_type="t2.micro",
    subnet_id=public_subnet.id,
    vpc_security_group_ids=[open_sg.id],
    key_name=ec2_keypair.key_name,
    iam_instance_profile=ec2_instance_profile.name,
    associate_public_ip_address=True,
    user_data=_windows_userdata,
    metadata_options=aws.ec2.InstanceMetadataOptionsArgs(
        http_endpoint="enabled",
        http_tokens="optional",  # IMDSv1 — mirrors DangerDev's default VPC behavior
    ),
    tags={**TAGS, "Name": "dangerdev-ec2-windows-instance"},
    volume_tags=TAGS,
)

# ============================================================
# 21. dangerdev-cloudtrail — multi-region trail, all management +
#     S3 data events on sensitive and leaked-creds buckets
# ============================================================
ct_log_group = aws.cloudwatch.LogGroup(
    "dangerdev-cloudtrail-log-group",
    name="/aws/cloudtrail/dangerdev",
    retention_in_days=90,
    tags=TAGS,
)

ct_cw_role = aws.iam.Role(
    "dangerdev-cloudtrail-cw-role",
    name="dangerdev-cloudtrail-cw-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicy(
    "dangerdev-cloudtrail-cw-role-policy",
    role=ct_cw_role.id,
    policy=ct_log_group.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": f"{arn}:*",
            }],
        })
    ),
)

cloudtrail = aws.cloudtrail.Trail(
    "dangerdev-cloudtrail",
    name="dangerdev-emulation-trail",
    s3_bucket_name=log_bucket.id,
    s3_key_prefix="cloudtrail",
    is_multi_region_trail=True,
    include_global_service_events=True,
    enable_log_file_validation=True,
    cloud_watch_logs_group_arn=ct_log_group.arn.apply(lambda arn: f"{arn}:*"),
    cloud_watch_logs_role_arn=ct_cw_role.arn,
    event_selectors=[
        aws.cloudtrail.TrailEventSelectorArgs(
            read_write_type="All",
            include_management_events=True,
            data_resources=[
                aws.cloudtrail.TrailEventSelectorDataResourceArgs(
                    type="AWS::S3::Object",
                    values=[
                        sensitive_bucket.arn.apply(lambda arn: f"{arn}/"),
                        leaked_creds_bucket.arn.apply(lambda arn: f"{arn}/"),
                    ],
                ),
            ],
        ),
    ],
    tags=TAGS,
)

# ============================================================
# Auto-trigger: launch attack.py after all resources are ready
# ============================================================
def _trigger_attack(
    leaked_key_id: str,
    leaked_secret: str,
    instance_public_ip: str,
    gd_detector_id: str,
    sensitive_bucket_name: str,
    leaked_creds_bucket_name: str,
    alice_key_id: str,
    alice_key_secret: str,
) -> None:
    env = os.environ.copy()
    env["LEAKED_KEY_ID"] = leaked_key_id
    env["LEAKED_SECRET_KEY"] = leaked_secret
    env["TARGET_ACCOUNT_ID"] = account_id
    env["TARGET_REGION"] = region
    env["EC2_INSTANCE_IP"] = instance_public_ip or ""
    env["GUARDDUTY_DETECTOR_ID"] = gd_detector_id
    env["SENSITIVE_BUCKET"] = sensitive_bucket_name
    env["LEAKED_CREDS_BUCKET"] = leaked_creds_bucket_name
    env["ADVERSARY_ACCOUNT_ID"] = adversary_account_id
    env["SES_EMAIL_IDENTITY"] = ses_email
    env["ALICE_KEY_ID"] = alice_key_id
    env["ALICE_KEY_SECRET"] = alice_key_secret
    subprocess.Popen(
        ["python", "attack.py", account_id],
        env=env,
    )


# AUTO-TRIGGER DISABLED — run attack.py manually after `pulumi stack output`
# to supply LAB_OPERATOR_KEY_ID and inspect outputs before execution.
# Uncomment below to re-enable:
# pulumi.Output.all(
#     admin_access_key.id,
#     admin_access_key.secret,
#     ec2_instance.public_ip,
#     guardduty_detector.id,
#     sensitive_bucket.id,
#     leaked_creds_bucket.id,
#     alice_access_key.id,
#     alice_access_key.secret,
# ).apply(lambda args: _trigger_attack(*args))

# ============================================================
# Stack exports
# ============================================================
pulumi.export("log_bucket_name", log_bucket.id)
pulumi.export("vpc_id", vpc.id)
pulumi.export("ec2_instance_id", ec2_instance.id)
pulumi.export("ec2_public_ip", ec2_instance.public_ip)
pulumi.export("guardduty_detector_id", guardduty_detector.id)
pulumi.export("cloudtrail_arn", cloudtrail.arn)
pulumi.export("sensitive_bucket_name", sensitive_bucket.id)
pulumi.export("leaked_creds_bucket_name", leaked_creds_bucket.id)
pulumi.export("admin_user_name", admin_user.name)
pulumi.export("admin_access_key_id", admin_access_key.id)
pulumi.export("backdoor_role_1_arn", backdoor_role_1.arn)
pulumi.export("backdoor_role_2_arn", backdoor_role_2.arn)
pulumi.export("honey_alert_topic_arn", honey_alert_topic.arn)
pulumi.export("honey_access_key_id", honey_access_key.id)
# Secrets — encrypted in local state, shown only via `pulumi stack output --show-secrets`
pulumi.export("admin_access_key_secret", pulumi.Output.secret(admin_access_key.secret))
pulumi.export("alice_access_key_id",     alice_access_key.id)
pulumi.export("alice_access_key_secret", pulumi.Output.secret(alice_access_key.secret))
# lab_private_key_pem is a Pulumi secret — encrypted in state, never plaintext in CLI output
pulumi.export("lab_private_key_pem", pulumi.Output.secret(lab_private_key.private_key_pem))