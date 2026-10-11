# FILE: __main__.py
import json
import pathlib
import sys

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import pulumi
import pulumi_aws as aws

# ============================================================
# Load resource names - single source of truth
# ============================================================
_NAMES = {'campaign': 'ATOMIC-SES-SEND-ABUSE',
 'csp': 'aws',
 'resources': {'attacker_role_name': 'atomic-ses-send-abuse-attacker-role',
               'ses_policy_name': 'atomic-ses-send-abuse-ses-policy',
               'email_identity': 'noreply@lab.example.com',
               'config_set_name': 'atomic-ses-send-abuse-config-set',
               'victim_secret_name': 'prod/marketing/ses-sending-credentials'},
 'pulumi_export_keys': {'attacker_role_name': 'attacker_role_name',
                        'attacker_role_arn': 'attacker_role_arn',
                        'ses_policy_arn': 'ses_policy_arn',
                        'email_identity_name': 'email_identity_name',
                        'email_identity_arn': 'email_identity_arn',
                        'config_set_name': 'config_set_name',
                        'campaigns_bucket_name': 'campaigns_bucket_name',
                        'victim_secret_name': 'victim_secret_name',
                        'victim_secret_arn': 'victim_secret_arn',
                        'ses_events_topic_arn': 'ses_events_topic_arn',
                        'ses_log_group_name': 'ses_log_group_name'}}
_R = _NAMES["resources"]

# === Resource Name Constants ===
ATTACKER_ROLE_NAME = _R["attacker_role_name"]
SES_POLICY_NAME    = _R["ses_policy_name"]
EMAIL_IDENTITY     = _R["email_identity"]
CONFIG_SET_NAME    = _R["config_set_name"]
VICTIM_SECRET_NAME = _R["victim_secret_name"]

# Common tags (ASCII only)
TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-ses-send-abuse",
    "Technique":   "T1496.004",
}

# AWS identity - synchronous calls, result is a plain string
caller     = aws.get_caller_identity()
account_id = caller.account_id
region     = aws.get_region().id

# Export static name constants so attack.py can resolve them from stack outputs
pulumi.export("attacker_role_name",  ATTACKER_ROLE_NAME)
pulumi.export("email_identity_name", EMAIL_IDENTITY)
pulumi.export("config_set_name",     CONFIG_SET_NAME)
pulumi.export("victim_secret_name",  VICTIM_SECRET_NAME)

# ============================================================
# 1. SES IAM Policy
#    - ForAllValues:StringLike on ses:Recipients restricts every
#      recipient to the AWS mailbox simulator (multi-recipient safe)
#    - Explicit Deny on production-access escalation (deny-guard)
# ============================================================
ses_policy = aws.iam.Policy(
    "ses-policy",
    name=SES_POLICY_NAME,
    description="SES send restricted to simulator recipients - deny-guard on account escalation",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SESAbuseSimulatorSendOnly",
                "Effect": "Allow",
                "Action": [
                    "ses:SendEmail",
                    "ses:SendRawEmail",
                    "ses:SendBulkEmail",
                    "ses:GetSendQuota",
                    "ses:GetAccountSendingEnabled",
                    "ses:GetSendStatistics",
                    "ses:ListIdentities",
                    "ses:GetIdentityVerificationAttributes",
                ],
                "Resource": "*",
                "Condition": {
                    "ForAllValues:StringLike": {
                        "ses:Recipients": "*@simulator.amazonses.com"
                    }
                },
            },
            {
                "Sid": "DenyProductionAccessEscalation",
                "Effect": "Deny",
                "Action": [
                    "ses:PutAccountDetails",
                    "ses:PutAccountSendingEnabled",
                    "ses:PutAccountSuppressionAttributes",
                    "ses:DeleteSuppressedDestination",
                ],
                "Resource": "*",
            },
        ],
    }),
    tags=TAGS,
)

pulumi.export("ses_policy_arn", ses_policy.arn)

# ============================================================
# 2. SES Configuration Set + Event Destination
#    CloudWatch log group created for reference; SNS topic used
#    as the SES v2 event destination (native support)
# ============================================================
config_set = aws.sesv2.ConfigurationSet(
    "config-set",
    configuration_set_name=CONFIG_SET_NAME,
    tags=TAGS,
)

ses_log_group = aws.cloudwatch.LogGroup(
    "ses-log-group",
    name=f"/aws/ses/{CONFIG_SET_NAME}",
    retention_in_days=7,
    tags=TAGS,
)

ses_events_topic = aws.sns.Topic(
    "ses-events-topic",
    name="atomic-ses-send-abuse-events",
    tags=TAGS,
)

aws.sesv2.ConfigurationSetEventDestination(
    "ses-event-dest",
    configuration_set_name=config_set.configuration_set_name,
    event_destination_name="ses-events-sns",
    event_destination=aws.sesv2.ConfigurationSetEventDestinationEventDestinationArgs(
        enabled=True,
        matching_event_types=["SEND", "DELIVERY", "BOUNCE", "COMPLAINT", "OPEN", "CLICK"],
        sns_destination=aws.sesv2.ConfigurationSetEventDestinationEventDestinationSnsDestinationArgs(
            topic_arn=ses_events_topic.arn,
        ),
    ),
    opts=pulumi.ResourceOptions(depends_on=[config_set, ses_events_topic]),
)

pulumi.export("ses_events_topic_arn", ses_events_topic.arn)
pulumi.export("ses_log_group_name",   ses_log_group.name)

# ============================================================
# 3. SES Email Identity
#    noreply@lab.example.com - example.com is IANA-reserved so
#    this identity is permanently unverified; delivery fails at
#    SES authorization even if the IAM condition were bypassed
# ============================================================
aws.sesv2.EmailIdentity(
    "email-identity",
    email_identity=EMAIL_IDENTITY,
    tags=TAGS,
)

# ARN constructed from static values - all are plain strings here
pulumi.export(
    "email_identity_arn",
    f"arn:aws:ses:{region}:{account_id}:identity/{EMAIL_IDENTITY}",
)

# ============================================================
# 4. S3 Bait Bucket - {account_id}-ses-abuse-email-campaigns
#    Seeded with realistic marketing templates + canary config
# ============================================================
campaigns_bucket = aws.s3.BucketV2(
    "campaigns-bucket",
    bucket=f"{account_id}-ses-abuse-email-campaigns",
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "campaigns-bucket-pab",
    bucket=campaigns_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
    opts=pulumi.ResourceOptions(depends_on=[campaigns_bucket]),
)

_PROMO_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Exclusive Offer Inside</title></head>
<body>
<h1>Special Promotional Offer</h1>
<p>Dear Valued Customer,</p>
<p>We have an exclusive discount ready for you on your next purchase.</p>
<p>Use code <strong>PROMO2026</strong> at checkout for 20 percent off.</p>
<p>This offer expires in 48 hours - act now!</p>
<p>Best regards,<br>Marketing Team</p>
</body>
</html>"""

# All simulator addresses - safe, no real recipients
_RECIPIENT_CSV = """\
email,first_name,last_name,segment
success@simulator.amazonses.com,Alice,Smith,premium
bounce@simulator.amazonses.com,Bob,Jones,standard
complaint@simulator.amazonses.com,Carol,Williams,inactive
success@simulator.amazonses.com,David,Brown,premium
success@simulator.amazonses.com,Eva,Davis,standard
bounce@simulator.amazonses.com,Frank,Miller,inactive
success@simulator.amazonses.com,Grace,Wilson,premium
success@simulator.amazonses.com,Henry,Moore,standard
success@simulator.amazonses.com,Iris,Taylor,premium
success@simulator.amazonses.com,James,Anderson,standard"""

# Canary placeholder access_key_id - AKIACANARY000000FAKE triggers honeypot alerting
_SENDER_CONFIG = json.dumps({
    "from_address":      EMAIL_IDENTITY,
    "configuration_set": CONFIG_SET_NAME,
    "access_key_id":     "AKIACANARY000000FAKE",
    "region":            "us-east-1",
    "note":              "SES bulk sending configuration for marketing campaigns",
})

aws.s3.BucketObjectv2(
    "promo-blast",
    bucket=campaigns_bucket.id,
    key="templates/promo_blast.html",
    content=_PROMO_HTML,
    content_type="text/html",
    opts=pulumi.ResourceOptions(depends_on=[campaigns_bucket]),
)

aws.s3.BucketObjectv2(
    "recipient-list",
    bucket=campaigns_bucket.id,
    key="data/recipient_list.csv",
    content=_RECIPIENT_CSV,
    content_type="text/csv",
    opts=pulumi.ResourceOptions(depends_on=[campaigns_bucket]),
)

aws.s3.BucketObjectv2(
    "sender-config",
    bucket=campaigns_bucket.id,
    key="config/ses_sender_config.json",
    content=_SENDER_CONFIG,
    content_type="application/json",
    opts=pulumi.ResourceOptions(depends_on=[campaigns_bucket]),
)

pulumi.export("campaigns_bucket_name", campaigns_bucket.bucket)

# ============================================================
# 5. IAM Attacker Role
#    Self-trust using current account - never a placeholder ID.
#    Lateral movement is out of scope: no iam:PassRole or
#    downstream sts:AssumeRole grants.
# ============================================================
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
    description="Seeded IAM role representing compromised victim credentials for SES abuse emulation",
    tags=TAGS,
)

pulumi.export("attacker_role_arn", attacker_role.arn)

# ============================================================
# 6. Attach SES Policy to Attacker Role
# ============================================================
aws.iam.RolePolicyAttachment(
    "role-policy-attachment",
    role=attacker_role.name,
    policy_arn=ses_policy.arn,
    opts=pulumi.ResourceOptions(depends_on=[attacker_role, ses_policy]),
)

# ============================================================
# 7. SecretsManager Bait Secret
#    prod/marketing/ses-sending-credentials - contains role ARN
#    only (no long-term access keys). recovery_window_in_days=0
#    so re-runs after pulumi destroy can recreate immediately.
# ============================================================
victim_secret = aws.secretsmanager.Secret(
    "victim-secret",
    name=VICTIM_SECRET_NAME,
    description="SES bulk sending role for marketing campaigns - platform-marketing-eng",
    recovery_window_in_days=0,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[attacker_role]),
)

aws.secretsmanager.SecretVersion(
    "victim-secret-version",
    secret_id=victim_secret.id,
    secret_string=attacker_role.arn.apply(
        lambda arn: json.dumps({
            "role_arn":    arn,
            "region":      "us-east-1",
            "description": "SES bulk sending role for marketing campaigns",
            "owner":       "platform-marketing-eng",
        })
    ),
    opts=pulumi.ResourceOptions(depends_on=[victim_secret, attacker_role]),
)

pulumi.export("victim_secret_arn", victim_secret.arn)
