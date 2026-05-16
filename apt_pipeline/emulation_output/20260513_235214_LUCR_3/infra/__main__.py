# FILE: __main__.py
# LUCR-3 adversary emulation infrastructure
# Threat actor: LUCR-3 (Scattered Spider affiliate)
# Platform: multi-cloud (AWS + Okta + Azure AD + GitHub)

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import os
import pathlib
import subprocess
import pulumi
import pulumi_aws as aws
import pulumi_okta as okta
import pulumi_azuread as azuread
import pulumi_github as github

# ============================================================
# Resource Name Constants (sourced from resource_names.json)
# ============================================================
_NAMES_FILE = pathlib.Path(__file__).parent / "resource_names.json"
_NAMES = json.loads(_NAMES_FILE.read_text()) if _NAMES_FILE.exists() else {"resources": {}, "pulumi_export_keys": {}}
_R = _NAMES.get("resources", {})

def _rn(key, default=""):
    """Return static resource name from resource_names.json, with inline default."""
    return _R.get(key, default)

TRAIL_NAME             = _rn("trail_name",            "lucr3-cloudtrail")
SAML_PROVIDER_NAME     = _rn("saml_provider_name",    "lucr3-okta-saml-idp")
FEDERATED_ROLE_NAME    = _rn("federated_role_name",   "lucr3-privileged-federated-role")
ATTACKER_USER_NAME     = _rn("attacker_iam_user",     "svc-automation-lucr3")
HONEY_USER_NAME        = _rn("honey_iam_user",        "svc-terraform-automation")
EC2_SSM_ROLE_NAME      = _rn("ec2_ssm_role_name",    "lucr3-ec2-ssm-role")
INSTANCE_PROFILE_NAME  = _rn("instance_profile_name", "lucr3-instance-profile")
ATTACKER_POLICY_NAME   = _rn("attacker_policy_name",  "lucr3-attacker-broad-policy")
DYNAMODB_TABLE_NAME    = _rn("dynamodb_table",        "lucr3-CustomerRecords")
GITHUB_REPO_NAME       = _rn("github_repo",           "lucr3-core-platform")
SECRET_PROD_DB_NAME    = _rn("secret_prod_db",        "prod/database/master_credentials")
SECRET_STRIPE_NAME     = _rn("secret_stripe",         "prod/payments/stripe_secret_key")
SECRET_HONEY_CREDS_NAME= _rn("secret_honey_creds",   "prod/infrastructure/terraform-automation-key")
SECRET_GITHUB_PAT_NAME = _rn("secret_github_pat",    "prod/cicd/github-actions-token")
VICTIM_USERNAME        = _rn("victim_okta_username",  "victim.employee@lab.internal")
VPC_NAME               = _rn("vpc_name",              "lucr3-sandbox-vpc")
SG_NAME                = _rn("sg_name",               "lucr3-sg-ec2")
SNS_TOPIC_NAME         = _rn("sns_topic_name",        "lucr3-canary-alerts")

# Export constants (attack.py reads these by name)
pulumi.export("trail_name", TRAIL_NAME)
pulumi.export("saml_provider_name", SAML_PROVIDER_NAME)
pulumi.export("federated_role_name", FEDERATED_ROLE_NAME)
pulumi.export("attacker_user_name", ATTACKER_USER_NAME)
pulumi.export("honey_user_name", HONEY_USER_NAME)
pulumi.export("dynamodb_table_name", DYNAMODB_TABLE_NAME)
pulumi.export("github_repo_name", GITHUB_REPO_NAME)
pulumi.export("victim_username", VICTIM_USERNAME)
pulumi.export("attacker_policy_name", ATTACKER_POLICY_NAME)

# ============================================================
# Account / Region / Config
# ============================================================
caller = aws.get_caller_identity()
account_id = caller.account_id
region_id = aws.get_region().id

config = pulumi.Config()
operator_cidr = config.get("operator_cidr") or "10.0.0.1"
okta_org_url = config.get("okta_org_url") or "https://lab.okta.com"
github_org = config.get("github_org") or "acme-lab"

# Okta SAML metadata XML for AWS IAM SAML provider
# Set via: pulumi config set okta_saml_metadata "$(cat okta-metadata.xml)"
# Obtain from: Okta Admin Console > Security > Identity Providers > Download metadata
saml_metadata_doc = config.get("okta_saml_metadata") or (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
    ' entityID="http://www.okta.com/LAB_ENTITY_ID_PLACEHOLDER">'
    '<md:IDPSSODescriptor WantAuthnRequestsSigned="false"'
    ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    '<ds:X509Data><ds:X509Certificate>'
    'MIIDpDCCAoygAwIBAgIGAVQGPyDPMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMjM0NTYxHTAbBgkqhkiG9w0BCQEWDmluZm9Ab2t0YS5jb20wHhcNMjUwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjCBkjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTIzNDU2MR0wGwYJKoZIhvcNAQkBFg5pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5RJbBN4N6kTFhQKuCmJSMHJRMSMMVnHLhCe9BU6OCH2yEGXHJTKCqzBdpBSFnBbEMFcyMXELqatMRGQBKYqNnKFBpAFEeGCnSSbLPBCRtBkCeYbDp3ht3VblwTkDmXtCMc6OA1YNJvPMPj4Y5Nv3AHPK0YAGblTq5XUagVP3vNkXjIQzAQIDAQABo1AwTjAdBgNVHQ4EFgQUQKNDuE7c/w7L2KQfXq5l5vXAlR0wHwYDVR0jBBgwFoAUQKNDuE7c/w7L2KQfXq5l5vXAlR0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARTUFq5FBJjCPLJYYS7mSBExnpAnkk3Nd6YhS7IhiOlTGjSxvDqh5jzECFaDe1U9jHp5w3Wa/IClX5k2AZJDhB7phlxXc2bLzSk3Gl6oM/4/Y5W5QIDAQAB'
    '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
    ' Location="https://lab.okta.com/app/amazon_aws/exkLABSAMLID/sso/saml"/>'
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
    ' Location="https://lab.okta.com/app/amazon_aws/exkLABSAMLID/sso/saml"/>'
    '</md:IDPSSODescriptor></md:EntityDescriptor>'
)

TAGS = {
    "MayaTrail": "true",
    "Purpose": "adversary-emulation",
    "ThreatActor": "LUCR-3",
    "Environment": "lab-isolated",
    "DataClassification": "synthetic-only",
}

# ============================================================
# SNS Topic for canary alerts
# ============================================================
canary_sns = aws.sns.Topic("lucr3-canary-sns",
    name=SNS_TOPIC_NAME,
    tags=TAGS,
)
pulumi.export("canary_sns_arn", canary_sns.arn)

# ============================================================
# 1. Log Bucket (CloudTrail + VPC flow logs)
# ============================================================
log_bucket_name = f"lucr3-logs-{account_id}"

log_bucket = aws.s3.Bucket("lucr3-log-bucket",
    bucket=log_bucket_name,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock("lucr3-log-bucket-pab",
    bucket=log_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketLifecycleConfigurationV2("lucr3-log-bucket-lifecycle",
    bucket=log_bucket.id,
    rules=[aws.s3.BucketLifecycleConfigurationV2RuleArgs(
        id="expire-logs",
        status="Enabled",
        expiration=aws.s3.BucketLifecycleConfigurationV2RuleExpirationArgs(days=30),
    )],
)

log_bucket_policy = aws.s3.BucketPolicy("lucr3-log-bucket-policy",
    bucket=log_bucket.id,
    policy=log_bucket.arn.apply(lambda arn: json.dumps({
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
    })),
)

pulumi.export("log_bucket_name", log_bucket_name)
pulumi.export("cloudtrail_bucket_name", log_bucket_name)

# ============================================================
# 2. VPC
# ============================================================
vpc = aws.ec2.Vpc("lucr3-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": VPC_NAME},
)

igw = aws.ec2.InternetGateway("lucr3-igw",
    vpc_id=vpc.id,
    tags={**TAGS, "Name": "lucr3-igw"},
)

route_table = aws.ec2.RouteTable("lucr3-rt",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(
        cidr_block="0.0.0.0/0",
        gateway_id=igw.id,
    )],
    tags={**TAGS, "Name": "lucr3-rt"},
)

# VPC flow log role
flow_log_role = aws.iam.Role("lucr3-flow-log-role",
    name="lucr3-flow-log-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicy("lucr3-flow-log-policy",
    role=flow_log_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
            ],
            "Resource": "*",
        }],
    }),
)

flow_log_group = aws.cloudwatch.LogGroup("lucr3-flow-log-group",
    name="/vpc/lucr3-flow-logs",
    retention_in_days=30,
    tags=TAGS,
)

aws.ec2.FlowLog("lucr3-vpc-flow-log",
    vpc_id=vpc.id,
    traffic_type="ALL",
    iam_role_arn=flow_log_role.arn,
    log_destination=flow_log_group.arn,
    tags=TAGS,
)

pulumi.export("vpc_id", vpc.id)

# ============================================================
# 3. Public Subnet
# ============================================================
subnet_pub = aws.ec2.Subnet("lucr3-subnet-pub",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone="us-east-1a",
    map_public_ip_on_launch=True,
    tags={**TAGS, "Name": "lucr3-subnet-pub"},
)

aws.ec2.RouteTableAssociation("lucr3-rt-assoc",
    subnet_id=subnet_pub.id,
    route_table_id=route_table.id,
)

pulumi.export("subnet_id", subnet_pub.id)

# ============================================================
# 4. EC2 Security Group
# ============================================================
sg_ec2 = aws.ec2.SecurityGroup("lucr3-sg-ec2",
    name=SG_NAME,
    vpc_id=vpc.id,
    description="EC2 security group for LUCR-3 lab target - SSH restricted to operator",
    ingress=[aws.ec2.SecurityGroupIngressArgs(
        from_port=22,
        to_port=22,
        protocol="tcp",
        cidr_blocks=[f"{operator_cidr}/32"],
        description="SSH from operator only",
    )],
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0,
        to_port=0,
        protocol="-1",
        cidr_blocks=["0.0.0.0/0"],
        description="All outbound for SSM and updates",
    )],
    tags={**TAGS, "Name": SG_NAME},
)

pulumi.export("ec2_sg_id", sg_ec2.id)

# ============================================================
# 5. Okta MFA Policy (SMS/OTP, no phishing-resistant)
# lucr3-okta-mfa-sms-policy
# ============================================================
okta_mfa_policy = okta.policy.MfaDefault("lucr3-okta-mfa-sms-policy",
    okta_password={"enroll": "REQUIRED"},
    okta_otp={"enroll": "REQUIRED"},
    okta_email={"enroll": "OPTIONAL"},
    okta_verify={"enroll": "OPTIONAL"},
    fido_webauthn={"enroll": "NOT_ALLOWED"},
    is_oie=False,
)

# ============================================================
# 6. Okta Victim User
# lucr3-okta-victim-user
# ============================================================
victim_password = config.get_secret("victim_password") or pulumi.Output.secret("LabP@ssw0rd2025!")

okta_victim_user = okta.user.User("lucr3-okta-victim-user",
    first_name="Alex",
    last_name="Employee",
    login=VICTIM_USERNAME,
    email=VICTIM_USERNAME,
    title="Cloud Infrastructure Engineer",
    department="Platform Engineering",
    organization="ACME Corp",
    password_inline_hook="",
)

pulumi.export("okta_victim_user_id", okta_victim_user.id)
pulumi.export("okta_org_url", okta_org_url)
pulumi.export("victim_username", VICTIM_USERNAME)

# NOTE: lucr3-okta-attacker-device (T1098.005) is provisioned via Okta API
# in the attack script (POST /api/v1/users/{userId}/factors), not as a
# declarative Pulumi resource. See emulation runbook for API call details.

# ============================================================
# 7. Azure AD SAML Application (Entra ID SP)
# lucr3-azuread-saml-app
# ============================================================
# Microsoft Graph API app ID (well-known)
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

azuread_app = azuread.Application("lucr3-azuread-saml-app",
    display_name="LUCR-3 Lab Corporate Portal (SAML SP)",
    sign_in_audience="AzureADMyOrg",
    required_resource_accesses=[
        azuread.ApplicationRequiredResourceAccessArgs(
            resource_app_id=MS_GRAPH_APP_ID,
            resource_accesses=[
                # Sites.Read.All - T1213.002
                azuread.ApplicationRequiredResourceAccessResourceAccessArgs(
                    id="332a536c-c7ef-4017-ab91-336970924f0d",
                    type="Role",
                ),
                # Mail.ReadWrite - T1070.008
                azuread.ApplicationRequiredResourceAccessResourceAccessArgs(
                    id="e2a3a72e-5f79-4c64-b1b1-878b674786c9",
                    type="Role",
                ),
                # Files.ReadWrite.All - T1530
                azuread.ApplicationRequiredResourceAccessResourceAccessArgs(
                    id="75359482-378d-4052-8f01-80520e7db3cd",
                    type="Role",
                ),
            ],
        ),
    ],
    web=azuread.ApplicationWebArgs(
        # Legacy auth left enabled to model real-world LUCR-3 target
        implicit_grant=azuread.ApplicationWebImplicitGrantArgs(
            access_token_issuance_enabled=True,
        ),
    ),
    tags=["lucr3-emulation", "lab-isolated", "synthetic-only"],
)

azuread_sp = azuread.ServicePrincipal("lucr3-azuread-sp",
    client_id=azuread_app.client_id,
)

pulumi.export("azuread_app_client_id", azuread_app.client_id)
pulumi.export("azuread_sp_id", azuread_sp.id)

# ============================================================
# 8. AWS IAM SAML Provider (Okta -> AWS federation bridge)
# lucr3-aws-saml-idp
# ============================================================
aws_saml_provider = aws.iam.SamlProvider("lucr3-aws-saml-idp",
    name=SAML_PROVIDER_NAME,
    saml_metadata_document=saml_metadata_doc,
    tags=TAGS,
)

pulumi.export("saml_provider_arn", aws_saml_provider.arn)

# ============================================================
# 9. IAM Instance Profile for EC2 (SSM only)
# lucr3-instance-profile
# ============================================================
ec2_ssm_role = aws.iam.Role("lucr3-ec2-ssm-role",
    name=EC2_SSM_ROLE_NAME,
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

aws.iam.RolePolicyAttachment("lucr3-ec2-ssm-managed-policy",
    role=ec2_ssm_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
)

instance_profile = aws.iam.InstanceProfile("lucr3-instance-profile",
    name=INSTANCE_PROFILE_NAME,
    role=ec2_ssm_role.name,
    tags=TAGS,
)

pulumi.export("instance_profile_name", INSTANCE_PROFILE_NAME)

# ============================================================
# 10. Attacker broad IAM policy
# lucr3-attacker-broad-policy
# ============================================================
attacker_broad_policy = aws.iam.Policy("lucr3-attacker-broad-policy",
    name=ATTACKER_POLICY_NAME,
    description="LUCR-3 emulation - over-permissioned policy replicating SAML federation blast radius",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "IAMManipulation",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateUser",
                    "iam:CreateAccessKey",
                    "iam:AttachUserPolicy",
                    "iam:PutUserPolicy",
                    "iam:ListUsers",
                    "iam:ListRoles",
                    "iam:GetUser",
                    "iam:ListAccessKeys",
                    "iam:ListAttachedRolePolicies",
                    "sts:AssumeRole",
                ],
                "Resource": "*",
            },
            {
                "Sid": "S3Exfil",
                "Effect": "Allow",
                "Action": [
                    "s3:ListAllMyBuckets",
                    "s3:ListBucket",
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:GetBucketLocation",
                    "s3:GetBucketPolicy",
                ],
                "Resource": "*",
            },
            {
                "Sid": "SecretsManagerScrape",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:ListSecrets",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                ],
                "Resource": "*",
            },
            {
                "Sid": "EC2Discovery",
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:DescribeImages",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeVpcs",
                    "ec2:RunInstances",
                    "ec2:CreateKeyPair",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DefenseImpairment",
                "Effect": "Allow",
                "Action": [
                    "cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail",
                    "cloudtrail:UpdateTrail",
                    "guardduty:DeleteDetector",
                    "guardduty:UpdateDetector",
                    "guardduty:ListDetectors",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DynamoDBExfil",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:Scan",
                    "dynamodb:Query",
                    "dynamodb:GetItem",
                    "dynamodb:ListTables",
                    "dynamodb:DescribeTable",
                ],
                "Resource": "*",
            },
            {
                "Sid": "CloudShellAccess",
                "Effect": "Allow",
                "Action": [
                    "cloudshell:CreateEnvironment",
                    "cloudshell:StartEnvironment",
                    "cloudshell:PutFiles",
                    "cloudshell:GetFiles",
                ],
                "Resource": "*",
            },
        ],
    }),
    tags=TAGS,
)

# ============================================================
# 11. Privileged Federated Role (Okta SAML -> AWS)
# lucr3-privileged-federated-role
# ============================================================
federated_role = aws.iam.Role("lucr3-privileged-federated-role",
    name=FEDERATED_ROLE_NAME,
    description="Over-privileged role assumable via Okta SAML federation - LUCR-3 emulation",
    max_session_duration=43200,
    assume_role_policy=aws_saml_provider.arn.apply(lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": arn},
            "Action": "sts:AssumeRoleWithSAML",
            "Condition": {
                "StringEquals": {
                    "SAML:aud": "https://signin.aws.amazon.com/saml",
                }
            },
        }],
    })),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment("lucr3-federated-role-policy",
    role=federated_role.name,
    policy_arn=attacker_broad_policy.arn,
)

pulumi.export("federated_role_arn", federated_role.arn)

# ============================================================
# 12. Attacker IAM User (backdoor, created by attack script)
# lucr3-attacker-iam-user (pre-provisioned for idempotency)
# ============================================================
attacker_iam_user = aws.iam.User("lucr3-attacker-iam-user",
    name=ATTACKER_USER_NAME,
    tags={**TAGS, "Description": "LUCR-3 emulation - backdoor service account"},
)

aws.iam.UserPolicyAttachment("lucr3-attacker-user-policy",
    user=attacker_iam_user.name,
    policy_arn=attacker_broad_policy.arn,
)

pulumi.export("attacker_iam_user_arn", attacker_iam_user.arn)

# ============================================================
# 13. Honey IAM User (canary - deny-all, triggers alert on use)
# lucr3-bait-honey-iam-user
# ============================================================
honey_user = aws.iam.User("lucr3-bait-honey-iam-user",
    name=HONEY_USER_NAME,
    tags={
        **TAGS,
        "Description": "Terraform automation service account",
        "Team": "Platform Engineering",
    },
)

# Deny-all policy on the honey user - access key valid but calls trigger detection
aws.iam.UserPolicy("lucr3-honey-user-deny-all",
    user=honey_user.name,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }],
    }),
)

# Access key for canary detection - stored in honey credentials secret below
honey_access_key = aws.iam.AccessKey("lucr3-honey-access-key",
    user=honey_user.name,
)

# EventBridge rule: any API call by honey user ARN -> SNS alert
honey_user_canary_rule = aws.cloudwatch.EventRule("lucr3-honey-user-canary-rule",
    name="lucr3-honey-user-canary",
    description="CANARY - alert when honey IAM user API call detected",
    event_pattern=honey_user.arn.apply(lambda arn: json.dumps({
        "source": ["aws.iam", "aws.s3", "aws.ec2", "aws.sts"],
        "detail": {
            "userIdentity": {
                "arn": [arn],
            },
        },
    })),
    tags=TAGS,
)

aws.cloudwatch.EventTarget("lucr3-honey-user-canary-target",
    rule=honey_user_canary_rule.name,
    arn=canary_sns.arn,
    input_transformer=aws.cloudwatch.EventTargetInputTransformerArgs(
        input_paths={"eventName": "$.detail.eventName"},
        input_template='"CANARY TRIGGERED: honey IAM user svc-terraform-automation accessed - action: <eventName>"',
    ),
)

pulumi.export("honey_user_arn", honey_user.arn)

# ============================================================
# 14. CloudTrail Trail (to be stopped by attacker - T1562.008)
# lucr3-cloudtrail
# ============================================================
trail = aws.cloudtrail.Trail("lucr3-cloudtrail",
    name=TRAIL_NAME,
    s3_bucket_name=log_bucket.id,
    include_global_service_events=True,
    is_multi_region_trail=True,
    enable_log_file_validation=True,
    enable_logging=True,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[log_bucket_policy]),
)

pulumi.export("cloudtrail_trail_arn", trail.arn)

# ============================================================
# 15. GuardDuty Detector (to be disabled by attacker - T1562.001)
# lucr3-guardduty-detector
# ============================================================
gd_detector = aws.guardduty.Detector("lucr3-guardduty-detector",
    enable=True,
    finding_publishing_frequency="ONE_HOUR",
    tags=TAGS,
)

# S3 protection via DetectorFeature (v7 API)
aws.guardduty.DetectorFeature("lucr3-gd-s3-protection",
    detector_id=gd_detector.id,
    name="S3_DATA_EVENTS",
    status="ENABLED",
)

# Malware protection via DetectorFeature (v7 API)
aws.guardduty.DetectorFeature("lucr3-gd-malware-protection",
    detector_id=gd_detector.id,
    name="EBS_MALWARE_PROTECTION",
    status="ENABLED",
)

pulumi.export("guardduty_detector_id", gd_detector.id)

# ============================================================
# 16. S3 Corporate Data Bucket (exfiltration target - T1530)
# lucr3-s3-corporate-data
# ============================================================
corporate_bucket_name = f"lucr3-corporate-data-{account_id}"

corporate_bucket = aws.s3.Bucket("lucr3-s3-corporate-data",
    bucket=corporate_bucket_name,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock("lucr3-corporate-pab",
    bucket=corporate_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketVersioningV2("lucr3-corporate-versioning",
    bucket=corporate_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
)

aws.s3.BucketServerSideEncryptionConfigurationV2("lucr3-corporate-sse",
    bucket=corporate_bucket.id,
    rules=[aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
        apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
            sse_algorithm="AES256",
        ),
    )],
)

# Synthetic bait files in corporate data bucket
aws.s3.BucketObject("lucr3-corp-financial-projections",
    bucket=corporate_bucket.id,
    key="financial_projections_2025.xlsx",
    content="SYNTHETIC FINANCIAL DATA - FOR EMULATION ONLY\nQ1 Revenue: $42M (FAKE)\nQ2 Revenue: $51M (FAKE)\nQ3 Forecast: $58M (FAKE)",
    content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    tags=TAGS,
)

aws.s3.BucketObject("lucr3-corp-customer-pii",
    bucket=corporate_bucket.id,
    key="customer_pii_export.csv",
    content="id,name,email,ssn_last4\n1,SYNTHETIC_FAKE_USER,fake@example.com,0000\n2,SYNTHETIC_FAKE_USER_2,fake2@example.com,0001",
    content_type="text/csv",
    tags=TAGS,
)

aws.s3.BucketObject("lucr3-corp-ma-docs",
    bucket=corporate_bucket.id,
    key="merger_acquisition_docs.pdf",
    content="SYNTHETIC M&A DOCUMENT - FOR EMULATION ONLY - NOT REAL FINANCIAL INFORMATION",
    content_type="application/pdf",
    tags=TAGS,
)

pulumi.export("corporate_bucket_name", corporate_bucket_name)

# ============================================================
# 17. S3 Engineering Artifacts Bucket (credential harvest target)
# lucr3-s3-engineering-artifacts
# ============================================================
engineering_bucket_name = f"lucr3-engineering-artifacts-{account_id}"

engineering_bucket = aws.s3.Bucket("lucr3-s3-engineering-artifacts",
    bucket=engineering_bucket_name,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock("lucr3-engineering-pab",
    bucket=engineering_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketVersioningV2("lucr3-engineering-versioning",
    bucket=engineering_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
)

aws.s3.BucketServerSideEncryptionConfigurationV2("lucr3-engineering-sse",
    bucket=engineering_bucket.id,
    rules=[aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
        apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
            sse_algorithm="AES256",
        ),
    )],
)

# Synthetic files with embedded fake secrets
aws.s3.BucketObject("lucr3-eng-setup-script",
    bucket=engineering_bucket.id,
    key="deploy-scripts/setup.sh",
    content="""#!/bin/bash
# SYNTHETIC FILE - FOR EMULATION ONLY
DB_PASSWORD="Synth3tic!FakeDB#2025"
DB_HOST="prod-rds.lab.internal"
DB_USER="dbadmin"
AWS_REGION="us-east-1"
echo "Deploying application..."
""",
    content_type="text/x-shellscript",
    tags=TAGS,
)

aws.s3.BucketObject("lucr3-eng-env-production",
    bucket=engineering_bucket.id,
    key=".env.production",
    content="""# SYNTHETIC FILE - FOR EMULATION ONLY
STRIPE_SECRET_KEY=sk_live_SYNTHETIC_FAKE_KEY_FOR_EMULATION_ONLY
SENDGRID_API_KEY=SG.SYNTHETIC_FAKE_SENDGRID_KEY_FOR_EMULATION
DATABASE_URL=postgresql://dbadmin:FakePassword123@prod-rds.lab.internal:5432/appdb
JWT_SECRET=synthetic_jwt_secret_not_real_do_not_use_abc123xyz
""",
    content_type="text/plain",
    tags=TAGS,
)

aws.s3.BucketObject("lucr3-eng-build-artifact",
    bucket=engineering_bucket.id,
    key="build-artifacts/app-v2.3.1.zip",
    content="SYNTHETIC BUILD ARTIFACT - FOR EMULATION ONLY",
    content_type="application/zip",
    tags=TAGS,
)

# EventBridge notification for bait terraform.tfstate access (set up after object creation)
engineering_bucket_notification = aws.s3.BucketNotification("lucr3-engineering-notifications",
    bucket=engineering_bucket.id,
    eventbridge=True,
)

pulumi.export("engineering_bucket_name", engineering_bucket_name)

# ============================================================
# 18. SecretsManager: prod DB credentials (T1555.006)
# lucr3-secrets-prod-db
# ============================================================
secret_prod_db = aws.secretsmanager.Secret("lucr3-secrets-prod-db",
    name=SECRET_PROD_DB_NAME,
    description="Production database master credentials - SYNTHETIC EMULATION ONLY",
    recovery_window_in_days=0,
    tags=TAGS,
)

aws.secretsmanager.SecretVersion("lucr3-secrets-prod-db-version",
    secret_id=secret_prod_db.id,
    secret_string=json.dumps({
        "username": "dbadmin",
        "password": "Synth3tic!Pass#2025",
        "host": "prod-rds.lab.internal",
        "port": 5432,
    }),
)

pulumi.export("secret_prod_db_arn", secret_prod_db.arn)

# ============================================================
# 19. SecretsManager: Stripe API key (T1555.006)
# lucr3-secrets-stripe-api
# ============================================================
secret_stripe = aws.secretsmanager.Secret("lucr3-secrets-stripe-api",
    name=SECRET_STRIPE_NAME,
    description="Payment processor API key - SYNTHETIC EMULATION ONLY",
    recovery_window_in_days=0,
    tags=TAGS,
)

aws.secretsmanager.SecretVersion("lucr3-secrets-stripe-version",
    secret_id=secret_stripe.id,
    secret_string=json.dumps({
        "key": "sk_live_SYNTHETIC_FAKE_KEY_FOR_EMULATION_ONLY_DO_NOT_USE",
    }),
)

pulumi.export("secret_stripe_arn", secret_stripe.arn)

# ============================================================
# 20. DynamoDB Customer Records table (T1530)
# lucr3-dynamodb-customer-records
# ============================================================
dynamo_table = aws.dynamodb.Table("lucr3-dynamodb-customer-records",
    name=DYNAMODB_TABLE_NAME,
    billing_mode="PAY_PER_REQUEST",
    hash_key="customerId",
    attributes=[
        aws.dynamodb.TableAttributeArgs(name="customerId", type="S"),
    ],
    tags=TAGS,
)

# Synthetic customer rows (full 100-row population done by attack setup script via Faker)
for i in range(1, 6):
    aws.dynamodb.TableItem(f"lucr3-dynamo-item-{i}",
        table_name=dynamo_table.name,
        hash_key=dynamo_table.hash_key,
        item=json.dumps({
            "customerId": {"S": f"CUST-{i:04d}"},
            "email": {"S": f"synthetic.user{i}@example-fake.com"},
            "ssn_last4": {"S": f"{i:04d}"},
            "creditCardBin": {"S": "411111"},
            "accountBalance": {"N": str(i * 100)},
        }),
    )

pulumi.export("dynamodb_table_name", DYNAMODB_TABLE_NAME)
pulumi.export("dynamodb_table_arn", dynamo_table.arn)

# ============================================================
# 21. EC2 Instance (lateral movement target - T1021.004, T1578.002)
# lucr3-ec2-target
# ============================================================
al2023_ami = aws.ec2.get_ami_output(
    most_recent=True,
    owners=["amazon"],
    filters=[
        aws.ec2.GetAmiFilterArgs(name="name", values=["al2023-ami-*-x86_64"]),
        aws.ec2.GetAmiFilterArgs(name="state", values=["available"]),
    ],
)

ec2_instance = aws.ec2.Instance("lucr3-ec2-target",
    ami=al2023_ami.id,
    instance_type="t3.micro",
    subnet_id=subnet_pub.id,
    vpc_security_group_ids=[sg_ec2.id],
    iam_instance_profile=instance_profile.name,
    # IMDSv1 left enabled to model real-world LUCR-3 credential harvesting via IMDS
    metadata_options=aws.ec2.InstanceMetadataOptionsArgs(
        http_endpoint="enabled",
        http_tokens="optional",
    ),
    user_data="""#!/bin/bash
# [EMULATED] T1082: System Information Discovery baseline setup
hostnamectl set-hostname lucr3-target-host
yum update -y --quiet
yum install -y --quiet curl wget jq python3 python3-pip awscli

# Install SSM agent (pre-installed on AL2023 but ensure it is running)
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Create realistic directory structure to model a production host
mkdir -p /opt/app/config /opt/app/logs /var/data
cat > /opt/app/config/app.yaml << 'EOF'
# SYNTHETIC CONFIGURATION - FOR EMULATION ONLY
database:
  host: prod-rds.lab.internal
  port: 5432
  name: appdb
  user: appuser
  password: SyntheticFakeAppPassword123
cache:
  host: elasticache.lab.internal
  port: 6379
EOF
echo "lucr3-target" > /etc/instance-label
""",
    tags={**TAGS, "Name": "lucr3-ec2-target"},
)

pulumi.export("ec2_instance_id", ec2_instance.id)
pulumi.export("ec2_public_ip", ec2_instance.public_ip)

# ============================================================
# 22. GitHub Repository (code exfiltration target - T1213.003)
# lucr3-github-target-repo
# ============================================================
gh_repo = github.Repository("lucr3-github-target-repo",
    name=GITHUB_REPO_NAME,
    description="LUCR-3 lab target - synthetic application repository",
    visibility="private",
    auto_init=True,
)

github.RepositoryFile("lucr3-github-dockerfile",
    repository=gh_repo.name,
    file="Dockerfile",
    content="""FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]
""",
    commit_message="Initial Dockerfile",
    overwrite_on_create=True,
)

github.RepositoryFile("lucr3-github-deploy-workflow",
    repository=gh_repo.name,
    file=".github/workflows/deploy.yml",
    content="""name: Deploy to Production
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      # SYNTHETIC VALUES - NOT REAL CREDENTIALS
      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7SYNTHETIC
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - uses: actions/checkout@v3
      - name: Deploy
        run: echo "Deploying to production..."
""",
    commit_message="Add deployment workflow",
    overwrite_on_create=True,
)

github.RepositoryFile("lucr3-github-terraform-main",
    repository=gh_repo.name,
    file="terraform/main.tf",
    content="""# SYNTHETIC TERRAFORM - FOR EMULATION ONLY
provider "aws" {
  region = "us-east-1"
}

# SYNTHETIC credentials embedded in IaC (models real-world LUCR-3 findings)
locals {
  # DO NOT USE - synthetic values for emulation
  db_password    = "SyntheticProd!DBPass#2025"
  api_secret_key = "synthetic_api_secret_not_real_abc123"
}
""",
    commit_message="Add Terraform infrastructure",
    overwrite_on_create=True,
)

# Add synthetic repo secrets (fake values)
github.ActionsSecret("lucr3-github-aws-secret",
    repository=gh_repo.name,
    secret_name="AWS_SECRET_ACCESS_KEY",
    plaintext_value="wJalrXUtnFEMI/K7MDENG/SYNTHETIC_FAKE_NOT_REAL",
)

pulumi.export("github_repo_name", GITHUB_REPO_NAME)
pulumi.export("github_repo_url", gh_repo.html_url)

# NOTE: lucr3-m365-sharepoint-site requires manual M365 E3 trial tenant setup.
# See infra plan configuration_notes for step-by-step instructions.
# Steps: Create M365 tenant, assign victim license, create SharePoint site
# 'Corporate-Internal', enable legacy auth (IMAP/SMTP AUTH) in Exchange Admin Center.

# ============================================================
# 23. Bait terraform.tfstate (T1555.006, T1619)
# lucr3-bait-terraform-state
# ============================================================
bait_tfstate_content = json.dumps({
    "version": 4,
    "terraform_version": "1.5.7",
    "serial": 142,
    "lineage": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "outputs": {
        "aws_access_key_id": {
            "value": "AKIAIOSFODNN7BAITXXXX",
            "type": "string",
            "sensitive": False,
        },
        "aws_secret_access_key": {
            "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYBAITKEYFAKE",
            "type": "string",
            "sensitive": True,
        },
        "database_password": {
            "value": "ProdDB!Bait#2025@secure_fake",
            "type": "string",
            "sensitive": True,
        },
        "github_token": {
            "value": "ghp_BAITTOKENxyz123456789abcdefghijklmnopq",
            "type": "string",
            "sensitive": True,
        },
        "rds_endpoint": {
            "value": "prod-rds.lab.internal:5432",
            "type": "string",
        },
    },
    "resources": [
        {
            "mode": "managed",
            "type": "aws_iam_access_key",
            "name": "deploy_user",
            "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
            "instances": [{
                "schema_version": 0,
                "attributes": {
                    "id": "AKIAIOSFODNN7BAITXXXX",
                    "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYBAITKEYFAKE",
                    "user": "svc-deploy-automation",
                    "status": "Active",
                },
            }],
        },
    ],
}, indent=2)

bait_tfstate = aws.s3.BucketObject("lucr3-bait-terraform-state",
    bucket=engineering_bucket.id,
    key="terraform/prod/terraform.tfstate",
    content=bait_tfstate_content,
    content_type="application/json",
    tags=TAGS,
)

# EventBridge rule: alert when bait tfstate object is GetObject'd
tfstate_canary_rule = aws.cloudwatch.EventRule("lucr3-tfstate-canary-rule",
    name="lucr3-tfstate-canary",
    description="CANARY - alert when bait terraform.tfstate is accessed",
    event_pattern=engineering_bucket.arn.apply(lambda arn: json.dumps({
        "source": ["aws.s3"],
        "detail-type": ["Object Access"],
        "detail": {
            "bucket": {"name": [engineering_bucket_name]},
            "object": {"key": ["terraform/prod/terraform.tfstate"]},
            "requestParameters": {"requestType": ["GetObject"]},
        },
    })),
    tags=TAGS,
)

aws.cloudwatch.EventTarget("lucr3-tfstate-canary-target",
    rule=tfstate_canary_rule.name,
    arn=canary_sns.arn,
    input=json.dumps("CANARY TRIGGERED: bait terraform.tfstate accessed - possible credential harvesting in progress"),
)

# ============================================================
# 24. Bait honey credentials secret (T1555.006)
# lucr3-bait-honey-credentials
# ============================================================
honey_creds_secret = aws.secretsmanager.Secret("lucr3-bait-honey-credentials",
    name=SECRET_HONEY_CREDS_NAME,
    description="Terraform automation service account key - CANARY - do not use in production",
    recovery_window_in_days=0,
    tags=TAGS,
)

aws.secretsmanager.SecretVersion("lucr3-honey-creds-version",
    secret_id=honey_creds_secret.id,
    secret_string=pulumi.Output.all(honey_access_key.id, honey_access_key.secret).apply(
        lambda args: json.dumps({
            "access_key_id": args[0],
            "secret_access_key": args[1],
            "note": "CANARY - any use of this key will trigger detection",
        })
    ),
)

# EventBridge canary: GetSecretValue on honey credentials
honey_creds_canary_rule = aws.cloudwatch.EventRule("lucr3-honey-creds-canary-rule",
    name="lucr3-honey-creds-canary",
    description="CANARY - alert when honey credentials secret is accessed",
    event_pattern=honey_creds_secret.arn.apply(lambda arn: json.dumps({
        "source": ["aws.secretsmanager"],
        "detail": {
            "eventName": ["GetSecretValue"],
            "requestParameters": {
                "secretId": [arn],
            },
        },
    })),
    tags=TAGS,
)

aws.cloudwatch.EventTarget("lucr3-honey-creds-canary-target",
    rule=honey_creds_canary_rule.name,
    arn=canary_sns.arn,
    input=json.dumps("CANARY TRIGGERED: honey credentials secret prod/infrastructure/terraform-automation-key accessed - SecretsManager scraping detected"),
)

pulumi.export("honey_creds_secret_arn", honey_creds_secret.arn)

# ============================================================
# 25. Bait GitHub PAT secret (T1550.001, T1555.006)
# lucr3-bait-github-pat-secret
# ============================================================
github_pat_secret = aws.secretsmanager.Secret("lucr3-bait-github-pat-secret",
    name=SECRET_GITHUB_PAT_NAME,
    description="GitHub Actions CI/CD token - CANARY bait - token is revoked and invalid",
    recovery_window_in_days=0,
    tags=TAGS,
)

aws.secretsmanager.SecretVersion("lucr3-github-pat-version",
    secret_id=github_pat_secret.id,
    secret_string=json.dumps({
        "token": "ghp_SYNTHETIC_BAIT_TOKEN_REVOKED_DO_NOT_USE_xyz123",
        "org": "acme-corp",
        "created": "2025-01-15",
        "scopes": "repo,workflow,admin:org",
    }),
)

# EventBridge canary: GetSecretValue on GitHub PAT bait
github_pat_canary_rule = aws.cloudwatch.EventRule("lucr3-github-pat-canary-rule",
    name="lucr3-github-pat-canary",
    description="CANARY - alert when GitHub PAT bait secret is accessed",
    event_pattern=github_pat_secret.arn.apply(lambda arn: json.dumps({
        "source": ["aws.secretsmanager"],
        "detail": {
            "eventName": ["GetSecretValue"],
            "requestParameters": {
                "secretId": [arn],
            },
        },
    })),
    tags=TAGS,
)

aws.cloudwatch.EventTarget("lucr3-github-pat-canary-target",
    rule=github_pat_canary_rule.name,
    arn=canary_sns.arn,
    input=json.dumps("CANARY TRIGGERED: GitHub PAT bait secret prod/cicd/github-actions-token accessed - CI/CD token harvesting detected"),
)

pulumi.export("github_pat_secret_arn", github_pat_secret.arn)

# ============================================================
# Consolidated exports for attack.py
# ============================================================
pulumi.export("log_bucket_name", log_bucket_name)
pulumi.export("cloudtrail_bucket_name", log_bucket_name)
pulumi.export("corporate_bucket_name", corporate_bucket_name)
pulumi.export("engineering_bucket_name", engineering_bucket_name)
pulumi.export("canary_sns_arn", canary_sns.arn)
pulumi.export("saml_provider_arn", aws_saml_provider.arn)
pulumi.export("federated_role_arn", federated_role.arn)
pulumi.export("ec2_instance_id", ec2_instance.id)
pulumi.export("subnet_id", subnet_pub.id)
pulumi.export("okta_org_url", okta_org_url)
pulumi.export("victim_username", VICTIM_USERNAME)

# ============================================================
# Auto-trigger: launch attack.py after all resources are ready
# ============================================================
def _launch_attack(
    log_bkt,
    corp_bkt,
    eng_bkt,
    saml_arn,
    fed_role_arn,
    gd_detector_id,
    ec2_id,
    subnet_id_val,
    ec2_sg_id_val,
    azuread_app_id,
):
    attack_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "emulation_scripts",
        "attack.py",
    )
    if not os.path.exists(attack_script):
        pulumi.log.warn(f"attack.py not found at {attack_script} - skipping auto-trigger")
        return

    env = os.environ.copy()
    # Env var names must match what attack.py reads via os.environ.get().
    # Static resource names — fallbacks used when Pulumi outputs are unavailable.
    env["TRAIL_NAME"]            = TRAIL_NAME
    env["ATTACKER_USER_NAME"]    = ATTACKER_USER_NAME
    env["HONEY_USER_NAME"]       = HONEY_USER_NAME
    env["DYNAMODB_TABLE_NAME"]   = DYNAMODB_TABLE_NAME
    env["GITHUB_REPO_NAME"]      = GITHUB_REPO_NAME
    env["SAML_PROVIDER_NAME"]    = SAML_PROVIDER_NAME
    env["FEDERATED_ROLE_NAME"]   = FEDERATED_ROLE_NAME
    # Dynamic resource values (resolved by Pulumi at deploy time)
    env["CORPORATE_BUCKET_NAME"]   = corp_bkt
    env["ENGINEERING_BUCKET_NAME"] = eng_bkt
    env["SAML_PROVIDER_ARN"]       = saml_arn
    env["FEDERATED_ROLE_ARN"]      = fed_role_arn
    env["GUARDDUTY_DETECTOR_ID"]   = gd_detector_id
    env["LUCR3_EC2_TARGET_ID"]     = ec2_id
    env["LUCR3_SUBNET_ID"]         = subnet_id_val
    env["LUCR3_SG_ID"]             = ec2_sg_id_val
    env["AZUREAD_APP_CLIENT_ID"]   = azuread_app_id
    env["OKTA_DOMAIN"]             = okta_org_url
    # Forward Pulumi passphrase so get_pulumi_outputs() can call 'pulumi stack output --show-secrets'
    env.setdefault("PULUMI_CONFIG_PASSPHRASE", os.environ.get("PULUMI_CONFIG_PASSPHRASE", ""))

    pulumi.log.info("Launching LUCR-3 emulation attack script...")
    subprocess.Popen(
        ["python", attack_script],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


pulumi.Output.all(
    log_bucket.id,
    corporate_bucket.id,
    engineering_bucket.id,
    aws_saml_provider.arn,
    federated_role.arn,
    gd_detector.id,
    ec2_instance.id,
    subnet_pub.id,
    sg_ec2.id,
    azuread_app.client_id,
).apply(lambda args: _launch_attack(*args))
