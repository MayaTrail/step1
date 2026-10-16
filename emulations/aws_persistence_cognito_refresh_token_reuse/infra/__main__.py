import json
import pathlib
import pulumi
import pulumi_aws as aws

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Resource Name Constants ──────────────────────────────────────────────────
_NAMES = {'campaign': 'ATOMIC-COGNITO-REFRESH-TOKEN-REUSE',
 'csp': 'aws',
 'resources': {'user_pool_name': 'atomic-cognito-refresh-token-reuse-user-pool',
               'app_client_name': 'atomic-cognito-refresh-token-reuse-app-client',
               'victim_username': 'prod.svc.account',
               'victim_password': 'LabVictim1!',
               'param_pool_id': '/atomic-cognito-refresh-token-reuse/pool-id',
               'param_client_id': '/atomic-cognito-refresh-token-reuse/client-id',
               'param_victim_password': '/atomic-cognito-refresh-token-reuse/victim-password',
               'attacker_role_name': 'atomic-cognito-refresh-token-reuse-attacker-role'},
 'pulumi_export_keys': {'user_pool_id': 'user_pool_id',
                        'user_pool_arn': 'user_pool_arn',
                        'app_client_id': 'app_client_id',
                        'attacker_role_arn': 'attacker_role_arn',
                        'victim_username': 'victim_username',
                        'victim_password': 'victim_password',
                        'param_pool_id_name': 'param_pool_id_name',
                        'param_client_id_name': 'param_client_id_name',
                        'param_victim_password_name': 'param_victim_password_name',
                        'user_pool_name': 'user_pool_name',
                        'app_client_name': 'app_client_name',
                        'attacker_role_name': 'attacker_role_name'}}
_R = _NAMES["resources"]

USER_POOL_NAME          = _R["user_pool_name"]
APP_CLIENT_NAME         = _R["app_client_name"]
VICTIM_USERNAME         = _R["victim_username"]
VICTIM_PASSWORD         = _R["victim_password"]
PARAM_POOL_ID           = _R["param_pool_id"]
PARAM_CLIENT_ID         = _R["param_client_id"]
PARAM_VICTIM_PASSWORD   = _R["param_victim_password"]
ATTACKER_ROLE_NAME      = _R["attacker_role_name"]
SSM_PARAM_PATH_PREFIX   = "/atomic-cognito-refresh-token-reuse/"

TAGS = {
    "MayaTrail": "true",
    "Purpose": "adversary-emulation",
    "ThreatActor": "ATOMIC-cognito-refresh-token-reuse",
    "Technique": "T1550.001",
}

# ── AWS provider identity ────────────────────────────────────────────────────
region_output   = aws.get_region_output()
identity_output = aws.get_caller_identity_output()

# ── Cognito User Pool ────────────────────────────────────────────────────────
# MFA off, no email/SMS verification, permissive password policy replicating
# the misconfigured pool configuration T1550.001 exploits.
user_pool = aws.cognito.UserPool(
    "user-pool",
    name=USER_POOL_NAME,
    mfa_configuration="OFF",
    auto_verified_attributes=[],
    username_attributes=[],
    deletion_protection="INACTIVE",
    admin_create_user_config=aws.cognito.UserPoolAdminCreateUserConfigArgs(
        allow_admin_create_user_only=False,
    ),
    password_policy=aws.cognito.UserPoolPasswordPolicyArgs(
        minimum_length=8,
        require_lowercase=False,
        require_numbers=False,
        require_symbols=False,
        require_uppercase=False,
    ),
    account_recovery_setting=aws.cognito.UserPoolAccountRecoverySettingArgs(
        recovery_mechanisms=[
            aws.cognito.UserPoolAccountRecoverySettingRecoveryMechanismArgs(
                name="admin_only",
                priority=1,
            )
        ]
    ),
    tags=TAGS,
)

# ── Cognito App Client ───────────────────────────────────────────────────────
# ALLOW_REFRESH_TOKEN_AUTH is the direct enabler of T1550.001.
# enable_token_revocation=False intentionally so stolen refresh tokens remain valid.
app_client = aws.cognito.UserPoolClient(
    "app-client",
    name=APP_CLIENT_NAME,
    user_pool_id=user_pool.id,
    explicit_auth_flows=[
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_USER_SRP_AUTH",
    ],
    generate_secret=False,
    refresh_token_validity=30,
    access_token_validity=60,
    id_token_validity=60,
    token_validity_units=aws.cognito.UserPoolClientTokenValidityUnitsArgs(
        access_token="minutes",
        id_token="minutes",
        refresh_token="days",
    ),
    prevent_user_existence_errors="ENABLED",
    supported_identity_providers=["COGNITO"],
    enable_token_revocation=False,
)

# ── Victim Cognito User ──────────────────────────────────────────────────────
# password= calls AdminSetUserPassword with Permanent=true, avoiding the
# FORCE_CHANGE_PASSWORD state and the NEW_PASSWORD_REQUIRED challenge.
# message_action=SUPPRESS - no email/SMS welcome message.
victim_user = aws.cognito.User(
    "victim-user",
    user_pool_id=user_pool.id,
    username=VICTIM_USERNAME,
    password=VICTIM_PASSWORD,
    message_action="SUPPRESS",
    attributes={
        "email": "prod.svc.account@internal.invalid",
        "email_verified": "true",
    },
)

# ── SSM Parameters ───────────────────────────────────────────────────────────
# Represent config-store exposure an attacker discovers during reconnaissance.

param_pool_id = aws.ssm.Parameter(
    "param-pool-id",
    name=PARAM_POOL_ID,
    type="String",
    value=user_pool.id,
    tags=TAGS,
)

param_client_id = aws.ssm.Parameter(
    "param-client-id",
    name=PARAM_CLIENT_ID,
    type="String",
    value=app_client.id,
    tags=TAGS,
)

param_victim_password = aws.ssm.Parameter(
    "param-victim-password",
    name=PARAM_VICTIM_PASSWORD,
    type="SecureString",
    value=VICTIM_PASSWORD,
    tags=TAGS,
)

# ── IAM Attacker Role ────────────────────────────────────────────────────────
# Self-account trust satisfies the pipeline backend-compat contract.
# Policy is pinned to the specific user pool ARN and SSM path prefix.
trust_policy = identity_output.account_id.apply(
    lambda account_id: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{account_id}:root"
                },
                "Action": "sts:AssumeRole",
            }
        ],
    })
)

attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=trust_policy,
    tags=TAGS,
)

attacker_inline_policy_doc = pulumi.Output.all(
    region_output.id,
    identity_output.account_id,
    user_pool.id,
).apply(
    lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CognitoRefreshTokenAuth",
                "Effect": "Allow",
                "Action": [
                    "cognito-idp:InitiateAuth",
                    "cognito-idp:RespondToAuthChallenge",
                ],
                "Resource": f"arn:aws:cognito-idp:{args[0]}:{args[1]}:userpool/{args[2]}",
            },
            {
                "Sid": "ReadLabParams",
                "Effect": "Allow",
                "Action": [
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                ],
                "Resource": f"arn:aws:ssm:{args[0]}:{args[1]}:parameter/atomic-cognito-refresh-token-reuse/*",
            },
        ],
    })
)

attacker_role_inline = aws.iam.RolePolicy(
    "attacker-inline",
    name="atomic-cognito-refresh-token-reuse-attacker-inline",
    role=attacker_role.id,
    policy=attacker_inline_policy_doc,
)

# ── Exports ──────────────────────────────────────────────────────────────────
pulumi.export("user_pool_id",              user_pool.id)
pulumi.export("user_pool_arn",             user_pool.arn)
pulumi.export("app_client_id",             app_client.id)
pulumi.export("attacker_role_arn",         attacker_role.arn)
pulumi.export("victim_username",           VICTIM_USERNAME)
pulumi.export("victim_password",           VICTIM_PASSWORD)
pulumi.export("param_pool_id_name",        PARAM_POOL_ID)
pulumi.export("param_client_id_name",      PARAM_CLIENT_ID)
pulumi.export("param_victim_password_name", PARAM_VICTIM_PASSWORD)
pulumi.export("user_pool_name",            USER_POOL_NAME)
pulumi.export("app_client_name",           APP_CLIENT_NAME)
pulumi.export("attacker_role_name",        ATTACKER_ROLE_NAME)
