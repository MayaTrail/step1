import json
import pathlib
import pulumi
import pulumi_aws as aws

# ---------------------------------------------------------------------------
# Resource Name Constants (single source of truth via resource_names.json)
# ---------------------------------------------------------------------------
_NAMES = {'campaign': 'ATOMIC-LAMBDA-PASSROLE-INVOKE',
 'csp': 'aws',
 'resources': {'victim_role_name': 'atomic-lambda-passrole-invoke-victim-role',
               'target_role_name': 'atomic-lambda-passrole-invoke-target-role',
               'decoy_execution_role_name': 'atomic-lambda-passrole-invoke-decoy-execution-role',
               'victim_policy_name': 'atomic-lambda-passrole-invoke-victim-policy',
               'target_role_policy_name': 'atomic-lambda-passrole-invoke-target-role-policy',
               'canary_secret_name': 'prod/rds/master-credentials',
               'decoy_lambda_name': 'prod-db-backup-handler',
               'victim_user_name': 'atomic-lambda-passrole-invoke-attacker',
               'victim_user_assume_policy_name': 'atomic-lambda-passrole-invoke-assume-victim-role'},
 'pulumi_export_keys': {'victim_role_arn': 'victim_role_arn',
                        'target_role_arn': 'target_role_arn',
                        'canary_secret_arn': 'canary_secret_arn',
                        'victim_access_key_id': 'victim_access_key_id',
                        'victim_secret_access_key': 'victim_secret_access_key',
                        'decoy_lambda_arn': 'decoy_lambda_arn',
                        'victim_role_name': 'victim_role_name',
                        'target_role_name': 'target_role_name',
                        'canary_secret_name': 'canary_secret_name',
                        'decoy_lambda_name': 'decoy_lambda_name',
                        'victim_user_name': 'victim_user_name'}}
_R = _NAMES["resources"]

VICTIM_ROLE_NAME            = _R["victim_role_name"]
TARGET_ROLE_NAME            = _R["target_role_name"]
DECOY_EXEC_ROLE_NAME        = _R["decoy_execution_role_name"]
VICTIM_POLICY_NAME          = _R["victim_policy_name"]
TARGET_ROLE_POLICY_NAME     = _R["target_role_policy_name"]
CANARY_SECRET_NAME          = _R["canary_secret_name"]
DECOY_LAMBDA_NAME           = _R["decoy_lambda_name"]
VICTIM_USER_NAME            = _R["victim_user_name"]
VICTIM_USER_ASSUME_POLICY   = _R["victim_user_assume_policy_name"]

# ---------------------------------------------------------------------------
# Account / region (plain strings from synchronous invokes)
# ---------------------------------------------------------------------------
account_id = aws.get_caller_identity().account_id
region     = aws.get_region().id

# ---------------------------------------------------------------------------
# Common tags
# ---------------------------------------------------------------------------
TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-lambda-passrole-invoke",
    "Technique":   "T1648",
}

# ---------------------------------------------------------------------------
# 1. Canary Secret  (target: data the escalated Lambda exfiltrates)
# ---------------------------------------------------------------------------
canary_secret = aws.secretsmanager.Secret(
    "canary-secret",
    name=CANARY_SECRET_NAME,
    description="Prod RDS master credentials - adversary emulation bait",
    recovery_window_in_days=0,
    tags=TAGS,
)

# ---------------------------------------------------------------------------
# 2. Canary Secret Version
# ---------------------------------------------------------------------------
canary_secret_version = aws.secretsmanager.SecretVersion(
    "canary-secret-version",
    secret_id=canary_secret.id,
    secret_string=json.dumps({
        "username": "dbadmin",
        "password": "Sup3rS3cr3t!",
        "engine":   "mysql",
        "host":     "prod-aurora-cluster.cluster-abc123.us-east-1.rds.amazonaws.com",
    }),
)

# ---------------------------------------------------------------------------
# 3. Decoy Lambda execution role  (no secret access - intentional)
# ---------------------------------------------------------------------------
decoy_exec_role = aws.iam.Role(
    "decoy-execution-role",
    name=DECOY_EXEC_ROLE_NAME,
    description="Execution role for decoy DB backup Lambda - no secret access",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    "decoy-exec-role-basic",
    role=decoy_exec_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

# ---------------------------------------------------------------------------
# 4. Target Role  (Lambda assumes this after PassRole escalation)
#    Trust: lambda.amazonaws.com only
# ---------------------------------------------------------------------------
target_role = aws.iam.Role(
    "target-role",
    name=TARGET_ROLE_NAME,
    description="Privileged role passed to attacker Lambda - grants canary secret read",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

# ---------------------------------------------------------------------------
# 5. Target Role inline policy  (scoped to canary secret ARN + Lambda logs)
# ---------------------------------------------------------------------------
target_role_policy = aws.iam.RolePolicy(
    "target-role-policy",
    name=TARGET_ROLE_POLICY_NAME,
    role=target_role.id,
    policy=canary_secret.arn.apply(lambda secret_arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":      "CanarySecretRead",
                "Effect":   "Allow",
                "Action":   "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
            },
            {
                "Sid":    "LambdaBasicExecution",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    })),
)

# ---------------------------------------------------------------------------
# 6. Victim Role  (attacker entry-point; trusts current account)
# ---------------------------------------------------------------------------
victim_role = aws.iam.Role(
    "victim-role",
    name=VICTIM_ROLE_NAME,
    description="Attacker entry-point role - Lambda plus scoped PassRole",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

# ---------------------------------------------------------------------------
# 7. Victim Role inline policy
#    PassRole is hard-scoped to target_role ARN only - never wildcard.
#    lambda:DeleteFunction included so attack.py can clean up what it creates.
# ---------------------------------------------------------------------------
victim_policy = aws.iam.RolePolicy(
    "victim-policy",
    name=VICTIM_POLICY_NAME,
    role=victim_role.id,
    policy=target_role.arn.apply(lambda target_arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":    "LambdaControl",
                "Effect": "Allow",
                "Action": [
                    "lambda:CreateFunction",
                    "lambda:UpdateFunctionConfiguration",
                    "lambda:InvokeFunction",
                    "lambda:GetFunction",
                    "lambda:ListFunctions",
                    "lambda:DeleteFunction",
                ],
                "Resource": "*",
            },
            {
                "Sid":      "ScopedPassRole",
                "Effect":   "Allow",
                "Action":   "iam:PassRole",
                "Resource": target_arn,
            },
        ],
    })),
)

# ---------------------------------------------------------------------------
# 8. Victim IAM User  (credentials delivered to attack.py via stack outputs)
# ---------------------------------------------------------------------------
victim_user = aws.iam.User(
    "victim-user",
    name=VICTIM_USER_NAME,
    tags=TAGS,
)

# User needs explicit AssumeRole permission to assume the victim role
victim_user_assume_policy = aws.iam.UserPolicy(
    "victim-user-assume-policy",
    name=VICTIM_USER_ASSUME_POLICY,
    user=victim_user.name,
    policy=victim_role.arn.apply(lambda role_arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":   "Allow",
            "Action":   "sts:AssumeRole",
            "Resource": role_arn,
        }],
    })),
)

victim_access_key = aws.iam.AccessKey(
    "victim-access-key",
    user=victim_user.name,
    opts=pulumi.ResourceOptions(depends_on=[victim_user]),
)

# ---------------------------------------------------------------------------
# 9. Decoy Lambda  (prod-db-backup-handler - primes attacker to seek RDS creds)
#    Code MUST be inline (constraint 13 - backend copies only Pulumi.yaml + __main__.py)
# ---------------------------------------------------------------------------
_DECOY_HANDLER_SRC = """\
import json

def handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"status": "ok", "job": "backup-complete"})}
"""

decoy_lambda = aws.lambda_.Function(
    "decoy-lambda",
    name=DECOY_LAMBDA_NAME,
    description="Prod DB backup handler - adversary emulation decoy",
    runtime="python3.12",
    handler="index.handler",
    role=decoy_exec_role.arn,
    code=pulumi.AssetArchive({
        "index.py": pulumi.StringAsset(_DECOY_HANDLER_SRC),
    }),
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[decoy_exec_role]),
)

# ---------------------------------------------------------------------------
# Pulumi Exports  (attack.py reads these via pulumi stack output)
# ---------------------------------------------------------------------------
pulumi.export("victim_role_arn",          victim_role.arn)
pulumi.export("target_role_arn",          target_role.arn)
pulumi.export("canary_secret_arn",        canary_secret.arn)
pulumi.export("victim_access_key_id",     victim_access_key.id)
pulumi.export("victim_secret_access_key", victim_access_key.secret)
pulumi.export("decoy_lambda_arn",         decoy_lambda.arn)

# Static name exports so attack.py can reference them without re-derivation
pulumi.export("victim_role_name",    VICTIM_ROLE_NAME)
pulumi.export("target_role_name",    TARGET_ROLE_NAME)
pulumi.export("canary_secret_name",  CANARY_SECRET_NAME)
pulumi.export("decoy_lambda_name",   DECOY_LAMBDA_NAME)
pulumi.export("victim_user_name",    VICTIM_USER_NAME)
