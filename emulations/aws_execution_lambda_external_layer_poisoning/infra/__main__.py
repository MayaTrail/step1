import json
import pathlib
import pulumi
import pulumi_aws as aws

# ── Resource name constants (single source of truth) ────────────────────────
_NAMES = {'campaign': 'ATOMIC-LAMBDA-EXTERNAL-LAYER-POISONING',
 'csp': 'aws',
 'resources': {'log_group_name': '/aws/lambda/atomic-lambda-external-layer-poisoning-victim',
               'victim_function_name': 'atomic-lambda-external-layer-poisoning-victim',
               'baseline_layer_name': 'atomic-lambda-external-layer-poisoning-common-deps',
               'prod_secret_name': 'atomic-lambda-external-layer-poisoning/prod/database/master_credentials',
               'victim_exec_role_name': 'atomic-lambda-external-layer-poisoning-victim-exec-role',
               'attacker_role_name': 'atomic-lambda-external-layer-poisoning-attacker-role'},
 'pulumi_export_keys': {'log_group_name': 'log_group_name',
                        'victim_function_name': 'victim_function_name',
                        'baseline_layer_name': 'baseline_layer_name',
                        'prod_secret_name': 'prod_secret_name',
                        'victim_exec_role_name': 'victim_exec_role_name',
                        'attacker_role_name': 'attacker_role_name',
                        'state_bucket_name': 'state_bucket_name',
                        'state_bucket_arn': 'state_bucket_arn',
                        'prod_secret_arn': 'prod_secret_arn',
                        'baseline_layer_arn': 'baseline_layer_arn',
                        'victim_function_arn': 'victim_function_arn',
                        'attacker_role_arn': 'attacker_role_arn',
                        'victim_exec_role_arn': 'victim_exec_role_arn'}}
_R = _NAMES["resources"]

LOG_GROUP_NAME        = _R["log_group_name"]
VICTIM_FUNCTION_NAME  = _R["victim_function_name"]
BASELINE_LAYER_NAME   = _R["baseline_layer_name"]
PROD_SECRET_NAME      = _R["prod_secret_name"]
VICTIM_EXEC_ROLE_NAME = _R["victim_exec_role_name"]
ATTACKER_ROLE_NAME    = _R["attacker_role_name"]

# Export name constants so attack.py can resolve them
pulumi.export("log_group_name",        LOG_GROUP_NAME)
pulumi.export("victim_function_name",  VICTIM_FUNCTION_NAME)
pulumi.export("baseline_layer_name",   BASELINE_LAYER_NAME)
pulumi.export("prod_secret_name",      PROD_SECRET_NAME)
pulumi.export("victim_exec_role_name", VICTIM_EXEC_ROLE_NAME)
pulumi.export("attacker_role_name",    ATTACKER_ROLE_NAME)

# ── AWS identity ─────────────────────────────────────────────────────────────
caller     = aws.get_caller_identity()
region_obj = aws.get_region()
account_id = caller.account_id
region_id  = region_obj.id  # .id per pulumi-aws v7 (.name deprecated)

# ── Tags ─────────────────────────────────────────────────────────────────────
TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-lambda-external-layer-poisoning",
    "Technique":   "T1195.002",
}

# ── 1. CloudWatch Log Group ──────────────────────────────────────────────────
# Pre-created so Pulumi owns retention and cleanup; LAYER_POISONED marker lands here.
log_group = aws.cloudwatch.LogGroup(
    "atomic-lambda-external-layer-poisoning-log-group",
    name=LOG_GROUP_NAME,
    retention_in_days=7,
    tags=TAGS,
)

# ── 2. S3 State Bucket ───────────────────────────────────────────────────────
# Hosts the bait terraform.tfstate; name embeds account_id for global uniqueness.
state_bucket_name_str = f"atomic-lambda-external-layer-poisoning-state-{account_id}"

state_bucket = aws.s3.BucketV2(
    "atomic-lambda-external-layer-poisoning-state-bucket",
    force_destroy=True,  # lab bucket: CloudTrail/log objects must not block destroy
    bucket=state_bucket_name_str,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "atomic-lambda-external-layer-poisoning-state-bucket-pab",
    bucket=state_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# ── 3. SecretsManager - Prod Secret ─────────────────────────────────────────
# High-value bait; victim Lambda reads it via SECRET_ARN env var.
prod_secret = aws.secretsmanager.Secret(
    "atomic-lambda-external-layer-poisoning-prod-secret",
    name=PROD_SECRET_NAME,
    recovery_window_in_days=0,
    tags=TAGS,
)

aws.secretsmanager.SecretVersion(
    "atomic-lambda-external-layer-poisoning-prod-secret-version",
    secret_id=prod_secret.id,
    secret_string=json.dumps({
        "db_host":     "prod-db.internal.example.com",
        "db_user":     "svc_app_prod",
        "db_password": "Tr0ub4dor&3-prod",
    }),
)

# ── 4. Baseline Lambda Layer ─────────────────────────────────────────────────
# Legitimate layer the victim ships with; attack.py publishes a poisoned version
# under the same layer name, which CloudTrail attributes to the attacker identity.
BASELINE_LAYER_SRC = "def helper(): return 'baseline'\n"

baseline_layer = aws.lambda_.LayerVersion(
    "atomic-lambda-external-layer-poisoning-baseline-layer",
    layer_name=BASELINE_LAYER_NAME,
    code=pulumi.AssetArchive({
        "python/common_utils.py": pulumi.StringAsset(BASELINE_LAYER_SRC),
    }),
    compatible_runtimes=["python3.12"],
)

# ── 5. Victim Execution Role ─────────────────────────────────────────────────
victim_exec_role = aws.iam.Role(
    "atomic-lambda-external-layer-poisoning-victim-exec-role",
    name=VICTIM_EXEC_ROLE_NAME,
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

# Inline policy - all resource ARNs from Pulumi outputs, no wildcards.
victim_exec_policy_doc = pulumi.Output.all(
    prod_secret_arn=prod_secret.arn,
    state_bucket_arn=state_bucket.arn,
).apply(lambda args: json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":      "Logs",
            "Effect":   "Allow",
            "Action":   ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": (
                f"arn:aws:logs:{region_id}:{account_id}"
                f":log-group:/aws/lambda/atomic-lambda-external-layer-poisoning-victim:*"
            ),
        },
        {
            "Sid":      "SecretRead",
            "Effect":   "Allow",
            "Action":   ["secretsmanager:GetSecretValue"],
            "Resource": args["prod_secret_arn"],
        },
        {
            "Sid":      "BaitRead",
            "Effect":   "Allow",
            "Action":   ["s3:GetObject"],
            "Resource": f"{args['state_bucket_arn']}/terraform.tfstate",
        },
    ],
}))

aws.iam.RolePolicy(
    "atomic-lambda-external-layer-poisoning-victim-exec-role-policy",
    role=victim_exec_role.id,
    policy=victim_exec_policy_doc,
)

# ── 6. Victim Lambda Function ─────────────────────────────────────────────────
# Explicit name matches the log group name exactly to prevent Pulumi auto-suffix mismatch.
# Imports common_utils so the poisoned module executes on next invocation after layer swap.
HANDLER_SRC = """\
import json
import os
import boto3
import common_utils

def handler(event, context):
    secret_arn = os.environ.get('SECRET_ARN', '')
    sm = boto3.client('secretsmanager')
    result = {'status': 'ok'}
    if secret_arn:
        try:
            resp = sm.get_secret_value(SecretId=secret_arn)
            result['secret_retrieved'] = True
        except Exception as e:
            result['secret_error'] = str(e)
    helper_result = common_utils.helper()
    result['helper'] = helper_result
    print('HANDLER_RESULT: ' + json.dumps(result))
    return result
"""

victim_function = aws.lambda_.Function(
    "atomic-lambda-external-layer-poisoning-victim-function",
    name=VICTIM_FUNCTION_NAME,
    runtime="python3.12",
    handler="index.handler",
    role=victim_exec_role.arn,
    code=pulumi.AssetArchive({
        "index.py": pulumi.StringAsset(HANDLER_SRC),
    }),
    layers=[baseline_layer.arn],
    environment=aws.lambda_.FunctionEnvironmentArgs(
        variables={"SECRET_ARN": prod_secret.arn},
    ),
    logging_config=aws.lambda_.FunctionLoggingConfigArgs(
        log_format="Text",
        log_group=LOG_GROUP_NAME,
    ),
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[log_group, victim_exec_role]),
)

# ── 7. Attacker Role ──────────────────────────────────────────────────────────
# Trust policy uses current-account root so AssumeRole in attack.py succeeds.
# Inline policy pins all resources to lab-specific ARNs - no wildcard Resource.
attacker_role = aws.iam.Role(
    "atomic-lambda-external-layer-poisoning-attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[victim_function]),
)

attacker_policy_doc = pulumi.Output.all(
    victim_function_arn=victim_function.arn,
).apply(lambda args: json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":    "LayerActions",
            "Effect": "Allow",
            "Action": [
                "lambda:PublishLayerVersion",
                "lambda:GetLayerVersion",
                "lambda:DeleteLayerVersion",
            ],
            # Scoped to the lab layer name only - not a wildcard
            # PublishLayerVersion authorises against the layer ARN without a version,
            # Get/DeleteLayerVersion against a version ARN - both are needed.
            "Resource": [
                f"arn:aws:lambda:{region_id}:{account_id}:layer:{BASELINE_LAYER_NAME}",
                f"arn:aws:lambda:{region_id}:{account_id}:layer:{BASELINE_LAYER_NAME}:*",
            ],
        },
        {
            "Sid":    "FunctionActions",
            "Effect": "Allow",
            "Action": [
                "lambda:UpdateFunctionConfiguration",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
                "lambda:InvokeFunction",
            ],
            "Resource": args["victim_function_arn"],
        },
    ],
}))

aws.iam.RolePolicy(
    "atomic-lambda-external-layer-poisoning-attacker-role-policy",
    role=attacker_role.id,
    policy=attacker_policy_doc,
)

# ── 8. Bait terraform.tfstate ─────────────────────────────────────────────────
# Decoy state file with structurally-valid but inactive example credentials.
# AKIAIOSFODNN7EXAMPLE is the AWS documentation example key - universally known fake.
BAIT_TFSTATE = json.dumps({
    "version": 4,
    "terraform_version": "1.5.0",
    "serial": 12,
    "lineage": "d4f3e2b1-a0c9-4d8e-b7f6-e5d4c3b2a1f0",
    "outputs": {
        "iam_access_key_id": {
            "value": "AKIAIOSFODNN7EXAMPLE",
            "type": "string",
            "sensitive": False,
        },
        "iam_secret_access_key": {
            "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "type": "string",
            "sensitive": True,
        },
    },
    "resources": [],
})

aws.s3.BucketObjectv2(
    "atomic-lambda-external-layer-poisoning-bait-tfstate",
    bucket=state_bucket.id,
    key="terraform.tfstate",
    content=BAIT_TFSTATE,
    content_type="application/json",
    opts=pulumi.ResourceOptions(depends_on=[state_bucket]),
)

# ── Pulumi Exports ────────────────────────────────────────────────────────────
pulumi.export("state_bucket_name",    state_bucket.bucket)
pulumi.export("state_bucket_arn",     state_bucket.arn)
pulumi.export("prod_secret_arn",      prod_secret.arn)
pulumi.export("baseline_layer_arn",   baseline_layer.arn)
pulumi.export("victim_function_arn",  victim_function.arn)
pulumi.export("attacker_role_arn",    attacker_role.arn)
pulumi.export("victim_exec_role_arn", victim_exec_role.arn)
