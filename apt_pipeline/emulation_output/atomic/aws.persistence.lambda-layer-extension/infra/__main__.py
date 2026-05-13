import json
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
FUNCTION_NAME = "stratus-red-team-layer-lambda"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.persistence.lambda-layer-extension",
}

HANDLER_CODE = """\
import json

def handler(event, context):
    return {"statusCode": 200, "body": "Hello from Lambda"}
"""

# ── IAM execution role ─────────────────────────────────────────────────────────
lambda_role = aws.iam.Role(
    "layer-lambda-role",
    name="stratus-red-team-layer-lambda-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    "layer-lambda-basic",
    role=lambda_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

# ── Lambda function ────────────────────────────────────────────────────────────
lambda_fn = aws.lambda_.Function(
    "layer-lambda",
    name=FUNCTION_NAME,
    runtime="python3.12",
    handler="index.handler",
    role=lambda_role.arn,
    code=pulumi.AssetArchive({
        "index.py": pulumi.StringAsset(HANDLER_CODE),
    }),
    tags=TAGS,
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("function_name", FUNCTION_NAME)
pulumi.export("function_arn",  lambda_fn.arn)
