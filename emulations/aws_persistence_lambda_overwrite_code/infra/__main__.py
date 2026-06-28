import json
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
FUNCTION_NAME = "stratus-red-team-overwrite-lambda"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.persistence.lambda-overwrite-code",
}

HANDLER_CODE = """\
import json

def handler(event, context):
    # Legitimate business logic
    return {"statusCode": 200, "body": json.dumps({"message": "Hello from Lambda", "version": "1.0"})}
"""

# ── IAM execution role ─────────────────────────────────────────────────────────
lambda_role = aws.iam.Role(
    "overwrite-lambda-role",
    name="stratus-red-team-overwrite-lambda-role",
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
    "overwrite-lambda-basic",
    role=lambda_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

# ── Lambda function ────────────────────────────────────────────────────────────
lambda_fn = aws.lambda_.Function(
    "overwrite-lambda",
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
