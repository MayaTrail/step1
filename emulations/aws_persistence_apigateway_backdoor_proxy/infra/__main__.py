import json
import pathlib
import pulumi
import pulumi_aws as aws

_NAMES = {'campaign': 'ATOMIC-APIGATEWAY-BACKDOOR-PROXY',
 'csp': 'aws',
 'resources': {'victim_rest_api_name': 'prod-customer-api',
               'backdoor_lambda_name': 'internal-health-check',
               'legit_lambda_name': 'atomic-apigateway-backdoor-proxy-legit-backend',
               'legit_lambda_role_name': 'atomic-apigateway-backdoor-proxy-legit-role',
               'backdoor_lambda_role_name': 'atomic-apigateway-backdoor-proxy-backdoor-role',
               'victim_role_name': 'atomic-apigateway-backdoor-proxy-victim-role',
               'api_stage_name': 'prod',
               'tfstate_object_key': 'infra/prod/terraform.tfstate',
               'access_log_group_name': '/aws/apigateway/prod-customer-api/prod'},
 'pulumi_export_keys': {'victim_rest_api_id': 'victim_rest_api_id',
                        'victim_rest_api_name': 'victim_rest_api_name',
                        'backdoor_lambda_arn': 'backdoor_lambda_arn',
                        'backdoor_lambda_name': 'backdoor_lambda_name',
                        'compromised_victim_role_arn': 'compromised_victim_role_arn',
                        'api_invoke_url': 'api_invoke_url',
                        'api_stage_name': 'api_stage_name',
                        'bait_bucket_name': 'bait_bucket_name',
                        'legit_lambda_arn': 'legit_lambda_arn'}}
_R = _NAMES["resources"]

VICTIM_REST_API_NAME   = _R["victim_rest_api_name"]
BACKDOOR_LAMBDA_NAME   = _R["backdoor_lambda_name"]
LEGIT_LAMBDA_NAME      = _R["legit_lambda_name"]
LEGIT_LAMBDA_ROLE_NAME = _R["legit_lambda_role_name"]
BACKDOOR_LAMBDA_ROLE_NAME = _R["backdoor_lambda_role_name"]
VICTIM_ROLE_NAME       = _R["victim_role_name"]
API_STAGE_NAME         = _R["api_stage_name"]
TFSTATE_OBJECT_KEY     = _R["tfstate_object_key"]
ACCESS_LOG_GROUP_NAME  = _R["access_log_group_name"]

account_id = aws.get_caller_identity().account_id
region     = aws.get_region().id

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-apigateway-backdoor-proxy",
    "Technique":   "T1190",
}

# Inline Lambda handlers - embedded so the backend worker has no sibling files to copy
LEGIT_LAMBDA_SRC = """\
import json

def handler(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps({'records': [{'id': 1, 'value': 'customer-record'}]})
    }
"""

BACKDOOR_LAMBDA_SRC = """\
import json

def handler(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps({'status': 'ok'})
    }
"""

# ── IAM Roles ──────────────────────────────────────────────────────────────────

legit_lambda_role = aws.iam.Role(
    "legit-lambda-role",
    name=LEGIT_LAMBDA_ROLE_NAME,
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
    "legit-lambda-role-basic-exec",
    role=legit_lambda_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

backdoor_lambda_role = aws.iam.Role(
    "backdoor-lambda-role",
    name=BACKDOOR_LAMBDA_ROLE_NAME,
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
    "backdoor-lambda-role-basic-exec",
    role=backdoor_lambda_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

# Self-trust so the pipeline executor can assume this role; never a placeholder account ID
compromised_victim_role = aws.iam.Role(
    "compromised-victim-role",
    name=VICTIM_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::{}:root".format(account_id)},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

# ── Lambda Functions ───────────────────────────────────────────────────────────

legit_lambda = aws.lambda_.Function(
    "legit-lambda",
    name=LEGIT_LAMBDA_NAME,
    runtime="python3.12",
    handler="index.handler",
    role=legit_lambda_role.arn,
    code=pulumi.AssetArchive({"index.py": pulumi.StringAsset(LEGIT_LAMBDA_SRC)}),
    timeout=10,
    tags=TAGS,
)

# Named to blend with legitimate internal utilities - no resource policy at deploy time;
# attack.py adds and removes a scoped InvokeFunction permission during the emulation run
backdoor_lambda = aws.lambda_.Function(
    "backdoor-lambda",
    name=BACKDOOR_LAMBDA_NAME,
    runtime="python3.12",
    handler="index.handler",
    role=backdoor_lambda_role.arn,
    code=pulumi.AssetArchive({"index.py": pulumi.StringAsset(BACKDOOR_LAMBDA_SRC)}),
    tags=TAGS,
)

# ── API Gateway REST API ───────────────────────────────────────────────────────

victim_rest_api = aws.apigateway.RestApi(
    "victim-rest-api",
    name=VICTIM_REST_API_NAME,
    endpoint_configuration=aws.apigateway.RestApiEndpointConfigurationArgs(
        types="REGIONAL",  # pulumi-aws v7: single string
    ),
    tags=TAGS,
)

legit_data_resource = aws.apigateway.Resource(
    "legit-data-resource",
    rest_api=victim_rest_api.id,
    parent_id=victim_rest_api.root_resource_id,
    path_part="data",
)

legit_get_method = aws.apigateway.Method(
    "legit-get-method",
    rest_api=victim_rest_api.id,
    resource_id=legit_data_resource.id,
    http_method="GET",
    authorization="NONE",
    api_key_required=False,
)

legit_lambda_integration = aws.apigateway.Integration(
    "legit-lambda-integration",
    rest_api=victim_rest_api.id,
    resource_id=legit_data_resource.id,
    http_method=legit_get_method.http_method,
    integration_http_method="POST",
    type="AWS_PROXY",
    uri=legit_lambda.invoke_arn,
)

# depends_on ensures the snapshot captures GET /data before the stage points to this deployment
api_prod_deployment = aws.apigateway.Deployment(
    "api-prod-deployment",
    rest_api=victim_rest_api.id,
    opts=pulumi.ResourceOptions(depends_on=[legit_get_method, legit_lambda_integration]),
)

access_log_group = aws.cloudwatch.LogGroup(
    "api-access-log-group",
    name=ACCESS_LOG_GROUP_NAME,
    retention_in_days=7,
    tags=TAGS,
)

api_prod_stage = aws.apigateway.Stage(
    "api-prod-stage",
    rest_api=victim_rest_api.id,
    stage_name=API_STAGE_NAME,
    deployment=api_prod_deployment.id,
    access_log_settings=aws.apigateway.StageAccessLogSettingsArgs(
        destination_arn=access_log_group.arn,
        format='{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","caller":"$context.identity.caller","user":"$context.identity.user","requestTime":"$context.requestTime","httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath","status":"$context.status"}',
    ),
    xray_tracing_enabled=False,
    tags=TAGS,
)

legit_lambda_permission = aws.lambda_.Permission(
    "legit-lambda-permission",
    action="lambda:InvokeFunction",
    function=legit_lambda.name,
    principal="apigateway.amazonaws.com",
    source_arn=victim_rest_api.id.apply(
        lambda api_id: "arn:aws:execute-api:{}:{}:{}/prod/GET/data".format(region, account_id, api_id)
    ),
    opts=pulumi.ResourceOptions(depends_on=[api_prod_stage]),
)

# ── Bait S3 Bucket ─────────────────────────────────────────────────────────────

bait_bucket_name_str = "{}-prod-deployments-tfstate".format(account_id)

bait_bucket = aws.s3.BucketV2(
    "bait-devops-bucket",
    bucket=bait_bucket_name_str,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "bait-bucket-public-access-block",
    bucket=bait_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# Realistic terraform.tfstate containing the victim API coordinates; simulates artifact
# an attacker reads during recon to discover the target before route injection
tfstate_content = pulumi.Output.all(
    api_id=victim_rest_api.id,
    invoke_url=api_prod_stage.invoke_url,
).apply(lambda args: json.dumps({
    "version": 4,
    "terraform_version": "1.5.7",
    "serial": 1,
    "lineage": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "outputs": {
        "api_gateway_id":  {"value": args["api_id"],     "type": "string"},
        "api_invoke_url":  {"value": args["invoke_url"], "type": "string"},
    },
    "resources": [{
        "mode":     "managed",
        "type":     "aws_api_gateway_rest_api",
        "name":     "prod_customer_api",
        "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
        "instances": [{
            "schema_version": 0,
            "attributes": {
                "id":                     args["api_id"],
                "name":                   "prod-customer-api",
                "endpoint_configuration": [{"types": ["REGIONAL"], "vpc_endpoint_ids": []}],
                "description":            "",
            },
        }],
    }],
}))

aws.s3.BucketObjectv2(
    "bait-devops-tfstate-object",
    bucket=bait_bucket.id,
    key=TFSTATE_OBJECT_KEY,
    content=tfstate_content,
    content_type="application/json",
    tags=TAGS,
)

# ── Victim Role Inline Policy ─────────────────────────────────────────────────
# Created after victim_rest_api and backdoor_lambda so their ARNs are available

aws.iam.RolePolicy(
    "victim-role-inline-policy",
    name="APIGatewayBackdoorEmulation",
    role=compromised_victim_role.name,
    policy=pulumi.Output.all(
        api_id=victim_rest_api.id,
        backdoor_arn=backdoor_lambda.arn,
    ).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":    "APIGatewayBackdoorWrite",
                "Effect": "Allow",
                "Action": [
                    "apigateway:GET",
                    "apigateway:PUT",
                    "apigateway:POST",
                    "apigateway:PATCH",
                    "apigateway:DELETE",
                ],
                # Scoped to this specific REST API - prevents abuse of the seeded role on other APIs
                "Resource": "arn:aws:apigateway:{}::/restapis/{}/*".format(region, args["api_id"]),
            },
            {
                "Sid":    "BackdoorLambdaPermissionManagement",
                "Effect": "Allow",
                "Action": [
                    "lambda:AddPermission",
                    "lambda:RemovePermission",
                ],
                # Scoped to backdoor Lambda only - no other Lambda can be modified
                "Resource": args["backdoor_arn"],
            },
        ],
    })),
)

# ── Exports ───────────────────────────────────────────────────────────────────

pulumi.export("victim_rest_api_id",          victim_rest_api.id)
pulumi.export("victim_rest_api_name",        VICTIM_REST_API_NAME)
pulumi.export("backdoor_lambda_arn",         backdoor_lambda.arn)
pulumi.export("backdoor_lambda_name",        BACKDOOR_LAMBDA_NAME)
pulumi.export("compromised_victim_role_arn", compromised_victim_role.arn)
pulumi.export("api_invoke_url",              api_prod_stage.invoke_url)
pulumi.export("api_stage_name",              API_STAGE_NAME)
pulumi.export("bait_bucket_name",            bait_bucket.id)
pulumi.export("legit_lambda_arn",            legit_lambda.arn)
