import json
import pathlib
import pulumi
import pulumi_aws as aws

# =========================================================================== #
# Resource Name Constants -- single source of truth via resource_names.json
# =========================================================================== #
_NAMES = json.loads((pathlib.Path(__file__).parent / "resource_names.json").read_text())
_R = _NAMES["resources"]

VICTIM_USER_NAME        = _R["victim_iam_user"]
VICTIM_POLICY_NAME      = _R["victim_policy"]
LAMBDA_EXEC_ROLE_NAME   = _R["lambda_exec_role"]
SSM_ROLE_NAME           = _R["ssm_role"]
INSTANCE_PROFILE_NAME   = _R["instance_profile"]
DECOY_ADMIN_USER_NAME   = _R["decoy_admin_user"]
SECRET_NAME             = _R["secret_name"]
TRAIL_NAME              = _R["trail_name"]
EXFIL_BUCKET_PREFIX     = _R["exfil_bucket_prefix"]
EXFIL_BUCKET_IAM_PATTERN = _R["exfil_bucket_iam_pattern"]
CT_BUCKET_PREFIX        = _R["cloudtrail_bucket_prefix"]
DEV_INSTANCE_NAME       = _R["dev_instance_name"]
TFSTATE_OBJECT_KEY      = _R["tfstate_object_key"]
FLOW_LOG_GROUP          = _R["flow_log_group"]
FLOW_LOG_ROLE_NAME      = _R["flow_log_role"]
RELAY_LAMBDA_NAME       = _R["relay_lambda_function"]

# AWS identity & region resolved at deploy time
identity   = aws.get_caller_identity()
account_id = identity.account_id
region     = aws.get_region().id

# =========================================================================== #
# VPC + Networking
# =========================================================================== #
vpc = aws.ec2.Vpc(
    "hazybeacon-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={"Name": "hazybeacon-vpc", "MayaTrail": "true", "Purpose": "adversary-emulation"},
)

igw = aws.ec2.InternetGateway(
    "hazybeacon-igw",
    vpc_id=vpc.id,
    tags={"Name": "hazybeacon-igw"},
)

public_subnet = aws.ec2.Subnet(
    "hazybeacon-public-subnet",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone=f"{region}a",
    map_public_ip_on_launch=True,
    tags={"Name": "hazybeacon-public-subnet"},
)

route_table = aws.ec2.RouteTable(
    "hazybeacon-route-table",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(
        cidr_block="0.0.0.0/0",
        gateway_id=igw.id,
    )],
    tags={"Name": "hazybeacon-route-table"},
)

aws.ec2.RouteTableAssociation(
    "hazybeacon-rta",
    subnet_id=public_subnet.id,
    route_table_id=route_table.id,
)

dev_sg = aws.ec2.SecurityGroup(
    "hazybeacon-dev-sg",
    vpc_id=vpc.id,
    description="HazyBeacon dev instance SG - HTTPS egress only for AWS API calls",
    ingress=[],
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=443,
        to_port=443,
        protocol="tcp",
        cidr_blocks=["0.0.0.0/0"],
        description="HTTPS outbound to AWS API endpoints and Lambda Function URLs",
    )],
    tags={"Name": "hazybeacon-dev-sg"},
)

# =========================================================================== #
# CloudTrail Bucket + Policy + Lifecycle
# =========================================================================== #
ct_bucket = aws.s3.BucketV2(
    "hazybeacon-cloudtrail-bucket",
    bucket_prefix=CT_BUCKET_PREFIX,
    force_destroy=True,
    tags={"Name": "hazybeacon-cloudtrail-bucket", "MayaTrail": "true"},
)

aws.s3.BucketPublicAccessBlock(
    "hazybeacon-ct-bucket-pab",
    bucket=ct_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

ct_bucket_policy_doc = pulumi.Output.all(ct_bucket.arn, ct_bucket.bucket).apply(
    lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudTrailGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": args[0],
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "CloudTrailPutObject",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{args[0]}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id,
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:cloudtrail:{region}:{account_id}:trail/{TRAIL_NAME}",
                    },
                },
            },
        ],
    })
)

# Bind to variable so trail can depend_on it (CreateTrail validates the policy server-side)
ct_bucket_policy_res = aws.s3.BucketPolicy(
    "hazybeacon-ct-bucket-policy",
    bucket=ct_bucket.id,
    policy=ct_bucket_policy_doc,
)

aws.s3.BucketLifecycleConfigurationV2(
    "hazybeacon-ct-bucket-lifecycle",
    bucket=ct_bucket.id,
    rules=[aws.s3.BucketLifecycleConfigurationV2RuleArgs(
        id="expire-cloudtrail-logs",
        status="Enabled",
        expiration=aws.s3.BucketLifecycleConfigurationV2RuleExpirationArgs(days=90),
    )],
)

# =========================================================================== #
# CloudTrail Trail
# =========================================================================== #
trail = aws.cloudtrail.Trail(
    "hazybeacon-cloudtrail",
    name=TRAIL_NAME,
    s3_bucket_name=ct_bucket.bucket,
    is_multi_region_trail=True,
    include_global_service_events=True,
    enable_log_file_validation=True,
    enable_logging=True,
    event_selectors=[aws.cloudtrail.TrailEventSelectorArgs(
        read_write_type="All",
        include_management_events=True,
    )],
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation", "ThreatActor": "HazyBeacon"},
    opts=pulumi.ResourceOptions(depends_on=[ct_bucket_policy_res]),
)

# =========================================================================== #
# Exfil Bucket + Public Access Block + Versioning + Seed Objects
# =========================================================================== #
exfil_bucket = aws.s3.BucketV2(
    "hazybeacon-exfil-bucket",
    bucket_prefix=EXFIL_BUCKET_PREFIX,
    force_destroy=True,
    tags={"Name": "hazybeacon-exfil-bucket", "MayaTrail": "true", "Purpose": "adversary-emulation"},
)

aws.s3.BucketPublicAccessBlock(
    "hazybeacon-exfil-bucket-pab",
    bucket=exfil_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketVersioningV2(
    "hazybeacon-exfil-bucket-versioning",
    bucket=exfil_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
)

# Seed objects -- placeholder text avoids empty-string serialization edge case
aws.s3.BucketObjectv2(
    "hazybeacon-exfil-pdf",
    bucket=exfil_bucket.id,
    key="internal-network-diagram.pdf",
    content="PLACEHOLDER - Internal Network Diagram v2.3 (emulation bait)",
    content_type="application/pdf",
)

aws.s3.BucketObjectv2(
    "hazybeacon-exfil-csv",
    bucket=exfil_bucket.id,
    key="employee-roster.csv",
    content=(
        "name,email,department,salary,ssn\n"
        "Alice Smith,alice@company.internal,Engineering,95000,111-22-3333\n"
        "Bob Jones,bob@company.internal,Finance,85000,222-33-4444\n"
        "Carol Davis,carol@company.internal,HR,78000,333-44-5555\n"
        "Dave Wilson,dave@company.internal,Marketing,72000,444-55-6666\n"
        "Eve Taylor,eve@company.internal,Engineering,98000,555-66-7777"
    ),
    content_type="text/csv",
)

aws.s3.BucketObjectv2(
    "hazybeacon-exfil-docx",
    bucket=exfil_bucket.id,
    key="q4-roadmap.docx",
    content="PLACEHOLDER - Q4 2025 Engineering Roadmap (emulation bait)",
    content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
)

# =========================================================================== #
# SecretsManager -- bait database credentials (discovery only, no retrieval)
# =========================================================================== #
secret = aws.secretsmanager.Secret(
    "hazybeacon-secrets",
    name=SECRET_NAME,
    description="Production PostgreSQL master credentials (adversary-emulation bait)",
    recovery_window_in_days=0,
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

aws.secretsmanager.SecretVersion(
    "hazybeacon-secrets-version",
    secret_id=secret.id,
    secret_string=json.dumps({
        "username": "db_admin",
        "password": "FAKE-NOT-REAL-Xk92mPqL",
        "host": "prod-db.internal.example.com",
        "port": 5432,
    }),
)

# =========================================================================== #
# Decoy / Canary IAM User (bait for T1087.004 enumeration)
# =========================================================================== #
decoy_admin = aws.iam.User(
    "hazybeacon-decoy-admin-user",
    name=DECOY_ADMIN_USER_NAME,
    path="/",
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation", "Canary": "true"},
)

# =========================================================================== #
# Lambda Execution Role (pre-provisioned for PassRole emulation)
# =========================================================================== #
lambda_exec_role = aws.iam.Role(
    "hazybeacon-lambda-exec-role",
    name=LAMBDA_EXEC_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

aws.iam.RolePolicyAttachment(
    "hazybeacon-lambda-exec-basic",
    role=lambda_exec_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

# =========================================================================== #
# Victim IAM User + Access Key + Inline Policy
# =========================================================================== #
victim_user = aws.iam.User(
    "hazybeacon-victim-iam-user",
    name=VICTIM_USER_NAME,
    path="/hazybeacon/",
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

victim_key = aws.iam.AccessKey(
    "hazybeacon-victim-access-key",
    user=victim_user.name,
)

# Policy references the exec role ARN (dynamic) -- built via Output.apply
victim_policy_doc = lambda_exec_role.arn.apply(
    lambda role_arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "STSAndAccountDiscovery",
                "Effect": "Allow",
                "Action": [
                    "sts:GetCallerIdentity",
                    "sts:AssumeRole",
                    "iam:ListUsers",
                    "iam:ListRoles",
                    "iam:ListGroups",
                    "iam:ListGroupsForUser",
                    "iam:ListAttachedUserPolicies",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListAttachedGroupPolicies",
                    "iam:ListUserPolicies",
                    "iam:GetUserPolicy",
                    "iam:GetPolicy",
                    "iam:GetUser",
                    "iam:GetRole",
                ],
                "Resource": "*",
            },
            {
                "Sid": "LambdaRelayDeploy",
                "Effect": "Allow",
                "Action": [
                    "lambda:CreateFunction",
                    "lambda:CreateFunctionUrlConfig",
                    "lambda:AddPermission",
                    "lambda:UpdateFunctionCode",
                    "lambda:GetFunction",
                    "lambda:GetFunctionUrlConfig",
                    "lambda:ListFunctions",
                    "lambda:DeleteFunction",
                    "lambda:DeleteFunctionUrlConfig",
                    "lambda:RemovePermission",
                    "lambda:TagResource",
                ],
                "Resource": "*",
            },
            {
                "Sid": "PassRoleToLambdaOnly",
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": role_arn,
                "Condition": {
                    "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"},
                },
            },
            {
                "Sid": "CloudWatchLogsForLambda",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {
                "Sid": "S3ListForDiscovery",
                "Effect": "Allow",
                "Action": ["s3:ListAllMyBuckets", "s3:ListBucket"],
                "Resource": "*",
            },
            {
                "Sid": "S3ReadForCredentialHarvest",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": f"arn:aws:s3:::{EXFIL_BUCKET_IAM_PATTERN}*/*",
            },
            {
                "Sid": "SecretsListForDiscovery",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:ListSecrets",
                    "secretsmanager:DescribeSecret",
                ],
                "Resource": "*",
            },
        ],
    })
)

aws.iam.UserPolicy(
    "hazybeacon-victim-policy-resource",
    name=VICTIM_POLICY_NAME,
    user=victim_user.name,
    policy=victim_policy_doc,
)

# =========================================================================== #
# SSM Role + Instance Profile (operator access -- separate from victim creds)
# =========================================================================== #
ssm_role = aws.iam.Role(
    "hazybeacon-ssm-role",
    name=SSM_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

aws.iam.RolePolicyAttachment(
    "hazybeacon-ssm-managed-core",
    role=ssm_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
)

instance_profile = aws.iam.InstanceProfile(
    "hazybeacon-instance-profile",
    name=INSTANCE_PROFILE_NAME,
    role=ssm_role.name,
)

# =========================================================================== #
# EC2 Dev Instance -- simulated developer workstation with harvested credentials
# =========================================================================== #
ami = aws.ec2.get_ami(
    most_recent=True,
    owners=["137112412989"],
    filters=[
        aws.ec2.GetAmiFilterArgs(name="name", values=["amzn2-ami-hvm-*-x86_64-gp2"]),
        aws.ec2.GetAmiFilterArgs(name="state", values=["available"]),
    ],
)


def make_userdata(args):
    key_id, key_secret = args
    tfstate_json = json.dumps(
        {
            "version": 4,
            "serial": 12,
            "terraform_version": "1.5.7",
            "outputs": {
                "deploy_access_key": {
                    "value": "AKIABAIT000000000000",
                    "type": "string",
                    "sensitive": False,
                },
                "deploy_secret_key": {
                    "value": "BAIT+notreal+XkP2mRqLx0000000000000000000",
                    "type": "string",
                    "sensitive": True,
                },
            },
            "resources": [],
        },
        separators=(",", ":"),
    )
    # Region captured from module-level constant (plain string, not Output)
    return "\n".join([
        "#!/bin/bash",
        "# [SIMULATED] T1552.001: Credential file placement on developer workstation",
        "mkdir -p /home/ec2-user/.aws",
        "cat > /home/ec2-user/.aws/credentials << 'CREDEOF'",
        "[default]",
        f"aws_access_key_id = {key_id}",
        f"aws_secret_access_key = {key_secret}",
        "CREDEOF",
        "cat > /home/ec2-user/.aws/config << 'CFGEOF'",
        "[default]",
        f"region = {region}",
        "output = json",
        "CFGEOF",
        "chown -R ec2-user:ec2-user /home/ec2-user/.aws",
        "chmod 600 /home/ec2-user/.aws/credentials /home/ec2-user/.aws/config",
        "history -cw",
        "mkdir -p /home/ec2-user/projects/infra-prod",
        "cat > /home/ec2-user/projects/infra-prod/terraform.tfstate << 'TFEOF'",
        tfstate_json,
        "TFEOF",
        "chown -R ec2-user:ec2-user /home/ec2-user/projects",
        "history -cw",
    ])


userdata = pulumi.Output.all(victim_key.id, victim_key.secret).apply(make_userdata)

dev_instance = aws.ec2.Instance(
    "hazybeacon-dev-instance",
    instance_type="t3.micro",
    ami=ami.id,
    subnet_id=public_subnet.id,
    vpc_security_group_ids=[dev_sg.id],
    iam_instance_profile=instance_profile.name,
    user_data=userdata,
    metadata_options=aws.ec2.InstanceMetadataOptionsArgs(
        http_tokens="optional",
        http_endpoint="enabled",
    ),
    tags={"Name": "hazybeacon-dev-instance", "MayaTrail": "true", "Purpose": "adversary-emulation"},
)

# =========================================================================== #
# TFState Bait Object in Exfil Bucket (static bait -- no real creds embedded)
# =========================================================================== #
tfstate_bait_content = json.dumps(
    {
        "version": 4,
        "serial": 12,
        "terraform_version": "1.5.7",
        "outputs": {
            "deploy_access_key": {
                "value": "AKIABAIT000000000000",
                "type": "string",
                "sensitive": False,
            },
            "deploy_secret_key": {
                "value": "BAIT+notreal+XkP2mRqLx0000000000000000000",
                "type": "string",
                "sensitive": True,
            },
        },
        "resources": [],
    },
    separators=(",", ":"),
)

aws.s3.BucketObjectv2(
    "hazybeacon-tfstate-bait",
    bucket=exfil_bucket.id,
    key=TFSTATE_OBJECT_KEY,
    content=tfstate_bait_content,
    content_type="application/json",
)

# =========================================================================== #
# VPC Flow Logs -- captures HTTPS connections to Lambda Function URLs (T1102, T1090)
# =========================================================================== #
flow_log_group_res = aws.cloudwatch.LogGroup(
    "hazybeacon-flow-log-group",
    name=FLOW_LOG_GROUP,
    retention_in_days=30,
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

flow_log_role = aws.iam.Role(
    "hazybeacon-flow-log-role",
    name=FLOW_LOG_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags={"MayaTrail": "true"},
)

aws.iam.RolePolicy(
    "hazybeacon-flow-log-role-policy",
    role=flow_log_role.name,
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

aws.ec2.FlowLog(
    "hazybeacon-flow-log",
    vpc_id=vpc.id,
    traffic_type="ALL",
    log_destination_type="cloud-watch-logs",
    log_destination=flow_log_group_res.arn,
    iam_role_arn=flow_log_role.arn,
    tags={"MayaTrail": "true", "Purpose": "adversary-emulation"},
)

# =========================================================================== #
# Exports -- static name constants + dynamic resource outputs
# All exported keys must match what attack.py reads from `pulumi stack output`
# =========================================================================== #

# Static name constants
pulumi.export("victim_iam_user_name",       pulumi.Output.from_input(VICTIM_USER_NAME))
pulumi.export("victim_policy_name",         pulumi.Output.from_input(VICTIM_POLICY_NAME))
pulumi.export("lambda_exec_role_name",      pulumi.Output.from_input(LAMBDA_EXEC_ROLE_NAME))
pulumi.export("ssm_role_name",              pulumi.Output.from_input(SSM_ROLE_NAME))
pulumi.export("instance_profile_name",      pulumi.Output.from_input(INSTANCE_PROFILE_NAME))
pulumi.export("decoy_admin_user_name",      pulumi.Output.from_input(DECOY_ADMIN_USER_NAME))
pulumi.export("secret_name",               pulumi.Output.from_input(SECRET_NAME))
pulumi.export("trail_name",                pulumi.Output.from_input(TRAIL_NAME))
pulumi.export("exfil_bucket_prefix",       pulumi.Output.from_input(EXFIL_BUCKET_PREFIX))
pulumi.export("exfil_bucket_iam_pattern",  pulumi.Output.from_input(EXFIL_BUCKET_IAM_PATTERN))
pulumi.export("cloudtrail_bucket_prefix",  pulumi.Output.from_input(CT_BUCKET_PREFIX))
pulumi.export("dev_instance_name",         pulumi.Output.from_input(DEV_INSTANCE_NAME))
pulumi.export("tfstate_object_key",        pulumi.Output.from_input(TFSTATE_OBJECT_KEY))
pulumi.export("flow_log_group_name",       pulumi.Output.from_input(FLOW_LOG_GROUP))
pulumi.export("flow_log_role_name",        pulumi.Output.from_input(FLOW_LOG_ROLE_NAME))
pulumi.export("relay_lambda_function_name", pulumi.Output.from_input(RELAY_LAMBDA_NAME))

# Dynamic outputs (known only after pulumi up)
pulumi.export("victim_access_key_id",      victim_key.id)
pulumi.export("victim_secret_access_key",  victim_key.secret)
pulumi.export("exfil_bucket_name",         exfil_bucket.bucket)
pulumi.export("cloudtrail_bucket_name",    ct_bucket.bucket)
pulumi.export("dev_instance_id",           dev_instance.id)
pulumi.export("lambda_exec_role_arn",      lambda_exec_role.arn)
pulumi.export("vpc_id",                    vpc.id)
pulumi.export("subnet_id",                 public_subnet.id)
pulumi.export("dev_sg_id",                 dev_sg.id)
pulumi.export("secret_arn",                secret.arn)
pulumi.export("victim_user_arn",           victim_user.arn)
