import json
import sys

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import pulumi
import pulumi_aws as aws
import pulumi_tls as tls

# ============================================================
# Account / region resolution (before derived name constants)
# ============================================================
caller_identity = aws.get_caller_identity()
account_id      = caller_identity.account_id
region          = aws.get_region().id

# ============================================================
# Resource Name Constants
# Inlined here because the backend worker copies only
# Pulumi.yaml + __main__.py; resource_names.json is written
# alongside for local/attack.py use but is absent at deploy time.
# ============================================================
_R = {
    "flow_log_bucket":        "elbv2-bypass-flow-log-bucket",
    "cognito_pool_name":      "elbv2-bypass-pool",
    "cognito_client_name":    "elbv2-bypass-alb-client",
    "cognito_domain_prefix":  "elbv2bypass",
    "lambda_exec_role_name":  "elbv2-bypass-lambda-exec-role",
    "backend_lambda_name":    "elbv2-bypass-backend-lambda",
    "protected_tg_name":      "elbv2-bypass-protected-tg",
    "alb_name":               "elbv2-bypass-alb",
    "victim_user_name":       "elbv2-bypass-devops-svc",
    "victim_policy_name":     "elbv2-bypass-victim-policy",
    "canary_secret_name":     "prod/internal-portal/db-master",
}

# S3 bucket names are global across all AWS accounts; suffix with
# last 6 digits of the account ID to avoid cross-tenant collisions.
# All other names are account-scoped and kept static for fidelity.
FLOW_LOG_BUCKET_NAME   = f"{_R['flow_log_bucket']}-{account_id[-6:]}"
COGNITO_POOL_NAME      = _R["cognito_pool_name"]
COGNITO_CLIENT_NAME    = _R["cognito_client_name"]
COGNITO_DOMAIN_PREFIX  = _R["cognito_domain_prefix"]
LAMBDA_EXEC_ROLE_NAME  = _R["lambda_exec_role_name"]
BACKEND_LAMBDA_NAME    = _R["backend_lambda_name"]
PROTECTED_TG_NAME      = _R["protected_tg_name"]
ALB_NAME               = _R["alb_name"]
VICTIM_USER_NAME       = _R["victim_user_name"]
VICTIM_POLICY_NAME     = _R["victim_policy_name"]
CANARY_SECRET_NAME     = _R["canary_secret_name"]

# Cognito user pool domain must be globally unique; derive a
# deterministic suffix from the last 6 digits of the account ID.
COGNITO_DOMAIN_NAME = f"{COGNITO_DOMAIN_PREFIX}{account_id[-6:]}"

# ============================================================
# Lambda handler - ALB event format response
# ============================================================
HANDLER_SRC = """\
import json

def handler(event, context):
    return {
        "statusCode": 200,
        "statusDescription": "200 OK",
        "isBase64Encoded": False,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "portal": "internal-hr",
            "records": [
                {"emp_id": "E0042", "salary": "REDACTED"},
                {"emp_id": "E0099", "salary": "REDACTED"}
            ]
        })
    }
"""

TAGS = {"MayaTrail": "true", "Purpose": "adversary-emulation", "TechniqueId": "T1556"}

# ============================================================
# 1. VPC Flow Log S3 Bucket
# ============================================================
flow_log_bucket = aws.s3.BucketV2(
    "elbv2-bypass-flow-log-bucket",
    bucket=FLOW_LOG_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "elbv2-bypass-flow-log-bucket-sse",
    bucket=flow_log_bucket.id,
    rules=[
        aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256",
            ),
        ),
    ],
)

flow_log_bucket_policy = aws.s3.BucketPolicy(
    "elbv2-bypass-flow-log-bucket-policy",
    bucket=flow_log_bucket.id,
    # account_id is a plain str resolved synchronously — use single-Output apply
    # to avoid Output.all() indexing ambiguity with mixed str/Output args.
    policy=flow_log_bucket.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSLogDeliveryWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "delivery.logs.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"{arn}/AWSLogs/{account_id}/*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account_id},
                    },
                },
                {
                    "Sid": "AWSLogDeliveryAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "delivery.logs.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": arn,
                },
            ],
        })
    ),
)

# ============================================================
# 2. TLS Key + Self-Signed Cert + ACM Import
# ============================================================
tls_key = tls.PrivateKey(
    "elbv2-bypass-self-signed-key",
    algorithm="RSA",
    rsa_bits=2048,
)

tls_cert = tls.SelfSignedCert(
    "elbv2-bypass-self-signed-cert",
    private_key_pem=tls_key.private_key_pem,
    subject=tls.SelfSignedCertSubjectArgs(
        common_name="sandbox.internal",
    ),
    validity_period_hours=8760,
    allowed_uses=["key_encipherment", "digital_signature", "server_auth"],
    is_ca_certificate=False,
)

acm_cert = aws.acm.Certificate(
    "elbv2-bypass-acm-cert",
    private_key=tls_key.private_key_pem,
    certificate_body=tls_cert.cert_pem,
    tags=TAGS,
)

# ============================================================
# 3. Lambda Execution Role
# ============================================================
lambda_exec_role = aws.iam.Role(
    "elbv2-bypass-lambda-exec-role",
    name=LAMBDA_EXEC_ROLE_NAME,
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
    "elbv2-bypass-lambda-exec-role-basic",
    role=lambda_exec_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

# ============================================================
# 4. Cognito User Pool
# ============================================================
cognito_pool = aws.cognito.UserPool(
    "elbv2-bypass-cognito-pool",
    name=COGNITO_POOL_NAME,
    admin_create_user_config=aws.cognito.UserPoolAdminCreateUserConfigArgs(
        allow_admin_create_user_only=True,
    ),
    password_policy=aws.cognito.UserPoolPasswordPolicyArgs(
        minimum_length=8,
        require_uppercase=False,
        require_lowercase=False,
        require_numbers=False,
        require_symbols=False,
    ),
    tags=TAGS,
)

# ============================================================
# 5. VPC
# ============================================================
vpc = aws.ec2.Vpc(
    "elbv2-bypass-vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": "elbv2-bypass-vpc"},
)

# ============================================================
# 6. Internet Gateway
# ============================================================
igw = aws.ec2.InternetGateway(
    "elbv2-bypass-igw",
    vpc_id=vpc.id,
    tags={**TAGS, "Name": "elbv2-bypass-igw"},
)

# ============================================================
# 7. Public Subnets (two AZs required by ALB)
# ============================================================
subnet_a = aws.ec2.Subnet(
    "elbv2-bypass-subnet-public-a",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    availability_zone=f"{region}a",
    map_public_ip_on_launch=True,
    tags={**TAGS, "Name": "elbv2-bypass-subnet-public-a"},
)

subnet_b = aws.ec2.Subnet(
    "elbv2-bypass-subnet-public-b",
    vpc_id=vpc.id,
    cidr_block="10.99.2.0/24",
    availability_zone=f"{region}b",
    map_public_ip_on_launch=True,
    tags={**TAGS, "Name": "elbv2-bypass-subnet-public-b"},
)

# ============================================================
# 8. ALB Security Group
# ============================================================
alb_sg = aws.ec2.SecurityGroup(
    "elbv2-bypass-alb-sg",
    name="elbv2-bypass-alb-sg",
    description="ALB SG - allow HTTPS and HTTP inbound for test traffic",
    vpc_id=vpc.id,
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            from_port=443,
            to_port=443,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
            description="HTTPS inbound",
        ),
        aws.ec2.SecurityGroupIngressArgs(
            from_port=80,
            to_port=80,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
            description="HTTP inbound",
        ),
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            from_port=0,
            to_port=0,
            protocol="-1",
            cidr_blocks=["0.0.0.0/0"],
            description="All outbound",
        ),
    ],
    tags=TAGS,
)

# ============================================================
# 9. Cognito Domain
# ============================================================
cognito_domain = aws.cognito.UserPoolDomain(
    "elbv2-bypass-cognito-domain",
    domain=COGNITO_DOMAIN_NAME,
    user_pool_id=cognito_pool.id,
)

# ============================================================
# 10. Route Table + Associations
# ============================================================
rt_public = aws.ec2.RouteTable(
    "elbv2-bypass-rt-public",
    vpc_id=vpc.id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            gateway_id=igw.id,
        ),
    ],
    tags={**TAGS, "Name": "elbv2-bypass-rt-public"},
)

rt_assoc_a = aws.ec2.RouteTableAssociation(
    "elbv2-bypass-rt-assoc-a",
    subnet_id=subnet_a.id,
    route_table_id=rt_public.id,
)

rt_assoc_b = aws.ec2.RouteTableAssociation(
    "elbv2-bypass-rt-assoc-b",
    subnet_id=subnet_b.id,
    route_table_id=rt_public.id,
)

# ============================================================
# 11. VPC Flow Log (depends on bucket policy being applied first)
# ============================================================
vpc_flow_log = aws.ec2.FlowLog(
    "elbv2-bypass-flow-log",
    log_destination=flow_log_bucket.arn,
    log_destination_type="s3",
    traffic_type="ALL",
    vpc_id=vpc.id,
    opts=pulumi.ResourceOptions(depends_on=[flow_log_bucket_policy]),
)

# ============================================================
# 12. Backend Lambda (inline code - no sibling files at deploy time)
# ============================================================
backend_lambda = aws.lambda_.Function(
    "elbv2-bypass-backend-lambda",
    name=BACKEND_LAMBDA_NAME,
    runtime="python3.12",
    handler="index.handler",
    role=lambda_exec_role.arn,
    code=pulumi.AssetArchive({"index.py": pulumi.StringAsset(HANDLER_SRC)}),
    tags=TAGS,
)

# ============================================================
# 13. Lambda-type Target Group
# ============================================================
protected_tg = aws.alb.TargetGroup(
    "elbv2-bypass-protected-tg",
    name=PROTECTED_TG_NAME,
    target_type="lambda",
    health_check=aws.alb.TargetGroupHealthCheckArgs(
        enabled=False,
        # Even with enabled=False the ELBv2 API validates interval > timeout;
        # the pulumi-aws v7 SDK-v2 provider sends defaults that violate this for
        # a lambda target group, so pin a valid pair.
        interval=30,
        timeout=5,
    ),
    tags=TAGS,
)

# ============================================================
# 14. Lambda Permission for ALB
# Must be created before TG attachment so ALB can invoke immediately
# ============================================================
lambda_permission = aws.lambda_.Permission(
    "elbv2-bypass-lambda-permission",
    action="lambda:InvokeFunction",
    function=backend_lambda.name,
    principal="elasticloadbalancing.amazonaws.com",
    source_arn=protected_tg.arn,
)

# ============================================================
# 15. Target Group Attachment
# ============================================================
tg_attachment = aws.alb.TargetGroupAttachment(
    "elbv2-bypass-tg-attachment",
    target_group_arn=protected_tg.arn,
    target_id=backend_lambda.arn,
    opts=pulumi.ResourceOptions(depends_on=[lambda_permission]),
)

# ============================================================
# 16. Internet-Facing ALB
# ============================================================
alb = aws.alb.LoadBalancer(
    "elbv2-bypass-alb",
    name=ALB_NAME,
    internal=False,
    load_balancer_type="application",
    subnets=[subnet_a.id, subnet_b.id],
    security_groups=[alb_sg.id],
    enable_deletion_protection=False,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[rt_assoc_a, rt_assoc_b]),
)

# ============================================================
# 17. Cognito App Client
# callback_urls computed from ALB DNS via Output chaining
# ============================================================
cognito_client = aws.cognito.UserPoolClient(
    "elbv2-bypass-cognito-client",
    name=COGNITO_CLIENT_NAME,
    user_pool_id=cognito_pool.id,
    generate_secret=True,
    supported_identity_providers=["COGNITO"],
    allowed_oauth_flows=["code"],
    allowed_oauth_scopes=["openid", "email", "profile"],
    allowed_oauth_flows_user_pool_client=True,
    callback_urls=alb.dns_name.apply(lambda dns: [f"https://{dns}/oauth2/idpresponse"]),
)

# ============================================================
# 18. HTTPS Listener with authenticate-cognito default action
# This is the listener the attacker targets with CreateRule/ModifyRule
# ============================================================
listener = aws.alb.Listener(
    "elbv2-bypass-listener",
    load_balancer_arn=alb.arn,
    port=443,
    protocol="HTTPS",
    certificate_arn=acm_cert.arn,
    ssl_policy="ELBSecurityPolicy-TLS13-1-2-2021-06",
    default_actions=[
        aws.alb.ListenerDefaultActionArgs(
            type="authenticate-cognito",
            order=1,
            authenticate_cognito=aws.alb.ListenerDefaultActionAuthenticateCognitoArgs(
                user_pool_arn=cognito_pool.arn,
                user_pool_client_id=cognito_client.id,
                user_pool_domain=cognito_domain.domain,
            ),
        ),
        aws.alb.ListenerDefaultActionArgs(
            type="forward",
            order=2,
            target_group_arn=protected_tg.arn,
        ),
    ],
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[tg_attachment]),
)

# ============================================================
# 19. Pre-seeded /health rule (priority 10)
# Simulates a real deployment where health checks bypass auth.
# Attack variant: modify this rule's condition from /health to /*
# ============================================================
health_rule = aws.alb.ListenerRule(
    "elbv2-bypass-health-rule",
    listener_arn=listener.arn,
    priority=10,
    conditions=[
        aws.alb.ListenerRuleConditionArgs(
            path_pattern=aws.alb.ListenerRuleConditionPathPatternArgs(
                values=["/health"],
            ),
        ),
    ],
    actions=[
        aws.alb.ListenerRuleActionArgs(
            type="forward",
            target_group_arn=protected_tg.arn,
        ),
    ],
    tags=TAGS,
)

# ============================================================
# 20. Victim IAM Policy (intentionally over-permissioned)
# Models a DevOps service account with broad ELB management permissions
# ============================================================
victim_policy = aws.iam.Policy(
    "elbv2-bypass-victim-policy",
    name=VICTIM_POLICY_NAME,
    description="Over-permissioned ELB policy for emulation - DevOps service account model",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateRule",
                "elasticloadbalancing:ModifyRule",
                "elasticloadbalancing:DeleteRule",
                "elasticloadbalancing:SetRulePriorities",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeRules",
                "elasticloadbalancing:DescribeTargetGroups",
            ],
            "Resource": "*",
        }],
    }),
    tags=TAGS,
)

# ============================================================
# 21. Victim IAM User + Access Key
# ============================================================
victim_user = aws.iam.User(
    "elbv2-bypass-victim-user",
    name=VICTIM_USER_NAME,
    tags=TAGS,
)

aws.iam.UserPolicyAttachment(
    "elbv2-bypass-victim-policy-attachment",
    user=victim_user.name,
    policy_arn=victim_policy.arn,
)

victim_access_key = aws.iam.AccessKey(
    "elbv2-bypass-victim-access-key",
    user=victim_user.name,
)

# ============================================================
# 22. Canary Secret (bait - victim role cannot read it)
# ============================================================
canary_secret = aws.secretsmanager.Secret(
    "elbv2-bypass-canary-secret",
    name=CANARY_SECRET_NAME,
    recovery_window_in_days=0,
    tags=TAGS,
)

aws.secretsmanager.SecretVersion(
    "elbv2-bypass-canary-secret-version",
    secret_id=canary_secret.id,
    secret_string=json.dumps({
        "username": "admin",
        "password": "CANARY-FAKE-kX9zRp3mQ7",
        "engine": "mysql",
        "host": "db.internal.company.com",
        "port": 3306,
    }),
)

# ============================================================
# Stack Outputs - consumed by attack.py via run(outputs, region)
# ============================================================
pulumi.export("alb_dns_name",             alb.dns_name)
pulumi.export("listener_arn",             listener.arn)
pulumi.export("health_rule_arn",          health_rule.arn)
pulumi.export("protected_tg_arn",         protected_tg.arn)
pulumi.export("cognito_pool_id",          cognito_pool.id)
pulumi.export("cognito_client_id",        cognito_client.id)
pulumi.export("cognito_domain",           cognito_domain.domain)
pulumi.export("victim_access_key_id",     victim_access_key.id)
pulumi.export("victim_secret_access_key", pulumi.Output.secret(victim_access_key.secret))
pulumi.export("victim_user_name",         VICTIM_USER_NAME)
pulumi.export("flow_log_bucket_name",     flow_log_bucket.bucket)
pulumi.export("access_key_id",            victim_access_key.id)
pulumi.export("secret_access_key",        pulumi.Output.secret(victim_access_key.secret))
pulumi.export("dns_name",                 alb.dns_name)
