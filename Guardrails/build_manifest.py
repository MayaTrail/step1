"""Generate Guardrails/MANIFEST.json.

Purposes are hand-authored (no source file carries them).  Type and service tags
are derived from the policy body so they cannot drift from the JSON:

  type      RCP if any statement carries Principal, else SCP.
  services  Service prefixes of Action entries.  NotAction enumerates exemptions
            from an otherwise-total deny, and Action:"*" is org-wide — both tag
            as "All services" rather than the enumerated prefixes.
"""
import json
import os
import sys

GUARDRAILS = os.path.dirname(os.path.abspath(__file__))

SOURCES = {
    "aws-docs": "AWS Organizations documentation",
    "data-perimeter": "aws-samples/data-perimeter-policy-examples",
    "ttc": "towardsthecloud.com — AWS SCP examples",
}

# file -> (purpose, source-key)
POLICIES = {
    # ── AWS Organizations documentation ──────────────────────────────────────
    "Cognito-Deny-deletion-and-only-allow-specific-roles.json": (
        "Restrict Cognito user pool and domain deletion to named roles", "aws-docs"),
    "Cognito-Deny-identity-pool-unauthenticated-access.json": (
        "Block unauthenticated (guest) access to Cognito identity pools", "aws-docs"),
    "Deny-AWS-Backup-deletion-and-changes-to-configuration.json": (
        "Prevent deletion of backup plans, vaults and vault access policies", "aws-docs"),
    "Deny-AWS-CLI-login-using-console-credentials.json": (
        "Block CLI sessions minted from console credentials", "aws-docs"),
    "Deny-Amazon-Virtual-Private-Network-connection-creation-modification-deletion.json": (
        "Lock down creation and teardown of VPN gateways and connections", "aws-docs"),
    "Deny-Bedrock-api-keys-longer-than-30-days.json": (
        "Cap Bedrock API key lifetime at 30 days", "aws-docs"),
    "Deny-Bedrock-api-keys.json": (
        "Block Bedrock API key creation and bearer-token invocation outright", "aws-docs"),
    "Deny-Bedrock-long-term-api-keys.json": (
        "Allow only short-term Bedrock bearer tokens", "aws-docs"),
    "Deny-Bedrock-model-invocation-except-approved-models.json": (
        "Allow Bedrock invocation only for an approved foundation-model allowlist", "aws-docs"),
    "Deny-CloudHSM-deletion.json": (
        "Restrict CloudHSM cluster and backup deletion to privileged roles", "aws-docs"),
    "Deny-KMS-key-deletion.json": (
        "Restrict KMS key, alias and key-store deletion to privileged roles", "aws-docs"),
    "Deny-RAM-from-sharing-resources-to-external-accounts.json": (
        "Block RAM resource shares that allow principals outside the organization", "aws-docs"),
    "Deny-access-to-AWS-based-on-the-requested-AWS-region-with-Bedrock-CRIS.json": (
        "Confine activity to approved regions while allowing Bedrock cross-region inference", "aws-docs"),
    "Deny-access-to-AWS-based-on-the-requested-AWS-region.json": (
        "Confine activity to approved regions, exempting global services", "aws-docs"),
    "Deny-account-region-enable-and-disable-actions.json": (
        "Prevent opt-in regions being enabled or disabled", "aws-docs"),
    "Deny-billing-modification-action.json": (
        "Protect billing preferences, tax settings and account contacts from change", "aws-docs"),
    "Deny-built-in-web-identity-providers.json": (
        "Block role assumption via the built-in public web identity providers", "aws-docs"),
    "Deny-creation-of-default-VPC-and-subnet.json": (
        "Prevent recreation of the default VPC and its subnets", "aws-docs"),
    "Deny-critical-IAM-user-actions.json": (
        "Block IAM user, access key and login profile creation outside break-glass roles", "aws-docs"),
    "Deny-disabling-default-EBS-encryption.json": (
        "Keep EBS encryption-by-default switched on", "aws-docs"),
    "Deny-key-actions-on-Route53-DNS-hosted-zones.json": (
        "Protect hosted zones and domain registration from transfer or deletion", "aws-docs"),
    "Deny-member-accounts-from-leaving-your-AWS-organization.json": (
        "Prevent member accounts from leaving the organization", "aws-docs"),
    "Deny-modification-to-Lambda-URL-Config.json": (
        "Require IAM auth on Lambda function URLs", "aws-docs"),
    "Deny-modification-to-SSM-service-settings.json": (
        "Protect Systems Manager service settings from modification", "aws-docs"),
    "Deny-modifications-to-specific-Amazon-Lambda-functions.json": (
        "Freeze designated Lambda functions against code and permission changes", "aws-docs"),
    "Deny-modifications-to-specific-IAM-roles.json": (
        "Freeze designated IAM roles against policy and trust changes", "aws-docs"),
    "Deny-resource-access-if-the-resource-belongs-to-a-specific-organizational-unit.json": (
        "Allow access to an OU's resources only from named principals", "aws-docs"),
    "Deny-access-to-resources-in-an-organizational-unit,except-for-principals-from-the-same-or-specified-organizational-unit.json": (
        "Confine an OU's resources to principals from the same or an allowed OU", "aws-docs"),
    "Deny-the-root-user-from-performing-actions-except-S3-bucketpolicy-changes.json": (
        "Deny the root user everything except S3 bucket-policy break-glass", "aws-docs"),
    "Deny-unwanted-cancellation-or-changes-to-AWS-Marketplace-product-subscription.json": (
        "Restrict Marketplace subscribe, unsubscribe and private-marketplace changes", "aws-docs"),
    "Deny-unwarranted-IAM-federations-creation-modification.json": (
        "Restrict creation and modification of SAML and OIDC identity providers", "aws-docs"),
    "Deny-use-of-IAM-user-credentials-from-unexpected-networks.json": (
        "Confine IAM user credentials to your corporate network and VPCs", "aws-docs"),
    "Deny-users-from-deleting-Amazon-Glacier-vaults-or-archives.json": (
        "Prevent deletion of S3 Glacier vaults and archives", "aws-docs"),
    "DenyGrantOnAWSManagedEKSKey.json": (
        "Block KMS grants on the AWS-managed EKS key", "aws-docs"),
    "Enforce-30-days-for-KMS-deletion.json": (
        "Require a 30-day pending window before any KMS key deletion", "aws-docs"),
    "Enforce-controls-on-AWS-services-that-use-service-principals-to-access-your-resources.json": (
        "Close the confused-deputy gap for AWS service principals reaching your resources", "aws-docs"),
    "IAM-Restrict-outbound-federation.json": (
        "Constrain outbound web identity tokens by audience, algorithm and lifetime", "aws-docs"),
    "KMS-Deny-AWS-Key-Management-Service-asymmetric-key-with-RSA-key-material-used-for-encryption-with-key-length-of-2048-bits.json": (
        "Block creation of RSA-2048 encryption keys", "aws-docs"),
    "KMS-Deny-the-accidental-or-intentional-deletion-of-a-KMS-key-and-only-allow-specific-roles-to-delete-KMS-keys.json": (
        "Restrict KMS key deletion to named roles, enforced at the key", "aws-docs"),
    "KMS-Require-an-AWS-Key-Management-Service-key-policy-limiting-creation-of-AWS-KMS-grants-to-AWS-services.json": (
        "Allow KMS grants only where AWS services create them for your resources", "aws-docs"),
    "KMS-Require-that-an-AWS-KMS-key-is-configured-with-the-bypass-policy-lockout-safety-check-enabled.json": (
        "Require the KMS policy-lockout safety check to stay enabled", "aws-docs"),
    "Prevent-creating-or-expanding-public-connectivity-for-VPCs.json": (
        "Block internet gateways, peering and other public VPC connectivity", "aws-docs"),
    "Prevent-root-credentials-management-in-member-accounts-in-AWS-Organizations.json": (
        "Deny member-account root credentials except via centralized root access", "aws-docs"),
    "ProtectPodIdentitiesTagsOnRolesAndUsers.json": (
        "Prevent EKS pod-identity tag keys being set on IAM roles and users", "aws-docs"),
    "Restrict-access-to-only-HTTPS-connections-to-your-resources.json": (
        "Require TLS for every request reaching your resources", "aws-docs"),
    "Restrict-deletion-and-modification-of-privileged-policies.json": (
        "Protect privileged managed policies from edit and deletion", "aws-docs"),
    "S3-Deny-ACL-disablement-for-all-new-buckets-(bucket-owner-enforced).json": (
        "Require bucket-owner-enforced ownership on new buckets, enforced at the resource", "aws-docs"),
    "S3-Deny-SSE-C.json": (
        "Block customer-provided-key (SSE-C) uploads", "aws-docs"),
    "S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects.json": (
        "Prevent deletion of buckets, objects and object versions", "aws-docs"),
    "S3-Deny-users-from-modifying-S3-Block-Public-Access-(Account-Level).json": (
        "Protect account-level S3 Block Public Access from being weakened", "aws-docs"),
    "STS-Protect-EKS-pod-identities-tags.json": (
        "Allow only EKS to set EKS pod-identity session tags", "aws-docs"),
    "STS-protect-IAMRA-session-tags.json": (
        "Allow only IAM Roles Anywhere to set x509 session tags", "aws-docs"),

    # ── aws-samples/data-perimeter-policy-examples ───────────────────────────
    "api_gateway_policy.json": (
        "Apply the full data perimeter to API Gateway APIs", "data-perimeter"),
    "data_perimeter_governance_rcp.json": (
        "Protect the session tags the data perimeter itself depends on", "data-perimeter"),
    "data_perimeter_governance_scp.json": (
        "Close the sharing and tagging gaps the primary perimeter controls miss", "data-perimeter"),
    "identity_perimeter_rcp.json": (
        "Allow only your organization's identities to reach your resources", "data-perimeter"),
    "network_perimeter_ec2_scp.json": (
        "Confine EC2 role credentials to expected networks", "data-perimeter"),
    "network_perimeter_glue_scp.json": (
        "Confine Glue role credentials to expected networks", "data-perimeter"),
    "network_perimeter_iam_users_scp.json": (
        "Confine IAM user credentials to expected networks", "data-perimeter"),
    "network_perimeter_lambda_scp.json": (
        "Confine Lambda role credentials to expected networks", "data-perimeter"),
    "network_perimeter_sourcevpc_scp.json": (
        "Confine all principals to your VPCs and corporate CIDRs", "data-perimeter"),
    "network_perimeter_sourcevpc_rcp.json": (
        "Accept requests to your resources only from your VPCs and corporate CIDRs", "data-perimeter"),
    "network_perimeter_vpceorgid_scp.json": (
        "Require requests to traverse VPC endpoints owned by your organization", "data-perimeter"),
    "network_perimeter_vpceorgid_rcp.json": (
        "Accept requests only through VPC endpoints owned by your organization", "data-perimeter"),
    "resource_perimeter_scp.json": (
        "Allow your principals to reach only your own and vetted third-party resources", "data-perimeter"),
    "restrict_idp_configurations_scp.json": (
        "Protect SAML, OIDC and Roles Anywhere trust configurations from tampering", "data-perimeter"),
    "restrict_nonvpc_deployment_scp.json": (
        "Require VPC placement for SageMaker, Lambda, Glue, CodeBuild and App Runner workloads", "data-perimeter"),
    "restrict_presignedURL_scp.json": (
        "Block service-generated presigned URLs that bypass the network perimeter", "data-perimeter"),
    "restrict_resource_policy_configurations_scp.json": (
        "Prevent resource policies being set on services RCPs do not cover", "data-perimeter"),
    "restrict_untrusted_endpoints_scp.json": (
        "Block SNS, EventBridge, Step Functions and SES delivery to untrusted endpoints", "data-perimeter"),
    "restrict_untrusted_resources_scp.json": (
        "Block API Gateway authorizers and Route 53 associations pointing at untrusted resources", "data-perimeter"),
    "signin_console_policy.json": (
        "Confine console sign-in to your networks", "data-perimeter"),
    "sns_topic_policy.json": (
        "Apply the identity and network perimeter to SNS topics", "data-perimeter"),

    # ── towardsthecloud.com ──────────────────────────────────────────────────
    "Block-Reserved-Instance-and-Savings-Plans-purchases.json": (
        "Centralize Reserved Instance and Savings Plans purchasing with FinOps", "ttc"),
    "Deny-access-to-AWS-services-in-unsupported-regions.json": (
        "Confine activity to approved regions, exempting SSO and service-linked roles", "ttc"),
    "Deny-all-RAM-resource-sharing.json": (
        "Block all RAM resource sharing to keep an account isolated", "ttc"),
    "Deny-expensive-AI-and-ML-services.json": (
        "Keep high-cost SageMaker, EMR and Redshift workloads out of non-production", "ttc"),
    "Deny-expensive-EC2-and-RDS-instance-types.json": (
        "Cap instance sizes, high-IOPS volumes and NAT gateways in development", "ttc"),
    "Deny-invocation-of-expensive-Bedrock-models.json": (
        "Block invocation of the highest-cost foundation models", "ttc"),
    "Enforce-IMDSv2-on-EC2-instances.json": (
        "Require IMDSv2 at instance launch to blunt SSRF credential theft", "ttc"),
    "Enforce-encryption-at-rest-for-production-data.json": (
        "Require encryption at rest for S3 uploads, EBS volumes and RDS instances", "ttc"),
    "Enforce-organization-only-access.json": (
        "Deny every action to principals outside your organization", "ttc"),
    "Lock-down-suspended-accounts.json": (
        "Deny all actions in suspended or decommissioned accounts", "ttc"),
    "Protect-IAM-password-policy-from-modification.json": (
        "Prevent the account password policy being weakened", "ttc"),
    "Protect-Security-Hub-configuration.json": (
        "Prevent Security Hub standards and controls being disabled", "ttc"),
    "Protect-VPC-flow-logs-and-log-groups-from-deletion.json": (
        "Preserve VPC flow logs and their log groups for investigations", "ttc"),
    "Protect-security-services-from-tampering.json": (
        "Prevent GuardDuty, Config, CloudTrail and Security Hub being disabled", "ttc"),
    "Protect-tagged-CloudFormation-stacks-from-deletion.json": (
        "Prevent manual deletion of IaC-managed CloudFormation stacks", "ttc"),
    "Require-MFA-for-sensitive-IAM-operations.json": (
        "Require MFA for IAM operations that can escalate privilege", "ttc"),
    "Require-VPC-configuration-for-SageMaker.json": (
        "Require SageMaker notebooks and training jobs to run inside your VPC", "ttc"),
    "Require-approval-role-for-critical-resource-deletion.json": (
        "Require an approval role to terminate EC2, RDS and DynamoDB resources", "ttc"),
    "Require-cost-allocation-tags-at-resource-creation.json": (
        "Require Environment and Owner tags when EC2 and RDS resources are created", "ttc"),
    "Restrict-IAM-operations-via-Amazon-Q-Developer.json": (
        "Block IAM changes made through the Amazon Q chat interface", "ttc"),
    "Restrict-network-accounts-to-networking-operations.json": (
        "Keep infrastructure accounts to networking services only", "ttc"),
    "Restrict-sandbox-accounts-to-basic-services.json": (
        "Limit sandbox accounts to basic services and small instances", "ttc"),
    "Restrict-security-accounts-to-security-operations.json": (
        "Keep security accounts from becoming application hosts", "ttc"),
    "S3-Deny-bucket-creation-without-bucket-owner-enforced.json": (
        "Require bucket-owner-enforced ownership on new buckets", "ttc"),
}

# Display labels for service prefixes that do not read well upper-cased.
SERVICE_LABELS: dict[str, str] = {
    "account": "Account", "acm-pca": "ACM PCA", "aoss": "OpenSearch Serverless",
    "apigateway": "API Gateway", "applicationinsights": "App Insights",
    "apprunner": "App Runner", "appstream": "AppStream", "aps": "Prometheus",
    "athena": "Athena", "auditmanager": "Audit Manager", "aws-marketplace": "Marketplace",
    "b2bi": "B2B Data Interchange", "backup": "Backup", "bedrock": "Bedrock",
    "bedrock-agentcore": "Bedrock AgentCore", "bedrock-mantle": "Bedrock",
    "billing": "Billing", "cassandra": "Keyspaces", "cloud9": "Cloud9",
    "cloudformation": "CloudFormation", "cloudhsm": "CloudHSM", "cloudshell": "CloudShell",
    "cloudtrail": "CloudTrail", "cloudwatch": "CloudWatch", "codeartifact": "CodeArtifact",
    "codebuild": "CodeBuild", "codestar-connections": "CodeConnections",
    "cognito-identity": "Cognito", "cognito-idp": "Cognito",
    "comprehendmedical": "Comprehend Medical", "compute-optimizer": "Compute Optimizer",
    "config": "Config", "connect": "Connect", "datasync": "DataSync",
    "detective": "Detective", "directconnect": "Direct Connect",
    "discovery": "App Discovery", "dms": "DMS", "ds": "Directory Service",
    "ds-data": "Directory Service", "dsql": "Aurora DSQL", "dynamodb": "DynamoDB",
    "ebs": "EBS", "ec2": "EC2", "ecr": "ECR", "ecs": "ECS", "eks": "EKS",
    "elasticache": "ElastiCache", "elasticfilesystem": "EFS",
    "elasticmapreduce": "EMR", "es": "OpenSearch", "events": "EventBridge",
    "firehose": "Firehose", "fis": "FIS", "gamelift": "GameLift",
    "glacier": "S3 Glacier", "globalaccelerator": "Global Accelerator",
    "glue": "Glue", "guardduty": "GuardDuty", "healthlake": "HealthLake",
    "iam": "IAM", "identitystore": "Identity Store", "imagebuilder": "Image Builder",
    "invoicing": "Invoicing", "iotfleetwise": "IoT FleetWise",
    "iottwinmaker": "IoT TwinMaker", "iotwireless": "IoT Wireless",
    "kafka": "MSK", "kinesis": "Kinesis", "kinesisanalytics": "Kinesis Analytics",
    "kms": "KMS", "lakeformation": "Lake Formation", "lambda": "Lambda",
    "lex": "Lex", "logs": "CloudWatch Logs", "macie2": "Macie",
    "medical-imaging": "HealthImaging", "network-firewall": "Network Firewall",
    "oam": "CloudWatch OAM", "omics": "HealthOmics", "organizations": "Organizations",
    "payment-cryptography": "Payment Cryptography", "payments": "Payments",
    "polly": "Polly", "pricing": "Pricing", "ram": "RAM", "rbin": "Recycle Bin",
    "rds": "RDS", "redshift": "Redshift", "redshift-serverless": "Redshift Serverless",
    "rekognition": "Rekognition", "rolesanywhere": "Roles Anywhere",
    "route53": "Route 53", "route53domains": "Route 53 Domains", "s3": "S3",
    "sagemaker": "SageMaker", "savingsplans": "Savings Plans",
    "scheduler": "EventBridge Scheduler", "schemas": "EventBridge Schemas",
    "secretsmanager": "Secrets Manager", "securityhub": "Security Hub",
    "serverlessrepo": "Serverless Repo", "servicecatalog": "Service Catalog",
    "servicediscovery": "Cloud Map", "servicequotas": "Service Quotas",
    "ses": "SES", "signin": "Sign-in", "sms-voice": "Pinpoint SMS",
    "sns": "SNS", "sqs": "SQS", "ssm": "Systems Manager",
    "ssm-contacts": "SSM Contacts", "ssm-incidents": "SSM Incidents",
    "sso": "IAM Identity Center", "states": "Step Functions",
    "storagegateway": "Storage Gateway", "sts": "STS", "tax": "Tax Settings",
    "textract": "Textract", "transcribe": "Transcribe", "transfer": "Transfer Family",
    "workmail": "WorkMail", "workspaces": "WorkSpaces",
}

ALL_SERVICES = "All services"


def statements(doc):
    stmts = doc.get("Statement", [])
    return stmts if isinstance(stmts, list) else [stmts]


def derive(doc):
    kind = "RCP" if any("Principal" in s for s in statements(doc)) else "SCP"
    prefixes, wildcard = set(), False
    for s in statements(doc):
        if "NotAction" in s:
            wildcard = True
        raw = s.get("Action", [])
        raw = [raw] if isinstance(raw, str) else raw
        for action in raw:
            if action == "*":
                wildcard = True
            elif ":" in action:
                prefixes.add(action.split(":", 1)[0].lower())
    if wildcard:
        return kind, [ALL_SERVICES]
    # Distinct prefixes can share a label (bedrock/bedrock-mantle, the two
    # cognito prefixes), so de-duplicate before sorting.
    labels = sorted(set(SERVICE_LABELS.get(p, p.upper()) for p in prefixes))
    return kind, labels or [ALL_SERVICES]


on_disk = {f for f in os.listdir(GUARDRAILS) if f.endswith(".json") and f != "MANIFEST.json"}
missing_meta = on_disk - set(POLICIES)
missing_file = set(POLICIES) - on_disk
if missing_meta or missing_file:
    print("MANIFEST/disk mismatch")
    for f in sorted(missing_meta):
        print(f"  no purpose authored: {f}")
    for f in sorted(missing_file):
        print(f"  no such file:        {f}")
    sys.exit(1)

entries = []
for filename in sorted(POLICIES):
    purpose, source_key = POLICIES[filename]
    with open(os.path.join(GUARDRAILS, filename), encoding="utf-8") as fh:
        doc = json.load(fh)
    kind, service_tags = derive(doc)
    entries.append({
        "id": os.path.splitext(filename)[0].lower().replace("_", "-"),
        "file": filename,
        "type": kind,
        "name": f"{kind} : {purpose}",
        "purpose": purpose,
        "services": service_tags,
        "source": SOURCES[source_key],
    })

entries.sort(key=lambda e: (e["type"], e["purpose"].lower()))

with open(os.path.join(GUARDRAILS, "MANIFEST.json"), "w", encoding="utf-8") as fh:
    json.dump({"guardrails": entries}, fh, indent=2)
    fh.write("\n")

scps = [e for e in entries if e["type"] == "SCP"]
rcps = [e for e in entries if e["type"] == "RCP"]
print(f"MANIFEST.json written: {len(entries)} guardrails ({len(scps)} SCP, {len(rcps)} RCP)")
ids = [e["id"] for e in entries]
assert len(set(ids)) == len(ids), "duplicate id"
for entry in entries:
    print(f"  [{', '.join(entry['services'][:4])}{' …' if len(entry['services']) > 4 else ''}] {entry['name']}")
