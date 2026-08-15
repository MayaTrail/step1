"""
Hand-authored metadata for the guardrail policy library.

Every document under policies/ is a verbatim copy of an upstream AWS sample.
Those documents carry no description of their own, so this module supplies the
one-line purpose the library displays and records which repository each came
from.

Nothing else lives here. The SCP/RCP split and the service tags are derived
from each policy body by registry.discover(), so they cannot drift from the
JSON. Only text a human has to write is kept by hand.

Adding a policy: drop the .json into policies/ and add one entry below. The
corpus test in the backend fails if the directory and this mapping disagree,
so a policy can never be shipped unnamed or named but missing.
"""

# Source key -> where the policy text came from. url is rendered as a link so a
# reader can verify a policy against its upstream original.
SOURCES = {
    "aws-scp": {
        "label": "AWS Organizations SCP examples",
        "url": "https://github.com/aws-samples/service-control-policy-examples",
    },
    "aws-rcp": {
        "label": "AWS Organizations RCP examples",
        "url": "https://github.com/aws-samples/resource-control-policy-examples",
    },
    "data-perimeter": {
        "label": "AWS data perimeter policy examples",
        "url": "https://github.com/aws-samples/data-perimeter-policy-examples",
    },
    "ttc": {
        "label": "Towards the Cloud, AWS SCP examples",
        "url": "https://towardsthecloud.com/aws-service-control-policies-scp",
    },
}

# Policy filename -> (purpose, source key). Sorted by filename so a new
# entry lands in a predictable place and diffs stay readable.
POLICIES = {
    "Block-Reserved-Instance-and-Savings-Plans-purchases.json": (
        "Centralize Reserved Instance and Savings Plans purchasing with FinOps",
        "ttc",
    ),
    "Cognito-Deny-deletion-and-only-allow-specific-roles.json": (
        "Restrict Cognito user pool and domain deletion to named roles",
        "aws-rcp",
    ),
    "Cognito-Deny-identity-pool-unauthenticated-access.json": (
        "Block unauthenticated (guest) access to Cognito identity pools",
        "aws-rcp",
    ),
    "Deny-AWS-Backup-deletion-and-changes-to-configuration.json": (
        "Prevent deletion of backup plans, vaults and vault access policies",
        "aws-scp",
    ),
    "Deny-AWS-CLI-login-using-console-credentials.json": (
        "Block CLI sessions minted from console credentials",
        "aws-scp",
    ),
    "Deny-Amazon-Virtual-Private-Network-connection-creation-modification-deletion.json": (
        "Lock down creation and teardown of VPN gateways and connections",
        "aws-scp",
    ),
    "Deny-Bedrock-api-keys-longer-than-30-days.json": (
        "Cap Bedrock API key lifetime at 30 days",
        "aws-scp",
    ),
    "Deny-Bedrock-api-keys.json": (
        "Block Bedrock API key creation and bearer-token invocation outright",
        "aws-scp",
    ),
    "Deny-Bedrock-long-term-api-keys.json": (
        "Allow only short-term Bedrock bearer tokens",
        "aws-scp",
    ),
    "Deny-Bedrock-model-invocation-except-approved-models.json": (
        "Allow Bedrock invocation only for an approved foundation-model allowlist",
        "aws-scp",
    ),
    "Deny-CloudHSM-deletion.json": (
        "Restrict CloudHSM cluster and backup deletion to privileged roles",
        "aws-scp",
    ),
    "Deny-KMS-key-deletion.json": (
        "Restrict KMS key, alias and key-store deletion to privileged roles",
        "aws-scp",
    ),
    "Deny-RAM-from-sharing-resources-to-external-accounts.json": (
        "Block RAM resource shares that allow principals outside the organization",
        "aws-scp",
    ),
    "Deny-access-to-AWS-based-on-the-requested-AWS-region-with-Bedrock-CRIS.json": (
        "Confine activity to approved regions while allowing Bedrock cross-region inference",
        "aws-scp",
    ),
    "Deny-access-to-AWS-based-on-the-requested-AWS-region.json": (
        "Confine activity to approved regions, exempting global services",
        "aws-scp",
    ),
    "Deny-access-to-AWS-services-in-unsupported-regions.json": (
        "Confine activity to approved regions, exempting SSO and service-linked roles",
        "ttc",
    ),
    "Deny-access-to-resources-in-an-organizational-unit,except-for-principals-from-the-same-or-specified-organizational-unit.json": (
        "Confine an OU's resources to principals from the same or an allowed OU",
        "aws-rcp",
    ),
    "Deny-account-region-enable-and-disable-actions.json": (
        "Prevent opt-in regions being enabled or disabled",
        "aws-scp",
    ),
    "Deny-all-RAM-resource-sharing.json": (
        "Block all RAM resource sharing to keep an account isolated",
        "ttc",
    ),
    "Deny-billing-modification-action.json": (
        "Protect billing preferences, tax settings and account contacts from change",
        "aws-scp",
    ),
    "Deny-built-in-web-identity-providers.json": (
        "Block role assumption via the built-in public web identity providers",
        "aws-rcp",
    ),
    "Deny-creation-of-default-VPC-and-subnet.json": (
        "Prevent recreation of the default VPC and its subnets",
        "aws-scp",
    ),
    "Deny-critical-IAM-user-actions.json": (
        "Block IAM user, access key and login profile creation outside break-glass roles",
        "aws-scp",
    ),
    "Deny-disabling-default-EBS-encryption.json": (
        "Keep EBS encryption-by-default switched on",
        "aws-scp",
    ),
    "Deny-expensive-AI-and-ML-services.json": (
        "Keep high-cost SageMaker, EMR and Redshift workloads out of non-production",
        "ttc",
    ),
    "Deny-expensive-EC2-and-RDS-instance-types.json": (
        "Cap instance sizes, high-IOPS volumes and NAT gateways in development",
        "ttc",
    ),
    "Deny-invocation-of-expensive-Bedrock-models.json": (
        "Block invocation of the highest-cost foundation models",
        "ttc",
    ),
    "Deny-key-actions-on-Route53-DNS-hosted-zones.json": (
        "Protect hosted zones and domain registration from transfer or deletion",
        "aws-scp",
    ),
    "Deny-member-accounts-from-leaving-your-AWS-organization.json": (
        "Prevent member accounts from leaving the organization",
        "aws-scp",
    ),
    "Deny-modification-to-Lambda-URL-Config.json": (
        "Require IAM auth on Lambda function URLs",
        "aws-scp",
    ),
    "Deny-modification-to-SSM-service-settings.json": (
        "Protect Systems Manager service settings from modification",
        "aws-scp",
    ),
    "Deny-modifications-to-specific-Amazon-Lambda-functions.json": (
        "Freeze designated Lambda functions against code and permission changes",
        "aws-scp",
    ),
    "Deny-modifications-to-specific-IAM-roles.json": (
        "Freeze designated IAM roles against policy and trust changes",
        "aws-scp",
    ),
    "Deny-resource-access-if-the-resource-belongs-to-a-specific-organizational-unit.json": (
        "Allow access to an OU's resources only from named principals",
        "aws-rcp",
    ),
    "Deny-the-root-user-from-performing-actions-except-S3-bucketpolicy-changes.json": (
        "Deny the root user everything except S3 bucket-policy break-glass",
        "aws-scp",
    ),
    "Deny-unwanted-cancellation-or-changes-to-AWS-Marketplace-product-subscription.json": (
        "Restrict Marketplace subscribe, unsubscribe and private-marketplace changes",
        "aws-scp",
    ),
    "Deny-unwarranted-IAM-federations-creation-modification.json": (
        "Restrict creation and modification of SAML and OIDC identity providers",
        "aws-scp",
    ),
    "Deny-use-of-IAM-user-credentials-from-unexpected-networks.json": (
        "Confine IAM user credentials to your corporate network and VPCs",
        "aws-scp",
    ),
    "Deny-users-from-deleting-Amazon-Glacier-vaults-or-archives.json": (
        "Prevent deletion of S3 Glacier vaults and archives",
        "aws-scp",
    ),
    "DenyGrantOnAWSManagedEKSKey.json": (
        "Block KMS grants on the AWS-managed EKS key",
        "aws-scp",
    ),
    "Enforce-30-days-for-KMS-deletion.json": (
        "Require a 30-day pending window before any KMS key deletion",
        "aws-scp",
    ),
    "Enforce-IMDSv2-on-EC2-instances.json": (
        "Require IMDSv2 at instance launch to blunt SSRF credential theft",
        "ttc",
    ),
    "Enforce-controls-on-AWS-services-that-use-service-principals-to-access-your-resources.json": (
        "Close the confused-deputy gap for AWS service principals reaching your resources",
        "aws-rcp",
    ),
    "Enforce-encryption-at-rest-for-production-data.json": (
        "Require encryption at rest for S3 uploads, EBS volumes and RDS instances",
        "ttc",
    ),
    "Enforce-organization-only-access.json": (
        "Deny every action to principals outside your organization",
        "ttc",
    ),
    "IAM-Restrict-outbound-federation.json": (
        "Constrain outbound web identity tokens by audience, algorithm and lifetime",
        "aws-rcp",
    ),
    "KMS-Deny-AWS-Key-Management-Service-asymmetric-key-with-RSA-key-material-used-for-encryption-with-key-length-of-2048-bits.json": (
        "Block creation of RSA-2048 encryption keys",
        "aws-rcp",
    ),
    "KMS-Deny-the-accidental-or-intentional-deletion-of-a-KMS-key-and-only-allow-specific-roles-to-delete-KMS-keys.json": (
        "Restrict KMS key deletion to named roles, enforced at the key",
        "aws-rcp",
    ),
    "KMS-Require-an-AWS-Key-Management-Service-key-policy-limiting-creation-of-AWS-KMS-grants-to-AWS-services.json": (
        "Allow KMS grants only where AWS services create them for your resources",
        "aws-rcp",
    ),
    "KMS-Require-that-an-AWS-KMS-key-is-configured-with-the-bypass-policy-lockout-safety-check-enabled.json": (
        "Require the KMS policy-lockout safety check to stay enabled",
        "aws-rcp",
    ),
    "Lock-down-suspended-accounts.json": (
        "Deny all actions in suspended or decommissioned accounts",
        "ttc",
    ),
    "Prevent-creating-or-expanding-public-connectivity-for-VPCs.json": (
        "Block internet gateways, peering and other public VPC connectivity",
        "aws-scp",
    ),
    "Prevent-root-credentials-management-in-member-accounts-in-AWS-Organizations.json": (
        "Deny member-account root credentials except via centralized root access",
        "aws-scp",
    ),
    "Protect-IAM-password-policy-from-modification.json": (
        "Prevent the account password policy being weakened",
        "ttc",
    ),
    "Protect-Security-Hub-configuration.json": (
        "Prevent Security Hub standards and controls being disabled",
        "ttc",
    ),
    "Protect-VPC-flow-logs-and-log-groups-from-deletion.json": (
        "Preserve VPC flow logs and their log groups for investigations",
        "ttc",
    ),
    "Protect-security-services-from-tampering.json": (
        "Prevent GuardDuty, Config, CloudTrail and Security Hub being disabled",
        "ttc",
    ),
    "Protect-tagged-CloudFormation-stacks-from-deletion.json": (
        "Prevent manual deletion of IaC-managed CloudFormation stacks",
        "ttc",
    ),
    "ProtectPodIdentitiesTagsOnRolesAndUsers.json": (
        "Prevent EKS pod-identity tag keys being set on IAM roles and users",
        "aws-scp",
    ),
    "Require-MFA-for-sensitive-IAM-operations.json": (
        "Require MFA for IAM operations that can escalate privilege",
        "ttc",
    ),
    "Require-VPC-configuration-for-SageMaker.json": (
        "Require SageMaker notebooks and training jobs to run inside your VPC",
        "ttc",
    ),
    "Require-approval-role-for-critical-resource-deletion.json": (
        "Require an approval role to terminate EC2, RDS and DynamoDB resources",
        "ttc",
    ),
    "Require-cost-allocation-tags-at-resource-creation.json": (
        "Require Environment and Owner tags when EC2 and RDS resources are created",
        "ttc",
    ),
    "Restrict-IAM-operations-via-Amazon-Q-Developer.json": (
        "Block IAM changes made through the Amazon Q chat interface",
        "ttc",
    ),
    "Restrict-access-to-only-HTTPS-connections-to-your-resources.json": (
        "Require TLS for every request reaching your resources",
        "aws-rcp",
    ),
    "Restrict-deletion-and-modification-of-privileged-policies.json": (
        "Protect privileged managed policies from edit and deletion",
        "aws-scp",
    ),
    "Restrict-network-accounts-to-networking-operations.json": (
        "Keep infrastructure accounts to networking services only",
        "ttc",
    ),
    "Restrict-sandbox-accounts-to-basic-services.json": (
        "Limit sandbox accounts to basic services and small instances",
        "ttc",
    ),
    "Restrict-security-accounts-to-security-operations.json": (
        "Keep security accounts from becoming application hosts",
        "ttc",
    ),
    "S3-Deny-ACL-disablement-for-all-new-buckets-(bucket-owner-enforced).json": (
        "Require bucket-owner-enforced ownership on new buckets, enforced at the resource",
        "aws-rcp",
    ),
    "S3-Deny-SSE-C.json": (
        "Block customer-provided-key (SSE-C) uploads",
        "aws-rcp",
    ),
    "S3-Deny-bucket-creation-without-bucket-owner-enforced.json": (
        "Require bucket-owner-enforced ownership on new buckets",
        "ttc",
    ),
    "S3-Deny-users-from-deleting-Amazon-S3-Buckets-or-objects.json": (
        "Prevent deletion of buckets, objects and object versions",
        "aws-rcp",
    ),
    "S3-Deny-users-from-modifying-S3-Block-Public-Access-(Account-Level).json": (
        "Protect account-level S3 Block Public Access from being weakened",
        "aws-rcp",
    ),
    "STS-Protect-EKS-pod-identities-tags.json": (
        "Allow only EKS to set EKS pod-identity session tags",
        "aws-rcp",
    ),
    "STS-protect-IAMRA-session-tags.json": (
        "Allow only IAM Roles Anywhere to set x509 session tags",
        "aws-rcp",
    ),
    "api_gateway_policy.json": (
        "Apply the full data perimeter to API Gateway APIs",
        "data-perimeter",
    ),
    "data_perimeter_governance_rcp.json": (
        "Protect the session tags the data perimeter itself depends on",
        "data-perimeter",
    ),
    "data_perimeter_governance_scp.json": (
        "Close the sharing and tagging gaps the primary perimeter controls miss",
        "data-perimeter",
    ),
    "identity_perimeter_rcp.json": (
        "Allow only your organization's identities to reach your resources",
        "data-perimeter",
    ),
    "network_perimeter_ec2_scp.json": (
        "Confine EC2 role credentials to expected networks",
        "data-perimeter",
    ),
    "network_perimeter_glue_scp.json": (
        "Confine Glue role credentials to expected networks",
        "data-perimeter",
    ),
    "network_perimeter_iam_users_scp.json": (
        "Confine IAM user credentials to expected networks",
        "data-perimeter",
    ),
    "network_perimeter_lambda_scp.json": (
        "Confine Lambda role credentials to expected networks",
        "data-perimeter",
    ),
    "network_perimeter_sourcevpc_rcp.json": (
        "Accept requests to your resources only from your VPCs and corporate CIDRs",
        "data-perimeter",
    ),
    "network_perimeter_sourcevpc_scp.json": (
        "Confine all principals to your VPCs and corporate CIDRs",
        "data-perimeter",
    ),
    "network_perimeter_vpceorgid_rcp.json": (
        "Accept requests only through VPC endpoints owned by your organization",
        "data-perimeter",
    ),
    "network_perimeter_vpceorgid_scp.json": (
        "Require requests to traverse VPC endpoints owned by your organization",
        "data-perimeter",
    ),
    "resource_perimeter_scp.json": (
        "Allow your principals to reach only your own and vetted third-party resources",
        "data-perimeter",
    ),
    "restrict_idp_configurations_scp.json": (
        "Protect SAML, OIDC and Roles Anywhere trust configurations from tampering",
        "data-perimeter",
    ),
    "restrict_nonvpc_deployment_scp.json": (
        "Require VPC placement for SageMaker, Lambda, Glue, CodeBuild and App Runner workloads",
        "data-perimeter",
    ),
    "restrict_presignedURL_scp.json": (
        "Block service-generated presigned URLs that bypass the network perimeter",
        "data-perimeter",
    ),
    "restrict_resource_policy_configurations_scp.json": (
        "Prevent resource policies being set on services RCPs do not cover",
        "data-perimeter",
    ),
    "restrict_untrusted_endpoints_scp.json": (
        "Block SNS, EventBridge, Step Functions and SES delivery to untrusted endpoints",
        "data-perimeter",
    ),
    "restrict_untrusted_resources_scp.json": (
        "Block API Gateway authorizers and Route 53 associations pointing at untrusted resources",
        "data-perimeter",
    ),
    "signin_console_policy.json": (
        "Confine console sign-in to your networks",
        "data-perimeter",
    ),
    "sns_topic_policy.json": (
        "Apply the identity and network perimeter to SNS topics",
        "data-perimeter",
    ),
}
