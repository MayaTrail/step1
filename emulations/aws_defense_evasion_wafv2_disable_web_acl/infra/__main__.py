import json
import pathlib
import pulumi
import pulumi_aws as aws

# =========================================================================== #
# Resource Name Constants -- loaded from resource_names.json when present;    #
# falls back to inline literals so the backend (which copies only this file   #
# and Pulumi.yaml into the run dir) can still deploy without the sibling file.#
# =========================================================================== #
_P = pathlib.Path(__file__).parent / "resource_names.json"
if _P.exists():
    _NAMES = json.loads(_P.read_text())
else:
    _NAMES = {
        "resources": {
            "victim_web_acl":  "atomic-wafv2-disable-web-acl-victim-web-acl",
            "attacker_role":   "atomic-wafv2-disable-web-acl-attacker-role",
            "attacker_policy": "atomic-wafv2-disable-web-acl-attacker-policy",
            "decoy_ssm_param": "/prod/security/waf-bypass-runbook",
            "trail_bucket":    "atomic-wafv2-disable-web-acl-trail-bucket",
            "cloudtrail":      "atomic-wafv2-disable-web-acl-cloudtrail",
        }
    }
_R = _NAMES["resources"]

VICTIM_WEB_ACL_NAME  = _R["victim_web_acl"]
ATTACKER_ROLE_NAME   = _R["attacker_role"]
ATTACKER_POLICY_NAME = _R["attacker_policy"]
DECOY_SSM_PARAM_NAME = _R["decoy_ssm_param"]
TRAIL_BUCKET_NAME    = _R["trail_bucket"]
TRAIL_NAME           = _R["cloudtrail"]

# Account identity resolved at deploy time (v7: use .id not .name for region)
identity   = aws.get_caller_identity()
account_id = identity.account_id

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-wafv2-disable-web-acl",
    "Technique":   "T1562.007",
}

# =========================================================================== #
# 1. Trail S3 bucket (support)                                                 #
# =========================================================================== #
trail_bucket = aws.s3.BucketV2(
    "trail-bucket",
    bucket=TRAIL_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "trail-bucket-pab",
    bucket=trail_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

aws.s3.BucketLifecycleConfigurationV2(
    "trail-bucket-lifecycle",
    bucket=trail_bucket.id,
    rules=[
        aws.s3.BucketLifecycleConfigurationV2RuleArgs(
            id="expire-7d",
            status="Enabled",
            filter=aws.s3.BucketLifecycleConfigurationV2RuleFilterArgs(prefix=""),
            expiration=aws.s3.BucketLifecycleConfigurationV2RuleExpirationArgs(days=7),
        )
    ],
)

# CloudTrail bucket policy.
# Constraint 6b: PutObject resource MUST be /AWSLogs/{account_id}/* (NOT /CloudTrail/).
# Bind to variable and pass via depends_on to the Trail so CreateTrail sees the policy.
trail_bucket_policy_doc = trail_bucket.arn.apply(
    lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudTrailGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "CloudTrailPutObject",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{arn}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id,
                    }
                },
            },
        ],
    })
)

trail_bucket_bp = aws.s3.BucketPolicy(
    "trail-bucket-policy",
    bucket=trail_bucket.id,
    policy=trail_bucket_policy_doc,
)

# =========================================================================== #
# 2. Attacker IAM Role (attack_surface)                                        #
# Uses current account as trusted principal (constraint 3 -- no placeholders). #
# =========================================================================== #
attacker_trust_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }
    ],
})

attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=attacker_trust_policy,
    tags=TAGS,
)

# =========================================================================== #
# 3. Attacker inline policy (attack_surface)                                   #
# Resource:* is intentional -- models over-scoped harvested WAF credential.   #
# =========================================================================== #
aws.iam.RolePolicy(
    "attacker-policy",
    name=ATTACKER_POLICY_NAME,
    role=attacker_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WAFModify",
                "Effect": "Allow",
                "Action": [
                    "wafv2:GetWebACL",
                    "wafv2:UpdateWebACL",
                    "wafv2:ListWebACLs",
                ],
                "Resource": "*",
            }
        ],
    }),
)

# =========================================================================== #
# 4. Victim WAFv2 Web ACL (attack_surface)                                     #
# REGIONAL scope; default_action=block; AWSManagedRulesCommonRuleSet at p10.  #
# Priority 0 is intentionally vacant -- the attack prepends ByteMatch there.  #
# No captcha_config, challenge_config, token_domains, or association_config   #
# so the full-config round-trip in attack.py stays clean.                     #
# =========================================================================== #
victim_web_acl = aws.wafv2.WebAcl(
    "victim-web-acl",
    name=VICTIM_WEB_ACL_NAME,
    scope="REGIONAL",
    default_action=aws.wafv2.WebAclDefaultActionArgs(
        block=aws.wafv2.WebAclDefaultActionBlockArgs()
    ),
    rules=[
        aws.wafv2.WebAclRuleArgs(
            name="AWSManagedRulesCommonRuleSet",
            priority=10,
            override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                none=aws.wafv2.WebAclRuleOverrideActionNoneArgs()
            ),
            statement=aws.wafv2.WebAclRuleStatementArgs(
                managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                    vendor_name="AWS",
                    name="AWSManagedRulesCommonRuleSet",
                )
            ),
            visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                cloudwatch_metrics_enabled=True,
                metric_name="atomic-wafv2-victim-common",
                sampled_requests_enabled=True,
            ),
        )
    ],
    visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
        cloudwatch_metrics_enabled=True,
        metric_name="atomic-wafv2-victim",
        sampled_requests_enabled=True,
    ),
    tags=TAGS,
)

# =========================================================================== #
# 5. Decoy SSM parameter (bait)                                                #
# Any GetParameter against this path is a high-fidelity detection signal.     #
# Attacker role has NO ssm:GetParameter -- not reachable; any GetParameter    #
# on this path by any principal is a high-fidelity detection signal.          #
# =========================================================================== #
aws.ssm.Parameter(
    "decoy-ssm-waf-runbook",
    name=DECOY_SSM_PARAM_NAME,
    type="SecureString",
    value=(
        "WAF admin credentials rotated 2026-07-01. "
        "For emergency bypass contact security-ops@corp.internal. "
        "Temporary header allowlist: X-Bypass header shared out-of-band."
    ),
    tags=TAGS,
)

# =========================================================================== #
# 6. CloudTrail trail (support)                                                #
# depends_on trail_bucket_bp: CreateTrail validates the bucket policy         #
# server-side (constraint 6b); must exist before the Trail resource is created.#
# =========================================================================== #
aws.cloudtrail.Trail(
    "cloudtrail",
    name=TRAIL_NAME,
    s3_bucket_name=trail_bucket.id,
    include_global_service_events=True,
    is_multi_region_trail=False,
    enable_log_file_validation=True,
    enable_logging=True,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[trail_bucket_bp]),
)

# =========================================================================== #
# Pulumi exports -- keys must match attack_plan_approved.json exactly:        #
#   outputs['web_acl_id'], outputs['web_acl_name'], outputs['attacker_role_arn']
# =========================================================================== #
pulumi.export("web_acl_id",          victim_web_acl.id)
pulumi.export("web_acl_name",        victim_web_acl.name)
pulumi.export("web_acl_arn",         victim_web_acl.arn)
pulumi.export("web_acl_scope",       "REGIONAL")
pulumi.export("attacker_role_arn",   attacker_role.arn)
pulumi.export("attacker_role_name",  attacker_role.name)
pulumi.export("trail_name",          TRAIL_NAME)
pulumi.export("trail_bucket_name",   trail_bucket.id)
pulumi.export("decoy_ssm_param_name", DECOY_SSM_PARAM_NAME)
