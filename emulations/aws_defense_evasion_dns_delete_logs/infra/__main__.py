"""
Infrastructure for aws.defense-evasion.dns-delete-logs.

Provisions a VPC with Route53 Resolver query logging, plus a scoped attacker
role holding only the resolver query-log actions the technique needs. The
technique is destructive (it removes DNS visibility), so the attack assumes that
role rather than running as the tenant's cross-account role. IAM, not the
script, bounds what the attack can reach.
"""

import json

import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
account_id     = aws.get_caller_identity().account_id
LOG_CONFIG_NAME = "stratus-red-team-dns-log-config"
LOG_GROUP_NAME  = "/stratus-red-team/dns-query-logs"
ATTACKER_ROLE_NAME   = "stratus-red-team-dns-logs-attacker-role"
ATTACKER_POLICY_NAME = "stratus-red-team-dns-logs-attacker-policy"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.defense-evasion.dns-delete-logs",
}

# ── VPC ───────────────────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    "dns-logs-vpc",
    cidr_block="10.0.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": "stratus-red-team-dns-logs-vpc"},
)

# ── CloudWatch Log Group for DNS queries ──────────────────────────────────────
log_group = aws.cloudwatch.LogGroup(
    "dns-query-log-group",
    name=LOG_GROUP_NAME,
    retention_in_days=7,
    tags=TAGS,
)

# ── Route53 Resolver Query Log Config ─────────────────────────────────────────
# Allows Route53 Resolver to log DNS queries from the VPC
resolver_log_config = aws.route53.ResolverQueryLogConfig(
    "dns-query-log-config",
    name=LOG_CONFIG_NAME,
    destination_arn=log_group.arn,
    tags=TAGS,
)

# Associate the log config with the VPC
aws.route53.ResolverQueryLogConfigAssociation(
    "dns-query-log-assoc",
    resolver_query_log_config_id=resolver_log_config.id,
    resource_id=vpc.id,
)

# ── Attacker role (scoped to the resolver query-log actions) ──────────────────
# Trusts the account root so the tenant's cross-account role can assume it. The
# resolver query-log APIs do not support resource-level permissions, so Resource
# must be "*" and the bound is the action list itself.
attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicy(
    "attacker-role-policy",
    name=ATTACKER_POLICY_NAME,
    role=attacker_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ResolverQueryLogTeardown",
            "Effect": "Allow",
            "Action": [
                "route53resolver:DeleteResolverQueryLogConfig",
                "route53resolver:DisassociateResolverQueryLogConfig",
                "route53resolver:ListResolverQueryLogConfigAssociations",
                "route53resolver:GetResolverQueryLogConfig",
            ],
            "Resource": "*",
        }],
    }),
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("resolver_query_log_config_id", resolver_log_config.id)
pulumi.export("resolver_query_log_config_arn", resolver_log_config.arn)
pulumi.export("log_group_name", LOG_GROUP_NAME)
pulumi.export("vpc_id",         vpc.id)
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", ATTACKER_ROLE_NAME)
