import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
account_id     = aws.get_caller_identity().account_id
LOG_CONFIG_NAME = "stratus-red-team-dns-log-config"
LOG_GROUP_NAME  = "/stratus-red-team/dns-query-logs"

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

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("resolver_query_log_config_id", resolver_log_config.id)
pulumi.export("resolver_query_log_config_arn", resolver_log_config.arn)
pulumi.export("log_group_name", LOG_GROUP_NAME)
pulumi.export("vpc_id",         vpc.id)
