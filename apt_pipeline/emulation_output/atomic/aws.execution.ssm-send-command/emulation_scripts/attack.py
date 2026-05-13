"""
Technique : aws.execution.ssm-send-command
Tactic    : Execution (T1651)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ssm-send-command/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create 3 EC2 instances with SSM agent.
  - Wait ~2-3 minutes after `pulumi up` for instances to register in SSM.
  - AWS credentials must have ssm:SendCommand + ssm:GetCommandInvocation.

Detection signal:
  - ssm:SendCommand in CloudTrail with DocumentName=AWS-RunShellScript targeting
    multiple instances simultaneously.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json
import os
import subprocess
import time
from pathlib import Path

import boto3

COMMAND_TO_EXECUTE = 'echo "id=$(id), hostname=$(hostname)"'
SSM_WAIT_TIMEOUT_S = 180   # wait up to 3 min for instances to register
COMMAND_TIMEOUT_S  = 120   # wait up to 2 min for command to complete


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


def wait_for_ssm_registration(ssm_client, instance_ids: list, timeout_s: int) -> list:
    """Wait until all instances appear as Online in SSM."""
    print(f"[*] Waiting up to {timeout_s}s for instances to register in SSM...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        resp       = ssm_client.describe_instance_information()
        online_ids = {i["InstanceId"] for i in resp.get("InstanceInformationList", [])
                      if i.get("PingStatus") == "Online"}
        ready      = [i for i in instance_ids if i in online_ids]
        print(f"  [*] {len(ready)}/{len(instance_ids)} instances online in SSM")
        if len(ready) == len(instance_ids):
            return ready
        time.sleep(15)
    ready = [i for i in instance_ids if i in online_ids]  # type: ignore[possibly-undefined]
    print(f"  [!] Timed out — only {len(ready)}/{len(instance_ids)} registered")
    return ready


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir    = str(Path(__file__).parent.parent / "infra")
    infra        = get_pulumi_outputs(stack_dir)
    instance_ids = infra.get("instance_ids", [])

    if not instance_ids:
        print("[!] No instance IDs in stack output — did you run pulumi up?")
        return

    session    = boto3.Session()
    ssm_client = session.client("ssm")

    # ── Step 1: Wait for SSM registration ─────────────────────────────────────
    banner("Step 1 — Wait for EC2 instances to register in SSM")
    ready_ids = wait_for_ssm_registration(ssm_client, instance_ids, SSM_WAIT_TIMEOUT_S)

    if not ready_ids:
        print("[!] No instances registered in SSM — aborting")
        return

    # ── Step 2: Send command across all instances ──────────────────────────────
    banner(f"Step 2 — SendCommand to {len(ready_ids)} instances (AWS-RunShellScript)")
    print(f"  Command: {COMMAND_TO_EXECUTE}")

    resp       = ssm_client.send_command(
        InstanceIds=ready_ids,
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [COMMAND_TO_EXECUTE]},
    )
    command_id = resp["Command"]["CommandId"]
    print(f"  [+] Command sent — ID: {command_id}")
    print("  [!] CloudTrail event: ssm:SendCommand with DocumentName=AWS-RunShellScript")

    # ── Step 3: Collect output from each instance ─────────────────────────────
    banner("Step 3 — Collect command output (GetCommandInvocation)")
    deadline = time.time() + COMMAND_TIMEOUT_S
    for instance_id in ready_ids:
        while time.time() < deadline:
            try:
                inv = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id,
                )
                status = inv["StatusDetails"]
                if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                    print(f"  [{'+' if status == 'Success' else '!'}] {instance_id}: {status}")
                    if inv.get("StandardOutputContent"):
                        print(f"      Output: {inv['StandardOutputContent'].strip()}")
                    break
                time.sleep(5)
            except ssm_client.exceptions.InvocationDoesNotExist:
                time.sleep(5)

    banner("Complete")
    print(f"ssm:SendCommand generated for {len(ready_ids)} instances.")
    print("Run `pulumi destroy` in ../infra/ to remove all prerequisites.")


if __name__ == "__main__":
    main()
