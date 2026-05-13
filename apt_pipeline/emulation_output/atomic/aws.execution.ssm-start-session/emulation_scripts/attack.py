"""
Technique : aws.execution.ssm-start-session
Tactic    : Execution (T1021.004)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ssm-start-session/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create 3 EC2 instances with SSM.
  - Wait ~2-3 minutes after `pulumi up` for instances to register in SSM.

How the attack works:
  An attacker with ssm:StartSession opens interactive SSM sessions to multiple
  EC2 instances in rapid succession.  SSM sessions bypass firewalls and do not
  require SSH keys or open port 22 — the only evidence is CloudTrail events.
  Each session is immediately terminated (simulating connection and disconnection).

Detection signal:
  - ssm:StartSession called on multiple instances from unexpected principals.
  - Rapid StartSession + TerminateSession pairs.

Revert:
  - Sessions are terminated immediately after opening.
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
from botocore.exceptions import ClientError


def get_pulumi_outputs(stack_dir: str) -> dict:
    result = subprocess.run(
        ["pulumi", "stack", "output", "--json", "--show-secrets"],
        cwd=stack_dir, capture_output=True, text=True,
        env={**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")},
    )
    if result.returncode != 0:
        print(f"[!] pulumi stack output failed: {result.stderr.strip()}")
        return {}
    return json.loads(result.stdout)


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


def wait_for_ssm(ssm_client, instance_ids: list[str], timeout_s: int = 180) -> list[str]:
    print(f"  Waiting up to {timeout_s}s for instances to register in SSM...")
    deadline = time.time() + timeout_s
    registered: list[str] = []
    while time.time() < deadline and len(registered) < len(instance_ids):
        resp = ssm_client.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": instance_ids}]
        )
        registered = [i["InstanceId"] for i in resp.get("InstanceInformationList", []) if i.get("PingStatus") == "Online"]
        if len(registered) >= len(instance_ids):
            break
        time.sleep(15)
    print(f"  [+] {len(registered)}/{len(instance_ids)} instances online in SSM.")
    return registered


def main() -> None:
    stack_dir    = str(Path(__file__).parent.parent / "infra")
    infra        = get_pulumi_outputs(stack_dir)
    instance_ids = infra.get("instance_ids", [])

    if not instance_ids:
        print("[!] instance_ids not found in Pulumi outputs. Did you run `pulumi up`?")
        return

    session    = boto3.Session()
    ssm_client = session.client("ssm")

    banner("Step 1 — Wait for SSM registration")
    registered = wait_for_ssm(ssm_client, instance_ids)
    if not registered:
        return

    banner("Step 2 — Open and terminate SSM sessions (StartSession + TerminateSession)")
    for instance_id in registered:
        try:
            response = ssm_client.start_session(Target=instance_id)
            session_id = response["SessionId"]
            print(f"  [+] Session opened: {session_id} on {instance_id}")
            print(f"  [!] CloudTrail event: ssm:StartSession")
            time.sleep(1)
            ssm_client.terminate_session(SessionId=session_id)
            print(f"  [+] Session terminated: {session_id}")
            print(f"  [!] CloudTrail event: ssm:TerminateSession")
        except ClientError as exc:
            print(f"  [!] {instance_id}: {exc}")

    banner("Complete")
    print(f"CloudTrail events: ssm:StartSession x{len(registered)}, ssm:TerminateSession x{len(registered)}")
    print("\nDetection guidance:")
    print("  Alert on ssm:StartSession from unexpected principals or IPs.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the instances.")


if __name__ == "__main__":
    main()
