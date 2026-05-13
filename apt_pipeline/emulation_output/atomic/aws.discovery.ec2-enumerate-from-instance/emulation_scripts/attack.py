"""
Technique : aws.discovery.ec2-enumerate-from-instance
Tactic    : Discovery (T1580)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the EC2 instance.
  - Wait ~2-3 minutes after `pulumi up` for SSM registration.

How the attack works:
  An attacker who has compromised an EC2 instance uses its attached IAM role
  to enumerate the AWS environment via AWS CLI commands sent through SSM.
  Discovery commands reveal VPC topology, running instances, S3 buckets,
  and IAM users — information used for planning lateral movement.

Detection signal:
  - Rapid ec2:Describe*, s3:ListBuckets, iam:ListUsers from an EC2 instance role.
  - SSM command output includes account enumeration data.

Revert:
  - Nothing to revert (read-only operations).
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


DISCOVERY_COMMANDS = [
    "aws sts get-caller-identity",
    "aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name]' --output table",
    "aws ec2 describe-vpcs --query 'Vpcs[].[VpcId,CidrBlock]' --output table",
    "aws s3 ls",
    "aws iam list-users --query 'Users[].[UserName,Arn]' --output table",
    "aws iam list-roles --query 'Roles[].[RoleName]' --output table",
]


def main() -> None:
    stack_dir   = str(Path(__file__).parent.parent / "infra")
    infra       = get_pulumi_outputs(stack_dir)
    instance_id = infra.get("instance_id", "")

    if not instance_id:
        print("[!] instance_id not found. Did you run `pulumi up`?")
        return

    session    = boto3.Session()
    ssm_client = session.client("ssm")

    banner("Step 1 — Wait for SSM registration")
    deadline = time.time() + 180
    while time.time() < deadline:
        resp = ssm_client.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        if resp.get("InstanceInformationList") and resp["InstanceInformationList"][0].get("PingStatus") == "Online":
            print(f"  [+] Instance online: {instance_id}")
            break
        time.sleep(15)
    else:
        print("  [!] Timed out — instance not registered in SSM.")
        return

    banner("Step 2 — Run discovery commands via SSM (SendCommand)")
    full_cmd = " && echo '---' && ".join(DISCOVERY_COMMANDS)
    resp = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [full_cmd]},
        Comment="Stratus Red Team - discovery enumeration",
    )
    command_id = resp["Command"]["CommandId"]
    print(f"  [+] Command sent: {command_id}")
    print(f"  [!] CloudTrail event: ssm:SendCommand")

    deadline = time.time() + 120
    output = ""
    while time.time() < deadline:
        time.sleep(5)
        try:
            inv = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
                output = inv.get("StandardOutputContent", "")
                break
        except ClientError:
            pass

    if output:
        print(f"\n  Discovery output:\n  {'─' * 50}")
        for line in output.splitlines()[:50]:
            print(f"  {line}")
        if output.count("\n") > 50:
            print(f"  ... [truncated]")

    banner("Complete")
    print("Detection guidance:")
    print("  Alert on multiple ec2:Describe*, s3:ListBuckets, iam:ListUsers")
    print("  called in quick succession from an EC2 instance role.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the instance.")


if __name__ == "__main__":
    main()
