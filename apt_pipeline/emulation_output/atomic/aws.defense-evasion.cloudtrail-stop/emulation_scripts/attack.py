"""
Technique : aws.defense-evasion.cloudtrail-stop
Tactic    : Defense Evasion (T1562.008)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-stop/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the CloudTrail trail.
  - AWS credentials must have cloudtrail:StopLogging + cloudtrail:StartLogging.

Detection signal:
  - cloudtrail:StopLogging event.
  - GuardDuty finding: Stealth:IAMUser/CloudTrailLoggingDisabled.

Revert:
  - attack.py restores logging via StartLogging after a configurable delay.
  - Or run `pulumi destroy` in ../infra/ to tear down all resources.
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


# ── Config ────────────────────────────────────────────────────────────────────
# How long (seconds) to leave logging disabled before restoring.
# Set to 0 to skip the delay (useful in test mode).
DISABLE_DURATION_S = int(os.environ.get("DISABLE_DURATION_S", "30"))


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
    trail_name = infra.get("trail_name", "stratus-red-team-ct-stop-trail")

    session = boto3.Session()
    ct      = session.client("cloudtrail")

    # ── Step 1: Stop CloudTrail logging ───────────────────────────────────────
    banner("Step 1 — Stop CloudTrail logging (StopLogging)")
    ct.stop_logging(Name=trail_name)
    print(f"  [+] Stopped logging on trail: {trail_name}")
    print("  [!] CloudTrail event: StopLogging")
    print("  [!] GuardDuty may raise: Stealth:IAMUser/CloudTrailLoggingDisabled")

    # ── Delay (configurable — simulates dwell time) ────────────────────────
    if DISABLE_DURATION_S > 0:
        print(f"\n[*] Logging disabled for {DISABLE_DURATION_S}s (DISABLE_DURATION_S)")
        time.sleep(DISABLE_DURATION_S)

    # ── Step 2: Restore CloudTrail logging ────────────────────────────────────
    banner("Step 2 — Restore CloudTrail logging (StartLogging)")
    ct.start_logging(Name=trail_name)
    print(f"  [+] Restored logging on trail: {trail_name}")

    banner("Complete")
    print("CloudTrail event generated: StopLogging")
    print("Run `pulumi destroy` in ../infra/ to remove all prerequisites.")


if __name__ == "__main__":
    main()
