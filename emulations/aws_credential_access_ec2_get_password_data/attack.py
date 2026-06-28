"""
Technique : aws.credential-access.ec2-get-password-data
Tactic    : Credential Access (T1552.005)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-get-password-data/

Pre-requisites:
  - None. No infrastructure required.

How the attack works:
  An attacker who has obtained EC2 read access may attempt to retrieve the
  Windows administrator password from EC2 instances.  ec2:GetPasswordData is
  called 30 times against randomly-generated instance IDs.  Each call fails
  with InvalidInstanceID.NotFound, but every attempt is captured in CloudTrail,
  revealing credential-hunting activity.

Detection signal:
  - ec2:GetPasswordData in CloudTrail at high frequency.
  - Calls against nonexistent instance IDs are a strong indicator of scanning.
  - Alert when call count per minute exceeds a threshold from a single principal.

Revert:
  - Nothing to revert (no real resources created).
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import secrets
import string
import time

import boto3
from botocore.exceptions import ClientError


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def generate_fake_instance_id() -> str:
    """Return a plausible but nonexistent EC2 instance ID."""
    hex_chars = string.digits + "abcdef"
    suffix = "".join(secrets.choice(hex_chars) for _ in range(17))
    return f"i-{suffix}"


# ── Config ────────────────────────────────────────────────────────────────────

NUM_CALLS = 30
DELAY_BETWEEN_CALLS_S = 0.3   # small delay to avoid throttling


# ── Main ──────────────────────────────────────────────────────────────────────

def main(session: "boto3.Session") -> None:
    ec2_client = session.client("ec2")

    banner("Step 1 — Call ec2:GetPasswordData 30x with fake instance IDs")
    print(f"  Generating {NUM_CALLS} fake instance IDs and probing each...")
    print()

    success_count = 0
    error_count   = 0

    for i in range(1, NUM_CALLS + 1):
        instance_id = generate_fake_instance_id()
        try:
            ec2_client.get_password_data(InstanceId=instance_id)
            # Real instance with no password yet returns empty PasswordData
            print(f"  [{i:02d}] {instance_id}  -> (no password data returned)")
            success_count += 1
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            print(f"  [{i:02d}] {instance_id}  -> {code}")
            error_count += 1
        time.sleep(DELAY_BETWEEN_CALLS_S)

    banner("Complete")
    print(f"  Calls made   : {NUM_CALLS}")
    print(f"  Succeeded    : {success_count}")
    print(f"  Errored      : {error_count}")
    print()
    print("CloudTrail events generated: ec2:GetPasswordData x30")
    print("\nDetection guidance:")
    print("  Alert when ec2:GetPasswordData is called at high frequency or")
    print("  against instance IDs that do not exist in the account.")


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
