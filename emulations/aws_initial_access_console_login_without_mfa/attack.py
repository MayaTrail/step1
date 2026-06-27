"""
Technique : aws.initial-access.console-login-without-mfa
Tactic    : Initial Access (T1078.004)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.initial-access.console-login-without-mfa/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target IAM user with login profile.
  - The user must NOT have MFA configured (this is the default after pulumi up).

How the attack works:
  An attacker who obtains an IAM user's username and password can log into the
  AWS Management Console without MFA if it is not enforced.  The CloudTrail
  ConsoleLogin event records MFAUsed=No, which is the detection signal.
  This simulates both credential theft and MFA policy gaps.

Detection signal:
  - CloudTrail ConsoleLogin event with additionalEventData.MFAUsed=No.
  - Alert when any console login occurs without MFA for users that should have
    MFA enforced (check against known MFA-exempt service accounts).

Note:
  The actual console login requires a browser — this script simulates the
  attack by calling sts:GetCallerIdentity to prove access with the user's
  credentials and documents the CloudTrail signal pattern.

Revert:
  - Run `pulumi destroy` in ../infra/ to delete the user.
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

def main(session: "boto3.Session") -> None:
    stack_dir = str(Path(__file__).parent.parent / "infra")
    infra     = get_pulumi_outputs(stack_dir)
    user_name = infra.get("user_name", "stratus-red-team-no-mfa-user")
    user_arn  = infra.get("user_arn",  "")

    iam_client = session.client("iam")

    # Verify the user exists and has a login profile
    try:
        iam_client.get_login_profile(UserName=user_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchEntityException":
            print(f"[!] No login profile for user: {user_name}")
            print("    Did you run `pulumi up` in ../infra/?")
        else:
            print(f"[!] GetLoginProfile failed: {exc}")
        return

    # Verify MFA is NOT set
    mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
    mfa_count   = len(mfa_devices.get("MFADevices", []))

    banner("Attack Scenario — Console Login Without MFA")
    print(f"  Target user      : {user_name}")
    print(f"  User ARN         : {user_arn}")
    print(f"  MFA devices      : {mfa_count} (should be 0)")
    print()

    if mfa_count > 0:
        print(f"  [~] WARNING: User has {mfa_count} MFA device(s) — MFA would be required for console login.")
    else:
        print("  [+] Confirmed: user has NO MFA device configured.")
        print("  [+] An attacker with username + password can log in without MFA.")
        print()
        print("  CloudTrail ConsoleLogin event (simulated) would show:")
        print('  {')
        print(f'    "eventName": "ConsoleLogin",')
        print(f'    "userIdentity": {{"type": "IAMUser", "userName": "{user_name}"}},')
        print('    "additionalEventData": {')
        print('      "MFAUsed": "No",')
        print('      "LoginTo": "https://console.aws.amazon.com/console/home"')
        print('    },')
        print('    "responseElements": {"ConsoleLogin": "Success"}')
        print('  }')

    banner("Complete")
    print("Simulated CloudTrail event: ConsoleLogin with MFAUsed=No")
    print("\nDetection guidance:")
    print("  Alert on CloudTrail ConsoleLogin events where MFAUsed=No for")
    print("  users that should require MFA.  Use IAM policies to enforce MFA.")
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
