# FILE: attack.py
"""
ATOMIC_IAM_DELETE_ENTITIES -- T1070.009 Clear Persistence
Assumes an ARN-pinned attacker execution role, then deletes both backdoor IAM
identities (user + role) in the correct IAM prerequisite order:
  access keys -> login profile -> inline/managed user policies -> user
  -> inline/managed role policies -> role
"""
import sys
import time
import random
import json
import pathlib

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError

# ── Resource names: single source of truth ──────────────────────────────────
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
    return _R.get(key, default)


def _p(outputs, key, default=""):
    """Resolve a dynamic value: pulumi_export_keys[key] -> outputs[export_key]."""
    export_key = _PKS.get(key, key)
    return outputs.get(export_key, default)


def _ok(msg):
    print(f"[+] {msg}")


def _step(msg):
    print(f"\n[*] {msg}")


def _err(msg):
    print(f"[-] {msg}")


def op_delay(min_s=1, max_s=3):
    time.sleep(random.uniform(min_s, max_s))


def phase_delay():
    time.sleep(random.uniform(5, 15))


def run(outputs: dict, region: str = "us-east-1") -> None:
    # ── Resolve names ────────────────────────────────────────────────────────
    # Static names from resource_names.json['resources']
    _set_tenant_credentials(outputs)

    backdoor_user_name = _r("backdoor_user_name")
    backdoor_role_name = _r("backdoor_role_name")

    # Dynamic values from Pulumi stack outputs via pulumi_export_keys mapping
    attacker_role_arn   = _p(outputs, "attacker_exec_role_arn")
    backdoor_user_key_id = _p(outputs, "backdoor_user_key_id")

    for name, val in [
        ("attacker_exec_role_arn",  attacker_role_arn),
        ("backdoor_user_name",      backdoor_user_name),
        ("backdoor_user_key_id",    backdoor_user_key_id),
        ("backdoor_role_name",      backdoor_role_name),
    ]:
        if not val:
            raise RuntimeError(f"Required value missing or empty: {name}")

    # ── Phase 1: Clear Persistence (T1070.009) ───────────────────────────────
    print("\n=== Phase 1: Clear Persistence (T1070.009) ===")

    # Step 1: Assume attacker execution role (must succeed before any mutation)
    _step("Step 1: Assuming attacker execution role for IAM deletion scope")
    sts_baseline = _base_session(region).client("sts")
    try:
        assume_resp = sts_baseline.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="AtomicT1070009IAMDeleteEntities",
        )
        creds = assume_resp["Credentials"]
        _ok(f"AssumeRole succeeded -> session expires at {creds['Expiration']}")
    except ClientError as e:
        raise RuntimeError(f"AssumeRole into {attacker_role_arn} failed: {e}") from e

    attacker_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    op_delay(1, 3)

    # Validate session identity before first mutation
    sts_attacker = attacker_session.client("sts")
    try:
        identity = sts_attacker.get_caller_identity()
        _ok(f"GetCallerIdentity -> arn={identity['Arn']} account={identity['Account']}")
    except ClientError as e:
        raise RuntimeError(f"GetCallerIdentity failed: {e}") from e

    op_delay(1, 3)
    iam = attacker_session.client("iam", region_name=region)

    # ── All mutations wrapped in try/finally ─────────────────────────────────
    # These are lab-owned resources; no client resources are modified.
    # The finally block ensures the summary always prints even on mid-run failure.
    _events_generated = []
    try:
        # Step 2: Delete active access key on backdoor user
        _step(f"Step 2: Deleting access key {backdoor_user_key_id} on user {backdoor_user_name}")
        try:
            existing_keys = iam.list_access_keys(UserName=backdoor_user_name)["AccessKeyMetadata"]
            found = False
            for key_meta in existing_keys:
                if key_meta["AccessKeyId"] == backdoor_user_key_id:
                    iam.delete_access_key(
                        UserName=backdoor_user_name,
                        AccessKeyId=backdoor_user_key_id,
                    )
                    _ok(f"DeleteAccessKey {backdoor_user_key_id} -> success")
                    _events_generated.append("DeleteAccessKey (iam.amazonaws.com)")
                    found = True
                    break
            if not found:
                _err(f"Key {backdoor_user_key_id} not found on {backdoor_user_name} -- already deleted or mismatch")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchEntity":
                _err(f"DeleteAccessKey: key already gone -- {e}")
            else:
                raise RuntimeError(f"DeleteAccessKey unexpected error: {e}") from e

        op_delay(1, 3)

        # Step 3: Delete console login profile (absent in lab config; swallow NoSuchEntity)
        _step(f"Step 3: Deleting login profile for user {backdoor_user_name}")
        try:
            iam.delete_login_profile(UserName=backdoor_user_name)
            _ok("DeleteLoginProfile -> success")
            _events_generated.append("DeleteLoginProfile (iam.amazonaws.com)")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchEntity":
                _ok("DeleteLoginProfile -> NoSuchEntity (no console profile, expected) -- CloudTrail records the attempt")
                _events_generated.append("DeleteLoginProfile error-record (iam.amazonaws.com)")
            elif code == "AccessDenied":
                _ok("DeleteLoginProfile -> AccessDenied (denied by environment control, expected)")
                _events_generated.append("DeleteLoginProfile AccessDenied (iam.amazonaws.com)")
            else:
                raise RuntimeError(f"DeleteLoginProfile unexpected error: {e}") from e

        op_delay(1, 3)

        # Step 4: Drain inline and managed policies from backdoor user
        _step(f"Step 4: Draining policies from user {backdoor_user_name}")
        try:
            inline_names = iam.list_user_policies(UserName=backdoor_user_name).get("PolicyNames", [])
            for policy_name in inline_names:
                iam.delete_user_policy(UserName=backdoor_user_name, PolicyName=policy_name)
                _ok(f"DeleteUserPolicy {policy_name} -> success")
                _events_generated.append(f"DeleteUserPolicy:{policy_name} (iam.amazonaws.com)")
                op_delay(1, 2)
            if not inline_names:
                _ok("No inline policies on user (expected for minimal backdoor user)")
        except ClientError as e:
            raise RuntimeError(f"list/delete_user_policy failed: {e}") from e

        try:
            attached_policies = iam.list_attached_user_policies(UserName=backdoor_user_name).get("AttachedPolicies", [])
            for policy in attached_policies:
                iam.detach_user_policy(UserName=backdoor_user_name, PolicyArn=policy["PolicyArn"])
                _ok(f"DetachUserPolicy {policy['PolicyArn']} -> success")
                _events_generated.append(f"DetachUserPolicy:{policy['PolicyArn']} (iam.amazonaws.com)")
                op_delay(1, 2)
            if not attached_policies:
                _ok("No managed policies attached to user (expected)")
        except ClientError as e:
            raise RuntimeError(f"list/detach_user_policy failed: {e}") from e

        op_delay(1, 3)

        # Step 5: Delete backdoor IAM user
        _step(f"Step 5: Deleting backdoor IAM user {backdoor_user_name}")
        try:
            # Ensure ALL remaining keys are cleared before delete_user
            remaining_keys = iam.list_access_keys(UserName=backdoor_user_name)["AccessKeyMetadata"]
            for key_meta in remaining_keys:
                iam.delete_access_key(UserName=backdoor_user_name, AccessKeyId=key_meta["AccessKeyId"])
                _ok(f"Pre-delete cleanup: removed residual key {key_meta['AccessKeyId']}")
                op_delay(1, 2)
            iam.delete_user(UserName=backdoor_user_name)
            _ok(f"DeleteUser {backdoor_user_name} -> success")
            _events_generated.append(f"DeleteUser:{backdoor_user_name} (iam.amazonaws.com)")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchEntity":
                _err(f"DeleteUser: user {backdoor_user_name} already gone")
            elif code == "AccessDenied":
                _ok("DeleteUser -> AccessDenied (denied by environment control, expected)")
                _events_generated.append("DeleteUser AccessDenied (iam.amazonaws.com)")
            else:
                raise RuntimeError(f"DeleteUser unexpected error: {e}") from e

        op_delay(2, 5)

        # Step 6: Drain policies and instance profiles from backdoor role
        _step(f"Step 6: Draining policies and instance profiles from role {backdoor_role_name}")
        try:
            inline_names = iam.list_role_policies(RoleName=backdoor_role_name).get("PolicyNames", [])
            for policy_name in inline_names:
                iam.delete_role_policy(RoleName=backdoor_role_name, PolicyName=policy_name)
                _ok(f"DeleteRolePolicy {policy_name} -> success")
                _events_generated.append(f"DeleteRolePolicy:{policy_name} (iam.amazonaws.com)")
                op_delay(1, 2)
            if not inline_names:
                _ok("No inline policies on role (expected)")
        except ClientError as e:
            raise RuntimeError(f"list/delete_role_policy failed: {e}") from e

        try:
            attached_policies = iam.list_attached_role_policies(RoleName=backdoor_role_name).get("AttachedPolicies", [])
            for policy in attached_policies:
                iam.detach_role_policy(RoleName=backdoor_role_name, PolicyArn=policy["PolicyArn"])
                _ok(f"DetachRolePolicy {policy['PolicyArn']} -> success")
                _events_generated.append(f"DetachRolePolicy:{policy['PolicyArn']} (iam.amazonaws.com)")
                op_delay(1, 2)
            if not attached_policies:
                _ok("No managed policies attached to role (expected)")
        except ClientError as e:
            raise RuntimeError(f"list/detach_role_policy failed: {e}") from e

        try:
            profiles = iam.list_instance_profiles_for_role(RoleName=backdoor_role_name).get("InstanceProfiles", [])
            for profile in profiles:
                iam.remove_role_from_instance_profile(
                    RoleName=backdoor_role_name,
                    InstanceProfileName=profile["InstanceProfileName"],
                )
                _ok(f"RemoveRoleFromInstanceProfile {profile['InstanceProfileName']} -> success")
                op_delay(1, 2)
            if not profiles:
                _ok("No instance profiles associated with role (expected)")
        except ClientError as e:
            raise RuntimeError(f"list/remove_role_from_instance_profile failed: {e}") from e

        op_delay(1, 3)

        # Step 7: Delete backdoor IAM role
        _step(f"Step 7: Deleting backdoor IAM role {backdoor_role_name}")
        try:
            iam.delete_role(RoleName=backdoor_role_name)
            _ok(f"DeleteRole {backdoor_role_name} -> success")
            _events_generated.append(f"DeleteRole:{backdoor_role_name} (iam.amazonaws.com)")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchEntity":
                _err(f"DeleteRole: role {backdoor_role_name} already gone")
            elif code == "AccessDenied":
                _ok("DeleteRole -> AccessDenied (denied by environment control, expected)")
                _events_generated.append("DeleteRole AccessDenied (iam.amazonaws.com)")
            else:
                raise RuntimeError(f"DeleteRole unexpected error: {e}") from e

        op_delay(2, 5)

    finally:
        # No client resources were modified -- lab-owned backdoor identities were the target.
        # STS session expires automatically (no explicit revocation needed).
        # Summary always prints regardless of success or failure.
        print("\n=== Emulation Complete ===")
        print("CloudTrail events generated (T1070.009 - Clear Persistence):")
        base_events = [
            "  AssumeRole               (sts.amazonaws.com)",
            "  GetCallerIdentity        (sts.amazonaws.com)",
        ]
        for ev in base_events:
            print(ev)
        for ev in _events_generated:
            print(f"  {ev}")
        print(
            "\nPost-emulation cleanup required:\n"
            "  pulumi state delete urn:...:atomic-iam-delete-backdoor-user   (if already deleted)\n"
            "  pulumi state delete urn:...:atomic-iam-delete-backdoor-role   (if already deleted)\n"
            "  pulumi destroy   (destroys attacker exec role + exec policy + any remaining resources)"
        )
