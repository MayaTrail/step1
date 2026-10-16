"""
Technique : aws.defense-evasion.organizations-leave
Tactic    : Defense Evasion (T1666 - Modify Cloud Resource Hierarchy)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.organizations-leave/

How the attack works:
  A member account that leaves its organization sheds every SCP, the
  organization trail, delegated GuardDuty/Security Hub and Config aggregation.
  The attacker first confirms membership with DescribeOrganization, then calls
  LeaveOrganization.

Safety:
  The attacker role carries an explicit Deny on LeaveOrganization. The call is
  made, so CloudTrail records it, but AWS returns AccessDenied in every account
  type. Organizations is a global service: the event lands in us-east-1.

Detection signal:
  - organizations:LeaveOrganization with ANY errorCode. Denied attempts are as
    significant as successful ones.

Revert:
  - Nothing to revert; the call cannot succeed.

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
    banner("Step 0 - Assume the scoped attacker role (AssumeRole)")
    session = _attacker_session(outputs, region, "atomic-t1666-org-leave")
    orgs = session.client("organizations", region_name="us-east-1")

    banner("Step 1 - Confirm organization membership (DescribeOrganization)")
    try:
        org = orgs.describe_organization()["Organization"]
        print(f"  [+] Account is a member of {org.get('Id')} (management account {org.get('MasterAccountId')})")
    except ClientError as exc:
        print(f"  [~] DescribeOrganization: {exc.response['Error']['Code']} (account may not be in an organization)")

    banner("Step 2 - Attempt to leave the organization (LeaveOrganization)")
    try:
        orgs.leave_organization()
        # Unreachable while the role's explicit Deny is in place.
        raise RuntimeError("LeaveOrganization unexpectedly succeeded - the safety Deny is missing")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        print(f"  [+] AWS refused the call: {code}")
        if code not in ("AccessDeniedException", "AccessDenied"):
            print("  [~] Not the IAM guard (account not in an organization, or it is the management account)")
        print("  [!] CloudTrail event: organizations:LeaveOrganization (errorCode set, us-east-1)")

    banner("Complete")
    print("CloudTrail events generated: sts:AssumeRole, organizations:DescribeOrganization, "
          "organizations:LeaveOrganization (denied)")
