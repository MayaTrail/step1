"""
Technique : aws.execution.ec2-launch-unusual-instances
Tactic    : Execution (T1204.003)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ec2-launch-unusual-instances/

Pre-requisites:
  - None. The script launches and immediately terminates its own EC2 instance.
  - AWS credentials must have ec2:RunInstances + ec2:TerminateInstances.

How the attack works:
  Attackers who gain AWS access often launch GPU instances (p2, p3, g4) or
  compute-dense instances to run cryptocurrency mining software, exploiting
  the victim's cloud billing for profit.  The instance type itself is a
  detection signal even without observing network mining traffic.

Detection signal:
  - ec2:RunInstances with unusual instance types (GPU/compute families) not
    in the account's baseline.
  - GuardDuty: CryptoCurrency:EC2/BitcoinTool.B if mining pool traffic detected.
  - Unexpected cost spike in EC2 billing.

Revert:
  - Automated: instance terminated in the finally block.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import time

import boto3
from botocore.exceptions import ClientError


# ── Config ────────────────────────────────────────────────────────────────────

# Instance types to try in order (p2 may not be available in all regions)
UNUSUAL_INSTANCE_TYPES = ["p2.xlarge", "p3.2xlarge", "g4dn.xlarge"]
# Fallback to something available if GPU types fail
FALLBACK_INSTANCE_TYPE = "t3.micro"

TAGS = [
    {"Key": "StratusRedTeam", "Value": "true"},
    {"Key": "Purpose",        "Value": "adversary-emulation"},
    {"Key": "Technique",      "Value": "aws.execution.ec2-launch-unusual-instances"},
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def get_latest_amazon_linux_ami(ec2_client) -> str:
    """Fetch the latest Amazon Linux 2 AMI ID for the current region."""
    response = ec2_client.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name",              "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state",             "Values": ["available"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
        ],
    )
    images = sorted(response["Images"], key=lambda x: x["CreationDate"], reverse=True)
    if not images:
        raise RuntimeError("No Amazon Linux 2 AMI found in this region")
    return images[0]["ImageId"]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    session    = boto3.Session()
    ec2_client = session.client("ec2")

    ami_id = get_latest_amazon_linux_ami(ec2_client)
    print(f"  AMI: {ami_id}")

    launched_instance_id: str | None = None
    launched_instance_type: str = ""

    try:
        # ── Step 1: Try to launch an unusual instance ─────────────────────────
        banner("Step 1 — Launch unusual GPU/compute instance (RunInstances)")
        for instance_type in UNUSUAL_INSTANCE_TYPES + [FALLBACK_INSTANCE_TYPE]:
            try:
                print(f"  Attempting to launch: {instance_type}...")
                response = ec2_client.run_instances(
                    ImageId=ami_id,
                    InstanceType=instance_type,
                    MinCount=1,
                    MaxCount=1,
                    TagSpecifications=[
                        {
                            "ResourceType": "instance",
                            "Tags": TAGS,
                        }
                    ],
                )
                launched_instance_id   = response["Instances"][0]["InstanceId"]
                launched_instance_type = instance_type
                print(f"  [+] Instance launched: {launched_instance_id} ({instance_type})")
                print(f"  [!] CloudTrail event: ec2:RunInstances")
                if instance_type != FALLBACK_INSTANCE_TYPE:
                    print(f"  [!] Unusual instance type — potential cryptomining!")
                else:
                    print(f"  [~] Fell back to {FALLBACK_INSTANCE_TYPE} (GPU types unavailable)")
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in (
                    "InsufficientInstanceCapacity", "Unsupported",
                    "InvalidParameterValue", "VcpuLimitExceeded",
                    "InstanceLimitExceeded",
                ):
                    print(f"  [~] {instance_type} unavailable: {code} — trying next...")
                else:
                    raise

        if not launched_instance_id:
            print("  [!] Could not launch any instance type.")
            return

        # Brief dwell
        time.sleep(3)

    finally:
        # ── Revert ────────────────────────────────────────────────────────────
        banner("Revert — Terminate instance")
        if launched_instance_id:
            try:
                ec2_client.terminate_instances(InstanceIds=[launched_instance_id])
                print(f"  [+] Instance terminated: {launched_instance_id}")
            except ClientError as exc:
                print(f"  [!] TerminateInstances failed: {exc}")

    banner("Complete")
    print(f"CloudTrail events: ec2:RunInstances ({launched_instance_type}), ec2:TerminateInstances")
    print("\nDetection guidance:")
    print("  Alert on ec2:RunInstances with GPU or compute instance types")
    print("  outside your account's normal instance type baseline.")
    print("  GuardDuty detects actual mining traffic if the instance runs long enough.")


if __name__ == "__main__":
    main()
