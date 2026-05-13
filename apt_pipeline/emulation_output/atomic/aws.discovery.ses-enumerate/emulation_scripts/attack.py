"""
Technique : aws.discovery.ses-enumerate
Tactic    : Discovery (T1087)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ses-enumerate/

Pre-requisites:
  - None. Reads existing SES configuration in the account and region.

How the attack works:
  An attacker who has gained AWS access may probe SES to determine whether
  the account can be used for phishing or spam campaigns.  Key signals include:
  - Is sending enabled?
  - What is the daily send quota?
  - Which email addresses / domains are verified (can be sent from)?

  Multiple read-only SES APIs are called in rapid succession.

Detection signal:
  - ses:GetAccountSendingEnabled, ses:GetSendQuota, ses:ListIdentities,
    ses:GetIdentityVerificationAttributes called in rapid succession.
  - Alert when the caller is not an expected monitoring or operational role.

Revert:
  - Nothing to revert (read-only operations).
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import boto3
from botocore.exceptions import ClientError


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    session    = boto3.Session()
    ses_client = session.client("ses")

    banner("Step 1 — Check account sending status (GetAccountSendingEnabled)")
    try:
        resp = ses_client.get_account_sending_enabled()
        enabled = resp.get("Enabled", False)
        print(f"  [+] Sending enabled : {enabled}")
        print(f"  [!] CloudTrail event: ses:GetAccountSendingEnabled")
    except ClientError as exc:
        print(f"  [!] GetAccountSendingEnabled failed: {exc}")

    banner("Step 2 — Check send quota (GetSendQuota)")
    try:
        resp = ses_client.get_send_quota()
        print(f"  [+] Max 24h send rate : {resp.get('Max24HourSend', 'N/A')} emails")
        print(f"  [+] Max send rate/s   : {resp.get('MaxSendRate', 'N/A')} emails/sec")
        print(f"  [+] Sent in last 24h  : {resp.get('SentLast24Hours', 'N/A')} emails")
        print(f"  [!] CloudTrail event: ses:GetSendQuota")
    except ClientError as exc:
        print(f"  [!] GetSendQuota failed: {exc}")

    banner("Step 3 — List verified identities (ListIdentities)")
    identities: list[str] = []
    try:
        paginator = ses_client.get_paginator("list_identities")
        for page in paginator.paginate():
            identities.extend(page.get("Identities", []))
        print(f"  [+] Verified identities found: {len(identities)}")
        for identity in identities:
            print(f"      • {identity}")
        print(f"  [!] CloudTrail event: ses:ListIdentities")
    except ClientError as exc:
        print(f"  [!] ListIdentities failed: {exc}")

    banner("Step 4 — Get identity verification status (GetIdentityVerificationAttributes)")
    if identities:
        # Batch at most 100 at a time (SES API limit)
        batch_size = 100
        for i in range(0, len(identities), batch_size):
            batch = identities[i:i + batch_size]
            try:
                resp = ses_client.get_identity_verification_attributes(
                    Identities=batch,
                )
                attrs = resp.get("VerificationAttributes", {})
                for identity, info in attrs.items():
                    status = info.get("VerificationStatus", "Unknown")
                    print(f"  [+] {identity:50s}  Status: {status}")
                print(f"  [!] CloudTrail event: ses:GetIdentityVerificationAttributes")
            except ClientError as exc:
                print(f"  [!] GetIdentityVerificationAttributes failed: {exc}")
    else:
        print("  [~] No identities to check.")

    banner("Complete")
    print("CloudTrail events: ses:GetAccountSendingEnabled, ses:GetSendQuota,")
    print("                   ses:ListIdentities, ses:GetIdentityVerificationAttributes")
    print("\nDetection guidance:")
    print("  Alert when multiple SES discovery APIs are called rapidly from")
    print("  unexpected principals — a strong indicator of phishing reconnaissance.")


if __name__ == "__main__":
    main()
