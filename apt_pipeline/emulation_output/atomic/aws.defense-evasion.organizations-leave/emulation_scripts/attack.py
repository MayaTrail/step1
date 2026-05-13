"""
Technique : aws.defense-evasion.organizations-leave
Tactic    : Defense Evasion (T1562)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.organizations-leave/

Pre-requisites:
  - None. The call is expected to fail (AccessDenied or account not in org).

How the attack works:
  An attacker who has gained control of an AWS account may attempt to remove it
  from its AWS Organization.  Leaving the org would disable Service Control
  Policies, GuardDuty org delegation, CloudTrail org-level trails, and AWS
  Config aggregation — effectively blinding centralized security tooling.

  The call is expected to return AccessDenied (master cannot leave) or
  AWSOrganizationsNotInUseException (account not in any org).  Either way,
  the attempt is logged to CloudTrail, which is the detection signal.

Detection signal:
  - organizations:LeaveOrganization in CloudTrail.
  - This API is almost never called legitimately outside of controlled
    account migrations — any occurrence warrants immediate investigation.

Revert:
  - Nothing to revert (call is expected to fail with no side effects).
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
    session      = boto3.Session()
    orgs_client  = session.client("organizations")

    banner("Step 1 — Attempt organizations:LeaveOrganization")
    print("  Calling LeaveOrganization (expected to be denied)...")

    try:
        orgs_client.leave_organization()
        # If this succeeds the account was in an org as a member account
        print("  [!] SUCCESS — account has left the organization!")
        print("  [!] CloudTrail org trails, SCPs, and GuardDuty delegation may now be gone.")
        print("  [!] MANUAL ACTION REQUIRED: re-join the org and re-enable controls.")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        msg  = exc.response["Error"]["Message"]
        if code in ("AWSOrganizationsNotInUseException",
                    "AccountIsAlreadyRegisteredWithOrganization"):
            print(f"  [~] Expected error: {code}")
            print("      Account is not part of any organization.")
            print("      CloudTrail event still generated — this is the signal.")
        elif code == "AccessDeniedException":
            print(f"  [~] Expected error: {code}")
            print("      Account is the management (master) account or SCP denies it.")
            print("      CloudTrail event still generated — this is the signal.")
        else:
            print(f"  [!] Unexpected error: {code} — {msg}")

    banner("Complete")
    print("CloudTrail event generated: organizations:LeaveOrganization")
    print("\nDetection guidance:")
    print("  Alert on any occurrence of organizations:LeaveOrganization —")
    print("  this API is almost never called outside planned account offboarding.")


if __name__ == "__main__":
    main()
