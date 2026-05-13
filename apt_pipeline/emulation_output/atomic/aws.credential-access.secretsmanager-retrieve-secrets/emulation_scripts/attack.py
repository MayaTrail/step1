"""
Technique : aws.credential-access.secretsmanager-retrieve-secrets
Tactic    : Credential Access (T1555)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.secretsmanager-retrieve-secrets/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the 20 test secrets.
  - AWS credentials must have secretsmanager:ListSecrets + secretsmanager:GetSecretValue.

Detection signal:
  - High volume of secretsmanager:GetSecretValue from a single principal in a short window.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import os
import subprocess
from pathlib import Path

import boto3


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_pulumi_outputs(stack_dir: str) -> dict:
    result = subprocess.run(
        ["pulumi", "stack", "output", "--json", "--show-secrets"],
        cwd=stack_dir,
        capture_output=True,
        text=True,
        env={**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")},
    )
    if result.returncode != 0:
        print(f"[!] pulumi stack output failed: {result.stderr.strip()}")
        return {}
    return json.loads(result.stdout)


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir = str(Path(__file__).parent.parent / "infra")
    infra     = get_pulumi_outputs(stack_dir)

    tag_key   = infra.get("tag_key",   "StratusRedTeam")
    tag_value = infra.get("tag_value", "true")

    session = boto3.Session()
    sm      = session.client("secretsmanager")

    # ── Step 1: Enumerate secrets tagged StratusRedTeam=true ──────────────────
    banner("Step 1 — Enumerate Secrets Manager secrets")
    paginator = sm.get_paginator("list_secrets")
    secret_arns = []
    for page in paginator.paginate(
        Filters=[{"Key": "tag-key", "Values": [tag_key]},
                 {"Key": "tag-value", "Values": [tag_value]}],
        MaxResults=100,
    ):
        for s in page.get("SecretList", []):
            secret_arns.append(s["ARN"])
            print(f"  [+] Found: {s['Name']} ({s['ARN']})")

    print(f"\n[*] Discovered {len(secret_arns)} secrets")

    if not secret_arns:
        print("[!] No secrets found — did you run pulumi up in ../infra/?")
        return

    # ── Step 2: Retrieve value of every discovered secret ────────────────────
    banner("Step 2 — Retrieve secret values (GetSecretValue x{len(secret_arns)})")
    retrieved = 0
    for arn in secret_arns:
        try:
            resp  = sm.get_secret_value(SecretId=arn)
            value = resp.get("SecretString", resp.get("SecretBinary", ""))
            print(f"  [+] Retrieved: {arn.split(':secret:')[1]} = {str(value)[:40]}")
            retrieved += 1
        except sm.exceptions.ResourceNotFoundException:
            print(f"  [!] Not found: {arn}")
        except Exception as e:
            print(f"  [!] Error retrieving {arn}: {e}")

    banner(f"Complete — {retrieved}/{len(secret_arns)} secrets retrieved")
    print("\nCloudTrail will show a burst of secretsmanager:GetSecretValue events")
    print("from a single principal. Detection rule: >= 10 GetSecretValue calls")
    print("from one principal within a 5-minute window.")


if __name__ == "__main__":
    main()
