"""
Technique : aws.credential-access.secretsmanager-batch-retrieve-secrets
Tactic    : Credential Access (T1555)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.secretsmanager-batch-retrieve-secrets/

Pre-requisites:
  - Run `pulumi up` in ../infra/ first to create the 20 test secrets.
  - AWS credentials must have secretsmanager:ListSecrets + secretsmanager:BatchGetSecretValue.

Detection signal:
  - secretsmanager:BatchGetSecretValue in CloudTrail — distinct from individual
    GetSecretValue calls; detection rules should cover both API variants.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json
import os
import subprocess
from pathlib import Path

import boto3

BATCH_SIZE = 10  # BatchGetSecretValue max per call


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

    # ── Step 1: Enumerate secrets by tag ──────────────────────────────────────
    banner("Step 1 — Enumerate secrets (ListSecrets by tag)")
    paginator   = sm.get_paginator("list_secrets")
    secret_ids  = []
    for page in paginator.paginate(
        Filters=[{"Key": "tag-key",   "Values": [tag_key]},
                 {"Key": "tag-value", "Values": [tag_value]}],
        MaxResults=100,
    ):
        for s in page.get("SecretList", []):
            secret_ids.append(s["ARN"])
            print(f"  [+] Found: {s['Name']}")

    print(f"\n[*] Discovered {len(secret_ids)} secrets")

    if not secret_ids:
        print("[!] No secrets found — did you run pulumi up in ../infra/?")
        return

    # ── Step 2: Batch retrieve all secrets ────────────────────────────────────
    banner(f"Step 2 — BatchGetSecretValue ({len(secret_ids)} secrets, batch size {BATCH_SIZE})")
    total_retrieved = 0
    for i in range(0, len(secret_ids), BATCH_SIZE):
        batch = secret_ids[i:i + BATCH_SIZE]
        resp  = sm.batch_get_secret_value(
            SecretIdList=batch,
        )
        for s in resp.get("SecretValues", []):
            value = s.get("SecretString", s.get("SecretBinary", ""))
            print(f"  [+] {s['Name']} = {str(value)[:40]}")
            total_retrieved += 1
        for e in resp.get("Errors", []):
            print(f"  [!] Error on {e['SecretId']}: {e['ErrorCode']}")

    banner(f"Complete — {total_retrieved}/{len(secret_ids)} secrets retrieved via BatchGetSecretValue")
    print("\nNote: BatchGetSecretValue is a distinct API from GetSecretValue.")
    print("Ensure detection rules cover BOTH API calls.")


if __name__ == "__main__":
    main()
