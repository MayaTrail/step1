#!/usr/bin/env python
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

"""
Atomic Emulation Runner
=======================
Runs each Stratus Red Team atomic technique end-to-end:
  1. pulumi stack init dev  (if needed)
  2. pulumi up --yes        (provision prerequisites)
  3. python attack.py       (execute the attack)
  4. pulumi destroy --yes   (teardown — always runs)

Usage:
    python run_atomics.py                          # run all
    python run_atomics.py --only cloudtrail-stop   # run one by name suffix
    python run_atomics.py --skip rds bedrock       # skip by substring
    python run_atomics.py --start-from ec2-user    # resume after interruption

Results are written to emulation_output/atomic_run_results.json
and a human-readable summary to emulation_output/atomic_run_summary.md
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────
SCRIPT_DIR  = Path(__file__).parent
ATOMIC_DIR  = SCRIPT_DIR / "emulation_output" / "atomic"
RESULTS_DIR = SCRIPT_DIR / "emulation_output"
RESULTS_JSON = RESULTS_DIR / "atomic_run_results.json"
SUMMARY_MD   = RESULTS_DIR / "atomic_run_summary.md"

# Use the Python that has all dependencies (3.14, not 3.9)
PYTHON = sys.executable   # the interpreter running this script

# Pulumi passphrase — empty string avoids interactive prompt
PULUMI_ENV = {**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")}

# ── Techniques ordered for execution (no-prereq first, expensive last) ────
TECHNIQUE_ORDER = [
    # ── No-prereq (fast, no infra) ──────────────────────────────────────
    "aws.credential-access.ec2-get-password-data",
    "aws.defense-evasion.organizations-leave",
    "aws.persistence.iam-create-backdoor-role",
    "aws.persistence.iam-create-user-login-profile",
    "aws.persistence.iam-create-admin-user",
    "aws.persistence.rolesanywhere-create-trust-anchor",
    "aws.persistence.sts-federation-token",
    "aws.discovery.ec2-download-user-data",
    "aws.discovery.ses-enumerate",
    "aws.execution.ec2-launch-unusual-instances",
    "aws.impact.bedrock-invoke-model",
    # ── Simple IAM prereqs ───────────────────────────────────────────────
    "aws.persistence.iam-backdoor-role",
    "aws.persistence.iam-backdoor-user",
    "aws.initial-access.console-login-without-mfa",
    "aws.privilege-escalation.iam-update-user-login-profile",
    # ── CloudTrail prereqs ───────────────────────────────────────────────
    "aws.defense-evasion.cloudtrail-stop",
    "aws.defense-evasion.cloudtrail-delete",
    "aws.defense-evasion.cloudtrail-event-selectors",
    "aws.defense-evasion.cloudtrail-lifecycle-rule",
    # ── S3 prereqs ───────────────────────────────────────────────────────
    "aws.exfiltration.s3-backdoor-bucket-policy",
    "aws.impact.s3-ransomware-batch-deletion",
    "aws.impact.s3-ransomware-client-side-encryption",
    "aws.impact.s3-ransomware-individual-deletion",
    # ── Lambda prereqs ───────────────────────────────────────────────────
    "aws.persistence.lambda-backdoor-function",
    "aws.persistence.lambda-layer-extension",
    "aws.persistence.lambda-overwrite-code",
    # ── EC2 prereqs ──────────────────────────────────────────────────────
    "aws.credential-access.ec2-steal-instance-credentials",
    "aws.execution.ec2-user-data",
    "aws.execution.ssm-send-command",
    "aws.execution.ssm-start-session",
    "aws.discovery.ec2-enumerate-from-instance",
    "aws.lateral-movement.ec2-instance-connect",
    "aws.lateral-movement.ec2-serial-console-send-ssh-public-key",
    # ── Other prereqs ────────────────────────────────────────────────────
    "aws.defense-evasion.dns-delete-logs",
    "aws.defense-evasion.vpc-remove-flow-logs",
    "aws.exfiltration.ec2-security-group-open-port-22-ingress",
    "aws.exfiltration.ec2-share-ami",
    "aws.exfiltration.ec2-share-ebs-snapshot",
    "aws.execution.sagemaker-update-lifecycle-config",
    # ── Credential access prereqs ─────────────────────────────────────────
    "aws.credential-access.secretsmanager-retrieve-secrets",
    "aws.credential-access.secretsmanager-batch-retrieve-secrets",
    "aws.credential-access.ssm-retrieve-securestring-parameters",
    # ── Slow/expensive last ───────────────────────────────────────────────
    "aws.exfiltration.rds-share-snapshot",
]

# Techniques with no real infra (pulumi up just exports a note — still run it)
NO_PREREQ_TECHNIQUES = {
    "aws.credential-access.ec2-get-password-data",
    "aws.defense-evasion.organizations-leave",
    "aws.persistence.iam-create-backdoor-role",
    "aws.persistence.iam-create-user-login-profile",
    "aws.persistence.iam-create-admin-user",
    "aws.persistence.rolesanywhere-create-trust-anchor",
    "aws.persistence.sts-federation-token",
    "aws.discovery.ec2-download-user-data",
    "aws.discovery.ses-enumerate",
    "aws.execution.ec2-launch-unusual-instances",
    "aws.impact.bedrock-invoke-model",
}


def run(cmd: list[str], cwd: str, timeout: int = 900) -> tuple[int, str, str]:
    """Run a subprocess, capture stdout/stderr, return (rc, stdout, stderr)."""
    print(f"    $ {' '.join(cmd)}")
    start = time.time()
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True,
            timeout=timeout, env=PULUMI_ENV,
        )
        elapsed = time.time() - start
        print(f"      → rc={proc.returncode} in {elapsed:.1f}s")
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        print(f"      → TIMEOUT after {elapsed:.1f}s")
        return -1, "", f"TIMEOUT after {elapsed:.1f}s"


def pulumi_stack_exists(infra_dir: str) -> bool:
    rc, out, _ = run(["pulumi", "stack", "ls", "--json"], cwd=infra_dir, timeout=30)
    if rc != 0:
        return False
    try:
        stacks = json.loads(out)
        return any(s.get("name") == "dev" for s in stacks)
    except Exception:
        return False


def run_technique(tech_id: str) -> dict:
    """Run one atomic technique end-to-end. Returns a result dict."""
    tech_dir   = ATOMIC_DIR / tech_id
    infra_dir  = str(tech_dir / "infra")
    attack_py  = str(tech_dir / "emulation_scripts" / "attack.py")

    result = {
        "id": tech_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stack_init": None,
        "pulumi_up": None,
        "attack": None,
        "pulumi_destroy": None,
        "status": "pending",
        "notes": [],
    }

    print(f"\n{'='*70}")
    print(f"  TECHNIQUE: {tech_id}")
    print(f"{'='*70}")

    total_start = time.time()

    try:
        # ── Step 1: stack init ────────────────────────────────────────────
        if not pulumi_stack_exists(infra_dir):
            print("  [1/4] pulumi stack init dev")
            rc, out, err = run(["pulumi", "stack", "init", "dev"], cwd=infra_dir, timeout=60)
            result["stack_init"] = {"rc": rc, "stdout": out[:500], "stderr": err[:500]}
            if rc != 0:
                result["status"] = "fail_stack_init"
                result["notes"].append(f"stack init failed: {err[:200]}")
                return result
        else:
            print("  [1/4] stack 'dev' already exists — selecting")
            rc, out, err = run(["pulumi", "stack", "select", "dev"], cwd=infra_dir, timeout=30)
            result["stack_init"] = {"rc": rc, "stdout": "existing", "stderr": ""}

        # ── Step 2: pulumi up (retry once on failure for DNS propagation) ───
        print("  [2/4] pulumi up --yes")
        up_timeout = 120 if tech_id in NO_PREREQ_TECHNIQUES else 900
        rc, out, err = run(
            ["pulumi", "up", "--yes", "--skip-preview"],
            cwd=infra_dir, timeout=up_timeout,
        )
        if rc != 0:
            print("  [!] pulumi up attempt 1 failed — waiting 15s for DNS propagation then retrying...")
            time.sleep(15)
            rc, out, err = run(
                ["pulumi", "up", "--yes", "--skip-preview"],
                cwd=infra_dir, timeout=up_timeout,
            )
        result["pulumi_up"] = {"rc": rc, "stdout": out[-2000:], "stderr": err[-1000:]}
        if rc != 0:
            result["status"] = "fail_pulumi_up"
            result["notes"].append("pulumi up failed after retry")
            # Still try to destroy whatever was partially created
            run(["pulumi", "destroy", "--yes", "--skip-preview"], cwd=infra_dir, timeout=600)
            return result

        # ── Step 3: run attack ────────────────────────────────────────────
        print("  [3/4] python attack.py")
        rc, out, err = run([PYTHON, attack_py], cwd=str(tech_dir), timeout=300)
        result["attack"] = {
            "rc": rc,
            "stdout": out[-3000:],
            "stderr": err[-1000:],
        }
        if rc != 0:
            result["notes"].append(f"attack.py exited with rc={rc}")

    except Exception as exc:
        result["status"] = "error"
        result["notes"].append(str(exc))
    finally:
        # ── Step 4: always destroy (retry once on failure) ────────────────
        print("  [4/4] pulumi destroy --yes")
        rc, out, err = run(
            ["pulumi", "destroy", "--yes", "--skip-preview"],
            cwd=infra_dir, timeout=900,
        )
        if rc != 0:
            print("  [!] destroy attempt 1 failed — waiting 15s then retrying...")
            time.sleep(15)
            rc, out, err = run(
                ["pulumi", "destroy", "--yes", "--skip-preview"],
                cwd=infra_dir, timeout=900,
            )
        result["pulumi_destroy"] = {"rc": rc, "stdout": out[-1000:], "stderr": err[-500:]}

    elapsed = time.time() - total_start
    result["elapsed_s"] = round(elapsed, 1)

    # ── Determine final status ────────────────────────────────────────────
    if result["status"] == "pending":
        attack_rc  = (result["attack"] or {}).get("rc", -1)
        destroy_rc = (result["pulumi_destroy"] or {}).get("rc", -1)
        if attack_rc == 0 and destroy_rc == 0:
            result["status"] = "pass"
        elif attack_rc != 0:
            result["status"] = "fail_attack"
        else:
            result["status"] = "warn_destroy"

    icon = "✅" if result["status"] == "pass" else "❌" if result["status"].startswith("fail") else "⚠️"
    print(f"\n  {icon} {result['status'].upper()} — {elapsed:.1f}s")
    return result


def write_summary(results: list[dict]) -> None:
    passed  = [r for r in results if r["status"] == "pass"]
    failed  = [r for r in results if r["status"].startswith("fail")]
    warned  = [r for r in results if r["status"] == "warn_destroy"]
    pending = [r for r in results if r["status"] == "pending"]

    lines = [
        "# Atomic Emulation Run Summary",
        f"\nGenerated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"\n## Overall: {len(passed)}/{len(results)} passed | {len(failed)} failed | {len(warned)} warn | {len(pending)} pending\n",
        "| Technique | Status | Time |",
        "|-----------|--------|------|",
    ]
    for r in results:
        icon = "✅" if r["status"] == "pass" else "❌" if r["status"].startswith("fail") else "⚠️"
        elapsed = f"{r.get('elapsed_s', '?')}s"
        lines.append(f"| `{r['id']}` | {icon} {r['status']} | {elapsed} |")

    if failed:
        lines.append("\n## Failures\n")
        for r in failed:
            lines.append(f"### {r['id']}")
            lines.append(f"- Status: `{r['status']}`")
            for note in r.get("notes", []):
                lines.append(f"- {note}")
            attack = r.get("attack") or {}
            if attack.get("stderr"):
                lines.append(f"```\n{attack['stderr'][-500:]}\n```")
            lines.append("")

    SUMMARY_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nSummary written → {SUMMARY_MD}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="Run only techniques matching this substring")
    parser.add_argument("--skip", nargs="+", default=[], help="Skip techniques matching these substrings")
    parser.add_argument("--start-from", help="Skip all techniques before this one (for resuming)")
    parser.add_argument("--dry-run", action="store_true", help="Print order only, don't run")
    args = parser.parse_args()

    # Build ordered list of techniques to run
    all_techniques = TECHNIQUE_ORDER.copy()
    # Add any in atomic dir not in TECHNIQUE_ORDER
    for d in sorted(ATOMIC_DIR.iterdir()):
        if d.is_dir() and d.name not in all_techniques:
            all_techniques.append(d.name)

    # Apply filters
    if args.only:
        all_techniques = [t for t in all_techniques if args.only in t]
    if args.skip:
        all_techniques = [t for t in all_techniques if not any(s in t for s in args.skip)]
    if args.start_from:
        idx = next((i for i, t in enumerate(all_techniques) if args.start_from in t), 0)
        all_techniques = all_techniques[idx:]

    print(f"\n{'='*70}")
    print(f"  ATOMIC EMULATION RUNNER")
    print(f"  Techniques to run: {len(all_techniques)}")
    print(f"  Python: {PYTHON}")
    print(f"  AWS account: {os.environ.get('AWS_PROFILE', 'default')}")
    print(f"{'='*70}")

    if args.dry_run:
        for i, t in enumerate(all_techniques, 1):
            prefix = "[no-infra]" if t in NO_PREREQ_TECHNIQUES else "[has-infra]"
            print(f"  {i:2d}. {prefix} {t}")
        return

    # Load existing results if any (for resume)
    if RESULTS_JSON.exists():
        existing = json.loads(RESULTS_JSON.read_text())
        done_ids = {r["id"] for r in existing if r["status"] == "pass"}
    else:
        existing = []
        done_ids = set()

    results = [r for r in existing if r["id"] in {t for t in all_techniques}]
    already_done = [t for t in all_techniques if t in done_ids]
    to_run = [t for t in all_techniques if t not in done_ids]

    if already_done:
        print(f"\n  Skipping {len(already_done)} already-passed techniques.")

    for i, tech_id in enumerate(to_run, 1):
        print(f"\n  [{i}/{len(to_run)}]")
        r = run_technique(tech_id)
        # Replace or append
        results = [x for x in results if x["id"] != tech_id]
        results.append(r)
        # Read-merge-write: always reload from disk first to preserve parallel results
        if RESULTS_JSON.exists():
            try:
                on_disk = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
            except Exception:
                on_disk = []
        else:
            on_disk = []
        merged = [x for x in on_disk if x["id"] != tech_id] + [r]
        RESULTS_JSON.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        write_summary(merged)

    # Final summary
    passed = sum(1 for r in results if r["status"] == "pass")
    print(f"\n\n{'='*70}")
    print(f"  DONE: {passed}/{len(results)} passed")
    print(f"  Results: {RESULTS_JSON}")
    print(f"  Summary: {SUMMARY_MD}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
