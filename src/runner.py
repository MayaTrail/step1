"""
MayaTrail Pulumi Runner.

Unified CLI for managing Pulumi infrastructure and running simulations.
Works both as a local script and as a Docker container entrypoint.

Usage (local):
    python runner.py --action deploy --stack dev-himan10
    python runner.py --action destroy --stack dev-himan10
    python runner.py --action preview --stack dev-himan10
    python runner.py --action refresh --stack dev-himan10
    python runner.py --emulate

Usage (Docker — env vars):
    docker run -e ACTION=up -e STACK=dev-himan10 step1-pulumi

All CLI flags fall back to environment variables, which fall back to defaults.
"""

import argparse
import json
import os
import subprocess
import sys

# Add the project root (step1/) to sys.path so the top-level `simulations`
# package is importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulations.logger import get_logger
from simulations.registry import discover

logger = get_logger("runner")

# Valid actions & simulation catalogue

VALID_ACTIONS = ("up", "destroy", "preview", "refresh")

# Pulumi helpers

def _pulumi_cmd(args: list[str]) -> bool:
    """
    Run a pulumi CLI command and return True on success.

    Args:
        args: List of arguments passed to the pulumi CLI.

    Returns:
        True if the command exited with code 0, False otherwise.
    """
    try:
        subprocess.run(
            ["pulumi"] + args,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            check=True,
        )
        return True
    except subprocess.CalledProcessError as err:
        logger.error(f"pulumi {' '.join(args)} failed: {err}")
        return False


def pulumi_login(state_bucket: str) -> bool:
    """
    Login to the S3-backed Pulumi state backend.

    Args:
        state_bucket: Name of the S3 bucket (without s3:// prefix).

    Returns:
        True on success.
    """
    logger.info(f"[1/4] Logging into Pulumi state backend: s3://{state_bucket}")
    return _pulumi_cmd(["login", f"s3://{state_bucket}", "--non-interactive"])


def pulumi_select_or_init_stack(stack: str) -> bool:
    """
    Select an existing Pulumi stack, or create it if it doesn't exist.

    Args:
        stack: The Pulumi stack name (e.g. dev-himan10).

    Returns:
        True on success.
    """
    logger.info(f"[2/4] Selecting stack: {stack}")
    # Try to select; if it doesn't exist, init it.
    try:
        subprocess.run(
            ["pulumi", "stack", "select", stack],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError:
        logger.info(f"Stack '{stack}' not found, creating it...")
        return _pulumi_cmd(["stack", "init", stack])


def pulumi_set_region(region: str) -> bool:
    """
    Set the AWS region config on the current Pulumi stack.

    Args:
        region: AWS region (e.g. us-east-1).

    Returns:
        True on success.
    """
    logger.info(f"[3/4] Setting AWS region: {region}")
    return _pulumi_cmd(["config", "set", "aws:region", region, "--non-interactive"])


def pulumi_execute(action: str) -> bool:
    """
    Execute a Pulumi action (up, destroy, preview, refresh).

    For 'up', also prints stack outputs as JSON after success.

    Args:
        action: One of "up", "destroy", "preview", "refresh".

    Returns:
        True on success.
    """
    logger.info(f"[4/4] Executing: pulumi {action}")

    if action == "up":
        success = _pulumi_cmd(["up", "--yes", "--non-interactive"])
        if success:
            print("\nStack outputs:")
            _pulumi_cmd(["stack", "output", "--json"])
        return success

    elif action == "destroy":
        return _pulumi_cmd(["destroy", "--yes", "--non-interactive"])

    elif action == "preview":
        return _pulumi_cmd(["preview", "--non-interactive"])

    elif action == "refresh":
        return _pulumi_cmd(["refresh", "--yes", "--non-interactive"])

    else:
        logger.error(f"Invalid action: '{action}'. Valid options: {', '.join(VALID_ACTIONS)}")
        return False

# High-level operations

def run_infra_action(
    action: str,
    stack: str,
    state_bucket: str,
    region: str,
) -> bool:
    """
    Full Pulumi workflow: login → select stack → set region → execute action.

    Args:
        action: One of "up", "destroy", "preview", "refresh".
        stack: Pulumi stack name.
        state_bucket: S3 bucket name for Pulumi state.
        region: AWS region for the stack.

    Returns:
        True if all steps succeeded.
    """
    print(f"\n MayaTrail Pulumi Runner")
    print(f" Action : {action}")
    print(f" Stack  : {stack}")
    print(f" State  : s3://{state_bucket}")
    print(f" Region : {region}\n")

    if not pulumi_login(state_bucket):
        return False

    if not pulumi_select_or_init_stack(stack):
        return False

    if not pulumi_set_region(region):
        return False

    success = pulumi_execute(action)

    if success:
        print("\nDone.")
    else:
        logger.error(f"Action '{action}' failed.")

    return success


def run_emulations() -> None:
    """Present simulation menu and run user-selected simulations."""
    sims = discover()

    if not sims:
        logger.error("No simulation modules found.")
        return

    # Build a lookup: string key → sim entry
    sim_by_key = {str(s["id"]): s for s in sims}

    print("\nAvailable simulations:")
    for key, sim in sim_by_key.items():
        print(f"  {key}. {sim['description']}")
    print("  a. Run all")
    print("  q. Quit\n")

    choice = input("Select simulation(s) to run (comma-separated, e.g. 1,3): ").strip().lower()

    if choice == "q":
        return

    selected = list(sim_by_key.keys()) if choice == "a" else [c.strip() for c in choice.split(",")]

    for key in selected:
        if key not in sim_by_key:
            logger.error(f"Invalid choice: {key}")
            continue

        sim = sim_by_key[key]
        logger.info(f"Running: {sim['description']}")
        try:
            sim["module"].run()
        except Exception as err:
            logger.error(f"Simulation '{sim['description']}' failed: {err}")


# CLI entry point

def main() -> None:
    parser = argparse.ArgumentParser(
        description="MayaTrail runner — Pulumi infrastructure management & security simulations.",
    )
    parser.add_argument(
        "--action",
        choices=VALID_ACTIONS,
        default=os.environ.get("ACTION"),
        help="Pulumi action to execute. Falls back to ACTION env var. (choices: up, destroy, preview, refresh)",
    )
    parser.add_argument(
        "--stack",
        default=os.environ.get("STACK", "dev-default"),
        help="Pulumi stack name (default: dev-default or STACK env var).",
    )
    parser.add_argument(
        "--state-bucket",
        default=os.environ.get("STATE_BUCKET", "mayatrail-pulumi-state"),
        help="S3 bucket for Pulumi state (default: mayatrail-pulumi-state or STATE_BUCKET env var).",
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION", "ap-south-1"),
        help="AWS region (default: ap-south-1 or AWS_REGION env var).",
    )
    parser.add_argument(
        "--emulate",
        action="store_true",
        help="Run security simulations interactively.",
    )

    args = parser.parse_args()

    if args.emulate:
        run_emulations()
        return

    if not args.action:
        parser.error("Provide --action (up|destroy|preview|refresh) or --emulate.")

    success = run_infra_action(
        action=args.action,
        stack=args.stack,
        state_bucket=args.state_bucket,
        region=args.region,
    )

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
