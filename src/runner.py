import subprocess
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "simulations"))

from simulations.logger import get_logger

logger = get_logger("runner")

SIMULATIONS = {
    "1": ("attach_role_policy", "Privilege escalation via AttachRolePolicy"),
    "2": ("enumeration",        "IAM policy simulator / service enumeration"),
    "3": ("s3_initial_access",  "S3 basic access & data exfiltration"),
    "4": ("s3_kms_encryption",  "S3 KMS ransomware simulation"),
    "5": ("eventual_consistency", "Eventual consistency attack"),
}


def _pulumi_run(command: str, stack: str) -> bool:
    try:
        subprocess.run(
            ["pulumi", command, "--yes", "--stack", stack],
            cwd=os.path.dirname(__file__),
            check=True
        )
        return True
    except subprocess.CalledProcessError as err:
        logger.error(f"pulumi {command} failed: {err}")
        return False


def deploy_infrastructure(stack: str = "aws-dev") -> bool:
    logger.info(f"Deploying infrastructure on stack: {stack}")
    success = _pulumi_run("up", stack)
    if success:
        logger.info("Infrastructure deployed successfully")
    return success


def destroy_infrastructure(stack: str = "aws-dev") -> bool:
    logger.info(f"Destroying infrastructure on stack: {stack}")
    success = _pulumi_run("destroy", stack)
    if success:
        logger.info("Infrastructure destroyed successfully")
    return success


def run_emulations() -> None:
    """present simulation menu and run user-selected simulations"""
    print("\nAvailable simulations:")
    for key, (_, desc) in SIMULATIONS.items():
        print(f"  {key}. {desc}")
    print("  a. Run all")
    print("  q. Quit\n")

    choice = input("Select simulation(s) to run (comma-separated, e.g. 1,3): ").strip().lower()

    if choice == "q":
        return

    selected = list(SIMULATIONS.keys()) if choice == "a" else [c.strip() for c in choice.split(",")]

    for key in selected:
        if key not in SIMULATIONS:
            logger.error(f"Invalid choice: {key}")
            continue

        module_name, desc = SIMULATIONS[key]
        logger.info(f"Running: {desc}")
        try:
            if module_name == "attach_role_policy":
                from simulations.attach_role_policy import get_role_creds, attach_administrator_policy
                logger.info("attach_role_policy: use get_role_creds() / attach_administrator_policy() directly")

            elif module_name == "enumeration":
                from simulations.enumeration import enumerate_services
                enumerate_services()

            elif module_name == "s3_initial_access":
                from simulations.s3_initial_access import attack_s3
                attack_s3()

            elif module_name == "s3_kms_encryption":
                from simulations.s3_kms_encryption import simulate_kms_ransomware
                simulate_kms_ransomware()

            elif module_name == "eventual_consistency":
                from simulations.eventual_consistency import eventual_consistency_attack
                eventual_consistency_attack()

        except Exception as err:
            logger.error(f"Simulation '{desc}' failed: {err}")


def main(deploy: bool = False, destroy: bool = False, emulate: bool = False, stack: str = "aws-dev") -> None:
    if not deploy and not destroy and not emulate:
        logger.error("Provide at least one flag: --deploy, --destroy, or --emulate")
        return
    if deploy:
        if not deploy_infrastructure(stack):
            logger.error("Deployment failed, skipping emulations")
            return
    if destroy:
        destroy_infrastructure(stack)
        return
    if emulate:
        run_emulations()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MayaTrail runner")
    parser.add_argument("--deploy", action="store_true", help="Deploy Pulumi infrastructure")
    parser.add_argument("--destroy", action="store_true", help="Destroy Pulumi infrastructure")
    parser.add_argument("--emulate", action="store_true", help="Run AWS simulations")
    parser.add_argument("--stack", default="aws-dev", help="Pulumi stack name (default: aws-dev)")
    args = parser.parse_args()
    main(deploy=args.deploy, destroy=args.destroy, emulate=args.emulate, stack=args.stack)
