"""
Celery tasks for the infrastructure app.

deploy_stack  — runs `pulumi up --yes` for a given stack.
destroy_stack — runs `pulumi destroy --yes` for a given stack.

Both tasks invoke the existing Pulumi IaC in src/ via subprocess.
SRC_DIR defaults to backend/../src but can be overridden with the SRC_DIR env var
(docker-compose sets SRC_DIR=/src and mounts the src/ directory there).
"""

import os
import subprocess
from pathlib import Path

from celery import shared_task
from django.apps import apps

# Absolute path to the src/ directory that contains Pulumi.yaml.
# parents[2] == backend/ locally or /app in the container.
# One level up from there lands at step1/ (locally) or / (container),
# so SRC_DIR can be overridden via the SRC_DIR environment variable.
# In docker-compose the src/ directory is mounted at /src and SRC_DIR=/src is set.
_BACKEND_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = Path(os.environ.get("SRC_DIR", str(_BACKEND_DIR.parent / "src")))


def _get_stack(stack_id: str):
    """
    Retrieve a Stack instance by its UUID primary key.

    Args:
        stack_id: String UUID of the Stack record.

    Returns:
        Stack model instance.
    """
    Stack = apps.get_model("infrastructure", "Stack")
    return Stack.objects.get(id=stack_id)


def _run_pulumi(stack_name: str, action: str) -> tuple[int, str, str]:
    """
    Execute a pulumi command against the given stack.

    Args:
        stack_name: The Pulumi stack name (e.g. dev-himan10).
        action: Either "up" or "destroy".

    Returns:
        Tuple of (return_code, stdout, stderr).
    """
    cmd = [
        "pulumi",
        action,
        "--yes",
        "--stack",
        stack_name,
        "--non-interactive",
    ]
    result = subprocess.run(
        cmd,
        cwd=SRC_DIR,
        capture_output=True,
        text=True,
        timeout=600,
    )
    return result.returncode, result.stdout, result.stderr


@shared_task(bind=True, name="infrastructure.deploy_stack")
def deploy_stack(self, stack_id: str) -> dict:
    """
    Celery task: deploy a Pulumi stack by running `pulumi up --yes`.

    Marks the Stack as READY on success, FAILED on error.
    Stores any stdout from Pulumi in the stack's outputs field as raw text
    until a proper JSON parser is added.

    Args:
        self: Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to deploy.

    Returns:
        Dict with keys: stack_id, status, stdout, stderr.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    try:
        stack = _get_stack(stack_id)
        returncode, stdout, stderr = _run_pulumi(stack.name, "up")

        if returncode == 0:
            stack.status = Stack.Status.READY
            stack.outputs = {"raw_stdout": stdout}
        else:
            stack.status = Stack.Status.FAILED

        stack.save(update_fields=["status", "outputs", "updated_at"])

        return {
            "stack_id": stack_id,
            "status": stack.status,
            "stdout": stdout,
            "stderr": stderr,
        }

    except Exception as exc:
        # Mark the stack as failed and re-raise so Celery records the error.
        try:
            stack = _get_stack(stack_id)
            stack.status = Stack.Status.FAILED
            stack.save(update_fields=["status", "updated_at"])
        except Exception:
            pass
        raise self.retry(exc=exc, max_retries=0) from exc


@shared_task(bind=True, name="infrastructure.destroy_stack")
def destroy_stack(self, stack_id: str) -> dict:
    """
    Celery task: destroy a Pulumi stack by running `pulumi destroy --yes`.

    Deletes the Stack record from the database on success.
    Marks the Stack as FAILED if the command exits non-zero.

    Args:
        self: Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to destroy.

    Returns:
        Dict with keys: stack_id, status, stdout, stderr.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    try:
        stack = _get_stack(stack_id)
        returncode, stdout, stderr = _run_pulumi(stack.name, "destroy")

        if returncode == 0:
            stack.delete()
            final_status = "destroyed"
        else:
            stack.status = Stack.Status.FAILED
            stack.save(update_fields=["status", "updated_at"])
            final_status = Stack.Status.FAILED

        return {
            "stack_id": stack_id,
            "status": final_status,
            "stdout": stdout,
            "stderr": stderr,
        }

    except Exception as exc:
        try:
            stack = _get_stack(stack_id)
            stack.status = Stack.Status.FAILED
            stack.save(update_fields=["status", "updated_at"])
        except Exception:
            pass
        raise self.retry(exc=exc, max_retries=0) from exc
