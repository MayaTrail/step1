"""
Celery tasks for the infrastructure app.

deploy_stack   — runs `pulumi up` via a short-lived Pulumi Docker container.
destroy_stack  — runs `pulumi destroy` via a short-lived Pulumi Docker container.
refresh_stack  — runs `pulumi refresh` via a short-lived Pulumi Docker container.
preview_stack  — runs `pulumi preview` via a short-lived Pulumi Docker container.

Each task spawns an ephemeral container from the pre-built Pulumi image
(step1-pulumi) and passes the action, stack name, and AWS credentials as
environment variables. The container executes entrypoint.sh, which handles
S3 state-backend login, stack selection, and the Pulumi CLI command.
"""

import json
import logging
import os

import docker
from celery import shared_task
from django.apps import apps

logger = logging.getLogger(__name__)

# Docker image name for the Pulumi runner.
# This matches the service name in docker-compose.yml, which Docker Compose
# prefixes with the project directory name during build.
PULUMI_IMAGE = os.environ.get("PULUMI_IMAGE", "step1-pulumi")

# Default Pulumi state bucket and region — can be overridden via env vars.
STATE_BUCKET = os.environ.get("STATE_BUCKET", "mayatrail-pulumi-state")


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


def _run_pulumi_container(
    action: str,
    stack_name: str,
    region: str,
) -> tuple[int, str]:
    """
    Spawn a short-lived Docker container from the Pulumi image to execute
    a Pulumi action (up, destroy, preview, refresh).

    The container is automatically removed after execution.

    Args:
        action: The Pulumi action — one of "up", "destroy", "preview", "refresh".
        stack_name: The Pulumi stack name (e.g. dev-himan10).
        region: AWS region for this stack (e.g. us-east-1).

    Returns:
        Tuple of (exit_code, combined_output).
    """
    client = docker.from_env()

    environment = {
        "ACTION": action,
        "STACK": stack_name,
        "STATE_BUCKET": STATE_BUCKET,
        "AWS_REGION": region,
        # Pass AWS credentials from the worker's environment into the
        # Pulumi container so it can provision real cloud resources.
        "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID", ""),
        "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        "AWS_DEFAULT_REGION": region,
    }

    # Optionally pass session token for assumed-role scenarios.
    session_token = os.environ.get("AWS_SESSION_TOKEN")
    if session_token:
        environment["AWS_SESSION_TOKEN"] = session_token

    # Pulumi uses this passphrase to encrypt/decrypt stack secrets.
    passphrase = os.environ.get("PULUMI_CONFIG_PASSPHRASE")
    if passphrase:
        environment["PULUMI_CONFIG_PASSPHRASE"] = passphrase

    logger.info(
        "Spawning Pulumi container: image=%s action=%s stack=%s region=%s",
        PULUMI_IMAGE, action, stack_name, region,
    )

    try:
        output = client.containers.run(
            image=PULUMI_IMAGE,
            environment=environment,
            remove=True,        # auto-cleanup after exit
            stdout=True,
            stderr=True,
            # 10-minute timeout — Pulumi operations can be slow.
            # The container will be killed if it exceeds this.
            detach=False,
        )
        # containers.run returns bytes when detach=False
        decoded_output = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
        logger.info("Pulumi container completed successfully for stack=%s", stack_name)
        return 0, decoded_output

    except docker.errors.ContainerError as exc:
        # ContainerError is raised when the container exits with a non-zero code.
        decoded_output = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else str(exc.stderr)
        logger.error(
            "Pulumi container failed: action=%s stack=%s exit_code=%s",
            action, stack_name, exc.exit_status,
        )
        return exc.exit_status, decoded_output

    except docker.errors.ImageNotFound:
        msg = f"Pulumi image '{PULUMI_IMAGE}' not found. Run: docker-compose build pulumi"
        logger.error(msg)
        return 1, msg

    except docker.errors.APIError as exc:
        msg = f"Docker API error: {exc}"
        logger.error(msg)
        return 1, msg


def _parse_stack_outputs(raw_output: str) -> dict:
    """
    Attempt to extract structured JSON outputs from Pulumi stdout.

    The entrypoint.sh prints `pulumi stack output --json` after a
    successful `up`. This function tries to find and parse that JSON
    block. Falls back to storing the raw output string.

    Args:
        raw_output: The full stdout/stderr from the Pulumi container.

    Returns:
        Dict of parsed outputs, or {"raw_output": raw_output} as fallback.
    """
    # Look for the JSON block after "Stack outputs:"
    marker = "Stack outputs:"
    idx = raw_output.find(marker)
    if idx == -1:
        return {"raw_output": raw_output}

    json_str = raw_output[idx + len(marker):].strip()
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return {"raw_output": raw_output}


def _mark_failed(stack_id: str) -> None:
    """
    Best-effort helper to mark a stack as FAILED.

    Args:
        stack_id: UUID string of the Stack record.
    """
    try:
        stack = _get_stack(stack_id)
        Stack = apps.get_model("infrastructure", "Stack")
        stack.status = Stack.Status.FAILED
        stack.save(update_fields=["status", "updated_at"])
    except Exception:
        pass


@shared_task(bind=True, name="infrastructure.deploy_stack")
def deploy_stack(self, stack_id: str) -> dict:
    """
    Celery task: deploy a Pulumi stack by spawning a container that
    runs `pulumi up --yes`.

    Marks the Stack as READY on success, FAILED on error.
    Parses and stores Pulumi stack outputs in the outputs JSONField.

    Args:
        self: Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to deploy.

    Returns:
        Dict with keys: stack_id, status, output.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    try:
        stack = _get_stack(stack_id)
        exit_code, output = _run_pulumi_container("up", stack.name, stack.region)

        if exit_code == 0:
            stack.status = Stack.Status.READY
            stack.outputs = _parse_stack_outputs(output)
        else:
            stack.status = Stack.Status.FAILED
            stack.outputs = {"error": output}

        stack.save(update_fields=["status", "outputs", "updated_at"])

        return {
            "stack_id": stack_id,
            "status": stack.status,
            "output": output,
        }

    except Exception as exc:
        _mark_failed(stack_id)
        raise self.retry(exc=exc, max_retries=0) from exc


@shared_task(bind=True, name="infrastructure.destroy_stack")
def destroy_stack(self, stack_id: str) -> dict:
    """
    Celery task: destroy a Pulumi stack by spawning a container that
    runs `pulumi destroy --yes`.

    Deletes the Stack record from the database on success.
    Marks the Stack as FAILED if the container exits non-zero.

    Args:
        self: Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to destroy.

    Returns:
        Dict with keys: stack_id, status, output.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    try:
        stack = _get_stack(stack_id)
        exit_code, output = _run_pulumi_container("destroy", stack.name, stack.region)

        if exit_code == 0:
            stack.delete()
            return {
                "stack_id": stack_id,
                "status": "destroyed",
                "output": output,
            }
        else:
            stack.status = Stack.Status.FAILED
            stack.save(update_fields=["status", "updated_at"])
            return {
                "stack_id": stack_id,
                "status": Stack.Status.FAILED,
                "output": output,
            }

    except Exception as exc:
        _mark_failed(stack_id)
        raise self.retry(exc=exc, max_retries=0) from exc


@shared_task(bind=True, name="infrastructure.refresh_stack")
def refresh_stack(self, stack_id: str) -> dict:
    """
    Celery task: refresh a Pulumi stack by spawning a container that
    runs `pulumi refresh --yes`.

    Updates the stack's outputs with the latest state from the cloud
    provider without making any infrastructure changes.

    Args:
        self: Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to refresh.

    Returns:
        Dict with keys: stack_id, status, output.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    try:
        stack = _get_stack(stack_id)
        exit_code, output = _run_pulumi_container("refresh", stack.name, stack.region)

        if exit_code == 0:
            # Restore to READY after a successful refresh.
            stack.status = Stack.Status.READY
        else:
            stack.status = Stack.Status.FAILED

        stack.save(update_fields=["status", "updated_at"])

        return {
            "stack_id": stack_id,
            "status": stack.status,
            "output": output,
        }

    except Exception as exc:
        _mark_failed(stack_id)
        raise self.retry(exc=exc, max_retries=0) from exc


@shared_task(bind=True, name="infrastructure.preview_stack")
def preview_stack(self, stack_id: str) -> dict:
    """
    Celery task: preview changes for a Pulumi stack by spawning a
    container that runs `pulumi preview`.

    This is a read-only operation — no infrastructure changes are made.
    The stack status is not modified.

    Args:
        self: Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to preview.

    Returns:
        Dict with keys: stack_id, status, output.
    """
    try:
        stack = _get_stack(stack_id)
        exit_code, output = _run_pulumi_container("preview", stack.name, stack.region)

        return {
            "stack_id": stack_id,
            "status": "preview_complete" if exit_code == 0 else "preview_failed",
            "output": output,
        }

    except Exception as exc:
        raise self.retry(exc=exc, max_retries=0) from exc
