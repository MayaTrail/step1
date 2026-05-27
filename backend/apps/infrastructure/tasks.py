"""
Celery tasks for the infrastructure app.

deploy_stack   — runs `pulumi up` via the Pulumi Automation API.
destroy_stack  — runs `pulumi destroy` via the Pulumi Automation API.
refresh_stack  — runs `pulumi refresh` via the Pulumi Automation API.
preview_stack  — runs `pulumi preview` via the Pulumi Automation API.

Each task uses the Pulumi Automation API (pulumi.automation) to drive the
Pulumi CLI directly from within the worker process.  No Docker containers
are spawned and the Docker socket is not required.

Each emulation's Pulumi program lives at {EMULATIONS_BASE_DIR}/{type}/infra/,
which must contain a Pulumi.yaml and a __main__.py.  The worker container
mounts ./emulations there as a read-only volume.

State is stored in the S3 bucket identified by STATE_BUCKET.  The backend
URL is injected as PULUMI_BACKEND_URL so no `pulumi login` step is needed.

AWS credentials are read from the worker's environment at task run time and
passed to the Pulumi workspace as scoped environment variables so they are
never stored in the database or visible in the process listing.
"""

import logging
import os
import shutil
import tempfile
from collections.abc import Callable

import boto3
from botocore.exceptions import ClientError
from celery import shared_task
from django.apps import apps
from pulumi import automation as auto

logger = logging.getLogger(__name__)

# Base directory under which emulation packages are mounted.
# Each emulation's Pulumi program lives at {EMULATIONS_BASE_DIR}/{type}/infra/.
# Mounted as a read-only volume from ./emulations in docker-compose.yml.
EMULATIONS_BASE_DIR = os.environ.get("EMULATIONS_BASE_DIR", "/opt/emulations")

# S3 bucket that holds the Pulumi state for all stacks.
STATE_BUCKET = os.environ.get("STATE_BUCKET", "mayatrail-state-bucket")

# AWS region where the state bucket lives.  Embedded in PULUMI_BACKEND_URL as a
# query parameter so Pulumi uses this region for S3 access independently of the
# stack's deployment region (which may differ).
STATE_BUCKET_REGION = os.environ.get("STATE_BUCKET_REGION", "ap-south-1")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _prepare_work_dir(source_dir: str) -> str:
    """
    Copy essential Pulumi program files into a fresh writable temp directory.

    Pulumi writes Pulumi.<stack>.yaml (stack config) and other workspace
    artefacts directly into work_dir.  Because the source directory is mounted
    read-only in Docker, we copy only the two files Pulumi needs to run the
    program into a throwaway temp directory instead.

    The caller is responsible for removing the directory with
    shutil.rmtree(tmp_dir, ignore_errors=True) after the operation completes.

    Args:
        source_dir: Absolute path to the read-only Pulumi program directory.

    Returns:
        Absolute path to the writable temp directory containing the program.
    """
    tmp_dir = tempfile.mkdtemp(prefix="mayatrail-pulumi-")
    for fname in ("Pulumi.yaml", "__main__.py"):
        src = os.path.join(source_dir, fname)
        if os.path.exists(src):
            shutil.copy2(src, tmp_dir)
    return tmp_dir


def _resolve_work_dir(emulation_type: str) -> str:
    """
    Resolve the Pulumi program directory for the given emulation type.

    Each emulation ships its own Pulumi program at:
        {EMULATIONS_BASE_DIR}/{emulation_type}/infra/

    This convention means adding a new emulation requires no changes here —
    simply placing a Pulumi.yaml and __main__.py under the infra/ directory
    of the new emulation package is sufficient.

    Args:
        emulation_type: The emulation package name stored on the Stack record
                        (e.g. "scarleteel", "apt29"). Must be non-empty.

    Returns:
        Absolute path to the emulation's infra/ directory.

    Raises:
        ValueError: If emulation_type is empty or the resolved directory does
                    not exist under EMULATIONS_BASE_DIR.
    """
    if not emulation_type:
        raise ValueError(
            "emulation_type is required. "
            "Every enterprise stack must be associated with an emulation package."
        )

    infra_dir = os.path.join(EMULATIONS_BASE_DIR, emulation_type, "infra")
    if not os.path.isdir(infra_dir):
        raise ValueError(
            f"Emulation infra directory not found: {infra_dir}. "
            f"Ensure emulations/{emulation_type}/infra/ exists and is mounted."
        )

    return infra_dir


def _get_stack_record(stack_id: str):
    """
    Retrieve a Stack model instance by its UUID primary key.

    Owner is select_related so tasks can read aws_role_arn for STS assume-role
    without an extra query.

    Args:
        stack_id: String UUID of the Stack record.

    Returns:
        Stack model instance with owner pre-fetched.
    """
    Stack = apps.get_model("infrastructure", "Stack")
    return Stack.objects.select_related("owner").get(id=stack_id)


def _assume_user_role(user) -> dict[str, str]:
    """
    Assume the enterprise user's cross-account IAM role via STS and return
    short-lived credentials scoped to that role.

    Enterprise users connect their own AWS account via the Connector page,
    which stores the role ARN on the User record.  Pulumi must run under that
    role so it operates in the user's account and can access their resources
    and the Pulumi state backend.

    Args:
        user: User instance with a non-empty aws_role_arn field.

    Returns:
        Dict with keys AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
        AWS_SESSION_TOKEN (all short-lived STS credentials).

    Raises:
        botocore.exceptions.ClientError if the role cannot be assumed.
        ValueError if the user has no aws_role_arn configured.
    """
    if not getattr(user, "aws_role_arn", None):
        raise ValueError(
            f"Enterprise user {user.email} has no aws_role_arn configured. "
            "Connect an AWS account via the Connector page first."
        )

    sts = boto3.client("sts")
    assumed = sts.assume_role(
        RoleArn=user.aws_role_arn,
        RoleSessionName=f"mayatrail-infra-{user.id}",
        DurationSeconds=3600,
    )
    creds = assumed["Credentials"]
    return {
        "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": creds["SessionToken"],
    }


def _get_aws_credentials(stack) -> dict[str, str]:
    """
    Return short-lived STS credentials for this stack's enterprise owner.

    All stacks in step1 are enterprise stacks — credentials are always obtained
    by assuming the user's cross-account IAM role via STS.

    Args:
        stack: Stack instance with owner pre-fetched.

    Returns:
        Dict of AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN.

    Raises:
        ValueError: If the owner has no aws_role_arn configured.
    """
    return _assume_user_role(stack.owner)


def _build_workspace_env(region: str, aws_creds: dict[str, str]) -> dict[str, str]:
    """
    Build the environment variable dict passed to the Pulumi LocalWorkspace.

    Sets PULUMI_BACKEND_URL so no `pulumi login` call is required.
    Injects the provided AWS credentials and the stack secrets passphrase.

    Args:
        region:    AWS region for this stack (e.g. "ap-south-1").
        aws_creds: AWS credential dict (from _get_aws_credentials).

    Returns:
        Dict of environment variable name/value pairs for the workspace.
    """
    env: dict[str, str] = {
        "PULUMI_BACKEND_URL": f"s3://{STATE_BUCKET}?region={STATE_BUCKET_REGION}",
        "AWS_REGION": region,
        "AWS_DEFAULT_REGION": region,
        **aws_creds,
    }

    passphrase = os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")
    if passphrase:
        env["PULUMI_CONFIG_PASSPHRASE"] = passphrase

    return env


def _get_pulumi_stack(
    stack_name: str,
    region: str,
    aws_creds: dict[str, str],
    work_dir: str,
) -> auto.Stack:
    """
    Return a configured Pulumi Automation API Stack for the given stack name.

    Uses the local program at work_dir (must contain Pulumi.yaml + __main__.py).
    If the stack does not yet exist in the S3 state backend, it is created.
    The AWS region is set as a Pulumi config value so that pulumi_aws picks it
    up without a separate `pulumi config set` step.

    Args:
        stack_name: Pulumi stack name (e.g. "dev-himan10").
        region:     AWS region for this stack.
        aws_creds:  AWS credential dict from _get_aws_credentials().
        work_dir:   Absolute path to the Pulumi program directory.

    Returns:
        Configured pulumi.automation.Stack instance ready for an operation.
    """
    env = _build_workspace_env(region, aws_creds)

    stack = auto.create_or_select_stack(
        stack_name=stack_name,
        work_dir=work_dir,
        opts=auto.LocalWorkspaceOptions(env_vars=env),
    )
    stack.set_config("aws:region", auto.ConfigValue(value=region))
    return stack


def _make_log_handler(label: str) -> tuple[list[str], Callable[[str], None]]:
    """
    Return a (lines_list, on_output) pair for capturing Pulumi output in real time.

    Each line is forwarded to the Python logger immediately so it appears in
    the worker log stream without waiting for the operation to complete.

    Args:
        label: Stack name used as context in log messages.

    Returns:
        Tuple of (accumulated_lines, on_output_callback).
        The callback appends to accumulated_lines and logs each line.
    """
    lines: list[str] = []

    def on_output(msg: str) -> None:
        stripped = msg.rstrip()
        logger.info("[pulumi/%s] %s", label, stripped)
        lines.append(stripped)

    return lines, on_output


def _mark_failed(stack_id: str) -> None:
    """
    Best-effort: mark a Stack record as FAILED.

    Intentionally swallows all exceptions so it never masks the original error
    that triggered the failure path.

    Args:
        stack_id: UUID string of the Stack record.
    """
    try:
        Stack = apps.get_model("infrastructure", "Stack")
        record = Stack.objects.get(id=stack_id)
        record.status = Stack.Status.FAILED
        record.save(update_fields=["status", "updated_at"])
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Celery tasks
# ---------------------------------------------------------------------------

@shared_task(bind=True, name="infrastructure.deploy_stack")
def deploy_stack(self, stack_id: str) -> dict:
    """
    Celery task: deploy a Pulumi stack via the Automation API (`pulumi up`).

    Marks the Stack record as READY and persists clean JSON outputs on success.
    Marks as FAILED if the Pulumi command exits non-zero.

    The Automation API provides typed stack outputs via result.outputs — no
    stdout scraping is needed.

    Args:
        self:     Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to deploy.

    Returns:
        Dict with keys: stack_id, status.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    record = _get_stack_record(stack_id)
    tmp_dir = _prepare_work_dir(_resolve_work_dir(record.emulation_type))
    try:
        aws_creds = _get_aws_credentials(record)
        pulumi_stack = _get_pulumi_stack(record.name, record.region, aws_creds, work_dir=tmp_dir)
        _, on_output = _make_log_handler(record.name)

        logger.info(
            "Starting deploy: stack=%s region=%s user=%s emulation=%s",
            record.name, record.region, record.owner.email, record.emulation_type,
        )
        result = pulumi_stack.up(on_output=on_output)

        # result.outputs is dict[str, OutputValue] — .value unwraps the typed value.
        outputs = {key: val.value for key, val in result.outputs.items()}

        record.status = Stack.Status.READY
        record.outputs = outputs
        record.save(update_fields=["status", "outputs", "updated_at"])

        logger.info("Deploy complete: stack=%s outputs_keys=%s", record.name, list(outputs))
        return {"stack_id": stack_id, "status": record.status}

    except Exception as exc:
        logger.error("Deploy failed: stack_id=%s error=%s", stack_id, exc, exc_info=True)
        _mark_failed(stack_id)
        raise self.retry(exc=exc, max_retries=0) from exc

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@shared_task(bind=True, name="infrastructure.destroy_stack")
def destroy_stack(self, stack_id: str) -> dict:
    """
    Celery task: destroy a Pulumi stack via the Automation API (`pulumi destroy`).

    Deletes the Stack DB record on success.
    Marks the Stack as FAILED if the Pulumi command exits non-zero.

    Args:
        self:     Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to destroy.

    Returns:
        Dict with keys: stack_id, status.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    record = _get_stack_record(stack_id)
    tmp_dir = _prepare_work_dir(_resolve_work_dir(record.emulation_type))
    try:
        aws_creds = _get_aws_credentials(record)
        pulumi_stack = _get_pulumi_stack(record.name, record.region, aws_creds, work_dir=tmp_dir)
        _, on_output = _make_log_handler(record.name)

        logger.info("Starting destroy: stack=%s region=%s emulation=%s", record.name, record.region, record.emulation_type)
        pulumi_stack.destroy(on_output=on_output)

        record.delete()
        logger.info("Destroy complete: stack_id=%s — DB record deleted", stack_id)
        return {"stack_id": stack_id, "status": "destroyed"}

    except Exception as exc:
        logger.error("Destroy failed: stack_id=%s error=%s", stack_id, exc, exc_info=True)
        _mark_failed(stack_id)
        raise self.retry(exc=exc, max_retries=0) from exc

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@shared_task(bind=True, name="infrastructure.refresh_stack")
def refresh_stack(self, stack_id: str) -> dict:
    """
    Celery task: refresh a Pulumi stack via the Automation API (`pulumi refresh`).

    Syncs Pulumi state with actual AWS resource state without making changes.
    Restores the Stack record to READY on success.

    Args:
        self:     Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to refresh.

    Returns:
        Dict with keys: stack_id, status.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    record = _get_stack_record(stack_id)
    tmp_dir = _prepare_work_dir(_resolve_work_dir(record.emulation_type))
    try:
        aws_creds = _get_aws_credentials(record)
        pulumi_stack = _get_pulumi_stack(record.name, record.region, aws_creds, work_dir=tmp_dir)
        _, on_output = _make_log_handler(record.name)

        logger.info("Starting refresh: stack=%s region=%s emulation=%s", record.name, record.region, record.emulation_type)
        pulumi_stack.refresh(on_output=on_output)

        record.status = Stack.Status.READY
        record.save(update_fields=["status", "updated_at"])

        logger.info("Refresh complete: stack=%s", record.name)
        return {"stack_id": stack_id, "status": record.status}

    except Exception as exc:
        logger.error("Refresh failed: stack_id=%s error=%s", stack_id, exc, exc_info=True)
        _mark_failed(stack_id)
        raise self.retry(exc=exc, max_retries=0) from exc

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@shared_task(bind=True, name="infrastructure.preview_stack")
def preview_stack(self, stack_id: str) -> dict:
    """
    Celery task: preview a Pulumi stack via the Automation API (`pulumi preview`).

    Read-only operation — shows what changes would be made without applying them.
    The Stack record's status is not modified.

    Args:
        self:     Celery task instance (provided by bind=True).
        stack_id: UUID string of the Stack record to preview.

    Returns:
        Dict with keys: stack_id, status ("preview_complete" or raises on failure).
    """
    record = _get_stack_record(stack_id)
    tmp_dir = _prepare_work_dir(_resolve_work_dir(record.emulation_type))
    try:
        aws_creds = _get_aws_credentials(record)
        pulumi_stack = _get_pulumi_stack(record.name, record.region, aws_creds, work_dir=tmp_dir)
        _, on_output = _make_log_handler(record.name)

        logger.info("Starting preview: stack=%s region=%s emulation=%s", record.name, record.region, record.emulation_type)
        pulumi_stack.preview(on_output=on_output)

        logger.info("Preview complete: stack=%s", record.name)
        return {"stack_id": stack_id, "status": "preview_complete"}

    except Exception as exc:
        logger.error("Preview failed: stack_id=%s error=%s", stack_id, exc, exc_info=True)
        raise self.retry(exc=exc, max_retries=0) from exc

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
