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
from datetime import datetime, timezone

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

# Maximum number of captured Pulumi output lines persisted on the Stack record.
# Pulumi runs can emit thousands of lines; we keep only the tail so the JSON
# column stays small while still covering the end of a run (where failures show).
MAX_LOG_LINES = 300

# Maximum length of the persisted failure reason.  Pulumi CommandError messages
# can be very large; the full detail lives in last_logs.
MAX_ERROR_CHARS = 2000

# Friendly display labels for common AWS service tokens parsed from Pulumi types.
# Anything not listed falls back to the upper-cased service token.
_SERVICE_LABELS: dict[str, str] = {
    "s3": "S3",
    "iam": "IAM",
    "lambda": "Lambda",
    "ec2": "EC2",
    "dynamodb": "DynamoDB",
    "cloudtrail": "CloudTrail",
    "secretsmanager": "Secrets Manager",
    "kms": "KMS",
    "cloudwatch": "CloudWatch",
    "guardduty": "GuardDuty",
    "rds": "RDS",
    "sns": "SNS",
    "sqs": "SQS",
}


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


def _make_log_handler(label: str) -> tuple[list[dict], Callable[[str], None]]:
    """
    Return an (entries_list, on_output) pair for capturing Pulumi output in real time.

    Each line is forwarded to the Python logger immediately so it appears in the
    worker log stream, and is also appended as a timestamped entry so it can be
    persisted on the Stack record for the deployment-logs view.

    Args:
        label: Stack name used as context in log messages.

    Returns:
        Tuple of (entries, on_output_callback).  Each entry is a dict
        {"t": ISO-8601 UTC timestamp, "line": str}.
    """
    entries: list[dict] = []

    def on_output(msg: str) -> None:
        stripped = msg.rstrip()
        logger.info("[pulumi/%s] %s", label, stripped)
        entries.append({
            "t": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "line": stripped,
        })

    return entries, on_output


def _make_stream_handler(
    task_instance, task_id: str, label: str,
) -> tuple[list[dict], Callable[[str], None]]:
    """
    Return an (entries, on_output) pair that streams Pulumi output to the Celery
    result backend in real time, so the deployment-logs view can show a long
    operation (e.g. a destroy) live via the /progress/ endpoint's recent_logs.

    Each line is logged and captured as a timestamped entry; every couple of
    lines the most recent lines are flushed to Redis via update_state(PROGRESS).

    IMPORTANT: Pulumi calls on_output from a dedicated output-consumer thread,
    where self.request.id is empty — so the task id must be captured in the main
    thread and passed in explicitly. Reporting failures are swallowed so they can
    never break the underlying operation.

    Args:
        task_instance: The bound Celery task (self), for update_state.
        task_id:       Task id captured in the main thread (self.request.id).
        label:         Stack name used as log context.

    Returns:
        Tuple of (entries, on_output_callback).
    """
    entries: list[dict] = []
    state = {"n": 0}

    def on_output(msg: str) -> None:
        stripped = msg.rstrip()
        logger.info("[pulumi/%s] %s", label, stripped)
        entries.append({
            "t": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "line": stripped,
        })
        state["n"] += 1
        if state["n"] % 2 == 0:
            try:
                task_instance.update_state(
                    task_id=task_id,
                    state="PROGRESS",
                    meta={"recent_logs": [e["line"] for e in entries[-12:]]},
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("stream update_state failed (non-fatal): %s", exc)

    return entries, on_output


def _trim_logs(entries: list[dict]) -> list[dict]:
    """Return only the most recent MAX_LOG_LINES entries (the run's tail)."""
    return entries[-MAX_LOG_LINES:]


def _extract_error(exc: Exception) -> str:
    """
    Build a concise failure reason from an exception, truncated for storage.

    The full Pulumi output is retained separately in last_logs; this is the short
    summary shown on the stack's failure node and logs header.

    Args:
        exc: The exception raised by the Pulumi operation.

    Returns:
        A trimmed single-string error message.
    """
    msg = str(exc).strip()
    if len(msg) > MAX_ERROR_CHARS:
        msg = msg[:MAX_ERROR_CHARS] + "… (truncated)"
    return msg


def _service_label(pulumi_type: str) -> str | None:
    """
    Derive a friendly AWS service label from a Pulumi resource type token.

    Pulumi types look like "aws:s3/bucket:Bucket".  Only "aws:"-prefixed types
    are counted; provider/stack pseudo-resources return None and are skipped.

    Args:
        pulumi_type: Pulumi type token from the exported state.

    Returns:
        A display label such as "S3" / "IAM", or None for non-AWS resources.
    """
    if not pulumi_type.startswith("aws:"):
        return None
    # "aws:s3/bucket:Bucket" -> module "s3/bucket" -> service "s3".
    parts = pulumi_type.split(":")
    if len(parts) < 2:
        return None
    service = parts[1].split("/")[0]
    return _SERVICE_LABELS.get(service, service.upper())


def _summarize_resources(pulumi_stack: "auto.Stack") -> dict:
    """
    Build an actual-resource inventory from the stack's exported Pulumi state.

    Best-effort: any failure returns an empty summary rather than raising, so a
    summary problem never fails an otherwise successful deploy.

    Args:
        pulumi_stack: The Automation API Stack whose state to export.

    Returns:
        Dict with keys:
            total      — count of AWS resources
            by_type    — {service_label: count}
            resources  — [{"urn": str, "name": logical_name, "type": pulumi_type}]
            edges      — [{"from": dependency_urn, "to": dependent_urn}]

        The `urn` is the stable node id used by the resource graph; `edges` are
        built from each resource's Pulumi `dependencies` (Milestone 2). Only
        edges whose endpoints are both included AWS resources are kept, so links
        to providers / the stack pseudo-resource are dropped.
    """
    try:
        deployment = pulumi_stack.export_stack()
        data = getattr(deployment, "deployment", None) or {}
        raw = data.get("resources", []) or []
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not export stack state for resource summary: %s", exc)
        return {}

    by_type: dict[str, int] = {}
    resources: list[dict] = []
    included_urns: set[str] = set()
    # (dependent_urn, [dependency_urns]) captured for a second pass, since an
    # edge is only kept once both endpoints are known to be included resources.
    dep_pairs: list[tuple[str, list]] = []

    for res in raw:
        ptype = res.get("type", "")
        label = _service_label(ptype)
        if label is None:
            continue  # skip pulumi:providers:*, pulumi:pulumi:Stack, etc.
        urn = res.get("urn", "")
        name = urn.split("::")[-1] if "::" in urn else ptype
        by_type[label] = by_type.get(label, 0) + 1
        resources.append({"urn": urn, "name": name, "type": ptype})
        included_urns.add(urn)
        dep_pairs.append((urn, res.get("dependencies", []) or []))

    # Build dependency edges (from = depended-upon, to = dependent), keeping only
    # edges where both endpoints are included AWS resources. Deduplicated.
    edges: list[dict] = []
    seen_edges: set[tuple[str, str]] = set()
    for to_urn, deps in dep_pairs:
        for from_urn in deps:
            if from_urn in included_urns and (from_urn, to_urn) not in seen_edges:
                edges.append({"from": from_urn, "to": to_urn})
                seen_edges.add((from_urn, to_urn))

    return {
        "total": len(resources),
        "by_type": by_type,
        "resources": resources,
        "edges": edges,
    }


def _persist_failure(stack_id: str, entries: list[dict], exc: Exception) -> None:
    """
    Best-effort: mark a Stack FAILED and persist its logs + failure reason.

    Intentionally swallows all exceptions so it never masks the original error
    that triggered the failure path.

    Args:
        stack_id: UUID string of the Stack record.
        entries:  Captured Pulumi output entries (may be empty).
        exc:      The exception that caused the failure.
    """
    try:
        Stack = apps.get_model("infrastructure", "Stack")
        record = Stack.objects.get(id=stack_id)
        record.status = Stack.Status.FAILED
        record.last_logs = _trim_logs(entries)
        record.last_error = _extract_error(exc)
        record.save(update_fields=["status", "last_logs", "last_error", "updated_at"])
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
    entries, on_output = _make_log_handler(record.name)
    tmp_dir = _prepare_work_dir(_resolve_work_dir(record.emulation_type))
    try:
        aws_creds = _get_aws_credentials(record)
        pulumi_stack = _get_pulumi_stack(record.name, record.region, aws_creds, work_dir=tmp_dir)

        logger.info(
            "Starting deploy: stack=%s region=%s user=%s emulation=%s",
            record.name, record.region, record.owner.email, record.emulation_type,
        )
        result = pulumi_stack.up(on_output=on_output)

        # result.outputs is dict[str, OutputValue] — .value unwraps the typed value.
        outputs = {key: val.value for key, val in result.outputs.items()}

        record.status = Stack.Status.READY
        record.outputs = outputs
        record.resource_summary = _summarize_resources(pulumi_stack)
        record.last_logs = _trim_logs(entries)
        record.last_error = ""
        record.save(update_fields=[
            "status", "outputs", "resource_summary",
            "last_logs", "last_error", "updated_at",
        ])

        logger.info("Deploy complete: stack=%s outputs_keys=%s", record.name, list(outputs))
        return {"stack_id": stack_id, "status": record.status}

    except Exception as exc:
        logger.error("Deploy failed: stack_id=%s error=%s", stack_id, exc, exc_info=True)
        _persist_failure(stack_id, entries, exc)
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
    # Store the destroy task id so the /progress/ endpoint can stream live logs.
    record.task_id = self.request.id
    record.save(update_fields=["task_id", "updated_at"])
    entries, on_output = _make_stream_handler(self, self.request.id, record.name)
    tmp_dir = _prepare_work_dir(_resolve_work_dir(record.emulation_type))
    try:
        aws_creds = _get_aws_credentials(record)
        pulumi_stack = _get_pulumi_stack(record.name, record.region, aws_creds, work_dir=tmp_dir)

        logger.info("Starting destroy: stack=%s region=%s emulation=%s", record.name, record.region, record.emulation_type)
        pulumi_stack.destroy(on_output=on_output)

        # Success removes the DB record entirely — no logs to retain.
        record.delete()
        logger.info("Destroy complete: stack_id=%s — DB record deleted", stack_id)
        return {"stack_id": stack_id, "status": "destroyed"}

    except Exception as exc:
        logger.error("Destroy failed: stack_id=%s error=%s", stack_id, exc, exc_info=True)
        _persist_failure(stack_id, entries, exc)
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
    entries, on_output = _make_log_handler(record.name)
    tmp_dir = _prepare_work_dir(_resolve_work_dir(record.emulation_type))
    try:
        aws_creds = _get_aws_credentials(record)
        pulumi_stack = _get_pulumi_stack(record.name, record.region, aws_creds, work_dir=tmp_dir)

        logger.info("Starting refresh: stack=%s region=%s emulation=%s", record.name, record.region, record.emulation_type)
        pulumi_stack.refresh(on_output=on_output)

        # Refresh re-syncs state with the cloud, so the inventory may have changed.
        record.status = Stack.Status.READY
        record.resource_summary = _summarize_resources(pulumi_stack)
        record.last_logs = _trim_logs(entries)
        record.last_error = ""
        record.save(update_fields=[
            "status", "resource_summary", "last_logs", "last_error", "updated_at",
        ])

        logger.info("Refresh complete: stack=%s", record.name)
        return {"stack_id": stack_id, "status": record.status}

    except Exception as exc:
        logger.error("Refresh failed: stack_id=%s error=%s", stack_id, exc, exc_info=True)
        _persist_failure(stack_id, entries, exc)
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
