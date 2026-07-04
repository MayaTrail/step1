"""
Celery tasks for the emulations app.

Enterprise emulation tasks (queue: enterprise):
    deploy_emulation_stack      — `pulumi up` against emulations/{type}/infra/ with STS creds.
    poll_ec2_readiness          — HTTP GET /health on the vulnerable EC2 instance; self.retry().
    run_emulation_attack        — importlib load attack.py, call run(outputs).
    destroy_emulation_stack     — `pulumi destroy` for an enterprise emulation stack.
    auto_destroy_expired_stacks — Beat task; destroys stacks past their TTL.

All Pulumi operations use the Automation API (pulumi.automation) via _get_pulumi_stack().
No Docker containers are spawned — the Docker socket is not required by any task.

Emulation Pulumi programs live at {EMULATIONS_BASE_DIR}/{type}/infra/
(e.g. /opt/emulations/scarleteel/infra/).  The emulations package is mounted
at /opt/emulations/ and its parent (/opt) is inserted into sys.path at runtime
so that `import emulations.*` resolves correctly.
"""

from __future__ import annotations

import importlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta

import boto3
from botocore.exceptions import ClientError
import requests as http_requests
from celery import shared_task
from django.apps import apps
from django.utils import timezone
from pulumi import automation as auto

from apps.emulations.registry import get_emulation
from apps.emulations.readiness import requires_http_probe, resolve_readiness

# Reuse the infrastructure app's persistence helpers so emulation stacks get the
# same logs / failure reason / resource inventory as generic stacks, without
# duplicating the logic. (infrastructure.tasks does not import this module, so
# there is no circular import.)
from apps.infrastructure.tasks import (
    _make_stream_handler,
    _persist_failure,
    _summarize_resources,
    _trim_logs,
)

logger = logging.getLogger(__name__)

# Pulumi state bucket. Each tenant's state lives in that tenant's own AWS
# account, so the bucket name is resolved per-tenant from the account id (see
# _state_bucket_from_creds). STATE_BUCKET is only the fallback when the account
# cannot be resolved. STATE_BUCKET_REGION is the region the state bucket lives in.
STATE_BUCKET = os.environ.get("STATE_BUCKET", "mayatrail-state-bucket")
STATE_BUCKET_REGION = os.environ.get("STATE_BUCKET_REGION", "ap-south-1")


def _state_bucket_from_creds(aws_creds: dict[str, str]) -> str:
    """Return the per-tenant Pulumi state bucket name for the given assumed creds.

    The state bucket lives in the tenant's own account. Since S3 bucket names are
    globally unique across all of AWS, a shared name cannot exist in more than
    one account; instead the name embeds the tenant's account id (resolved from
    the assumed credentials via STS GetCallerIdentity), which is globally unique.
    Falls back to STATE_BUCKET when the account id cannot be resolved.

    Args:
        aws_creds: STS credential dict from _assume_user_role().

    Returns:
        The bucket name, e.g. "mayatrail-state-123456789012".
    """
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=aws_creds["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=aws_creds["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=aws_creds["AWS_SESSION_TOKEN"],
        )
        account_id = sts.get_caller_identity()["Account"]
    except (ClientError, KeyError):
        return STATE_BUCKET
    return f"mayatrail-state-{account_id}"


def _ensure_state_bucket(bucket: str, aws_creds: dict[str, str]) -> None:
    """Create the Pulumi state bucket in the tenant's account if it is missing.

    The Pulumi S3 backend requires the bucket to exist before any stack
    operation. Buckets are created lazily with the tenant's assumed credentials
    in STATE_BUCKET_REGION, so onboarding a new account needs no manual bucket
    setup and a deleted bucket self-heals on the next operation. Creating a
    bucket the caller already owns is treated as success (idempotent).

    Args:
        bucket: The bucket name to ensure exists.
        aws_creds: STS credential dict from _assume_user_role().
    """
    s3 = boto3.client(
        "s3",
        aws_access_key_id=aws_creds["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=aws_creds["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=aws_creds["AWS_SESSION_TOKEN"],
        region_name=STATE_BUCKET_REGION,
    )
    try:
        s3.head_bucket(Bucket=bucket)
        return
    except ClientError as exc:
        # 404 / NoSuchBucket means it does not exist yet, so fall through and
        # create it. Any other error (e.g. 403: the name is taken by another
        # account) is surfaced rather than masked by a later, more cryptic failure.
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code not in ("404", "NoSuchBucket"):
            raise

    params: dict = {"Bucket": bucket}
    # us-east-1 rejects an explicit LocationConstraint; every other region needs
    # one, or the bucket is silently created in us-east-1 instead.
    if STATE_BUCKET_REGION != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": STATE_BUCKET_REGION}
    try:
        s3.create_bucket(**params)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        # A concurrent create or a prior run is fine as long as we own the bucket.
        if code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise

# Base directory under which emulation packages are mounted.
# Each emulation's Pulumi program lives at {EMULATIONS_BASE_DIR}/{type}/infra/.
# Mounted as ./emulations:/opt/emulations:ro in worker_enterprise.
# The parent of this directory is inserted into sys.path so that
# `import emulations.*` resolves correctly.
EMULATIONS_BASE_DIR = os.environ.get("EMULATIONS_BASE_DIR", "/opt/emulations")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_stack(stack_id: str):
    """
    Retrieve a Stack model instance by its UUID primary key.

    Args:
        stack_id: String UUID of the Stack record.

    Returns:
        Stack model instance.
    """
    Stack = apps.get_model("infrastructure", "Stack")
    return Stack.objects.select_related("owner").get(id=stack_id)


def _assume_user_role(user) -> dict[str, str]:
    """
    Assume the enterprise user's cross-account IAM role via STS.

    Returns temporary credentials valid for 1 hour, which is more than
    sufficient for a full emulation deploy + attack cycle (~20-27 min).
    Credentials are never stored in the database — they are generated per-task
    invocation and discarded once the task completes.

    Args:
        user: Authenticated User instance with a valid aws_role_arn.

    Returns:
        Dict with keys: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
        AWS_SESSION_TOKEN.

    Raises:
        botocore.exceptions.ClientError if the role cannot be assumed.
    """
    sts = boto3.client("sts")
    assumed = sts.assume_role(
        RoleArn=user.aws_role_arn,
        RoleSessionName=f"mayatrail-emulation-{user.id}",
        DurationSeconds=3600,
    )
    creds = assumed["Credentials"]
    return {
        "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": creds["SessionToken"],
    }


def _build_workspace_env(
    region: str,
    aws_creds: dict[str, str],
    bucket: str,
) -> dict[str, str]:
    """
    Build the environment variable dict passed to a Pulumi LocalWorkspace.

    Sets PULUMI_BACKEND_URL so no `pulumi login` call is required.
    All stacks in step1 are enterprise stacks — credentials are always
    short-lived STS credentials obtained via _assume_user_role().

    Args:
        region:    AWS region for this stack (e.g. "ap-south-1").
        aws_creds: STS credential dict from _assume_user_role().
        bucket:    Per-tenant Pulumi state bucket name (from _state_bucket_from_creds).

    Returns:
        Dict of environment variable name/value pairs for the workspace.
    """
    env: dict[str, str] = {
        "PULUMI_BACKEND_URL": f"s3://{bucket}?region={STATE_BUCKET_REGION}",
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
    work_dir: str,
    aws_creds: dict[str, str],
) -> auto.Stack:
    """
    Return a configured Pulumi Automation API Stack for the given program.

    Uses the local program at work_dir (must contain Pulumi.yaml + __main__.py).
    If the stack does not yet exist in the S3 state backend, it is created.
    The AWS region is set as a Pulumi config value so pulumi_aws picks it up.

    Args:
        stack_name: Pulumi stack name (e.g. "scarleteel-abc12345").
        region:     AWS region for this stack.
        work_dir:   Absolute path to the Pulumi program directory.
        aws_creds:  STS credential dict from _assume_user_role().

    Returns:
        Configured pulumi.automation.Stack instance ready for an operation.
    """
    # Resolve the tenant's own state bucket from the assumed creds and make sure
    # it exists before selecting the stack, so a new account needs no manual
    # bucket setup and the S3 backend never points at a missing bucket.
    bucket = _state_bucket_from_creds(aws_creds)
    _ensure_state_bucket(bucket, aws_creds)
    env = _build_workspace_env(region, aws_creds, bucket)

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
        label: Stack name used as log context.

    Returns:
        Tuple of (entries, on_output_callback).  Each entry is a dict
        {"t": ISO-8601 UTC timestamp, "line": str}.
    """
    entries: list[dict] = []

    def on_output(msg: str) -> None:
        stripped = msg.rstrip()
        logger.info("[pulumi/%s] %s", label, stripped)
        entries.append({
            "t": timezone.now().isoformat(timespec="seconds"),
            "line": stripped,
        })

    return entries, on_output


def _make_progress_handler(
    task_instance,
    task_id: str,
    total_resources: int,
    label: str,
) -> tuple[list[dict], Callable[[str], None]]:
    """
    Return a (lines_list, on_output) pair that tracks Pulumi resource creation
    progress and reports it to the Celery result backend via update_state.

    Pulumi emits a line ending in " created" each time a resource finishes
    provisioning.  Counting these gives an accurate resources_created value.
    Progress is flushed to Redis every 2 lines so the polling endpoint stays
    responsive without hammering the result backend on every character.

    IMPORTANT: Pulumi invokes on_output from a dedicated output-consumer thread,
    not the main task thread.  Celery's update_state() defaults to reading the
    task id from self.request.id, which is thread-local and therefore empty in
    that consumer thread.  The task id must be captured in the main thread and
    passed in explicitly here.  The update is also wrapped in a broad except so
    that a progress-reporting failure can never abort the underlying deploy.

    Args:
        task_instance:   The bound Celery task (self) — used for update_state.
        task_id:         The task id captured in the main thread (self.request.id).
        total_resources: Expected total resource count from the emulation MANIFEST.
        label:           Stack name used as log context.

    Returns:
        Tuple of (accumulated_lines, on_output_callback).
    """
    entries: list[dict] = []
    state: dict = {"resources_created": 0, "flush_counter": 0}

    def on_output(msg: str) -> None:
        stripped = msg.rstrip()
        logger.info("[pulumi/%s] %s", label, stripped)
        entries.append({
            "t": timezone.now().isoformat(timespec="seconds"),
            "line": stripped,
        })

        if " created" in stripped:
            state["resources_created"] += 1

        state["flush_counter"] += 1
        if state["flush_counter"] % 2 == 0:
            created = state["resources_created"]
            pct = int((created / total_resources) * 100) if total_resources else 0
            try:
                task_instance.update_state(
                    task_id=task_id,
                    state="PROGRESS",
                    meta={
                        "resources_created": created,
                        "total_resources": total_resources,
                        "percentage": min(pct, 99),
                        "recent_logs": [e["line"] for e in entries[-10:]],
                    },
                )
            except Exception as exc:  # noqa: BLE001
                # Progress reporting is best-effort — it must never break the
                # deploy.  Log once at debug level and carry on.
                logger.debug("progress update_state failed (non-fatal): %s", exc)

    return entries, on_output


def _prepare_work_dir(source_dir: str) -> str:
    """
    Copy Pulumi program files into a fresh writable temp directory.

    Pulumi writes Pulumi.<stack>.yaml into work_dir when selecting or creating
    a stack. Because source directories are mounted read-only in Docker, we
    copy only the two essential files to a throwaway directory per task.

    Caller is responsible for cleanup: shutil.rmtree(tmp_dir, ignore_errors=True).

    Args:
        source_dir: Read-only directory containing Pulumi.yaml and __main__.py.

    Returns:
        Absolute path to the writable temp directory.
    """
    tmp_dir = tempfile.mkdtemp(prefix="mayatrail-pulumi-")
    for fname in ("Pulumi.yaml", "__main__.py"):
        src = os.path.join(source_dir, fname)
        if os.path.exists(src):
            shutil.copy2(src, tmp_dir)
    return tmp_dir


def _emulation_work_dir(emulation_type: str) -> str:
    """
    Return the absolute path to an emulation's Pulumi infra program directory.

    Convention: {EMULATIONS_BASE_DIR}/{emulation_type}/infra/
    Each emulation must place a valid Pulumi.yaml and __main__.py there.
    Adding a new emulation requires no changes to this function.

    Args:
        emulation_type: Emulation package name (e.g. "scarleteel").

    Returns:
        Absolute path string (e.g. "/opt/emulations/scarleteel/infra").

    Raises:
        ValueError: If the resolved directory does not exist.
    """
    infra_dir = os.path.join(EMULATIONS_BASE_DIR, emulation_type, "infra")
    if not os.path.isdir(infra_dir):
        raise ValueError(
            f"Emulation infra directory not found: {infra_dir}. "
            f"Ensure emulations/{emulation_type}/infra/ exists and is mounted."
        )
    return infra_dir


def _live_stack_outputs(stack) -> dict:
    """
    Read a stack's full outputs (secret values decrypted) live from Pulumi state.

    Secret outputs are deliberately NOT persisted to Stack.outputs (see
    deploy_emulation_stack), so the attack phase reads them fresh from the Pulumi
    state backend at run time instead.  This keeps leaked credentials and private
    keys out of the database while still making them available to the attack that
    needs them.

    Reuses the same workspace machinery as deploy/destroy: assume the owner's
    role, select the stack, and return its outputs.  Non-secret outputs are
    included too, so the result is a complete superset of the persisted copy and
    can be passed to attack.run() directly.

    Args:
        stack: The Stack model instance whose outputs to read.

    Returns:
        Dict of {output_name: value} including decrypted secret values.
    """
    aws_creds = _assume_user_role(stack.owner)
    source_dir = _emulation_work_dir(stack.emulation_type)
    tmp_dir = _prepare_work_dir(source_dir)
    try:
        pulumi_stack = _get_pulumi_stack(
            stack_name=stack.name,
            region=stack.region,
            work_dir=tmp_dir,
            aws_creds=aws_creds,
        )
        return {key: out.value for key, out in pulumi_stack.outputs().items()}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Enterprise emulation tasks
# ---------------------------------------------------------------------------

@shared_task(bind=True, name="emulations.deploy_emulation_stack", queue="enterprise")
def deploy_emulation_stack(self, stack_id: str) -> dict:
    """
    Deploy an enterprise emulation stack by running `pulumi up` against
    the emulation's infra/ Pulumi program.

    Assumes the enterprise user's cross-account IAM role via STS before
    running Pulumi.  Temporary STS credentials are scoped to the Pulumi
    workspace and are never stored in the database or logged.

    On success, transitions the stack to EC2_BOOTING and enqueues
    poll_ec2_readiness to wait for the vulnerable instance to come up.

    Args:
        self:     Celery task instance (bind=True).
        stack_id: String UUID of the enterprise Stack to deploy.

    Returns:
        Dict with keys: stack_id, status.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    # Defined before the try so the failure path can persist whatever was
    # captured even if the deploy aborts early.
    entries: list[dict] = []
    try:
        stack = _get_stack(stack_id)
        aws_creds = _assume_user_role(stack.owner)
        source_dir = _emulation_work_dir(stack.emulation_type)

        entry = get_emulation(stack.emulation_type)
        manifest = entry.get("manifest", entry) if entry else {}
        total_resources = manifest.get("total_resources", 19)

        tmp_dir = _prepare_work_dir(source_dir)
        try:
            pulumi_stack = _get_pulumi_stack(
                stack_name=stack.name,
                region=stack.region,
                work_dir=tmp_dir,
                aws_creds=aws_creds,
            )
            entries, on_output = _make_progress_handler(self, self.request.id, total_resources, stack.name)

            logger.info(
                "Deploying emulation stack: name=%s type=%s region=%s",
                stack.name, stack.emulation_type, stack.region,
            )
            result = pulumi_stack.up(on_output=on_output)

            # Persist only NON-secret outputs.  Secret outputs (e.g. the leaked
            # access key secret, alice's key, the EC2 private-key PEM) must never
            # land in the Stack.outputs DB column in plaintext; the attack reads
            # them live from Pulumi state at run time via _live_stack_outputs().
            stack.outputs = {
                key: val.value
                for key, val in result.outputs.items()
                if not val.secret
            }
            readiness = resolve_readiness(manifest)
            if requires_http_probe(readiness):
                stack.status = Stack.Status.EC2_BOOTING
            else:
                # No vulnerable web service — ready for attack immediately.
                stack.status = Stack.Status.READY_FOR_ATTACK
            stack.resource_summary = _summarize_resources(pulumi_stack)
            stack.last_logs = _trim_logs(entries)
            stack.last_error = ""
            stack.save(update_fields=[
                "status", "outputs", "resource_summary",
                "last_logs", "last_error", "updated_at",
            ])
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        # Begin non-blocking readiness polling only when the emulation declares
        # an HTTP probe; "none"-readiness stacks are already READY_FOR_ATTACK.
        if requires_http_probe(readiness):
            poll_ec2_readiness.apply_async(args=[stack_id], queue="enterprise")
            logger.info("Emulation stack deployed: name=%s → EC2_BOOTING", stack.name)
        else:
            logger.info("Emulation stack deployed: name=%s → READY_FOR_ATTACK (no probe)", stack.name)
        return {"stack_id": stack_id, "status": stack.status}

    except Exception as exc:
        logger.error(
            "deploy_emulation_stack failed for stack=%s: %s", stack_id, exc, exc_info=True,
        )
        _persist_failure(stack_id, entries, exc)
        raise self.retry(exc=exc, max_retries=0) from exc


@shared_task(
    bind=True,
    name="emulations.poll_ec2_readiness",
    queue="enterprise",
    max_retries=30,
)
def poll_ec2_readiness(self, stack_id: str) -> None:
    """
    Poll the vulnerable EC2 instance's /health endpoint until it responds.

    Uses Celery self.retry() to re-queue this task rather than blocking
    the worker with time.sleep().  The worker is released between retries.

    Retry schedule: every 30 seconds, up to 30 retries = 15 minutes max.
    If all retries are exhausted, the stack is marked FAILED.

    Args:
        self:     Celery task instance (bind=True, max_retries=30).
        stack_id: String UUID of the enterprise Stack to check.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    stack = _get_stack(stack_id)
    entry = get_emulation(stack.emulation_type)
    manifest = entry.get("manifest", entry) if entry else {}
    readiness = resolve_readiness(manifest)
    ip = stack.outputs.get(readiness["ip_output"])

    if not ip:
        logger.error(
            "poll_ec2_readiness: no %s in outputs for stack=%s",
            readiness["ip_output"], stack_id,
        )
        stack.status = Stack.Status.FAILED
        stack.save(update_fields=["status", "updated_at"])
        return

    try:
        resp = http_requests.get(
            f"http://{ip}:{readiness['port']}{readiness['path']}", timeout=5,
        )
        if resp.status_code == 200:
            stack.status = Stack.Status.READY_FOR_ATTACK
            stack.save(update_fields=["status", "updated_at"])
            logger.info("EC2 ready for attack: stack=%s ip=%s", stack_id, ip)
            return
    except http_requests.RequestException:
        pass

    try:
        raise self.retry(countdown=30)
    except self.MaxRetriesExceededError:
        logger.error(
            "poll_ec2_readiness: EC2 not ready after 15 minutes — marking FAILED: stack=%s",
            stack_id,
        )
        stack.status = Stack.Status.FAILED
        stack.save(update_fields=["status", "updated_at"])


_PHASE_MARKER = re.compile(r"\bPHASE\s+(\d+)", re.IGNORECASE)


class _ProgressWriter:
    """
    stdout proxy that streams captured attack output to the EmulationRun.

    It buffers everything (so the task's final save still holds the complete
    log) while periodically flushing the growing stdout and the current phase
    to the database, so the frontend can render a live view by polling the run.

    The current phase is inferred from "PHASE N" markers the attack modules
    print, clamped to [0, phase_total]. Modules that do not print such markers
    simply leave the phase at 0 and stream logs only (graceful degradation).
    """

    _FLUSH_INTERVAL_SECONDS = 1.5

    def __init__(self, run, phase_total: int):
        """Wrap an EmulationRun; phase_total bounds the inferred phase index."""
        self._run = run
        self._phase_total = phase_total
        self._buffer = io.StringIO()
        self._phase = 0
        self._last_flush = 0.0

    def write(self, text: str) -> int:
        """Buffer text, update the inferred phase, and flush on a time debounce."""
        self._buffer.write(text)
        markers = _PHASE_MARKER.findall(text)
        if markers:
            highest = max(int(marker) for marker in markers)
            if self._phase_total:
                highest = min(highest, self._phase_total)
            self._phase = max(self._phase, highest)
        if time.monotonic() - self._last_flush >= self._FLUSH_INTERVAL_SECONDS:
            self.flush()
        return len(text)

    def flush(self) -> None:
        """Persist the current stdout and phase to the run record."""
        self._last_flush = time.monotonic()
        self._run.stdout = self._buffer.getvalue()
        self._run.phase_current = self._phase
        try:
            self._run.save(update_fields=["stdout", "phase_current"])
        except Exception as exc:  # noqa: BLE001
            # A transient DB error mid-stream must not abort the attack; the
            # task's final save in its finally block is authoritative.
            logger.debug("Progress flush failed for run=%s: %s", self._run.id, exc)

    def getvalue(self) -> str:
        """Return the full buffered stdout."""
        return self._buffer.getvalue()


@shared_task(bind=True, name="emulations.run_emulation_attack", queue="enterprise")
def run_emulation_attack(self, run_id: str) -> dict:
    """
    Execute an enterprise emulation's attack phase against a ready stack.

    Dynamically loads the emulation's attack.py module using importlib and
    calls its run(outputs) function.  Captures stdout and stderr and stores
    them on the EmulationRun record.

    Transitions the EmulationRun status:
        PENDING -> RUNNING -> COMPLETED (or FAILED)

    Transitions the Stack status:
        READY_FOR_ATTACK -> ATTACKING -> ATTACK_COMPLETE (or FAILED)

    Args:
        self:   Celery task instance (bind=True).
        run_id: String UUID of the EmulationRun to execute.

    Returns:
        Dict with keys: run_id, status, stdout, stderr.
    """
    EmulationRun = apps.get_model("emulations", "EmulationRun")
    Stack = apps.get_model("infrastructure", "Stack")

    run = EmulationRun.objects.select_related("stack").get(id=run_id)
    stack = run.stack

    run.status = EmulationRun.Status.RUNNING
    run.started_at = timezone.now()
    run.save(update_fields=["status", "started_at"])

    stack.status = Stack.Status.ATTACKING
    stack.save(update_fields=["status", "updated_at"])

    stderr_buf = io.StringIO()
    # Placeholder so the finally block is safe if setup fails before the real
    # writer (bound to phase_total) is created inside the try below.
    stdout_writer = _ProgressWriter(run, 0)

    try:
        # Ensure the emulations package is importable.
        # The package lives at EMULATIONS_BASE_DIR (/opt/emulations/), so its
        # parent (/opt) must be on sys.path for `import emulations.*` to resolve.
        emulations_parent = os.path.dirname(EMULATIONS_BASE_DIR)
        if emulations_parent and emulations_parent not in sys.path:
            sys.path.insert(0, emulations_parent)

        mod = importlib.import_module(f"emulations.{run.emulation_type}.attack")
        from apps.emulations.registry import get_emulation  # noqa: PLC0415
        entry = get_emulation(run.emulation_type)
        phase_total = entry.get("phase_count", 0) if entry else 0
        run.phase_total = phase_total
        run.save(update_fields=["phase_total"])

        # Streams stdout and inferred phase progress to the DB during the run so
        # the frontend live view can follow the attack as it walks the kill chain.
        stdout_writer = _ProgressWriter(run, phase_total)

        # Secret outputs are not persisted to the DB, so fetch the full output
        # set (including decrypted secrets) live from Pulumi state for the attack.
        attack_outputs = _live_stack_outputs(stack)

        # Option-C credential model (atomic emulations): the worker assumes the
        # stack owner's role and hands the short-lived (1h, auto-expiring) creds
        # to the attack IN-MEMORY via the outputs dict — never via os.environ — so
        # an attack that calls boto3 directly runs in the user's account without a
        # process-global credential. Attacks that bootstrap from their own
        # provisioned outputs (scarleteel, dangerdev) simply ignore this key.
        # (Two STS assumptions per attack — here and in _live_stack_outputs; an
        # acceptable cost, optimisable later by assuming once and threading creds.)
        attack_outputs["_aws_credentials"] = _assume_user_role(stack.owner)

        with redirect_stdout(stdout_writer), redirect_stderr(stderr_buf):
            mod.run(attack_outputs, region=stack.region)

        run.status = EmulationRun.Status.COMPLETED
        stack.status = Stack.Status.ATTACK_COMPLETE
        # A completed run has walked every phase; mark the kill chain full.
        run.phase_current = phase_total

    except Exception as exc:
        stderr_buf.write(f"\nTask exception: {exc}\n")
        run.status = EmulationRun.Status.FAILED
        stack.status = Stack.Status.FAILED
        logger.error("run_emulation_attack failed for run=%s: %s", run_id, exc)

    finally:
        run.stdout = stdout_writer.getvalue()
        run.stderr = stderr_buf.getvalue()
        run.completed_at = timezone.now()
        run.save(update_fields=[
            "status", "stdout", "stderr", "completed_at", "phase_total", "phase_current",
        ])
        stack.save(update_fields=["status", "updated_at"])

    return {
        "run_id": run_id,
        "status": run.status,
        "stdout": run.stdout,
        "stderr": run.stderr,
    }


@shared_task(bind=True, name="emulations.destroy_emulation_stack", queue="enterprise")
def destroy_emulation_stack(self, stack_id: str) -> dict:
    """
    Destroy an enterprise emulation stack via `pulumi destroy`.

    Assumes the enterprise user's IAM role before running Pulumi so that
    destruction happens in the user's own AWS account, not the platform account.

    On success the Stack record is deleted from the database (same behaviour
    as infrastructure.destroy_stack for enterprise stacks).

    Args:
        self:     Celery task instance (bind=True).
        stack_id: String UUID of the enterprise Stack to destroy.

    Returns:
        Dict with keys: stack_id, status.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    # Defined before the try so the failure path can persist captured output.
    entries: list[dict] = []
    try:
        stack = _get_stack(stack_id)
        stack.status = Stack.Status.DESTROYING
        # Store the destroy task id so /progress/ can stream live teardown logs.
        stack.task_id = self.request.id
        stack.save(update_fields=["status", "task_id", "updated_at"])

        aws_creds = _assume_user_role(stack.owner)
        source_dir = _emulation_work_dir(stack.emulation_type)

        tmp_dir = _prepare_work_dir(source_dir)
        try:
            pulumi_stack = _get_pulumi_stack(
                stack_name=stack.name,
                region=stack.region,
                work_dir=tmp_dir,
                aws_creds=aws_creds,
            )
            entries, on_output = _make_stream_handler(self, self.request.id, stack.name)

            logger.info(
                "Destroying emulation stack: name=%s type=%s region=%s",
                stack.name, stack.emulation_type, stack.region,
            )
            pulumi_stack.destroy(on_output=on_output)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        # Success removes the DB record entirely — no logs to retain.
        stack.delete()
        logger.info("Emulation stack destroyed: stack_id=%s — DB record deleted", stack_id)
        return {"stack_id": stack_id, "status": "destroyed"}

    except Exception as exc:
        logger.error(
            "destroy_emulation_stack failed for stack=%s: %s", stack_id, exc, exc_info=True,
        )
        _persist_failure(stack_id, entries, exc)
        raise self.retry(exc=exc, max_retries=0) from exc


@shared_task(bind=True, name="emulations.estimate_emulation_cost", queue="enterprise")
def estimate_emulation_cost(self, emulation_type: str, region: str, user_id: str) -> dict:
    """
    Compute a pre-deployment cost estimate by running `pulumi preview --json`.

    Assumes the enterprise user's role, runs a throwaway preview of the
    emulation's infra program against an ephemeral stack (no resources are
    created), enumerates the planned resources, and prices them via the
    cost_estimator module.  The ephemeral stack is removed afterward.

    Runs on the worker because the Pulumi CLI is only installed in the worker
    image, not the API backend.

    Args:
        self:           Celery task instance (bind=True).
        emulation_type: Emulation package name (e.g. "scarleteel").
        region:         AWS region to price for.
        user_id:        UUID of the requesting enterprise user (for STS role).

    Returns:
        Cost estimate dict from cost_estimator.estimate_from_preview, plus
        emulationType and region echoed back.
    """
    from apps.emulations import cost_estimator  # noqa: PLC0415

    User = apps.get_model("users", "User")
    user = User.objects.get(id=user_id)
    aws_creds = _assume_user_role(user)
    source_dir = _emulation_work_dir(emulation_type)
    tmp_dir = _prepare_work_dir(source_dir)
    # Keep the ephemeral stack name short: it is interpolated into resource
    # names (e.g. mayatrail-scarleteel-ec2-role-{stack}) and IAM role names are
    # capped at 64 chars after Pulumi appends its random suffix.
    stack_name = f"est-{uuid.uuid4().hex[:8]}"

    bucket = _state_bucket_from_creds(aws_creds)
    _ensure_state_bucket(bucket, aws_creds)
    env = {
        **os.environ,
        "PULUMI_BACKEND_URL": f"s3://{bucket}?region={STATE_BUCKET_REGION}",
        "AWS_REGION": region,
        "AWS_DEFAULT_REGION": region,
        "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", ""),
        **aws_creds,
    }

    def _pulumi(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["pulumi", *args, "--stack", stack_name, "--non-interactive"],
            cwd=tmp_dir, env=env, capture_output=True, text=True, check=check,
        )

    try:
        logger.info("Cost estimate: preview stack=%s type=%s region=%s", stack_name, emulation_type, region)
        _pulumi("stack", "init")
        _pulumi("config", "set", "aws:region", region)

        preview = _pulumi("preview", "--json", check=False)
        if not preview.stdout.strip():
            raise RuntimeError(f"pulumi preview produced no output: {preview.stderr[:500]}")

        data = json.loads(preview.stdout)

        # A non-zero exit means the program errored partway through preview, so
        # `steps` is partial and the estimate would be silently wrong.  Surface
        # the error (the view falls back to the static MANIFEST estimate).
        error_diags = [
            d.get("message", "") for d in data.get("diagnostics", [])
            if d.get("severity") == "error"
        ]
        if preview.returncode != 0 or error_diags:
            raise RuntimeError(
                "pulumi preview failed (estimate would be partial): "
                f"rc={preview.returncode} diagnostics={error_diags[:3]} "
                f"stderr={preview.stderr[:300]}"
            )

        steps = data.get("steps", [])
        result = cost_estimator.estimate_from_preview(steps, region)
        result["emulationType"] = emulation_type
        logger.info("Cost estimate complete: type=%s hourly=%s", emulation_type, result.get("hourlyUsd"))
        return result

    finally:
        # Remove the ephemeral stack from the backend; best-effort.
        try:
            _pulumi("stack", "rm", "--yes", check=False)
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(tmp_dir, ignore_errors=True)


@shared_task(name="emulations.auto_destroy_expired_stacks", queue="enterprise")
def auto_destroy_expired_stacks() -> dict:
    """
    Celery Beat task: destroy all enterprise stacks that have exceeded their TTL.

    Runs every 15 minutes via the CELERY_BEAT_SCHEDULE in settings/base.py.
    A stack is expired when Stack.expires_at <= now().  The TTL is set at
    deploy time from the emulation MANIFEST's default_ttl_hours field.

    Returns:
        Dict with key enterprise_queued: count of stacks queued for destruction.
    """
    Stack = apps.get_model("infrastructure", "Stack")

    now = timezone.now()
    enterprise_queued = 0

    terminal_statuses = [
        Stack.Status.READY_FOR_ATTACK,
        Stack.Status.ATTACK_COMPLETE,
        Stack.Status.FAILED,
        Stack.Status.READY,
    ]
    expired_enterprise = Stack.objects.filter(
        expires_at__lte=now,
        expires_at__isnull=False,
        status__in=terminal_statuses,
    )
    for stack in expired_enterprise:
        destroy_emulation_stack.apply_async(args=[str(stack.id)], queue="enterprise")
        enterprise_queued += 1
        logger.info("Queued destroy for expired enterprise stack=%s", stack.id)

    logger.info("auto_destroy_expired_stacks: queued enterprise=%d", enterprise_queued)
    return {"enterprise_queued": enterprise_queued}
