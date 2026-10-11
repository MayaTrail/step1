"""
Pulumi helpers shared by the emulation tasks.

Every stack is deployed, attacked and destroyed by apps.emulations.tasks. This
module keeps what those tasks share with the Stack model's own concerns:
streaming Pulumi output into Celery progress, trimming the persisted log,
summarising the deployed resources, recording a failure, and running
`pulumi destroy` past a stranded lock.
"""

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from django.apps import apps

from apps.logs.models import LogEntry
from apps.logs.record import record_activity
from pulumi import automation as auto

logger = logging.getLogger(__name__)

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
        record.transition_to(Stack.Status.FAILED, save=False)
        record.last_logs = _trim_logs(entries)
        record.last_error = _extract_error(exc)
        record.save(update_fields=["status", "status_history", "last_logs", "last_error", "updated_at"])
        record_activity(
            LogEntry.Event.STACK_FAILED,
            f"{record.name} failed: {record.last_error or 'see the deployment log'}",
            actor=record.owner,
            stack=record,
            level=LogEntry.Level.ERROR,
        )
    except Exception:
        pass


# Pulumi's file backend writes a lock per in-flight operation but gives it no
# lease and no expiry. A worker killed mid-run (restart, redeploy, OOM) leaves
# the lock behind for good, and every later operation on that stack refuses to
# start. These markers appear in the resulting error.
_LOCK_ERROR_MARKERS = ("currently locked", "pulumi cancel")


def destroy_with_lock_recovery(pulumi_stack, on_output, label: str) -> None:
    """
    Run `pulumi destroy`, releasing a stranded lock and retrying once if needed.

    Only a lock failure is retried; every other error propagates untouched.
    cancel() removes the lock without touching any resource, so the retry reads
    the same state and proceeds normally.

    Cancelling would also release a lock held by a genuinely running operation,
    but both destroy paths refuse to start while the stack is in a busy status,
    so a lock still present here has outlived the process that took it.

    Args:
        pulumi_stack: Automation API Stack to destroy.
        on_output:    Callback receiving Pulumi's output lines.
        label:        Stack name, for log context.
    """
    try:
        pulumi_stack.destroy(on_output=on_output)
        return
    except Exception as exc:
        message = str(exc).lower()
        if not any(marker in message for marker in _LOCK_ERROR_MARKERS):
            raise
        logger.warning(
            "Destroy blocked by a stale Pulumi lock on %s; cancelling the lock and retrying",
            label,
        )

    pulumi_stack.cancel()
    pulumi_stack.destroy(on_output=on_output)
