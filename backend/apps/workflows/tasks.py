"""
Advancing workflows and settling them against a client's SIEM alerts.

One beat job drives every transition rather than a task that runs the pipeline
end to end. A workflow spends most of its life waiting: minutes for Pulumi,
minutes for the attack, then tens of minutes for a SIEM that evaluates on its
own schedule. A task holding a worker slot through all of that would occupy one
of four concurrency slots for an hour, and would lose the run entirely if the
worker restarted.

Keeping the state in the database and advancing it on a tick costs nothing
while waiting, survives a restart, and means the user can close the page, which
is the behaviour this feature was asked for.

Deploy and attack are the emulations app's existing tasks, invoked unchanged.
This module decides when, never how.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from celery import shared_task
from django.apps import apps as django_apps
from django.conf import settings
from django.utils import timezone

from apps.emulations.registry import get_emulation
from apps.emulations.tasks import deploy_emulation_stack, run_emulation_attack

from . import correlate, scoring
from .expectations import expected_detections
from .models import AlertEndpoint, IngestedAlert, WorkflowRun

logger = logging.getLogger(__name__)

# How long to keep collecting alerts after the attack ends. SIEMs evaluate on a
# schedule, commonly every five to fifteen minutes, so a window measured in
# seconds would score a working detection as silent. The default spans at least
# two evaluation cycles for the slowest common cadence.
DEFAULT_ALERT_WAIT_MINUTES = 30

# A workflow stuck in a step for longer than this is abandoned rather than
# advanced forever. Pulumi deploys are minutes; an hour means something failed
# in a way that did not update the stack.
STEP_TIMEOUT_MINUTES = 90


def _wait_minutes() -> int:
    """
    Return the configured alert collection window in minutes.

    Returns:
        WORKFLOW_ALERT_WAIT_MINUTES when set, otherwise the default.
    """
    return int(getattr(settings, "WORKFLOW_ALERT_WAIT_MINUTES", DEFAULT_ALERT_WAIT_MINUTES))


def _fail(workflow: WorkflowRun, detail: str, step: str) -> None:
    """
    Mark a workflow failed, recording which step gave up.

    The step is passed in rather than derived, because only the branch that
    abandoned the run knows it. A previous version left the frontend to infer it
    from timestamps, which marked a failed deploy as done and blamed the attack
    step that had never started.

    Args:
        workflow: The run to close.
        detail: Human-readable cause.
        step: One of the STEPS keys the frontend renders: deploy, attack,
            alerts or score.
    """
    workflow.status = WorkflowRun.Status.FAILED
    workflow.detail = detail
    workflow.failed_step = step
    workflow.completed_at = timezone.now()
    workflow.save(update_fields=["status", "detail", "failed_step", "completed_at"])
    logger.warning("Workflow %s failed at %s: %s", workflow.id, step, detail)


def _start_deploy(workflow: WorkflowRun) -> None:
    """
    Provision the emulation's infrastructure and move to DEPLOYING.

    Args:
        workflow: A pending workflow.
    """
    Stack = django_apps.get_model("infrastructure", "Stack")

    entry = get_emulation(workflow.emulation_type)
    if entry is None:
        _fail(workflow, f"Unknown emulation: {workflow.emulation_type}", "deploy")
        return

    stack = Stack.objects.create(
        owner=workflow.owner,
        emulation_type=workflow.emulation_type,
        status=Stack.Status.PENDING,
    )
    workflow.stack = stack
    workflow.status = WorkflowRun.Status.DEPLOYING
    workflow.started_at = timezone.now()
    workflow.save(update_fields=["stack", "status", "started_at"])

    deploy_emulation_stack.apply_async(args=[str(stack.id)], queue="enterprise")
    logger.info("Workflow %s: deploying stack %s", workflow.id, stack.id)


def _start_attack(workflow: WorkflowRun) -> None:
    """
    Launch the emulation once its stack is ready, and move to ATTACKING.

    Args:
        workflow: A workflow whose stack has reached ready_for_attack.
    """
    EmulationRun = django_apps.get_model("emulations", "EmulationRun")

    entry = get_emulation(workflow.emulation_type) or {}
    manifest = entry.get("manifest", entry)

    run = EmulationRun.objects.create(
        stack=workflow.stack,
        emulation_type=workflow.emulation_type,
        status=EmulationRun.Status.PENDING,
        phase_total=manifest.get("phase_count", 0),
        triggered_by=workflow.owner,
    )
    workflow.emulation_run = run
    workflow.status = WorkflowRun.Status.ATTACKING
    workflow.save(update_fields=["emulation_run", "status"])

    run_emulation_attack.apply_async(args=[str(run.id)], queue="enterprise")
    logger.info("Workflow %s: attacking via run %s", workflow.id, run.id)


def _open_alert_window(workflow: WorkflowRun) -> None:
    """
    Close the attack and start collecting alerts.

    Entered for a failed attack as well as a completed one. A guardrail that
    blocked the attack still produced API calls a SIEM may have alerted on, and
    several attack modules raise rather than catch a denial, so treating a
    failed run as nothing to validate would hide exactly the accounts whose
    controls are working.

    Args:
        workflow: A workflow whose emulation run has reached a terminal status.
    """
    run = workflow.emulation_run
    start = run.started_at or run.created_at
    end = run.completed_at or timezone.now()

    workflow.window_start = start
    workflow.window_end = end
    workflow.alert_deadline = end + timedelta(minutes=_wait_minutes())
    workflow.status = WorkflowRun.Status.AWAITING_ALERTS
    workflow.save(update_fields=["window_start", "window_end", "alert_deadline", "status"])
    logger.info(
        "Workflow %s: collecting alerts until %s", workflow.id, workflow.alert_deadline
    )


def attributed_alerts(workflow: WorkflowRun) -> list[dict[str, Any]]:
    """
    Collect the alerts that belong to a workflow's evidence window.

    Attribution is by owner and arrival time rather than by anything the alert
    claims, because the webhook is unauthenticated at the application level and
    a posted body must never be able to choose which run it counts towards.

    Args:
        workflow: The run being settled.

    Returns:
        Normalised alert dicts, oldest first.
    """
    if workflow.window_start is None:
        return []

    end = workflow.alert_deadline or timezone.now()
    rows = (
        IngestedAlert.objects.filter(
            endpoint__owner=workflow.owner,
            received_at__gte=workflow.window_start,
            received_at__lte=end,
        )
        .order_by("received_at")
    )
    return [
        {
            "id": str(row.id),
            "ruleId": row.rule_id,
            "ruleName": row.rule_name,
            "technique": row.technique,
            "severity": row.severity,
            "firedAt": row.fired_at.isoformat() if row.fired_at else None,
            "receivedAt": row.received_at.isoformat(),
        }
        for row in rows
    ]


def settle(workflow: WorkflowRun) -> dict[str, Any]:
    """
    Score a workflow against whatever its window collected, and close it.

    Args:
        workflow: A workflow in AWAITING_ALERTS.

    Returns:
        The score written to the run.
    """
    entry = get_emulation(workflow.emulation_type)
    rules = expected_detections(entry) if entry else []
    alerts = attributed_alerts(workflow)

    matched = correlate.match_alerts(rules, alerts)
    score = scoring.build_score(
        matched,
        endpoint_configured=AlertEndpoint.objects.filter(
            owner=workflow.owner, enabled=True
        ).exists(),
        alerts_received=len(alerts),
    )

    workflow.report = matched
    workflow.score = score
    workflow.status = WorkflowRun.Status.COMPLETED
    workflow.completed_at = timezone.now()
    workflow.save(update_fields=["report", "score", "status", "completed_at"])

    logger.info(
        "Workflow %s settled: %s (%d alert(s) attributed)",
        workflow.id, scoring.headline(score), len(alerts),
    )
    return score


def _step_for(status: str) -> str:
    """
    Map an open status to the pipeline step it is sitting on.

    Used only when an unexpected exception ends a run, where the branch that
    raised did not name a step itself.

    Args:
        status: The workflow's status at the moment it failed.

    Returns:
        A STEPS key, defaulting to deploy for a run that had not started.
    """
    return {
        WorkflowRun.Status.PENDING: "deploy",
        WorkflowRun.Status.DEPLOYING: "deploy",
        WorkflowRun.Status.ATTACKING: "attack",
        WorkflowRun.Status.AWAITING_ALERTS: "alerts",
    }.get(status, "deploy")


def _timed_out(workflow: WorkflowRun) -> bool:
    """
    Report whether a workflow has sat in one step past the timeout.

    Args:
        workflow: The run to check.

    Returns:
        True when the run should be abandoned rather than advanced again.
    """
    reference = workflow.started_at or workflow.created_at
    return timezone.now() - reference > timedelta(minutes=STEP_TIMEOUT_MINUTES)


@shared_task(name="workflows.advance_workflows", queue="enterprise")
def advance_workflows() -> dict[str, int]:
    """
    Move every open workflow to its next step.

    Scheduled by CELERY_BEAT_SCHEDULE. Each tick is cheap: it reads the status
    of runs that are open and acts only where something has changed, so a quiet
    platform costs one query.

    Returns:
        Counts of the transitions this tick performed.
    """
    Stack = django_apps.get_model("infrastructure", "Stack")
    EmulationRun = django_apps.get_model("emulations", "EmulationRun")

    moved = {"deployed": 0, "attacked": 0, "awaiting": 0, "settled": 0, "failed": 0}
    open_states = [
        WorkflowRun.Status.PENDING,
        WorkflowRun.Status.DEPLOYING,
        WorkflowRun.Status.ATTACKING,
        WorkflowRun.Status.AWAITING_ALERTS,
    ]

    for workflow in WorkflowRun.objects.filter(status__in=open_states).select_related(
        "stack", "emulation_run"
    ):
        try:
            if workflow.status == WorkflowRun.Status.PENDING:
                _start_deploy(workflow)
                moved["deployed"] += 1

            elif workflow.status == WorkflowRun.Status.DEPLOYING:
                stack = workflow.stack
                if stack is None or stack.status == Stack.Status.FAILED:
                    _fail(workflow, "Infrastructure deployment failed.", "deploy")
                    moved["failed"] += 1
                elif stack.status == Stack.Status.READY_FOR_ATTACK:
                    _start_attack(workflow)
                    moved["attacked"] += 1
                elif _timed_out(workflow):
                    _fail(workflow, "Deployment did not become ready in time.", "deploy")
                    moved["failed"] += 1

            elif workflow.status == WorkflowRun.Status.ATTACKING:
                run = workflow.emulation_run
                if run is None:
                    _fail(workflow, "Emulation run is missing.", "attack")
                    moved["failed"] += 1
                elif run.status in (
                    EmulationRun.Status.COMPLETED,
                    EmulationRun.Status.FAILED,
                ):
                    _open_alert_window(workflow)
                    moved["awaiting"] += 1
                elif _timed_out(workflow):
                    _fail(workflow, "Emulation did not finish in time.", "attack")
                    moved["failed"] += 1

            elif workflow.status == WorkflowRun.Status.AWAITING_ALERTS:
                if workflow.alert_deadline and timezone.now() >= workflow.alert_deadline:
                    settle(workflow)
                    moved["settled"] += 1

        except Exception as exc:  # noqa: BLE001 - one bad workflow must not stall the rest
            logger.exception("Workflow %s could not be advanced", workflow.id)
            _fail(workflow, f"{type(exc).__name__}: {exc}", _step_for(workflow.status))
            moved["failed"] += 1

    if any(moved.values()):
        logger.info("advance_workflows: %s", moved)
    return moved
