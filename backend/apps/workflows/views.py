"""
Views for the workflows app.

POST /api/workflows/alerts/<endpoint_id>/   AlertWebhookView       (unauthenticated)
GET  POST /api/workflows/endpoints/         AlertEndpointView
GET  POST /api/workflows/runs/              WorkflowRunListView
GET  /api/workflows/runs/<id>/              WorkflowRunDetailView

AlertWebhookView is the only route in the platform that does not carry a JWT,
because a client's SIEM cannot hold one. It authenticates on an HMAC signature
instead, and is written to refuse before it allocates: signature, freshness and
size are checked ahead of parsing.

Everything else is owner-scoped. A workflow report names principals and rule
titles from the client's own environment, so authentication alone is not enough
to read one.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import timedelta

from cryptography.fernet import InvalidToken
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.emulations.registry import get_emulation
from apps.emulations.sigma_convert import BackendUnavailable
from apps.emulations.views import (
    _bundle_response,
    _get_emulation_or_404,
    _unavailable,
    _validate_target,
)
from apps.emulations.detection_export import export_rules

from .crypto import EncryptionNotConfigured, decrypt, encrypt
from .export import silent_rule_ids
from .ingest import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    IngestRejected,
    parse_alert,
    verify,
)
from .models import AlertEndpoint, IngestedAlert, WorkflowRun
from .serializers import (
    AlertEndpointSerializer,
    WorkflowRunDetailSerializer,
    WorkflowRunSerializer,
)

logger = logging.getLogger(__name__)

# Upper bound on how far ahead a workflow may be scheduled. A run deploys real
# infrastructure against a MANIFEST and a connector role that may not look the
# same in three months, so a schedule further out than this is more likely a
# typo in a date than an intention.
MAX_SCHEDULE_DAYS = 30

# Characters of the secret kept in clear, so a user can tell two endpoints
# apart without the value being recoverable from the hint.
SECRET_HINT_LENGTH = 6


class AlertWebhookView(APIView):
    """
    Accept one alert from a client's SIEM.

    POST /api/workflows/alerts/<endpoint_id>/

    Returns 202 on acceptance and 401 on any rejection, with no detail. A
    caller holding the secret does not need to be told why a signature failed,
    and a caller without it should not be helped.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "alert_webhook"

    def post(self, request: Request, endpoint_id: str) -> Response:
        """
        Verify and store a posted alert.

        Args:
            request: DRF request; the raw body is read for signing.
            endpoint_id: UUID of the endpoint being posted to.

        Returns:
            202 when stored, 401 when the request is not from the secret holder.
        """
        endpoint = AlertEndpoint.objects.filter(id=endpoint_id, enabled=True).first()
        if endpoint is None:
            # Same response as a bad signature, so the endpoint id cannot be
            # probed for existence.
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        body = request.body
        try:
            verify(
                decrypt(bytes(endpoint.secret_encrypted)),
                request.META.get(TIMESTAMP_HEADER, ""),
                request.META.get(SIGNATURE_HEADER, ""),
                body,
            )
        except IngestRejected as exc:
            logger.warning("Alert rejected for endpoint %s: %s", endpoint_id, exc)
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        except Exception:  # noqa: BLE001 - a decrypt failure must not leak a stack trace
            logger.exception("Could not verify alert for endpoint %s", endpoint_id)
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return Response(
                {"detail": "Body is not valid JSON."}, status=status.HTTP_400_BAD_REQUEST
            )
        if not isinstance(payload, dict):
            return Response(
                {"detail": "Body must be a JSON object."}, status=status.HTTP_400_BAD_REQUEST
            )

        parsed = parse_alert(payload)
        IngestedAlert.objects.create(
            endpoint=endpoint,
            fired_at=parse_datetime(parsed["firedAt"]) if parsed["firedAt"] else None,
            rule_id=parsed["ruleId"],
            rule_name=parsed["ruleName"],
            technique=parsed["technique"].upper(),
            severity=parsed["severity"],
            raw=parsed["raw"],
        )
        AlertEndpoint.objects.filter(id=endpoint.id).update(last_alert_at=timezone.now())

        return Response({"status": "accepted"}, status=status.HTTP_202_ACCEPTED)


class AlertEndpointView(APIView):
    """
    List a user's alert endpoints, or create one.

    GET  /api/workflows/endpoints/
    POST /api/workflows/endpoints/   {"name": "Splunk production"}
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        List the caller's endpoints.

        Args:
            request: DRF request.

        Returns:
            200 with one entry per endpoint. Secrets are never included.
        """
        endpoints = AlertEndpoint.objects.filter(owner=request.user)
        return Response({"endpoints": AlertEndpointSerializer(endpoints, many=True).data})

    def post(self, request: Request) -> Response:
        """
        Create an endpoint and return its secret once.

        Args:
            request: DRF request carrying a `name`.

        Returns:
            201 with the endpoint and its plaintext secret. This is the only
            time the secret is returned; it is stored encrypted and cannot be
            read back, so the client must copy it into their SIEM now.
        """
        name = (request.data.get("name") or "").strip()
        if not name:
            return Response(
                {"detail": "A name is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        secret = secrets.token_urlsafe(32)
        endpoint = AlertEndpoint.objects.create(
            owner=request.user,
            name=name[:120],
            secret_encrypted=encrypt(secret),
            secret_hint=secret[-SECRET_HINT_LENGTH:],
        )
        logger.info("Alert endpoint created: user=%s endpoint=%s", request.user.username, endpoint.id)

        data = AlertEndpointSerializer(endpoint).data
        data["secret"] = secret
        return Response(data, status=status.HTTP_201_CREATED)


class AlertEndpointDetailView(APIView):
    """
    Read or delete one endpoint.

    GET    /api/workflows/endpoints/<endpoint_id>/
    DELETE /api/workflows/endpoints/<endpoint_id>/
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request, endpoint_id) -> Response:
        """
        Return one endpoint, without its secret.

        Args:
            request: DRF request.
            endpoint_id: The endpoint's UUID.

        Returns:
            200 with the endpoint, or 404 when it is not the caller's.
        """
        endpoint = AlertEndpoint.objects.filter(owner=request.user, id=endpoint_id).first()
        if endpoint is None:
            return Response({"detail": "Endpoint not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(AlertEndpointSerializer(endpoint).data)

    def delete(self, request: Request, endpoint_id) -> Response:
        """
        Delete an endpoint that has never been used.

        An endpoint that has accepted alerts is refused. `IngestedAlert.endpoint`
        cascades, so deleting one would take its alerts with it and silently
        rewrite the reports of completed workflow runs: a run that proved a
        detection fired would lose the evidence behind that verdict. An endpoint
        is either unused and disposable, or it is part of the audit trail.

        Args:
            request: DRF request.
            endpoint_id: The endpoint's UUID.

        Returns:
            204 on deletion, 409 with the reason when the endpoint is in use,
            404 when it is not the caller's.
        """
        endpoint = AlertEndpoint.objects.filter(owner=request.user, id=endpoint_id).first()
        if endpoint is None:
            return Response({"detail": "Endpoint not found."}, status=status.HTTP_404_NOT_FOUND)

        alert_count = endpoint.alerts.count()
        if alert_count or endpoint.last_alert_at:
            return Response(
                {
                    "detail": (
                        f"This endpoint has received {alert_count} alert"
                        f"{'' if alert_count == 1 else 's'} and cannot be deleted. "
                        f"Those alerts are the evidence behind past workflow reports. "
                        f"Disable it instead to stop accepting new alerts."
                    ),
                    "reason": "has_alerts",
                    "alertCount": alert_count,
                },
                status=status.HTTP_409_CONFLICT,
            )

        # A run still collecting alerts may yet receive one through this
        # endpoint, and attribution is by owner and arrival time rather than by
        # a foreign key, so any open window is a claim on every endpoint.
        open_runs = WorkflowRun.objects.filter(
            owner=request.user,
            status=WorkflowRun.Status.AWAITING_ALERTS,
        ).count()
        if open_runs:
            return Response(
                {
                    "detail": (
                        f"{open_runs} workflow run{'' if open_runs == 1 else 's'} "
                        f"{'is' if open_runs == 1 else 'are'} still collecting alerts. "
                        f"Wait for the alert window to close before deleting an endpoint."
                    ),
                    "reason": "run_in_progress",
                },
                status=status.HTTP_409_CONFLICT,
            )

        endpoint.delete()
        logger.info(
            "Alert endpoint deleted: user=%s endpoint=%s", request.user.username, endpoint_id
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class AlertEndpointSecretView(APIView):
    """
    Reveal or rotate an endpoint's signing secret.

    GET  /api/workflows/endpoints/<endpoint_id>/secret/   reveal
    POST /api/workflows/endpoints/<endpoint_id>/secret/   rotate

    The secret is recoverable by design. It is stored Fernet-encrypted rather
    than hashed precisely because the server has to reproduce an HMAC with it on
    every inbound alert, so "we cannot read it back" was never true. Revealing
    it on request is honest about that, and saves a client whose SIEM operator
    lost their copy from having to re-point their integration.

    Both actions are throttled and logged. The secret only authorises posting
    alerts, so a leak lets someone inflate a detection score rather than read
    anything, but a credential handed out over an API is still a credential.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "endpoint_secret"

    def get(self, request: Request, endpoint_id) -> Response:
        """
        Return the endpoint's current secret in plaintext.

        Args:
            request: DRF request.
            endpoint_id: The endpoint's UUID.

        Returns:
            200 with the secret, 404 when it is not the caller's, or 503 when
            the encryption key is missing.
        """
        endpoint = AlertEndpoint.objects.filter(owner=request.user, id=endpoint_id).first()
        if endpoint is None:
            return Response({"detail": "Endpoint not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            secret = decrypt(bytes(endpoint.secret_encrypted))
        except EncryptionNotConfigured as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        except InvalidToken:
            return Response(
                {
                    "detail": (
                        "This endpoint's secret cannot be decrypted, which means "
                        "WORKFLOW_FERNET_KEY has changed since it was created. "
                        "Rotate the secret and update your SIEM."
                    )
                },
                status=status.HTTP_409_CONFLICT,
            )

        logger.info(
            "Alert endpoint secret revealed: user=%s endpoint=%s",
            request.user.username, endpoint_id,
        )
        return Response({"secret": secret})

    def post(self, request: Request, endpoint_id) -> Response:
        """
        Replace the endpoint's secret with a new one.

        Alerts signed with the old secret stop verifying the moment this
        returns, so the client has to update their SIEM before the next run.

        Args:
            request: DRF request.
            endpoint_id: The endpoint's UUID.

        Returns:
            200 with the new secret, 404 when it is not the caller's, or 503
            when the encryption key is missing.
        """
        endpoint = AlertEndpoint.objects.filter(owner=request.user, id=endpoint_id).first()
        if endpoint is None:
            return Response({"detail": "Endpoint not found."}, status=status.HTTP_404_NOT_FOUND)

        secret = secrets.token_urlsafe(32)
        try:
            endpoint.secret_encrypted = encrypt(secret)
        except EncryptionNotConfigured as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        endpoint.secret_hint = secret[-SECRET_HINT_LENGTH:]
        endpoint.save(update_fields=["secret_encrypted", "secret_hint"])

        logger.info(
            "Alert endpoint secret rotated: user=%s endpoint=%s",
            request.user.username, endpoint_id,
        )
        data = AlertEndpointSerializer(endpoint).data
        data["secret"] = secret
        return Response(data)


class WorkflowRunListView(APIView):
    """
    List the caller's workflows, or start one.

    GET  /api/workflows/runs/
    POST /api/workflows/runs/   {"emulationType": "scarleteel"}
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        List the caller's workflows, newest first.

        Args:
            request: DRF request.

        Returns:
            200 with summary rows; the full report is on the detail route.
        """
        runs = WorkflowRun.objects.filter(owner=request.user)[:100]
        return Response({"runs": WorkflowRunSerializer(runs, many=True).data})

    def post(self, request: Request) -> Response:
        """
        Queue a workflow for one emulation, now or at a chosen time.

        Created in PENDING and picked up by the advance_workflows beat job, so
        the request returns immediately and the run survives a worker restart.
        With `scheduledFor` it is created in SCHEDULED instead and the same beat
        job starts it once that time has passed.

        Args:
            request: DRF request carrying `emulationType`, and optionally
                `scheduledFor` as an ISO-8601 timestamp.

        Returns:
            201 with the created workflow, 400 for an unknown emulation or an
            unusable schedule.
        """
        emulation_type = (request.data.get("emulationType") or "").strip()
        if not emulation_type or get_emulation(emulation_type) is None:
            return Response(
                {"detail": "Unknown emulation."}, status=status.HTTP_400_BAD_REQUEST
            )

        raw_schedule = request.data.get("scheduledFor")
        scheduled_for = None
        if raw_schedule:
            scheduled_for = parse_datetime(raw_schedule)
            if scheduled_for is None:
                return Response(
                    {"detail": "scheduledFor must be an ISO-8601 timestamp."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # A naive timestamp is read as the server's timezone rather than
            # rejected, so a client that sends a local time still schedules.
            if timezone.is_naive(scheduled_for):
                scheduled_for = timezone.make_aware(scheduled_for)
            if scheduled_for <= timezone.now():
                return Response(
                    {"detail": "scheduledFor must be in the future."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if scheduled_for > timezone.now() + timedelta(days=MAX_SCHEDULE_DAYS):
                return Response(
                    {
                        "detail": (
                            f"A workflow cannot be scheduled more than "
                            f"{MAX_SCHEDULE_DAYS} days ahead."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        workflow = WorkflowRun.objects.create(
            owner=request.user,
            emulation_type=emulation_type,
            scheduled_for=scheduled_for,
            status=(
                WorkflowRun.Status.SCHEDULED if scheduled_for
                else WorkflowRun.Status.PENDING
            ),
        )
        # The beat tick runs every two minutes, so a run started now would sit
        # in "Queued" for up to that long with nothing happening and no way for
        # the reader to tell it apart from a run that has hung. Nudging the same
        # task immediately starts it in about a second; the tick stays as the
        # safety net and as the only thing a scheduled run needs.
        if scheduled_for is None:
            from .tasks import advance_workflows  # noqa: PLC0415
            advance_workflows.apply_async(queue="enterprise")

        logger.info(
            "Workflow queued: user=%s emulation=%s workflow=%s scheduled_for=%s",
            request.user.username, emulation_type, workflow.id, scheduled_for,
        )
        return Response(WorkflowRunSerializer(workflow).data, status=status.HTTP_201_CREATED)


class WorkflowRunDetailView(APIView):
    """
    Return one workflow with its full report, or delete a finished one.

    GET    /api/workflows/runs/<workflow_id>/
    DELETE /api/workflows/runs/<workflow_id>/
    """

    permission_classes = [IsAuthenticated]

    # A run in one of these states is over or has not begun, so removing its row
    # cannot interrupt anything. Everything else is mid-flight.
    DELETABLE = (WorkflowRun.Status.FAILED, WorkflowRun.Status.SCHEDULED)

    def get(self, request: Request, workflow_id: str) -> Response:
        """
        Read one of the caller's workflows.

        Args:
            request: DRF request.
            workflow_id: UUID of the workflow.

        Returns:
            200 with the run, its per-rule verdicts and its score, or 404. The
            queryset is owner-scoped, so another user's workflow is not found
            rather than forbidden.
        """
        workflow = WorkflowRun.objects.filter(id=workflow_id, owner=request.user).first()
        if workflow is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(WorkflowRunDetailSerializer(workflow).data)

    def delete(self, request: Request, workflow_id: str) -> Response:
        """
        Remove a failed run, or cancel a scheduled one.

        A failed run is a dead row: its stack reference is SET_NULL, so deleting
        it leaves any infrastructure it created on the Stacks page to be
        destroyed there. Nothing is torn down here, because a workflow does not
        own the stack it asked for.

        A completed run is refused. Its report is the record of what a client's
        SIEM did catch, which is the only durable output the feature produces.
        An open run is refused because it is mid-flight: deleting the row would
        leave a Pulumi deploy or an attack running with nothing tracking it.

        Args:
            request: DRF request.
            workflow_id: UUID of the workflow.

        Returns:
            204 on deletion, 409 with the reason when the run cannot be removed,
            404 when it is not the caller's.
        """
        workflow = WorkflowRun.objects.filter(id=workflow_id, owner=request.user).first()
        if workflow is None:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if workflow.status not in self.DELETABLE:
            completed = workflow.status == WorkflowRun.Status.COMPLETED
            return Response(
                {
                    "detail": (
                        "A completed run cannot be deleted. Its report is the record of "
                        "what your SIEM caught."
                        if completed else
                        "This run is still in progress. Wait for it to finish or fail "
                        "before deleting it."
                    ),
                    "reason": "completed" if completed else "in_progress",
                },
                status=status.HTTP_409_CONFLICT,
            )

        was_scheduled = workflow.status == WorkflowRun.Status.SCHEDULED
        stack_name = workflow.stack.name if workflow.stack else None
        workflow.delete()

        logger.info(
            "Workflow %s: user=%s removed a %s run (stack left in place: %s)",
            workflow_id,
            request.user.username,
            "scheduled" if was_scheduled else "failed",
            stack_name or "none",
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class WorkflowDetectionExportView(APIView):
    """
    Compile the detections this workflow found silent.

    GET /api/workflows/runs/<workflow_id>/export/?target=splunk&output_format=default

    Where the loop closes. The run reports that two expected detections never
    reached the client's SIEM; this hands back those two, compiled into the
    dialect their SIEM speaks, so the finding arrives with the fix attached.

    Only silent rules are offered, and that is not a default but the whole
    contract: a rule that fired needs nothing, and `not_integrated` means no
    alert route existed, so the rule was never exercised and shipping a query
    for it would assert a gap nobody measured.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request, workflow_id) -> Response:
        """
        Return the compiled bundle for this workflow's silent rules.

        Args:
            request: DRF request carrying `target` and `output_format`.
            workflow_id: UUID of the workflow.

        Returns:
            200 with the bundle, 404 when the run is not the caller's or
            nothing was silent, 400 for an unusable target.
        """
        workflow = WorkflowRun.objects.filter(id=workflow_id, owner=request.user).first()
        if workflow is None:
            return Response({"detail": "Run not found."}, status=status.HTTP_404_NOT_FOUND)

        rule_ids = silent_rule_ids(workflow.score)
        if not rule_ids:
            return Response(
                {
                    "detail": (
                        "Nothing to export. Either this run has not settled, every "
                        "expected detection fired, or no alert endpoint was integrated "
                        "so no rule was actually exercised."
                    ),
                    "reason": "no_silent_rules",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        target, output_format, err = _validate_target(request)
        if err:
            return err

        entry, entry_err = _get_emulation_or_404(workflow.emulation_type)
        if entry_err:
            return entry_err

        try:
            bundle = export_rules(entry, rule_ids, target, output_format)
        except BackendUnavailable:
            return _unavailable(target)

        note = (
            "Detections your SIEM did not report during this run. "
            "Deploy them, then run the workflow again to confirm."
        )
        return _bundle_response(
            request, bundle, note=note, stem=f"{workflow.emulation_type}-silent"
        )
