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

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.emulations.registry import get_emulation

from .crypto import decrypt, encrypt
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
        Queue a workflow for one emulation.

        Created in PENDING and picked up by the advance_workflows beat job, so
        the request returns immediately and the run survives a worker restart.

        Args:
            request: DRF request carrying `emulationType`.

        Returns:
            201 with the created workflow, or 400 for an unknown emulation.
        """
        emulation_type = (request.data.get("emulationType") or "").strip()
        if not emulation_type or get_emulation(emulation_type) is None:
            return Response(
                {"detail": "Unknown emulation."}, status=status.HTTP_400_BAD_REQUEST
            )

        workflow = WorkflowRun.objects.create(
            owner=request.user,
            emulation_type=emulation_type,
            status=WorkflowRun.Status.PENDING,
        )
        logger.info(
            "Workflow queued: user=%s emulation=%s workflow=%s",
            request.user.username, emulation_type, workflow.id,
        )
        return Response(WorkflowRunSerializer(workflow).data, status=status.HTTP_201_CREATED)


class WorkflowRunDetailView(APIView):
    """
    Return one workflow with its full report.

    GET /api/workflows/runs/<workflow_id>/
    """

    permission_classes = [IsAuthenticated]

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
