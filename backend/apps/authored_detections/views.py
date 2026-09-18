"""
Views for the authored_detections app.

GET    /api/detections/authored/                 list rules visible to the caller
POST   /api/detections/authored/                 create one
GET    /api/detections/authored/<id>/            read one
PATCH  /api/detections/authored/<id>/            edit (owner only)
DELETE /api/detections/authored/<id>/            delete (owner only)
POST   /api/detections/authored/generate/        draft a rule with the LLM
POST   /api/detections/authored/validate/        score ad-hoc Sigma (unsaved)
POST   /api/detections/authored/<id>/validate/   score a saved rule, store fidelity
GET    /api/detections/authored/<id>/export/     compile to a SIEM (?target=)

All routes require IsEnterpriseUser. 'generate/' and 'validate/' must precede
'<uuid:pk>/' in urls.py.
"""

from __future__ import annotations

import logging
import re

from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.emulations.detections import parse_sigma, parse_sigma_documents
from apps.emulations.sigma_convert import TARGETS, BackendUnavailable, convert
from apps.emulations.sigma_eval import is_evaluable
from apps.infrastructure.permissions import IsEnterpriseUser

from .generation import generate_detection
from .models import AuthoredDetection
from .serializers import (
    AuthoredDetectionListSerializer,
    AuthoredDetectionSerializer,
    DetectionGenerateSerializer,
    DetectionValidateSerializer,
)

logger = logging.getLogger(__name__)


class IsOwner(BasePermission):
    """Only the author may modify or delete a rule."""

    message = "You can only modify detections you created."

    def has_object_permission(self, request: Request, view, obj) -> bool:
        """Return True when the requesting user owns the rule."""
        return obj.owner_id == request.user.id


def _visible_to(user):
    """Rules a user may read: their own, plus organisation-shared ones."""
    return (
        AuthoredDetection.objects
        .filter(Q(owner=user) | Q(visibility=AuthoredDetection.Visibility.ORGANIZATION))
        .select_related("owner")
    )


def _connector_creds(user):
    """
    Resolve the caller's LLM connector to (provider, creds, model), or a
    Response describing why it is unavailable.

    Imported lazily: apps.ai.views pulls in boto3 for the Bedrock STS path, and
    this app should stay importable without it.
    """
    from apps.ai.models import LLMConnector
    from apps.ai.views import build_credentials

    connector = LLMConnector.objects.filter(user=user).first()
    if connector is None or not connector.enabled:
        return None, Response(
            {"detail": "No active AI connector. Add one in Settings -> AI Assistant."},
            status=status.HTTP_409_CONFLICT,
        )
    creds, error = build_credentials(user, connector)
    if error:
        return None, Response({"detail": error}, status=status.HTTP_409_CONFLICT)
    return (connector.provider, creds, connector.model), None


def _validate_sigma(user, sigma_text: str) -> dict:
    """
    Score a Sigma rule against AI-synthesised events, gating first on whether
    it is the kind of rule the evaluator can judge.

    Returns the validator's report dict, or {"error"/"evaluable": ...} for the
    cases that cannot be scored. Mirrors apps.emulations.views.DetectionValidate.
    """
    from apps.ai.detection_validation import run_validation

    # A correlation/aggregation rule spans many events; scoring it against
    # single synthetic events would measure the wrong thing.
    try:
        documents = parse_sigma_documents(sigma_text)
    except Exception:  # noqa: BLE001 - malformed YAML is a user error, not a 500
        return {"error": "That is not valid Sigma YAML."}
    if any(doc.get("correlation") for doc in documents):
        return {"evaluable": False, "reason": "aggregation/correlation condition"}

    try:
        sigma_rule = parse_sigma(sigma_text)
    except Exception:  # noqa: BLE001
        return {"error": "That is not valid Sigma YAML."}

    evaluable, reason = is_evaluable(sigma_rule)
    if not evaluable:
        return {"evaluable": False, "reason": reason}

    resolved, err_response = _connector_creds(user)
    if err_response is not None:
        return {"error": "no_connector"}
    provider, creds, model = resolved
    return run_validation(provider, creds, model, sigma_text, sigma_rule)


class AuthoredDetectionListCreateView(APIView):
    """List visible rules, or create one."""

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """Return rules visible to the caller, newest edit first."""
        qs = _visible_to(request.user)
        if request.query_params.get("mine") in ("1", "true", "yes"):
            qs = qs.filter(owner=request.user)
        technique = request.query_params.get("technique")
        if technique:
            qs = qs.filter(technique_id__iexact=technique)
        return Response(AuthoredDetectionListSerializer(qs, many=True).data)

    def post(self, request: Request) -> Response:
        """Create a rule owned by the caller."""
        serializer = AuthoredDetectionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # origin defaults to manual; the generate flow sets it explicitly.
        detection = serializer.save(owner=request.user)
        return Response(
            AuthoredDetectionSerializer(detection).data, status=status.HTTP_201_CREATED
        )


class AuthoredDetectionDetailView(APIView):
    """Read, edit or delete a single rule."""

    permission_classes = [IsEnterpriseUser]

    def _get(self, request: Request, pk, *, for_write: bool):
        detection = get_object_or_404(_visible_to(request.user), pk=pk)
        if for_write:
            checker = IsOwner()
            if not checker.has_object_permission(request, self, detection):
                self.permission_denied(request, message=checker.message)
        return detection

    def get(self, request: Request, pk) -> Response:
        """Return the full rule."""
        return Response(AuthoredDetectionSerializer(self._get(request, pk, for_write=False)).data)

    def patch(self, request: Request, pk) -> Response:
        """Apply a partial update. Owner only."""
        detection = self._get(request, pk, for_write=True)
        serializer = AuthoredDetectionSerializer(detection, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        # Editing the rule body invalidates any stored fidelity score.
        if "sigma" in serializer.validated_data:
            serializer.validated_data["last_fidelity"] = None
        serializer.save()
        return Response(serializer.data)

    def delete(self, request: Request, pk) -> Response:
        """Delete the rule. Owner only."""
        self._get(request, pk, for_write=True).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class DetectionGenerateView(APIView):
    """
    Draft a Sigma rule with the user's LLM connector.

    POST /api/detections/authored/generate/
    Body: { "brief": "...", "technique_id": "T1562.008", "reference_urls": [...] }

    Returns the Sigma unsaved. Nothing is persisted until the author saves it -
    a generated rule that looks plausible but never fires is worse than none, so
    a human validates and saves. Shares the 'ai_chat' throttle.
    """

    permission_classes = [IsEnterpriseUser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ai_chat"

    def post(self, request: Request) -> Response:
        """Draft one rule and return it unsaved."""
        serializer = DetectionGenerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        resolved, err_response = _connector_creds(request.user)
        if err_response is not None:
            return err_response
        provider, creds, model = resolved

        result = generate_detection(
            provider, creds, model,
            brief=data["brief"],
            technique_id=data.get("technique_id") or "",
            reference_urls=data.get("reference_urls") or [],
            reference_text=data.get("reference_text") or "",
        )
        if "error" in result:
            return Response({"detail": result["error"]}, status=status.HTTP_502_BAD_GATEWAY)
        return Response(result)


class DetectionValidateAdhocView(APIView):
    """
    Score a Sigma rule that has not been saved yet.

    POST /api/detections/authored/validate/  Body: { "sigma": "..." }

    This is what closes the loop right after generation: draft -> score -> tune,
    before deciding the rule is worth keeping.
    """

    permission_classes = [IsEnterpriseUser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ai_chat"

    def post(self, request: Request) -> Response:
        """Validate posted Sigma and return the fidelity report."""
        serializer = DetectionValidateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = _validate_sigma(request.user, serializer.validated_data["sigma"])
        if result.get("error") == "no_connector":
            return Response(
                {"detail": "No active AI connector. Add one in Settings -> AI Assistant."},
                status=status.HTTP_409_CONFLICT,
            )
        if "error" in result:
            return Response({"detail": result["error"]}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result)


class DetectionValidateSavedView(APIView):
    """
    Score a saved rule and store its fidelity.

    POST /api/detections/authored/<id>/validate/

    Persists last_fidelity so the card and list can show a real number without
    re-running the paid synthesis, until the rule is next edited.
    """

    permission_classes = [IsEnterpriseUser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ai_chat"

    def post(self, request: Request, pk) -> Response:
        """Validate the stored rule and record its score."""
        detection = get_object_or_404(_visible_to(request.user), pk=pk)
        result = _validate_sigma(request.user, detection.sigma)
        if result.get("error") == "no_connector":
            return Response(
                {"detail": "No active AI connector. Add one in Settings -> AI Assistant."},
                status=status.HTTP_409_CONFLICT,
            )
        if "error" in result:
            return Response({"detail": result["error"]}, status=status.HTTP_400_BAD_REQUEST)
        # Only the owner's validation updates the stored score.
        if result.get("evaluable", True) and "fidelity" in result and detection.owner_id == request.user.id:
            detection.last_fidelity = result["fidelity"]
            detection.save(update_fields=["last_fidelity", "updated_at"])
        return Response(result)


class DetectionExportView(APIView):
    """
    Compile a saved rule into a SIEM dialect.

    GET /api/detections/authored/<id>/export/?target=splunk&output_format=default
        &download=1
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, pk) -> Response:
        """Return the compiled query, as JSON or a downloadable file."""
        detection = get_object_or_404(_visible_to(request.user), pk=pk)

        target = (request.query_params.get("target") or "").strip().lower()
        if target not in TARGETS:
            return Response(
                {"detail": "Unknown target '%s'. Available: %s."
                           % (target or "", ", ".join(sorted(TARGETS)))},
                status=status.HTTP_400_BAD_REQUEST,
            )
        spec = TARGETS[target]
        output_format = (request.query_params.get("output_format") or "default").strip()
        if output_format not in spec.output_formats:
            return Response(
                {"detail": "Unknown output_format '%s' for %s. Available: %s."
                           % (output_format, spec.label, ", ".join(spec.output_formats))},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not detection.sigma.strip():
            return Response(
                {"detail": "This rule has no Sigma body to compile."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            result = convert(detection.sigma, target, output_format)
        except BackendUnavailable:
            return Response(
                {"detail": "%s conversion is unavailable on this server: %s is not "
                           "installed." % (spec.label, spec.install)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        if not result.ok:
            return Response(
                {"detail": "This rule could not be compiled: %s" % result.error},
                status=status.HTTP_400_BAD_REQUEST,
            )

        queries = [{"title": q.title, "query": q.query} for q in result.queries]
        skipped = [{"title": s.title, "reason": s.reason} for s in result.skipped]

        if request.query_params.get("download") in ("1", "true", "yes"):
            stem = re.sub(r"[^a-z0-9-]", "", detection.slug) or "detection"
            lines = [f"# {detection.title} -> {spec.label}", ""]
            for q in queries:
                lines += [f"# {q['title']}", q["query"], ""]
            for s in skipped:
                lines += [f"# NOT INCLUDED - {s['title']}: {s['reason']}"]
            response = HttpResponse("\n".join(lines), content_type="text/plain; charset=utf-8")
            response["Content-Disposition"] = 'attachment; filename="%s-%s.txt"' % (stem, target)
            return response

        return Response({
            "target": target, "label": spec.label, "format": output_format,
            "queries": queries, "skipped": skipped,
        })
