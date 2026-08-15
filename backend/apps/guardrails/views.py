"""
Views for the guardrails app.

GET /api/guardrails/        GuardrailListView
GET /api/guardrails/<id>/   GuardrailDetailView

Both endpoints require IsAuthenticated rather than IsEnterpriseUser.  The
library is a catalogue of published AWS sample policies: it reads nothing from
the user's account and exposes no stack, IAM or resource metadata, so a
verified AWS connection is not a meaningful gate on it.

The list response mirrors the detections endpoint (a named rule bucket plus a
count and a format summary) so the frontend renders both libraries the same
way.  It omits each policy document, which the list never displays and which
would otherwise make the response roughly three times its size; the detail
endpoint serves the document for the one policy a reader opened.
"""

import logging

from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .registry import get_guardrail, list_guardrails

logger = logging.getLogger(__name__)

# Catalogue keys the list response carries. "code" and "file" are detail-only.
_SUMMARY_FIELDS = ("id", "type", "purpose", "services", "source")


def _summary(guardrail: dict) -> dict:
    """
    Reduce a catalogue entry to the fields the library list renders.

    Args:
        guardrail: A catalogue dict from the registry.

    Returns:
        The entry without its policy document.
    """
    return {field: guardrail[field] for field in _SUMMARY_FIELDS}


class GuardrailListView(APIView):
    """
    Return the guardrail library index.

    GET /api/guardrails/

    Policy documents are excluded; fetch one from the detail endpoint.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        Read the catalogue and summarise it by policy type.

        Args:
            request: DRF request.

        Returns:
            200 with the guardrail list and per-type counts.  An empty library
            (base directory unset or unreadable) returns zero counts rather
            than an error, so the UI shows its empty state instead of a
            failure.
        """
        guardrails = list_guardrails()
        scp_count = sum(1 for g in guardrails if g["type"] == "SCP")
        rcp_count = sum(1 for g in guardrails if g["type"] == "RCP")

        return Response({
            "guardrails": [_summary(g) for g in guardrails],
            "totalCount": len(guardrails),
            "formats": f"SCP ({scp_count}) · RCP ({rcp_count})",
        })


class GuardrailDetailView(APIView):
    """
    Return one guardrail with its policy document.

    GET /api/guardrails/<guardrail_id>/

    The frontend renders `code` in a CodeBlock exactly as it renders a
    detection rule.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request, guardrail_id: str) -> Response:
        """
        Read a single guardrail by catalogue id.

        Args:
            request:      DRF request.
            guardrail_id: URL path parameter, the catalogue slug.

        Returns:
            200 with the guardrail and its policy document, or 404 if no
            guardrail carries that id.
        """
        guardrail = get_guardrail(guardrail_id)
        if guardrail is None:
            return Response({"detail": "Guardrail not found."}, status=404)

        return Response(guardrail)
