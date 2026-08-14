"""
Views for the guardrails app.

All endpoints require IsEnterpriseUser.

GET /api/guardrails/   GuardrailListView

The response shape mirrors the detections endpoint (two named rule buckets plus
a count and a format summary) so the frontend renders both libraries the same way.
"""

import logging

from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.infrastructure.permissions import IsEnterpriseUser

from .registry import list_guardrails

logger = logging.getLogger(__name__)


class GuardrailListView(APIView):
    """
    Return the full SCP/RCP guardrail library.

    GET /api/guardrails/

    Each guardrail carries its policy document verbatim in `code`; the frontend
    renders it in a CodeBlock exactly as it renders a detection rule.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """
        Read the guardrails catalogue and split it by policy type.

        Args:
            request: DRF request.

        Returns:
            200 with scp and rcp guardrail lists.  An empty library (base
            directory unset or unreadable) returns zero counts rather than an
            error, so the UI shows its empty state instead of a failure.
        """
        guardrails = list_guardrails()

        scp = [g for g in guardrails if g["type"] == "SCP"]
        rcp = [g for g in guardrails if g["type"] == "RCP"]

        return Response({
            "scp": scp,
            "rcp": rcp,
            "totalCount": len(guardrails),
            "formats": f"SCP ({len(scp)}) · RCP ({len(rcp)})",
        })
