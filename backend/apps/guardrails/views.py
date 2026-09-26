"""
Views for the guardrails app.

GET /api/guardrails/        GuardrailListView
GET /api/guardrails/<id>/   GuardrailDetailView
GET /api/guardrails/emulation/<emulation_type>/   EmulationGuardrailsView

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

from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.emulations.registry import get_emulation
from apps.infrastructure.permissions import IsEnterpriseUser

from .matching import analyse
from .registry import get_guardrail, list_guardrails

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


class EmulationGuardrailsView(APIView):
    """
    Which catalogue policies would interrupt one emulation's attack.

    GET /api/guardrails/emulation/<emulation_type>/

    Enterprise-gated, unlike the rest of this app. The catalogue itself is
    public AWS samples and reads nothing from the user's account, but this
    names an emulation's phases and the actions each performs, which is our
    content rather than AWS's.

    Every verdict means "if you deployed this policy". The library is a
    catalogue, not a reading of the caller's Organization, and the response
    says so in `basis` so a client cannot render it as deployed protection.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, emulation_type: str) -> Response:
        """
        Analyse one emulation against the whole guardrail catalogue.

        Args:
            request:        DRF request.
            emulation_type: Registry name of the emulation.

        Returns:
            200 with the analysis, or 404 when the emulation is unknown. An
            emulation whose phases declare no actions returns 200 with
            `analysed: false`: that is "nobody has mapped this one yet", not
            "no policy can stop it", and the two must not look alike.
        """
        entry = get_emulation(emulation_type)
        if entry is None:
            return Response(
                {"detail": f"Unknown emulation '{emulation_type}'."}, status=404
            )

        manifest = entry.get("manifest", entry) or {}
        result = analyse(manifest.get("attack_path") or [], list_guardrails())
        result["emulationType"] = emulation_type
        result["displayName"] = manifest.get("display_name", emulation_type)
        result["basis"] = "catalogue"
        return Response(result)
