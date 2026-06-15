"""
Read-only API views for the dashboard metrics.

Each view is a thin wrapper that delegates to a pure function in
apps.metrics.aggregations and returns the result verbatim.  The figures are
platform-wide capability/coverage metrics (not per-user or AWS-account scoped),
so they require only an authenticated user — this lets evaluator/demo users see
what the platform can emulate, which is the explicit goal of the redesign.
"""

from __future__ import annotations

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from . import aggregations


class CoverageSummaryView(APIView):
    """
    GET /api/metrics/summary

    The four KPI-card figures: APT coverage score, emulations executed, total
    detection rules, and the most recent successful run timestamp.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Return the KPI summary payload."""
        return Response(aggregations.coverage_summary())


def _coverage_filters(request: Request) -> dict[str, str | None]:
    """Extract the optional platform / actor / emulation coverage filters."""
    return {
        "platform": request.query_params.get("platform"),
        "actor": request.query_params.get("actor"),
        "emulation": request.query_params.get("emulation"),
    }


class MitreCoverageView(APIView):
    """
    GET /api/metrics/mitre-coverage[?platform=&actor=&emulation=]

    The redesigned coverage payload: executive summary, per-tactic coverage
    (status + percentage), derived insights, and filter options.  Coverage is
    computed over the emulation subset matching the filters.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Return the MITRE coverage summary payload, optionally filtered."""
        return Response(aggregations.mitre_coverage(**_coverage_filters(request)))


class TacticDetailView(APIView):
    """
    GET /api/metrics/mitre-coverage/<shortname>/[?platform=&actor=&emulation=]

    Drill-down for a single tactic: covered and missing techniques, related
    emulations/playbooks/detections, and a recommendation.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request, shortname: str) -> Response:
        """Return the tactic drill-down payload, or 404 for an unknown tactic."""
        detail = aggregations.tactic_detail(shortname, **_coverage_filters(request))
        if detail is None:
            return Response(
                {"detail": f"Unknown ATT&CK tactic '{shortname}'."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(detail)


class NavigatorLayerView(APIView):
    """
    GET /api/metrics/mitre-coverage/navigator-layer/

    A MITRE ATT&CK Navigator layer (format 4.5) preloaded with Mayatrail's
    covered techniques, for users who want to explore coverage in the full
    official matrix.  Served as a JSON attachment so the browser downloads a
    .json file ready to load via the Navigator's "Open Existing Layer" flow.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Return the Navigator layer as a downloadable JSON attachment."""
        response = Response(aggregations.navigator_layer())
        response["Content-Disposition"] = (
            'attachment; filename="mayatrail-attack-navigator.json"'
        )
        return response


class ThreatCoverageView(APIView):
    """
    GET /api/metrics/threat-coverage

    Per-emulation (per threat-actor campaign) coverage rows for the progress
    bars, sorted by coverage descending.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Return the threat-coverage payload."""
        return Response(aggregations.threat_coverage())


class PlatformCoverageView(APIView):
    """
    GET /api/metrics/platform-coverage[?platform=aws]

    Content-depth counts (emulations, playbooks, detections) per platform.
    Without the query parameter every supported platform is returned (zeros for
    empty ones); with it the result is restricted to the named platform.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Return the platform-coverage payload, optionally filtered."""
        platform = request.query_params.get("platform")
        return Response(aggregations.platform_coverage(platform))
