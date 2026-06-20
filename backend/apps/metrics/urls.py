"""
URL routing for the metrics app.

Mounted at /api/metrics/ in config/urls.py.  All routes are read-only GETs.
"""

from django.urls import path

from .views import (
    CoverageSummaryView,
    MitreCoverageView,
    NavigatorLayerView,
    PlatformCoverageView,
    TacticDetailView,
    ThreatCoverageView,
)

urlpatterns = [
    path("summary/", CoverageSummaryView.as_view(), name="metrics-summary"),
    path("mitre-coverage/", MitreCoverageView.as_view(), name="metrics-mitre-coverage"),
    path(
        "mitre-coverage/navigator-layer/",
        NavigatorLayerView.as_view(),
        name="metrics-navigator-layer",
    ),
    path(
        "mitre-coverage/<slug:shortname>/",
        TacticDetailView.as_view(),
        name="metrics-tactic-detail",
    ),
    path("threat-coverage/", ThreatCoverageView.as_view(), name="metrics-threat-coverage"),
    path("platform-coverage/", PlatformCoverageView.as_view(), name="metrics-platform-coverage"),
]
