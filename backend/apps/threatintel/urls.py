"""
URL routing for the threatintel app.

Mounted at /api/threat-intel/ in config/urls.py.

All routes require IsEnterpriseUser (enforced in each view).

GET /api/threat-intel/feed/                    ThreatIntelFeedView
GET /api/threat-intel/sources/                 ThreatIntelSourceListView
GET /api/threat-intel/advisories/              AdvisoryListView
GET /api/threat-intel/advisories/<advisory_id>/ AdvisoryDetailView
"""

from django.urls import path

from .views import (
    AdvisoryDetailView,
    AdvisoryListView,
    ThreatIntelFeedView,
    ThreatIntelSourceListView,
)

urlpatterns = [
    path("feed/", ThreatIntelFeedView.as_view(), name="threatintel-feed"),
    path("sources/", ThreatIntelSourceListView.as_view(), name="threatintel-sources"),
    path("advisories/", AdvisoryListView.as_view(), name="threatintel-advisories"),
    path(
        "advisories/<slug:advisory_id>/",
        AdvisoryDetailView.as_view(),
        name="threatintel-advisory-detail",
    ),
]
