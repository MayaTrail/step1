"""
URL routing for the threatintel app.

Mounted at /api/threat-intel/ in config/urls.py.

All routes require IsEnterpriseUser (enforced in each view).

GET /api/threat-intel/feed/        ThreatIntelFeedView
GET /api/threat-intel/sources/     ThreatIntelSourceListView
GET /api/threat-intel/advisories/  AdvisoryListView
"""

from django.urls import path

from .views import AdvisoryListView, ThreatIntelFeedView, ThreatIntelSourceListView

urlpatterns = [
    path("feed/", ThreatIntelFeedView.as_view(), name="threatintel-feed"),
    path("sources/", ThreatIntelSourceListView.as_view(), name="threatintel-sources"),
    path("advisories/", AdvisoryListView.as_view(), name="threatintel-advisories"),
]
