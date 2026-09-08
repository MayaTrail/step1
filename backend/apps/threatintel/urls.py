"""
URL routing for the threatintel app.

Mounted at /api/threat-intel/ in config/urls.py.

All routes require IsAuthenticated (enforced in each view).

GET /api/threat-intel/feed/      ThreatFeedView
GET /api/threat-intel/sources/   ThreatFeedSourceListView
"""

from django.urls import path

from .views import ThreatFeedSourceListView, ThreatFeedView

urlpatterns = [
    path("feed/", ThreatFeedView.as_view(), name="threatintel-feed"),
    path("sources/", ThreatFeedSourceListView.as_view(), name="threatintel-sources"),
]
