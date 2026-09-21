"""
URL routing for the attack_graph app.

Mounted at /api/attack-graph/ in config/urls.py.

POST /api/attack-graph/scan/            ScoutScanTriggerView
GET  /api/attack-graph/scan/            ScoutScanListView
GET  /api/attack-graph/scan/<scan_id>/  ScoutScanDetailView
"""

from django.urls import path

from .views import ScoutScanDetailView, ScoutScanListView, ScoutScanTriggerView

urlpatterns = [
    path("scan/", ScoutScanTriggerView.as_view(), name="attack-graph-scan-trigger"),
    path("scan/list/", ScoutScanListView.as_view(), name="attack-graph-scan-list"),
    path("scan/<uuid:scan_id>/", ScoutScanDetailView.as_view(), name="attack-graph-scan-detail"),
]
