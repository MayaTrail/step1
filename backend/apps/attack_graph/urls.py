"""
URL routing for the attack_graph app.

Mounted at /api/attack-graph/ in config/urls.py.

POST /api/attack-graph/scan/                              ScoutScanTriggerView
GET  /api/attack-graph/scan/list/                          ScoutScanListView
GET  /api/attack-graph/scan/<scan_id>/                     ScoutScanDetailView
GET  /api/attack-graph/scan/<scan_id>/graph/nodes/          ScoutScanGraphNodesView
GET  /api/attack-graph/scan/<scan_id>/graph/entity/         ScoutScanGraphEntityView
GET  /api/attack-graph/scan/<scan_id>/graph/path/           ScoutScanGraphPathView
"""

from django.urls import path

from .views import (
    ScoutScanDetailView,
    ScoutScanGraphEntityView,
    ScoutScanGraphNodesView,
    ScoutScanGraphPathView,
    ScoutScanListView,
    ScoutScanTriggerView,
)

urlpatterns = [
    path("scan/", ScoutScanTriggerView.as_view(), name="attack-graph-scan-trigger"),
    path("scan/list/", ScoutScanListView.as_view(), name="attack-graph-scan-list"),
    path("scan/<uuid:scan_id>/", ScoutScanDetailView.as_view(), name="attack-graph-scan-detail"),
    # Node ids ride as query parameters, never path segments: they contain "/"
    # and are not always ARNs (a SERVICE node is "lambda.amazonaws.com",
    # PUBLIC is "*").
    path("scan/<uuid:scan_id>/graph/nodes/", ScoutScanGraphNodesView.as_view(),
         name="attack-graph-graph-nodes"),
    path("scan/<uuid:scan_id>/graph/entity/", ScoutScanGraphEntityView.as_view(),
         name="attack-graph-graph-entity"),
    path("scan/<uuid:scan_id>/graph/path/", ScoutScanGraphPathView.as_view(),
         name="attack-graph-graph-path"),
]
