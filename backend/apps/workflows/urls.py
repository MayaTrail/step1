"""
URL routing for the workflows app.

Mounted at /api/workflows/ in config/urls.py.

POST /api/workflows/alerts/<endpoint_id>/   AlertWebhookView, unauthenticated
GET  POST /api/workflows/endpoints/         AlertEndpointView
GET  DELETE /api/workflows/endpoints/<id>/  AlertEndpointDetailView
GET  POST /api/workflows/endpoints/<id>/secret/  AlertEndpointSecretView
GET  POST /api/workflows/runs/              WorkflowRunListView
GET  DELETE /api/workflows/runs/<workflow_id>/   WorkflowRunDetailView

The alerts route is the only one without a JWT, because a client's SIEM cannot
hold one. It authenticates on an HMAC signature instead.
"""

from django.urls import path

from .views import (
    AlertEndpointDetailView,
    AlertEndpointSecretView,
    AlertEndpointView,
    AlertWebhookView,
    WorkflowRunDetailView,
    WorkflowRunListView,
)

urlpatterns = [
    path("alerts/<uuid:endpoint_id>/", AlertWebhookView.as_view(), name="workflow-alert-webhook"),
    path("endpoints/", AlertEndpointView.as_view(), name="workflow-endpoints"),
    path(
        "endpoints/<uuid:endpoint_id>/",
        AlertEndpointDetailView.as_view(),
        name="workflow-endpoint-detail",
    ),
    path(
        "endpoints/<uuid:endpoint_id>/secret/",
        AlertEndpointSecretView.as_view(),
        name="workflow-endpoint-secret",
    ),
    path("runs/", WorkflowRunListView.as_view(), name="workflow-runs"),
    path("runs/<uuid:workflow_id>/", WorkflowRunDetailView.as_view(), name="workflow-run-detail"),
]
