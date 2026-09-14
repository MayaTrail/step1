"""
URL routing for the workflows app.

Mounted at /api/workflows/ in config/urls.py.

POST /api/workflows/alerts/<endpoint_id>/   AlertWebhookView, unauthenticated
GET  POST /api/workflows/endpoints/         AlertEndpointView
GET  POST /api/workflows/runs/              WorkflowRunListView
GET  /api/workflows/runs/<workflow_id>/     WorkflowRunDetailView

The alerts route is the only one without a JWT, because a client's SIEM cannot
hold one. It authenticates on an HMAC signature instead.
"""

from django.urls import path

from .views import (
    AlertEndpointView,
    AlertWebhookView,
    WorkflowRunDetailView,
    WorkflowRunListView,
)

urlpatterns = [
    path("alerts/<uuid:endpoint_id>/", AlertWebhookView.as_view(), name="workflow-alert-webhook"),
    path("endpoints/", AlertEndpointView.as_view(), name="workflow-endpoints"),
    path("runs/", WorkflowRunListView.as_view(), name="workflow-runs"),
    path("runs/<uuid:workflow_id>/", WorkflowRunDetailView.as_view(), name="workflow-run-detail"),
]
