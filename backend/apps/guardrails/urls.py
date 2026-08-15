"""
URL routing for the guardrails app.

Mounted at /api/guardrails/ in config/urls.py.

All routes require IsAuthenticated (enforced in each view).

GET /api/guardrails/                     GuardrailListView
GET /api/guardrails/<guardrail_id>/      GuardrailDetailView
"""

from django.urls import path

from .views import GuardrailDetailView, GuardrailListView

urlpatterns = [
    path("", GuardrailListView.as_view(), name="guardrail-list"),
    path("<slug:guardrail_id>/", GuardrailDetailView.as_view(), name="guardrail-detail"),
]
