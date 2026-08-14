"""
URL routing for the guardrails app.

Mounted at /api/guardrails/ in config/urls.py.

All routes require IsEnterpriseUser (enforced in each view).

GET /api/guardrails/   GuardrailListView
"""

from django.urls import path

from .views import GuardrailListView

urlpatterns = [
    path("", GuardrailListView.as_view(), name="guardrail-list"),
]
