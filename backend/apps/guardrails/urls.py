"""
URL routing for the guardrails app.

Mounted at /api/guardrails/ in config/urls.py.

All routes require IsAuthenticated (enforced in each view).

GET  /api/guardrails/                                   GuardrailListView
GET  /api/guardrails/<guardrail_id>/                    GuardrailDetailView
POST /api/guardrails/emulation/<emulation_type>/check/  EmulationAccountCheckView
"""

from django.urls import path

from .views import (
    EmulationAccountCheckView,
    EmulationGuardrailsView,
    GuardrailDetailView,
    GuardrailListView,
)

urlpatterns = [
    # Before the <str:guardrail_id> route below, which would otherwise match
    # the literal "emulation" as a catalogue id. The check route comes first
    # because its path is a prefix of the analysis route's.
    path(
        "emulation/<str:emulation_type>/check/",
        EmulationAccountCheckView.as_view(),
        name="emulation-account-check",
    ),
    path(
        "emulation/<str:emulation_type>/",
        EmulationGuardrailsView.as_view(),
        name="emulation-guardrails",
    ),
    path("", GuardrailListView.as_view(), name="guardrail-list"),
    path("<slug:guardrail_id>/", GuardrailDetailView.as_view(), name="guardrail-detail"),
]
