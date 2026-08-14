"""
App configuration for the guardrails Django app.
"""

from django.apps import AppConfig


class GuardrailsConfig(AppConfig):
    """Configuration for the guardrails app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.guardrails"
    verbose_name = "Guardrails"
