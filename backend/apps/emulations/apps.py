"""
App configuration for the emulations Django app.
"""

from django.apps import AppConfig


class EmulationsConfig(AppConfig):
    """Configuration for the emulations app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.emulations"
    verbose_name = "Emulations"
