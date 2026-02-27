"""AppConfig for the infrastructure application."""

from django.apps import AppConfig


class InfrastructureConfig(AppConfig):
    """Configuration class for the infrastructure app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.infrastructure"
    verbose_name = "Infrastructure"
