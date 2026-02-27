"""AppConfig for the logs application."""

from django.apps import AppConfig


class LogsConfig(AppConfig):
    """Configuration class for the logs app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.logs"
    verbose_name = "Logs"
