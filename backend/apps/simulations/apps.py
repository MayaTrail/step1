"""AppConfig for the simulations application."""

from django.apps import AppConfig


class SimulationsConfig(AppConfig):
    """Configuration class for the simulations app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.simulations"
    verbose_name = "Simulations"
