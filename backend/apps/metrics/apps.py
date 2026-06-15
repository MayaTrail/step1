"""AppConfig for the metrics application."""

from django.apps import AppConfig


class MetricsConfig(AppConfig):
    """
    Configuration class for the metrics app.

    The metrics app is read-only: it owns no models.  It exposes aggregation
    endpoints that fold over the emulation registry, EmulationRun rows, the
    LogEntry audit trail, and Stack records to produce the security-focused
    figures rendered by the dashboard.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.metrics"
    verbose_name = "Metrics"
