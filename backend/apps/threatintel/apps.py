"""AppConfig for the threatintel application."""

from django.apps import AppConfig


class ThreatIntelConfig(AppConfig):
    """
    Configuration class for the threatintel app.

    The app is read-only and owns no models: a daily Celery task writes one
    JSON document to THREATINTEL_DIR and the views read it back. Feed items are
    matched against the emulation registry at ingest time, so the API can link
    a post to a runnable emulation without querying anything per request.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.threatintel"
    label = "threatintel"
    verbose_name = "Threat Feed"
