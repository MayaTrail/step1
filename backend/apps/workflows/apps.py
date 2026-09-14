"""AppConfig for the workflows application."""

from django.apps import AppConfig


class WorkflowsConfig(AppConfig):
    """
    Configuration class for the workflows app.

    A workflow is one end-to-end validation of a single emulation against the
    detections a client already runs: deploy, attack, wait for their SIEM to
    report what it caught, then score the difference. The waiting is why this is
    a persisted record rather than a request: alert latency is measured in tens
    of minutes, so the user must be able to leave the page.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.workflows"
    label = "workflows"
    verbose_name = "Workflows"
