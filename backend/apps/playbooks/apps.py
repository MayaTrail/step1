"""App config for the playbooks app."""

from django.apps import AppConfig


class PlaybooksConfig(AppConfig):
    """Configuration for apps.playbooks."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.playbooks"
    verbose_name = "Playbooks"

    def ready(self) -> None:
        """Connect the signal that seeds a new user's example playbooks."""
        from . import signals  # noqa: F401
