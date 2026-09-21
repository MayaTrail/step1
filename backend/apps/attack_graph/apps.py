from django.apps import AppConfig


class AttackGraphConfig(AppConfig):
    """The Attack Graph app: Scout-powered IAM privilege-escalation scans."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.attack_graph"
    label = "attack_graph"
