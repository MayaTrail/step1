"""
Seed a new user's starting playbooks.

Runs on user creation rather than on first page load, so the examples are
already there the first time the Playbooks page is opened, and so nothing has
to be created as a side effect of a GET.

Seeding is best-effort. A user must be able to sign up even if the emulation
packages are not mounted or the database is momentarily unhappy, so every
failure here is logged and swallowed - the cost is a user with an empty
library, which `seed_example_playbooks` can fix later.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)


@receiver(post_save, sender=settings.AUTH_USER_MODEL, dispatch_uid="playbooks.seed_examples")
def seed_playbook_examples(sender, instance, created, **kwargs) -> None:
    """Give a newly created user their two example playbooks."""
    if not created:
        return

    # Imported here rather than at module scope: this module is loaded from
    # AppConfig.ready(), which runs before the app registry is fully populated.
    from .examples import seed_examples

    try:
        seeded = seed_examples(instance)
    except Exception:  # noqa: BLE001 - signup must not fail over an example
        logger.exception("Could not seed example playbooks for %s", instance)
        return

    if seeded:
        logger.info("Seeded %d example playbook(s) for %s", len(seeded), instance)
