"""
Shared helpers for the playbooks tests.

Creating a user now seeds example playbooks (apps/playbooks/signals.py), which
is right for the product and inconvenient for any test asserting an exact set
of playbooks. `make_user` creates a user with that seeding suppressed, so a
test starts from an empty library unless it is specifically testing seeding.
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest import mock

from django.contrib.auth import get_user_model


@contextmanager
def no_seeding():
    """Suppress example-playbook seeding for the duration of the block."""
    # The signal resolves seed_examples from apps.playbooks.examples at call
    # time, so patching it there is what actually intercepts the call.
    with mock.patch("apps.playbooks.examples.seed_examples", return_value=[]):
        yield


def make_user(username: str, **extra):
    """
    Create a user with an empty playbook library.

    Args:
        username: Username; the email is derived from it unless given.
        **extra: Passed through to create_user.

    Returns:
        The created user.
    """
    extra.setdefault("email", f"{username}@example.com")
    extra.setdefault("password", "pw")
    with no_seeding():
        return get_user_model().objects.create_user(username=username, **extra)
