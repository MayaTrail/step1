"""
Custom User model for MayaTrail.

Extends Django's AbstractUser with a unique email constraint.
Using a custom model from the start allows easy extension later
without requiring a migration that swaps the auth model.
"""

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """
    MayaTrail user.

    Inherits all standard Django user fields (username, email, password,
    first_name, last_name, is_staff, is_active, date_joined, etc.).

    The email field is overridden to enforce uniqueness at the database
    level — AbstractUser does not set unique=True by default.
    """

    email = models.EmailField("email address", unique=True, blank=False)

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
        db_table = "users"

    def __str__(self) -> str:
        """Return the username as the string representation."""
        return self.username

