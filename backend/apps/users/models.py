"""
Custom User model for MayaTrail.

Extends Django's AbstractUser with no additional fields in v1.
Using a custom model from the start allows easy extension later
without requiring a migration that swaps the auth model.
"""

from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """
    MayaTrail user.

    Inherits all standard Django user fields (username, email, password,
    first_name, last_name, is_staff, is_active, date_joined, etc.).
    No extra fields are added in v1.
    """

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
        db_table = "users"

    def __str__(self) -> str:
        """Return the username as the string representation."""
        return self.username
