"""Admin registration for the users app."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Admin panel configuration for the User model.

    Inherits all standard Django UserAdmin behaviour (list display,
    search, fieldsets for changing passwords, etc.).
    """

    list_display = ["username", "email", "is_staff", "is_active", "date_joined"]
    search_fields = ["username", "email"]
    ordering = ["-date_joined"]
