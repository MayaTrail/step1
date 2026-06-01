"""Admin registration for the users app."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import EmailOTP, User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Admin panel configuration for the User model.

    Inherits all standard Django UserAdmin behaviour (list display,
    search, fieldsets for changing passwords, etc.).
    """

    list_display = ["username", "email", "is_staff", "is_active", "is_demo", "demo_used", "date_joined"]
    search_fields = ["username", "email"]
    ordering = ["-date_joined"]


@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    """Admin panel configuration for the EmailOTP model."""

    list_display = ["email", "otp", "created_at", "expires_at", "is_used", "attempts"]
    list_filter = ["is_used"]
    search_fields = ["email"]
    readonly_fields = ["otp", "created_at"]
    ordering = ["-created_at"]
