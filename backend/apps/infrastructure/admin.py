"""Admin registration for the infrastructure app."""

from django.contrib import admin

from .models import Stack


@admin.register(Stack)
class StackAdmin(admin.ModelAdmin):
    """
    Admin panel configuration for the Stack model.

    Displays key lifecycle fields and allows filtering by status.
    The outputs JSONField is shown in the detail view but excluded from
    the list to keep it readable.
    """

    list_display = ["name", "region", "status", "owner", "created_at", "updated_at"]
    list_filter = ["status", "region"]
    search_fields = ["name", "owner__username"]
    readonly_fields = ["id", "created_at", "updated_at"]
    ordering = ["-created_at"]
