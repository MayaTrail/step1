"""Admin registration for the logs app."""

from django.contrib import admin

from .models import LogEntry


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    """
    Admin panel configuration for the LogEntry model.

    Log entries are immutable; no add or delete permissions are granted
    through the admin.  All fields are read-only.
    """

    list_display = ["event", "level", "actor", "stack", "run", "timestamp"]
    list_filter = ["level", "event"]
    search_fields = ["message", "actor__username", "stack__name"]
    readonly_fields = ["id", "level", "event", "message", "actor", "stack", "run", "timestamp"]
    ordering = ["-timestamp"]

    def has_add_permission(self, request) -> bool:
        """Prevent manual creation of log entries via admin."""
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        """Prevent deletion of log entries via admin."""
        return False
