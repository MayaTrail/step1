"""
Django admin registration for the emulations app.
"""

from django.contrib import admin

from .models import EmulationRun


@admin.register(EmulationRun)
class EmulationRunAdmin(admin.ModelAdmin):
    """Admin view for EmulationRun records."""

    list_display = (
        "id",
        "emulation_type",
        "status",
        "phase_current",
        "phase_total",
        "triggered_by",
        "started_at",
        "completed_at",
    )
    list_filter = ("status", "emulation_type")
    search_fields = ("emulation_type", "triggered_by__username")
    readonly_fields = ("id", "created_at", "started_at", "completed_at")
    ordering = ("-created_at",)
