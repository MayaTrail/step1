"""Admin registration for the simulations app."""

from django.contrib import admin

from .models import SimulationRun


@admin.register(SimulationRun)
class SimulationRunAdmin(admin.ModelAdmin):
    """
    Admin panel configuration for the SimulationRun model.

    Stdout and stderr are shown in the detail view only, not the list,
    to keep the changelist readable.
    """

    list_display = ["module", "stack", "status", "triggered_by", "created_at", "completed_at"]
    list_filter = ["status", "module"]
    search_fields = ["module", "stack__name", "triggered_by__username"]
    readonly_fields = ["id", "created_at", "started_at", "completed_at"]
    ordering = ["-created_at"]
