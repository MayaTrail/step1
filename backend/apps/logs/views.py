"""
Views for the logs app.

LogEntryViewSet — read-only list and retrieve for log entries.
                  Results are filtered to entries where the actor
                  is the authenticated user, or entries referencing
                  stacks or runs owned by that user.
"""

from django.db.models import Q
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import LogEntry
from .serializers import LogEntrySerializer


class LogEntryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only ViewSet for LogEntry resources.

    Returns entries relevant to the authenticated user:
    - entries where the actor is the current user
    - entries for stacks owned by the current user
    """

    serializer_class = LogEntrySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Return log entries relevant to the authenticated user.

        Returns:
            QuerySet of LogEntry objects filtered for the current user.
        """
        user = self.request.user
        return LogEntry.objects.filter(
            Q(actor=user)
            | Q(stack__owner=user)
        ).select_related("actor", "stack").distinct()
