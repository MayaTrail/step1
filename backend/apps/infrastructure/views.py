"""
Views for the infrastructure app.

StackViewSet is read-only: it lists a user's stacks, returns one, and reports
a running deploy's progress.

    GET /api/stacks/                - the caller's stacks
    GET /api/stacks/{id}/           - one stack
    GET /api/stacks/{id}/progress/  - live deploy progress (enterprise only)

Stacks are created, attacked and destroyed through /api/emulations/, which
runs Pulumi as the user's connected role against the Pulumi state kept in the
user's own account.
"""

from celery.result import AsyncResult
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from . import lifecycle
from .models import Stack
from .permissions import IsEnterpriseUser
from .serializers import StackSerializer


class StackViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only ViewSet for Stack resources.

    All endpoints require a valid JWT, and users see only their own stacks.

    There are no write actions here. The generic deploy, destroy, refresh and
    preview actions this ViewSet once had read Pulumi state from a shared
    bucket rather than the user's own, so a destroy found no state, deleted
    the record and left every AWS resource running. Deleting only the row
    would orphan the resources the same way. Tearing a stack down goes through
    POST /api/emulations/{id}/destroy/, which runs `pulumi destroy` first and
    deletes the record only after it succeeds.
    """

    serializer_class = StackSerializer

    def get_serializer_context(self):
        """
        Add the per-emulation phase baselines the lifecycle track compares to.

        Computed once for the whole response rather than per stack. The list
        endpoint returns every stack the user owns, and deriving a baseline
        inside the serializer would run one query per card.

        The samples come from the user's own finished stacks of the same
        emulation, so "slow" means slow for this emulation in this account
        rather than against a figure someone once wrote in a MANIFEST.

        Returns:
            The default context plus `phase_baselines`, keyed by emulation type.
        """
        context = super().get_serializer_context()
        context["phase_baselines"] = self._phase_baselines()
        return context

    def _phase_baselines(self) -> dict:
        """
        Build median phase durations per emulation type, for this owner.

        Returns:
            {emulation_type: {status: median_seconds}}. An emulation with too
            few finished runs is absent, and the UI then shows elapsed time
            without calling anything slow.
        """
        histories: dict[str, list] = {}
        rows = (
            Stack.objects.filter(owner=self.request.user)
            .exclude(status_history=[])
            .values_list("emulation_type", "status_history")
        )
        for emulation_type, history in rows:
            histories.setdefault(emulation_type, []).append(history)

        return {
            emulation_type: lifecycle.baselines(entries)
            for emulation_type, entries in histories.items()
        }

    def get_queryset(self):
        """
        Return only stacks owned by the currently authenticated user.

        Returns:
            QuerySet of Stack objects belonging to request.user.
        """
        return Stack.objects.filter(owner=self.request.user)

    def get_permissions(self):
        """
        Return the appropriate permission classes based on the action.

        list and retrieve are open to every authenticated user; progress
        requires IsEnterpriseUser, as it always has.

        Returns:
            List of instantiated permission classes.
        """
        if self.action in ("list", "retrieve"):
            return [IsAuthenticated()]
        return [IsEnterpriseUser()]

    @action(detail=True, methods=["get"], url_path="progress")
    def progress(self, request: Request, pk: str = None) -> Response:
        """
        Return live deployment progress for a stack currently being deployed.

        Reads Celery task state from the Redis result backend using the
        task_id stored on the Stack record.  The deploy_emulation_stack task
        calls self.update_state(state='PROGRESS', meta={...}) every 2 Pulumi
        log lines, so this endpoint stays current within a few seconds.

        GET /api/stacks/{id}/progress/

        Response shape:
            {
                "stack_id":          "<uuid>",
                "status":            "<stack status>",
                "resources_created": 7,
                "total_resources":   19,
                "percentage":        36,
                "recent_logs":       ["...", "..."]
            }

        Falls back gracefully when no task is running:
          - DEPLOYING with no task_id yet  → percentage 0, empty logs
          - Terminal status (READY / FAILED / DESTROYED) → percentage 100 / 0

        Args:
            request: DRF request.
            pk:      UUID primary key of the Stack.

        Returns:
            200 with progress data.
        """
        stack = self.get_object()

        base = {
            "stack_id": str(stack.id),
            "status": stack.status,
            "resources_created": 0,
            "total_resources": 0,
            "percentage": 0,
            "recent_logs": [],
        }

        # Terminal states — deployment is done (success or failure).
        if stack.status in (
            Stack.Status.READY,
            Stack.Status.EC2_BOOTING,
            Stack.Status.READY_FOR_ATTACK,
            Stack.Status.ATTACKING,
            Stack.Status.ATTACK_COMPLETE,
            Stack.Status.DESTROYED,
        ):
            base["percentage"] = 100
            return Response(base)

        if stack.status == Stack.Status.FAILED:
            base["percentage"] = 0
            return Response(base)

        # No task id stored yet — deploy was just enqueued.
        if not stack.task_id:
            return Response(base)

        result = AsyncResult(stack.task_id)

        if result.state == "PROGRESS" and isinstance(result.info, dict):
            info = result.info
            base["resources_created"] = info.get("resources_created", 0)
            base["total_resources"] = info.get("total_resources", 0)
            base["percentage"] = info.get("percentage", 0)
            base["recent_logs"] = info.get("recent_logs", [])
        elif result.state == "SUCCESS":
            base["percentage"] = 100

        return Response(base)
