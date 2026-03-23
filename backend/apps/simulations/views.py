"""
Views for the simulations app.

SimulationRunViewSet provides:
    GET  /api/simulations/       — list all runs for the authenticated user
    GET  /api/simulations/{id}/  — retrieve a single run (for status polling)
    POST /api/simulations/run/   — trigger a new simulation run
"""

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from apps.infrastructure.models import Stack

from .models import SimulationRun
from .serializers import SimulationRunSerializer, TriggerSimulationSerializer
from .tasks import run_simulation


class SimulationRunViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for SimulationRun resources.

    Read-only by default (list + retrieve).  The only write operation is
    the /run/ custom action, which enqueues a Celery task.
    """

    serializer_class = SimulationRunSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Return simulation runs triggered by the authenticated user.

        Returns:
            QuerySet of SimulationRun objects belonging to request.user.
        """
        return SimulationRun.objects.filter(triggered_by=self.request.user).select_related(
            "stack", "triggered_by"
        )

    @action(detail=False, methods=["get"], url_path="modules")
    def modules(self, request: Request) -> Response:
        """
        List all available simulation modules.

        GET /api/simulations/modules/

        Returns:
            200 with a list of module names and descriptions.
        """
        return Response(SimulationRun.get_modules(), status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="run")
    def run(self, request: Request) -> Response:
        """
        Trigger a new simulation run.

        POST /api/simulations/run/
        Body: { "stack_id": "<uuid>", "module_id": <int> }

        Validates that the referenced Stack belongs to the authenticated user
        and is in READY status before enqueuing the task.

        Args:
            request: DRF request with stack_id and module_id in the body.

        Returns:
            201 Created with the SimulationRun record and Celery task_id,
            or 400/404/409 on validation failure.
        """
        input_serializer = TriggerSimulationSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(input_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        stack_id = input_serializer.validated_data["stack_id"]
        module_id = input_serializer.validated_data["module_id"]

        # Resolve numeric ID to module name.
        module_info = SimulationRun.get_module_by_id()[module_id]
        module_name = module_info["name"]

        try:
            stack = Stack.objects.get(id=stack_id, owner=request.user)
        except Stack.DoesNotExist:
            return Response(
                {"detail": "Stack not found or does not belong to you."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if stack.status != Stack.Status.READY:
            return Response(
                {"detail": f"Stack must be in READY state to run simulations (current: {stack.status})."},
                status=status.HTTP_409_CONFLICT,
            )

        run = SimulationRun.objects.create(
            stack=stack,
            module=module_name,
            triggered_by=request.user,
        )

        task = run_simulation.delay(str(run.id))

        return Response(
            {"run": SimulationRunSerializer(run).data, "task_id": task.id},
            status=status.HTTP_201_CREATED,
        )

