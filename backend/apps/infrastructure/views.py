"""
Views for the infrastructure app.

StackViewSet provides CRUD operations on Stack objects plus two
custom actions:

    POST /api/stacks/{id}/deploy/   — enqueue a deploy_stack Celery task
    POST /api/stacks/{id}/destroy/  — enqueue a destroy_stack Celery task
"""

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from .models import Stack
from .serializers import StackSerializer
from .tasks import deploy_stack, destroy_stack


class StackViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Stack resources.

    All endpoints require a valid JWT.  Users can only see their own stacks
    (queryset is filtered by owner).
    """

    serializer_class = StackSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "post", "delete", "head", "options"]

    def get_queryset(self):
        """
        Return only stacks owned by the currently authenticated user.

        Returns:
            QuerySet of Stack objects belonging to request.user.
        """
        return Stack.objects.filter(owner=self.request.user)

    def perform_create(self, serializer: StackSerializer) -> None:
        """
        Persist a new Stack with the current user set as owner.

        Args:
            serializer: Validated StackSerializer ready to be saved.
        """
        serializer.save(owner=self.request.user)

    @action(detail=True, methods=["post"], url_path="deploy")
    def deploy(self, request: Request, pk: str = None) -> Response:
        """
        Enqueue a Celery task to run `pulumi up` for this stack.

        POST /api/stacks/{id}/deploy/

        Args:
            request: DRF request (body ignored).
            pk: UUID primary key of the Stack.

        Returns:
            202 Accepted with stack data and task_id, or 409 if the stack
            is already in a non-terminal state.
        """
        stack = self.get_object()

        if stack.status in (Stack.Status.DEPLOYING, Stack.Status.DESTROYING):
            return Response(
                {"detail": f"Stack is currently {stack.status}. Wait for it to finish."},
                status=status.HTTP_409_CONFLICT,
            )

        stack.status = Stack.Status.DEPLOYING
        stack.save(update_fields=["status", "updated_at"])

        task = deploy_stack.delay(str(stack.id))

        return Response(
            {"stack": StackSerializer(stack).data, "task_id": task.id},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["post"], url_path="destroy")
    def destroy_stack(self, request: Request, pk: str = None) -> Response:
        """
        Enqueue a Celery task to run `pulumi destroy` for this stack.

        POST /api/stacks/{id}/destroy/

        Args:
            request: DRF request (body ignored).
            pk: UUID primary key of the Stack.

        Returns:
            202 Accepted with stack data and task_id, or 409 if the stack
            is already in a non-terminal state.
        """
        stack = self.get_object()

        if stack.status in (Stack.Status.DEPLOYING, Stack.Status.DESTROYING):
            return Response(
                {"detail": f"Stack is currently {stack.status}. Wait for it to finish."},
                status=status.HTTP_409_CONFLICT,
            )

        stack.status = Stack.Status.DESTROYING
        stack.save(update_fields=["status", "updated_at"])

        task = destroy_stack.delay(str(stack.id))

        return Response(
            {"stack": StackSerializer(stack).data, "task_id": task.id},
            status=status.HTTP_202_ACCEPTED,
        )
