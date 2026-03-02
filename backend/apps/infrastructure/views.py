"""
Views for the infrastructure app.

StackViewSet provides CRUD operations on Stack objects plus four
custom actions:

    POST /api/stacks/{id}/deploy/   — enqueue a deploy_stack Celery task
    POST /api/stacks/{id}/destroy/  — enqueue a destroy_stack Celery task
    POST /api/stacks/{id}/refresh/  — enqueue a refresh_stack Celery task
    POST /api/stacks/{id}/preview/  — enqueue a preview_stack Celery task
"""

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from .models import Stack
from .serializers import StackSerializer
from .tasks import deploy_stack, destroy_stack, preview_stack, refresh_stack

# Statuses that indicate an operation is already in progress.
_BUSY_STATUSES = (
    Stack.Status.DEPLOYING,
    Stack.Status.DESTROYING,
    Stack.Status.REFRESHING,
)


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

    # Helper

    def _check_busy(self, stack: Stack) -> Response | None:
        """
        Return a 409 Conflict response if the stack is currently busy,
        or None if the stack is available for a new operation.

        Args:
            stack: The Stack instance to check.

        Returns:
            Response with 409 status, or None.
        """
        if stack.status in _BUSY_STATUSES:
            return Response(
                {"detail": f"Stack is currently {stack.status}. Wait for it to finish."},
                status=status.HTTP_409_CONFLICT,
            )
        return None

    # Custom actions

    @action(detail=True, methods=["post"], url_path="deploy")
    def deploy(self, request: Request, pk: str = None) -> Response:
        """
        Enqueue a Celery task to deploy this stack via a Pulumi container
        running `pulumi up --yes`.

        POST /api/stacks/{id}/deploy/

        Args:
            request: DRF request (body ignored).
            pk: UUID primary key of the Stack.

        Returns:
            202 Accepted with stack data and task_id, or 409 if the stack
            is already in a busy state.
        """
        stack = self.get_object()

        conflict = self._check_busy(stack)
        if conflict:
            return conflict

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
        Enqueue a Celery task to destroy this stack via a Pulumi container
        running `pulumi destroy --yes`.

        POST /api/stacks/{id}/destroy/

        Args:
            request: DRF request (body ignored).
            pk: UUID primary key of the Stack.

        Returns:
            202 Accepted with stack data and task_id, or 409 if the stack
            is already in a busy state.
        """
        stack = self.get_object()

        conflict = self._check_busy(stack)
        if conflict:
            return conflict

        stack.status = Stack.Status.DESTROYING
        stack.save(update_fields=["status", "updated_at"])

        task = destroy_stack.delay(str(stack.id))

        return Response(
            {"stack": StackSerializer(stack).data, "task_id": task.id},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["post"], url_path="refresh")
    def refresh(self, request: Request, pk: str = None) -> Response:
        """
        Enqueue a Celery task to refresh this stack via a Pulumi container
        running `pulumi refresh --yes`.

        Refresh syncs the Pulumi state with the actual cloud resources
        without making any changes. Useful after manual changes in AWS.

        POST /api/stacks/{id}/refresh/

        Args:
            request: DRF request (body ignored).
            pk: UUID primary key of the Stack.

        Returns:
            202 Accepted with stack data and task_id, or 409 if the stack
            is already in a busy state.
        """
        stack = self.get_object()

        conflict = self._check_busy(stack)
        if conflict:
            return conflict

        stack.status = Stack.Status.REFRESHING
        stack.save(update_fields=["status", "updated_at"])

        task = refresh_stack.delay(str(stack.id))

        return Response(
            {"stack": StackSerializer(stack).data, "task_id": task.id},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["post"], url_path="preview")
    def preview(self, request: Request, pk: str = None) -> Response:
        """
        Enqueue a Celery task to preview changes for this stack via a
        Pulumi container running `pulumi preview`.

        Preview is a read-only operation that shows what changes would be
        made without actually deploying. The stack status is not modified.

        POST /api/stacks/{id}/preview/

        Args:
            request: DRF request (body ignored).
            pk: UUID primary key of the Stack.

        Returns:
            202 Accepted with stack data and task_id, or 409 if the stack
            is already in a busy state.
        """
        stack = self.get_object()

        conflict = self._check_busy(stack)
        if conflict:
            return conflict

        task = preview_stack.delay(str(stack.id))

        return Response(
            {"stack": StackSerializer(stack).data, "task_id": task.id},
            status=status.HTTP_202_ACCEPTED,
        )
