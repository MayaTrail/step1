"""
Views for the infrastructure app.

StackViewSet provides CRUD operations on Stack objects plus five
custom actions:

    POST /api/stacks/{id}/deploy/        — enqueue a deploy_stack Celery task (enterprise only)
    POST /api/stacks/{id}/destroy/       — enqueue a destroy_stack Celery task (enterprise only)
    POST /api/stacks/{id}/force-destroy/ — force-destroy regardless of busy status (enterprise only)
    POST /api/stacks/{id}/refresh/       — enqueue a refresh_stack Celery task (enterprise only)
    POST /api/stacks/{id}/preview/       — enqueue a preview_stack Celery task (enterprise only)

Permission model:
  - list / retrieve: any authenticated user
  - create / deploy / destroy / refresh / preview: enterprise users only (IsEnterpriseUser)

All Pulumi operations use the Automation API in-process inside the worker.
No Docker containers are spawned.
"""

from rest_framework import status, viewsets
from celery.result import AsyncResult
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from .models import Stack
from .permissions import IsDemoUser, IsEnterpriseUser
from .serializers import StackSerializer
from .tasks import deploy_stack, destroy_stack, preview_stack, refresh_stack

# Statuses that indicate an operation is already in progress.
_BUSY_STATUSES = (
    Stack.Status.DEPLOYING,
    Stack.Status.DESTROYING,
    Stack.Status.REFRESHING,
    Stack.Status.ATTACKING,
)


class StackViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Stack resources.

    All endpoints require a valid JWT.  Users can only see their own stacks
    (queryset is filtered by owner).  Mutating actions (create, deploy,
    destroy, refresh, preview) are restricted to enterprise users.
    """

    serializer_class = StackSerializer
    http_method_names = ["get", "post", "delete", "head", "options"]

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

        list and retrieve are open to all authenticated users so demo
        users can see their system-provisioned stack.  All mutating
        actions require IsEnterpriseUser.  The demo endpoint requires
        IsDemoUser.

        Returns:
            List of instantiated permission classes.
        """
        if self.action in ("list", "retrieve"):
            return [IsAuthenticated()]
        if self.action == "demo":
            return [IsDemoUser()]
        return [IsEnterpriseUser()]

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

    @action(detail=False, methods=["get"], url_path="demo")
    def demo(self, request: Request) -> Response:
        """
        Return the authenticated demo user's stack outputs.

        The demo stack is provisioned automatically when demo mode is
        activated.  Returns 404 if the stack is still provisioning or
        has not yet been created by the system.

        GET /api/stacks/demo/

        Args:
            request: DRF request (body and params ignored).

        Returns:
            200 with stack data, or 404 if no ready demo stack exists.
        """
        stack = (
            Stack.objects.filter(owner=request.user)
            .exclude(status=Stack.Status.PENDING)
            .exclude(status=Stack.Status.DEPLOYING)
            .first()
        )
        if stack is None:
            return Response(
                {"detail": "Demo stack is still provisioning. Check back shortly."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(StackSerializer(stack).data)

    @action(detail=True, methods=["post"], url_path="deploy")
    def deploy(self, request: Request, pk: str = None) -> Response:
        """
        Enqueue a Celery task to deploy this stack via the Pulumi Automation API.

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
        Enqueue a Celery task to destroy this stack via the Pulumi Automation API.

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

    @action(detail=True, methods=["post"], url_path="force-destroy")
    def force_destroy(self, request: Request, pk: str = None) -> Response:
        """
        Force-destroy a stack regardless of its current status.

        Unlike the standard destroy action, this endpoint is not blocked by
        busy statuses such as DEPLOYING or REFRESHING.  It is intended for
        recovering stacks that are stuck in a non-terminal state because the
        Celery task was never picked up or the Pulumi run hung.

        Only DESTROYING is blocked — if a destroy is already in progress there
        is nothing to do.

        POST /api/stacks/{id}/force-destroy/

        Args:
            request: DRF request (body ignored).
            pk: UUID primary key of the Stack.

        Returns:
            202 Accepted with stack data and task_id, or 409 if the stack
            is already in a DESTROYING state.
        """
        stack = self.get_object()

        if stack.status == Stack.Status.DESTROYING:
            return Response(
                {"detail": "Stack is already being destroyed."},
                status=status.HTTP_409_CONFLICT,
            )

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
        Enqueue a Celery task to refresh this stack via the Pulumi Automation API.

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
        Enqueue a Celery task to preview changes for this stack via the Pulumi Automation API.

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
