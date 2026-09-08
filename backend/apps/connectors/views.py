"""
Views for the connectors app.

AWSConnectorView  — verifies an AWS IAM role via STS AssumeRole.
DemoActivateView  — switches the user to demo mode.
"""

import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.infrastructure.models import Stack

from .serializers import AWSConnectorSerializer

logger = logging.getLogger(__name__)

# Stack statuses that mean a Pulumi operation or an attack is still running.
# Disconnecting during any of these pulls the role ARN out from under a task
# that resolves credentials from it at run time.
IN_FLIGHT_STACK_STATUSES = (
    Stack.Status.PENDING,
    Stack.Status.DEPLOYING,
    Stack.Status.EC2_BOOTING,
    Stack.Status.ATTACKING,
    Stack.Status.DESTROYING,
    Stack.Status.REFRESHING,
)


class AWSConnectorView(APIView):
    """
    Verify an AWS IAM role ARN via STS AssumeRole.

    POST /api/connectors/aws/verify/
    Accepts: { role_arn: "arn:aws:iam::123456789012:role/MayaTrailRole" }
    Returns:
      200 — { status: "verified", account_id: "..." }
      400 — validation errors (bad ARN format)
      422 — STS call failed (role not assumable)

    DELETE /api/connectors/aws/verify/
    Returns:
      200 — { status: "disconnected" }
      409 — a stack is mid-operation; the response names the blocking stacks
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        """
        Validate the ARN format, then attempt an STS AssumeRole call.

        On success, persist the role ARN on the user and set is_verified=True.
        """
        serializer = AWSConnectorSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        role_arn: str = serializer.validated_data["role_arn"]

        # STS verification
        try:
            sts = boto3.client("sts")
            resp = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="mayatrail-connector-verify",
                DurationSeconds=900,  # minimum allowed
            )
            account_id = resp["AssumedRoleUser"]["Arn"].split(":")[4]
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "STS AssumeRole failed for user=%s arn=%s: %s",
                request.user.username,
                role_arn,
                exc,
            )
            message = str(exc)
            # Extract the human-readable part from ClientError
            if hasattr(exc, "response"):
                message = exc.response.get("Error", {}).get(
                    "Message", str(exc)
                )
            return Response(
                {"status": "error", "message": message},
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        # Persist on the user
        user = request.user
        user.aws_role_arn = role_arn
        user.is_verified = True
        user.is_demo = False
        user.save(update_fields=["aws_role_arn", "is_verified", "is_demo"])

        return Response(
            {
                "status": "verified",
                "account_id": account_id,
            }
        )

    def delete(self, request: Request) -> Response:
        """
        Disconnect the AWS account by clearing the stored role ARN.

        Refused while any of the user's stacks is mid-operation. Those statuses
        mean Pulumi is partway through creating or removing resources, or an
        attack is running, and every one of those tasks resolves credentials by
        reading aws_role_arn at task time. Clearing it underneath a running task
        makes the task fail against a half-built stack.

        Settled stacks do not block. A user may disconnect while stacks are
        still deployed, which leaves those resources running in their account
        with no way for MayaTrail to destroy them, including the TTL sweep. The
        UI states this before asking for confirmation.

        Nothing is changed in AWS. MayaTrail only ever assumes a role the user
        created, so revoking access properly means deleting that role in their
        own account.

        Args:
            request: DRF request from the authenticated user.

        Returns:
            200 with {"status": "disconnected"}, or 409 naming the stacks that
            must settle first.
        """
        user = request.user

        blocking = list(
            Stack.objects.filter(owner=user, status__in=IN_FLIGHT_STACK_STATUSES)
            .values_list("name", "status")
        )
        if blocking:
            return Response(
                {
                    "detail": (
                        "Cannot disconnect while a stack operation is in progress. "
                        "Wait for it to finish, then try again."
                    ),
                    "blocking_stacks": [
                        {"name": name, "status": stack_status} for name, stack_status in blocking
                    ],
                },
                status=status.HTTP_409_CONFLICT,
            )

        user.aws_role_arn = ""
        user.is_verified = False
        user.save(update_fields=["aws_role_arn", "is_verified"])

        logger.info("AWS connector disconnected for user %s", user.id)

        return Response({"status": "disconnected"})


class DemoActivateView(APIView):
    """
    Switch the authenticated user to demo mode.

    POST /api/connectors/demo/
    Accepts: {} (empty body)
    Returns: { status: "ok", is_demo: true }

    Demo can only be activated **once** per user.  The server records
    the activation timestamp so the DemoExpiryMiddleware can enforce
    the time limit.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        """
        Set the user's is_demo=True and is_verified=False.

        Rejects with 409 if the user has already used their demo.
        """
        user = request.user

        if user.demo_used:
            return Response(
                {
                    "code": "DEMO_ALREADY_USED",
                    "detail": "Demo mode can only be activated once.",
                },
                status=status.HTTP_409_CONFLICT,
            )

        user.is_demo = True
        user.is_verified = False
        user.aws_role_arn = ""
        user.demo_activated_at = timezone.now()
        user.demo_used = True
        user.save(update_fields=[
            "is_demo", "is_verified", "aws_role_arn",
            "demo_activated_at", "demo_used",
        ])

        return Response({"status": "ok", "is_demo": True})
