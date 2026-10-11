"""
Views for the connectors app.

AWSConnectorView  — verifies an AWS IAM role via STS AssumeRole.
"""

import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.connectors.aws import (
    VERIFY_SESSION_SECONDS,
    assume_role_arn,
    probe_account_authorization_details,
)
from apps.infrastructure.models import Stack

from .serializers import AWSAuditConnectorSerializer, AWSConnectorSerializer

logger = logging.getLogger(__name__)


def _aws_message(exc) -> str:
    """Return the human-readable part of a botocore exception."""
    if hasattr(exc, "response"):
        return exc.response.get("Error", {}).get("Message", str(exc))
    return str(exc)

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
            return Response(
                {"status": "error", "message": _aws_message(exc)},
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


class AWSAuditConnectorView(APIView):
    """
    Connect the read-only role the Attack Graph scan assumes.

    POST /api/connectors/aws/audit/
    Accepts: { role_arn: "arn:aws:iam::123456789012:role/MayaTrailScoutAudit" }
    Returns:
      200 — { status: "verified", account_id: "..." }
      400 — validation errors (bad ARN format)
      422 — the role could not be assumed, or cannot read account-wide IAM

    DELETE /api/connectors/aws/audit/
    Returns:
      200 — { status: "disconnected" }
      409 — a scan is running against this role

    IsAuthenticated rather than HasAWSConnection: connecting this role is how a
    user acquires a connection, and an org may provision the auditor role
    before ever connecting an emulation role.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        """
        Assume the role, prove it can read IAM, then store it.

        The probe is the point. A role that is assumable but cannot call
        iam:GetAccountAuthorizationDetails produces a scan that finds nothing,
        which a reader takes for a clean account. Rejecting it here puts the
        failure in front of the person who can fix it.
        """
        serializer = AWSAuditConnectorSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        role_arn: str = serializer.validated_data["role_arn"]

        try:
            creds = assume_role_arn(
                role_arn,
                f"mayatrail-scout-verify-{request.user.id}",
                duration_seconds=VERIFY_SESSION_SECONDS,
            )
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "Audit role AssumeRole failed for user=%s arn=%s: %s",
                request.user.username, role_arn, exc,
            )
            return Response(
                {"status": "error", "message": _aws_message(exc)},
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        try:
            probe_account_authorization_details(creds)
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "Audit role cannot read IAM for user=%s arn=%s: %s",
                request.user.username, role_arn, exc,
            )
            return Response(
                {
                    "status": "error",
                    "message": (
                        "This role was assumed successfully but cannot call "
                        "iam:GetAccountAuthorizationDetails. Attach that permission "
                        "and try again — without it a scan can only see the role "
                        "itself and would report no findings."
                    ),
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        # The serializer's regex fixes the ARN's shape, so field 4 is the
        # account. Taken from the submitted ARN rather than the STS response
        # because assume_role_arn returns credentials only.
        account_id = role_arn.split(":")[4]

        user = request.user

        # Two roles, and nothing else compares their accounts. A user who
        # pastes an auditor ARN from a different account gets a scan that
        # succeeds, reports on an account they were not looking at, and says
        # so nowhere. Refused when both are connected and they disagree;
        # allowed when no emulation role is connected, because an org may
        # legitimately provision the auditor role first.
        if user.aws_role_arn and user.aws_role_arn.split(":")[4] != account_id:
            return Response(
                {
                    "status": "error",
                    "message": (
                        f"This audit role is in account {account_id}, but the "
                        f"connected emulation role is in account "
                        f"{user.aws_role_arn.split(':')[4]}. Scanning one "
                        "account while emulating in another would produce an "
                        "attack graph for neither. Disconnect the emulation "
                        "role first if the move is intentional."
                    ),
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        user.aws_audit_role_arn = role_arn
        user.aws_audit_regions = serializer.validated_data["regions"]
        # is_verified and is_demo are deliberately untouched: they record that
        # this user proved they own an account they can write to, and a
        # read-only role proves nothing about writes.
        user.save(update_fields=["aws_audit_role_arn", "aws_audit_regions"])

        return Response({"status": "verified", "account_id": account_id})

    def delete(self, request: Request) -> Response:
        """
        Disconnect the audit role.

        Refused while a scan is genuinely in flight: that task resolves
        credentials by reading aws_audit_role_arn at task time, so clearing it
        underneath makes the scan fail against a role it already assumed.

        "Genuinely" is what active_scans() adds over a status filter. Celery's
        hard time_limit kills the worker process outright, so a crashed scan
        never reaches a terminal status — and a status-only guard would then
        refuse this disconnect forever, with no way out from the UI. See
        attack_graph.models.active_scans.

        Nothing is changed in AWS. Revoking access properly means deleting the
        role in the tenant's own account.
        """
        # Imported here, not at module scope: the connectors app must not
        # depend on attack_graph at import time, and this view ships (Task 4)
        # before that app exists (Task 6).
        from apps.attack_graph.models import active_scans  # noqa: PLC0415

        if active_scans(request.user).exists():
            return Response(
                {
                    "detail": (
                        "Cannot disconnect while an attack graph scan is running. "
                        "Wait for it to finish, then try again."
                    ),
                },
                status=status.HTTP_409_CONFLICT,
            )

        user = request.user
        user.aws_audit_role_arn = ""
        user.save(update_fields=["aws_audit_role_arn"])

        logger.info("Scout audit role disconnected for user %s", user.id)

        return Response({"status": "disconnected"})
