"""
Permission gate for the Attack Graph endpoints.
"""

from rest_framework.permissions import SAFE_METHODS, BasePermission


class HasScoutConnection(BasePermission):
    """
    Allows reads to any authenticated user; gates a scan on the audit role.

    Modelled on infrastructure.permissions.HasAWSConnection, deliberately not
    reusing it. That class keys on the emulation role's own verified flag, and
    the two connections are independent: an organisation may provision the
    read-only auditor role for Scout and never connect an emulation role at
    all. Gating this endpoint on the other connection would refuse that
    organisation its own scan.
    """

    message = "Connect a read-only Scout audit role to run a scan."

    def has_permission(self, request, view):
        """
        Return True for any authenticated read, or for a scan by a connected user.

        Args:
            request: The DRF request.
            view: The view being accessed (unused).

        Returns:
            True when the request may proceed.
        """
        user = request.user
        if not (user and user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        return bool(user.aws_audit_role_arn)
