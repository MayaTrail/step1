"""
DRF permission classes for the infrastructure app.

IsEnterpriseUser  — grants access only to users with a verified AWS IAM role.
IsDemoUser        — grants access only to users in demo mode.
"""

from rest_framework.permissions import BasePermission


class IsEnterpriseUser(BasePermission):
    """
    Allows access only to enterprise users (is_verified=True, is_demo=False).

    Used to gate stack-mutating actions (deploy, destroy, refresh, preview)
    and all /api/emulations/ endpoints.  Demo users and unverified users are
    denied with a clear error message.
    """

    message = "This action requires a verified AWS account connection."

    def has_permission(self, request, view):
        """
        Return True only when the user is authenticated, verified, and not in demo mode.

        Args:
            request: The incoming DRF request.
            view:    The view being accessed (unused).

        Returns:
            bool — True if the user is an enterprise user.
        """
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_verified
            and not request.user.is_demo
        )


class IsDemoUser(BasePermission):
    """
    Allows access only to users in demo mode (is_demo=True).

    Used to gate the GET /api/stacks/demo/ endpoint so enterprise users
    cannot accidentally call the demo stack lookup route.
    """

    message = "This endpoint is only available to demo users."

    def has_permission(self, request, view):
        """
        Return True only when the user is authenticated and in demo mode.

        Args:
            request: The incoming DRF request.
            view:    The view being accessed (unused).

        Returns:
            bool — True if the user is a demo user.
        """
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_demo
        )
