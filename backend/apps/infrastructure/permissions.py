"""
DRF permission classes for the infrastructure app.

HasAWSConnection  — reads open to any authenticated user; writes need a verified
                    AWS IAM role.  The default for anything touching AWS.
IsEnterpriseUser  — grants access only to users with a verified AWS IAM role,
                    on every method.  Kept for endpoints whose GET is itself
                    privileged.
IsDemoUser        — grants access only to users in demo mode.
"""

from rest_framework.permissions import SAFE_METHODS, BasePermission


class HasAWSConnection(BasePermission):
    """
    Allows reads to any authenticated user; gates writes behind a verified AWS role.

    A signed-up user with no AWS connection ("Explorer") browses the whole
    product to decide whether connecting is worth it, so the gate belongs on the
    action rather than on the page.  Every mutating endpoint in the platform
    ultimately changes something in the tenant's AWS account, which is precisely
    what an unconnected user has not proven they own.

    Keying on the HTTP method rather than on a per-view list means a newly added
    endpoint is governed correctly by default: a new POST is gated without its
    author having to remember to gate it.  That property is the reason this is a
    single class instead of a classification table.

    Demo users are treated as unconnected for writes, preserving the behaviour
    IsEnterpriseUser had before this class existed.
    """

    message = "Connect your AWS account to perform this action."

    def has_permission(self, request, view):
        """
        Return True for any authenticated read, or for a write by a connected user.

        Args:
            request: The incoming DRF request.
            view:    The view being accessed (unused).

        Returns:
            bool — True when the request is permitted.
        """
        if not (request.user and request.user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user.is_verified and not request.user.is_demo)


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
