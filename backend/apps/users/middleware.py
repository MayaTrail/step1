"""
Demo Expiry Middleware.

Blocks demo users whose sandbox window has expired from accessing
any protected API endpoint.  Returns a 403 with a machine-readable
``code`` so the frontend can distinguish this from other permission
errors and redirect to the connector/upgrade flow.

Exempt paths
------------
- ``/api/auth/*``        — login, refresh, /me  (so the user can still
                           authenticate and see their profile status)
- ``/api/connectors/*``  — so expired demo users can upgrade to AWS
"""

import logging

from django.http import JsonResponse

logger = logging.getLogger(__name__)

# Paths that expired demo users are still allowed to hit.
_EXEMPT_PREFIXES = ("/api/auth/", "/api/connectors/")


class DemoExpiryMiddleware:
    """
    Django middleware that enforces the server-side demo time limit.

    It runs after ``AuthenticationMiddleware`` (so ``request.user`` is
    populated) and before any view.  For every authenticated request
    from a demo user whose window has elapsed, it short-circuits with::

        HTTP 403
        {"code": "DEMO_EXPIRED", "detail": "Your demo session has expired. ..."}

    The ``code`` field lets the frontend's Axios interceptor react
    specifically to demo expiry (as opposed to a generic 403).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only check authenticated users on non-exempt paths.
        if (
            hasattr(request, "user")
            and request.user.is_authenticated
            and not self._is_exempt(request.path)
        ):
            user = request.user
            if getattr(user, "is_demo", False) and getattr(user, "is_demo_expired", False):
                logger.info(
                    "Demo expired for user=%s — blocking %s %s",
                    user.username,
                    request.method,
                    request.path,
                )
                return JsonResponse(
                    {
                        "code": "DEMO_EXPIRED",
                        "detail": (
                            "Your demo session has expired. "
                            "Please connect your AWS account to continue."
                        ),
                    },
                    status=403,
                )

        return self.get_response(request)

    @staticmethod
    def _is_exempt(path: str) -> bool:
        """Return True if the path is exempt from demo-expiry checks."""
        return any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES)
