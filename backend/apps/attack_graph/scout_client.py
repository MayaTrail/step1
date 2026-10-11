"""
HTTP client for the Scout scan service.

Scout runs as its own container (`scout serve`, image ghcr.io/mayatrail/scout)
and this module is the only place MayaTrail talks to it. The service's API is
asynchronous because a scan reads an account for minutes: start a scan, poll
it until it finishes, then delete it once the result is stored here.

Every error is raised as ScoutServiceError carrying a message that is safe to
show the user. The request body holds temporary AWS credentials, so neither
it nor a raw requests exception (whose text can echo the request) is ever put
in a message or a log line.
"""

import time
from typing import Any

import requests
from django.conf import settings

# Per-request timeout. The service answers every call immediately (the scan
# itself runs in the background), so a slow reply means it is unreachable.
REQUEST_TIMEOUT_SECONDS = 15

# How often a running scan is polled. A scan takes minutes, so a few seconds of
# extra latency on completion costs nothing and keeps the worker quiet.
POLL_INTERVAL_SECONDS = 5

FINISHED_STATUSES = ("completed", "failed")

UNREACHABLE = (
    "The Scout service could not be reached. Check that the scout container "
    "is running, then retry the scan."
)
NOT_CONFIGURED = (
    "The Scout service is not configured: SCOUT_SERVICE_TOKEN is not set on "
    "the worker."
)


class ScoutServiceError(Exception):
    """A failed call to the Scout service, with a message safe to show the user."""


def _url(path: str) -> str:
    """The full URL of a service path."""
    return settings.SCOUT_SERVICE_URL.rstrip("/") + path


def _headers() -> dict[str, str]:
    """The bearer-token header the service requires."""
    token = settings.SCOUT_SERVICE_TOKEN
    if not token:
        raise ScoutServiceError(NOT_CONFIGURED)
    return {"Authorization": f"Bearer {token}"}


def _call(method: str, path: str, **kwargs) -> requests.Response:
    """
    One request to the service.

    requests' own exceptions are replaced rather than chained into the
    message: their text can include the request, and a scan request carries
    credentials.
    """
    try:
        return requests.request(
            method, _url(path), headers=_headers(), timeout=REQUEST_TIMEOUT_SECONDS, **kwargs,
        )
    except requests.RequestException:
        raise ScoutServiceError(UNREACHABLE) from None


def _error_detail(response: requests.Response) -> str:
    """The service's own error message, or the HTTP status when it sent none."""
    try:
        detail = response.json().get("error")
    except ValueError:
        detail = None
    return detail or f"HTTP {response.status_code}"


def start_scan(credentials: dict[str, str], regions: list[str], narrate_top: int) -> str:
    """
    Ask the service to scan an account. Returns the service's scan id.

    Args:
        credentials: The dict returned by connectors.aws.assume_role_arn().
        regions: Regions to collect resources from; empty means IAM only.
        narrate_top: How many top chains get a narrative.

    Raises:
        ScoutServiceError: the service is unreachable, refused the token, is
            at capacity, or rejected the request.
    """
    body = {
        "credentials": {
            "access_key_id": credentials["AWS_ACCESS_KEY_ID"],
            "secret_access_key": credentials["AWS_SECRET_ACCESS_KEY"],
            "session_token": credentials["AWS_SESSION_TOKEN"],
        },
        "regions": regions,
        "narrate_top": narrate_top,
    }
    response = _call("POST", "/v1/scans", json=body)
    if response.status_code == 429:
        raise ScoutServiceError("The Scout service is busy with other scans. Retry in a few minutes.")
    if response.status_code != 202:
        raise ScoutServiceError(f"The Scout service refused the scan: {_error_detail(response)}")
    return response.json()["scan_id"]


def get_scan(scan_id: str) -> dict[str, Any]:
    """
    The service's current view of one scan.

    Raises:
        ScoutServiceError: the scan is unknown to the service (it restarted,
            or the result expired before it was fetched), or the call failed.
    """
    response = _call("GET", f"/v1/scans/{scan_id}")
    if response.status_code == 404:
        raise ScoutServiceError(
            "The Scout service lost track of this scan, most likely because it "
            "restarted. Retry the scan."
        )
    if response.status_code != 200:
        raise ScoutServiceError(f"The Scout service returned an error: {_error_detail(response)}")
    return response.json()


def wait_for_scan(scan_id: str) -> dict[str, Any]:
    """
    Poll a scan until it completes or fails, and return its final view.

    There is no deadline here on purpose: the Celery task's soft time limit
    bounds the whole scan, and a second, shorter limit in this loop would cut
    off scans the task still has time for.
    """
    while True:
        scan = get_scan(scan_id)
        if scan.get("status") in FINISHED_STATUSES:
            return scan
        time.sleep(POLL_INTERVAL_SECONDS)


def delete_scan(scan_id: str) -> None:
    """
    Drop a finished scan from the service once its result is stored here.

    Best effort: the service also expires results on its own, so a failure
    here leaves nothing behind for longer than that expiry.
    """
    try:
        _call("DELETE", f"/v1/scans/{scan_id}")
    except ScoutServiceError:
        pass
