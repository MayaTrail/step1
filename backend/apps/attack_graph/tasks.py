"""
Celery task for the attack_graph app.

run_scout_scan assumes the tenant's read-only audit role, has the Scout
service scan the account with those credentials, and stores the serialized
envelope and the full graph.

Scout runs as its own container and this task only orchestrates; the HTTP
calls live in scout_client.py. boto3 is imported inside _audit_credentials,
not at module scope: views import this module, config/urls.py imports the
views, and Django imports the URL configuration during system checks, so a
module-scope import would drag the AWS runtime into every management command
and break the CI suite, which does not install it (see config/settings/ci.py).
"""

import logging

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone

from apps.logs.models import LogEntry
from apps.logs.record import record_activity

from . import scout_client
from .constants import SCAN_SOFT_TIME_LIMIT, SCAN_TIME_LIMIT
from .envelope import MAX_CHAINS, serialize_scan
from .models import ScoutScan

logger = logging.getLogger(__name__)

# What a user sees when the scan died of something this code did not
# anticipate. The exception text goes to the logger, not to the page:
# error_message is rendered verbatim, and an arbitrary Python exception string
# can carry a stack-adjacent detail, a credential fragment from a boto3 repr,
# or simply nothing a reader can act on.
UNEXPECTED_FAILURE_MESSAGE = (
    "The scan failed unexpectedly. The error has been logged — retry the "
    "scan, and contact support if it fails again."
)


class ScanFailure(Exception):
    """A scan that failed for a reason written for the person reading it."""


@shared_task(soft_time_limit=SCAN_SOFT_TIME_LIMIT, time_limit=SCAN_TIME_LIMIT)
def run_scout_scan(scan_id: str) -> None:
    """
    Run one Attack Graph scan to a terminal status.

    Args:
        scan_id: String UUID of the ScoutScan row to execute.

    Returns:
        None. Every outcome is recorded on the row: the caller polls it, and a
        raised exception would leave the row at "running" with nothing to show
        the user.
    """
    scan = ScoutScan.objects.select_related("user").get(id=scan_id)
    user = scan.user

    ScoutScan.objects.filter(id=scan_id).update(
        status=ScoutScan.Status.RUNNING, started_at=timezone.now(),
    )
    record_activity(
        LogEntry.Event.SCAN_STARTED,
        "Attack graph scan started.",
        actor=user,
    )

    service_scan_id = None
    try:
        creds = _audit_credentials(user)
        # Resource collection is scoped to the regions the tenant declared when
        # connecting the audit role. Unscoped, collection took ~17 minutes on a
        # 67-identity account; scoped to the 2 regions it used, ~3.5 minutes
        # with identical results. Empty means an IAM-only scan.
        regions = list(user.aws_audit_regions or [])
        # The narrative count matches the envelope's chain cap, so nothing
        # below the cutoff pays for an analysis nobody sees.
        service_scan_id = scout_client.start_scan(creds, regions, narrate_top=MAX_CHAINS)
        outcome = scout_client.wait_for_scan(service_scan_id)
        if outcome["status"] == "failed":
            raise ScanFailure(outcome.get("error") or UNEXPECTED_FAILURE_MESSAGE)

        # The service returns Scout's own shapes; the envelope is where they
        # become this product's versioned contract.
        envelope = serialize_scan(
            report=outcome["report"],
            collection=outcome["collection"],
            account_id=outcome["account_id"],
            scanned_at=timezone.now(),
            regions=regions,
        )
        ScoutScan.objects.filter(id=scan_id).update(
            status=ScoutScan.Status.COMPLETED,
            result=envelope,
            # Scout's own loss-free graph serialization, every node and edge,
            # read by the /graph/ endpoints. Deliberately not in the detail
            # serializer: the page polls that.
            graph=outcome["graph"],
            completed_at=timezone.now(),
        )
        record_activity(
            LogEntry.Event.SCAN_COMPLETED,
            f"Attack graph scan finished: {len(envelope['chains'])} chains "
            f"({envelope['state']}).",
            actor=user,
        )
    except SoftTimeLimitExceeded:
        _fail(
            scan_id,
            user,
            f"The scan timed out after {SCAN_SOFT_TIME_LIMIT // 60} minutes.",
        )
    except (ScanFailure, scout_client.ScoutServiceError) as exc:
        _fail(scan_id, user, str(exc))
    except Exception:  # noqa: BLE001 - the row must reach a terminal status
        # The detail goes to the logger. error_message is rendered to the user
        # verbatim, and str(exc) on an unanticipated exception is not text
        # written for a person — see UNEXPECTED_FAILURE_MESSAGE.
        logger.exception("Scout scan %s failed", scan_id)
        _fail(scan_id, user, UNEXPECTED_FAILURE_MESSAGE)
    finally:
        # The service holds the result in memory until it is deleted or
        # expires; this result is stored here now, so free it. A scan still
        # running there (a timeout) is refused and expires on its own.
        if service_scan_id:
            scout_client.delete_scan(service_scan_id)


def _audit_credentials(user) -> dict[str, str]:
    """
    Assume the user's read-only audit role.

    The session name differs from the emulation path's on purpose: a tenant
    reading their own CloudTrail can then tell a read-only scan apart from an
    emulation without cross-referencing timestamps.

    Raises:
        ScanFailure: the role could not be assumed, with AWS's own reason.
    """
    from botocore.exceptions import BotoCoreError, ClientError  # noqa: PLC0415

    from apps.connectors.aws import assume_role_arn  # noqa: PLC0415

    try:
        return assume_role_arn(user.aws_audit_role_arn, f"mayatrail-scout-{user.id}")
    except (ClientError, BotoCoreError) as exc:
        raise ScanFailure(_aws_message(exc)) from exc


def _aws_message(exc) -> str:
    """Return the human-readable part of a botocore exception."""
    if hasattr(exc, "response"):
        return exc.response.get("Error", {}).get("Message", str(exc))
    return str(exc)


def _fail(scan_id: str, user, message: str) -> None:
    """Move a scan to failed with a message written for the person reading it."""
    ScoutScan.objects.filter(id=scan_id).update(
        status=ScoutScan.Status.FAILED,
        error_message=message,
        completed_at=timezone.now(),
    )
    record_activity(
        LogEntry.Event.SCAN_FAILED,
        f"Attack graph scan failed: {message}",
        actor=user,
        level=LogEntry.Level.ERROR,
    )
