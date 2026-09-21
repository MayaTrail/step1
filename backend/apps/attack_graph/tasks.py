"""
Celery task for the attack_graph app.

run_scout_scan — assume the tenant's read-only audit role, collect the account
                 authorization details, rank privilege-escalation chains with
                 Scout, and store the serialized envelope.

Scout and boto3 are imported inside the function, not at module scope. Views
import this module, config/urls.py imports the views, and Django imports the
URL configuration during system checks — so a module-scope import here would
drag the whole AWS runtime into every management command and break the CI
suite, which installs neither (see config/settings/ci.py).
"""

import logging

from celery import shared_task
from django.utils import timezone

from apps.logs.models import LogEntry
from apps.logs.record import record_activity

from .constants import SCAN_SOFT_TIME_LIMIT, SCAN_TIME_LIMIT
from .envelope import serialize_scan
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
    from botocore.exceptions import BotoCoreError, ClientError  # noqa: PLC0415
    from celery.exceptions import SoftTimeLimitExceeded  # noqa: PLC0415

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

    try:
        import boto3  # noqa: PLC0415
        from scout import pipeline  # noqa: PLC0415
        from scout.aws.collect import gaad  # noqa: PLC0415
        # Import path verified in Task 1, Step 3: pipeline.run()'s
        # evaluator=None default resolves internally to
        # scout.eval.effective.EffectivePermissionEvaluator. envelope.EVALUATOR
        # names the same evaluator; if Scout ever renames or relocates this
        # class, both must change together — they are one claim about how a
        # finding was computed, split across two files.
        from scout.eval.effective import EffectivePermissionEvaluator  # noqa: PLC0415

        creds = _audit_credentials(user)
        session = boto3.Session(
            aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=creds["AWS_SESSION_TOKEN"],
        )

        # collect() degrades to self-scoped enumeration rather than raising
        # when the role cannot read account-wide IAM. That is not success:
        # collection["mode"] carries it into the envelope, and the envelope's
        # state keeps it out of the clean-result copy.
        #
        # self_only and evaluator are passed explicitly rather than left to
        # their defaults. The envelope records which evaluator produced the
        # chains, and a default that changes in a Scout release would make
        # that record false without anything here changing.
        #
        # collection["mode"] itself is the one Task 1 assumption not
        # exercised against live AWS (the spike ran offline, against a
        # pre-built gaad fixture) — confirmed by Task 5, Step 5's real-account
        # check below, not by this code.
        raw_gaad, account_id, collection = gaad.collect(session.client, self_only=False)
        report, _graph = pipeline.run(
            gaad=raw_gaad,
            account_id=account_id,
            evaluator=EffectivePermissionEvaluator(),
        )

        envelope = serialize_scan(
            report=report,
            collection=collection,
            account_id=account_id,
            scanned_at=timezone.now(),
        )

        ScoutScan.objects.filter(id=scan_id).update(
            status=ScoutScan.Status.COMPLETED,
            result=envelope,
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
    except (ClientError, BotoCoreError) as exc:
        _fail(scan_id, user, _aws_message(exc))
    except Exception:  # noqa: BLE001 - the row must reach a terminal status
        # The detail goes to the logger. error_message is rendered to the user
        # verbatim, and str(exc) on an unanticipated exception is not text
        # written for a person — see UNEXPECTED_FAILURE_MESSAGE.
        logger.exception("Scout scan %s failed", scan_id)
        _fail(scan_id, user, UNEXPECTED_FAILURE_MESSAGE)


def _audit_credentials(user) -> dict[str, str]:
    """
    Assume the user's read-only audit role.

    The session name differs from the emulation path's on purpose: a tenant
    reading their own CloudTrail can then tell a read-only scan apart from an
    emulation without cross-referencing timestamps.
    """
    from apps.connectors.aws import assume_role_arn  # noqa: PLC0415

    return assume_role_arn(user.aws_audit_role_arn, f"mayatrail-scout-{user.id}")


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
