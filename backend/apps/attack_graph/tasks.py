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
        from scout.aws import collector  # noqa: PLC0415
        from scout.aws.collect.session import make_thread_factory  # noqa: PLC0415
        from scout.reason.engine import reason as annotate_with_narrative  # noqa: PLC0415

        creds = _audit_credentials(user)
        # make_thread_factory's ClientFactory supports region= (collect_resources
        # calls it per region); a raw boto3.Session.client bound method does not,
        # and fails the moment resource collection reaches its first regional
        # service call. gaad.collect() never asked for a region, which is why
        # this went unnoticed until resource collection was added.
        client_factory = make_thread_factory(credentials={
            "AccessKeyId": creds["AWS_ACCESS_KEY_ID"],
            "SecretAccessKey": creds["AWS_SECRET_ACCESS_KEY"],
            "SessionToken": creds["AWS_SESSION_TOKEN"],
        })
        # A plain boto3.Session, on the same assumed-role credentials, for
        # pipeline.run(session=...) below. Not the same object as
        # client_factory: that is a per-call ClientFactory (factory(service,
        # region=...)) collect_resources() needs for its region fan-out, while
        # Scout's resource-policy enrichment (enrich_inventory) calls
        # session.client(service, region_name=...) directly — a real
        # boto3.Session, not a callable. Without this, pipeline.run() silently
        # skips fetching S3/Lambda/KMS/... resource *policies* (it only runs
        # enrich_inventory when session is not None), so any chain that only
        # exists because of a resource-based grant — not an identity-based
        # one — is never found, not merely hidden.
        boto_session = boto3.Session(
            aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=creds["AWS_SESSION_TOKEN"],
        )

        # collect() degrades to self-scoped enumeration rather than raising
        # when the role cannot read account-wide IAM. That is not success:
        # collection["mode"] carries it into the envelope, and the envelope's
        # state keeps it out of the clean-result copy.
        #
        # self_only is passed explicitly rather than left to its default.
        raw_gaad, account_id, collection = collector.collect(client_factory, self_only=False)

        # Resources (EC2, Lambda, S3, ...) are what let Scout trace an actual
        # escalation path rather than only "this identity already has this
        # impact" — GAAD alone cannot see a role a low-privileged user could
        # pass to a Lambda they can create, only that the Lambda's role itself
        # is over-permissioned. Scoped to regions.aws_audit_regions: the
        # tenant declares its own footprint (this is an authenticated,
        # consented scan, not adversarial recon, so there is no reason to
        # probe for it) and scoping is what keeps this bounded — unscoped,
        # collect_resources() took ~17 minutes against a 67-identity account;
        # scoped to the 2 regions that account actually used, ~3.5 minutes,
        # with identical results. An empty list means IAM-only, matching this
        # task's behaviour before resource collection existed.
        regions = list(user.aws_audit_regions or [])
        resources = None
        if regions:
            resources = collector.collect_resources(
                client_factory, account_id=account_id, regions=regions,
                parallel=True, max_workers=8, factory_is_thread_safe=True,
            )

        # evaluator is left as None deliberately: pipeline.run() builds the
        # AccountModel internally from gaad and only then can construct
        # scout.eval.effective.EffectivePermissionEvaluator(model) — this task
        # has no model to hand it one from outside. evaluator=None resolves to
        # that same evaluator (verified in Task 1, Step 3), which is what
        # envelope.EVALUATOR's "effective" literal claims ran. If Scout ever
        # changes that default, both this comment and envelope.EVALUATOR need
        # updating together — they are one claim about how a finding was
        # computed, split across two files.
        report, graph = pipeline.run(
            gaad=raw_gaad,
            account_id=account_id,
            evaluator=None,
            resources=resources,
            session=boto_session,
        )

        # Attaches report["chains"][i]["analysis"] = {narrative, detection,
        # remediation, ...} for the top MAX_CHAINS chains — the same count
        # the envelope keeps, so nothing below the cutoff pays for an
        # analysis nobody sees. provider=None (the default) is a
        # deterministic offline template, not an LLM call: no external
        # request, no cost, safe to run on every scan.
        annotate_with_narrative(report, top=MAX_CHAINS)

        envelope = serialize_scan(
            report=report,
            collection=collection,
            account_id=account_id,
            scanned_at=timezone.now(),
            regions=regions,
        )

        ScoutScan.objects.filter(id=scan_id).update(
            status=ScoutScan.Status.COMPLETED,
            result=envelope,
            # Scout's own loss-free serializer (scout/graph/schema.py) — no
            # reshaping. This is every node and edge, not the chain endpoints
            # the envelope keeps, and it is what the /graph/ endpoints read.
            # Deliberately not in the detail serializer: the page polls that.
            graph=graph.to_dict(),
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
