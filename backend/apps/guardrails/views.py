"""
Views for the guardrails app.

GET /api/guardrails/        GuardrailListView
GET /api/guardrails/<id>/   GuardrailDetailView
GET  /api/guardrails/emulation/<emulation_type>/        EmulationGuardrailsView
POST /api/guardrails/emulation/<emulation_type>/check/  EmulationAccountCheckView

Both endpoints require IsAuthenticated rather than IsEnterpriseUser.  The
library is a catalogue of published AWS sample policies: it reads nothing from
the user's account and exposes no stack, IAM or resource metadata, so a
verified AWS connection is not a meaningful gate on it.

The list response mirrors the detections endpoint (a named rule bucket plus a
count and a format summary) so the frontend renders both libraries the same
way.  It omits each policy document, which the list never displays and which
would otherwise make the response roughly three times its size; the detail
endpoint serves the document for the one policy a reader opened.
"""

import logging
import re

from botocore.exceptions import BotoCoreError, ClientError
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.emulations.registry import get_emulation
from apps.infrastructure.models import Stack
from apps.infrastructure.permissions import IsEnterpriseUser
from apps.logs.models import LogEntry
from apps.logs.record import record_activity

from . import simulate
from .matching import acting_identities, analyse, declared_identities, emulation_actions
from .registry import get_guardrail, list_guardrails

logger = logging.getLogger(__name__)

# The region a lab is deployed to unless the caller chooses otherwise. Passing
# it lets AWS decide a region-conditional policy; passing the wrong one would
# produce a confident but wrong answer, which is why only this default and an
# explicit choice are ever sent.
_DEFAULT_REGION = "us-east-1"

# An AWS region name, validated before it reaches a condition value so a
# caller cannot put arbitrary text into the simulator request.
_REGION_RE = re.compile(r"[a-z]{2}(-[a-z]+)+-\d")

# Catalogue keys the list response carries. "code" and "file" are detail-only.
_SUMMARY_FIELDS = ("id", "type", "purpose", "services", "source")


def _summary(guardrail: dict) -> dict:
    """
    Reduce a catalogue entry to the fields the library list renders.

    Args:
        guardrail: A catalogue dict from the registry.

    Returns:
        The entry without its policy document.
    """
    return {field: guardrail[field] for field in _SUMMARY_FIELDS}


class GuardrailListView(APIView):
    """
    Return the guardrail library index.

    GET /api/guardrails/

    Policy documents are excluded; fetch one from the detail endpoint.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        Read the catalogue and summarise it by policy type.

        Args:
            request: DRF request.

        Returns:
            200 with the guardrail list and per-type counts.  An empty library
            (base directory unset or unreadable) returns zero counts rather
            than an error, so the UI shows its empty state instead of a
            failure.
        """
        guardrails = list_guardrails()
        scp_count = sum(1 for g in guardrails if g["type"] == "SCP")
        rcp_count = sum(1 for g in guardrails if g["type"] == "RCP")

        return Response({
            "guardrails": [_summary(g) for g in guardrails],
            "totalCount": len(guardrails),
            "formats": f"SCP ({scp_count}) · RCP ({rcp_count})",
        })


class GuardrailDetailView(APIView):
    """
    Return one guardrail with its policy document.

    GET /api/guardrails/<guardrail_id>/

    The frontend renders `code` in a CodeBlock exactly as it renders a
    detection rule.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request, guardrail_id: str) -> Response:
        """
        Read a single guardrail by catalogue id.

        Args:
            request:      DRF request.
            guardrail_id: URL path parameter, the catalogue slug.

        Returns:
            200 with the guardrail and its policy document, or 404 if no
            guardrail carries that id.
        """
        guardrail = get_guardrail(guardrail_id)
        if guardrail is None:
            return Response({"detail": "Guardrail not found."}, status=404)

        return Response(guardrail)


class EmulationGuardrailsView(APIView):
    """
    Which catalogue policies would interrupt one emulation's attack.

    GET /api/guardrails/emulation/<emulation_type>/

    Enterprise-gated, unlike the rest of this app. The catalogue itself is
    public AWS samples and reads nothing from the user's account, but this
    names an emulation's phases and the actions each performs, which is our
    content rather than AWS's.

    Every verdict means "if you deployed this policy". The library is a
    catalogue, not a reading of the caller's Organization, and the response
    says so in `basis` so a client cannot render it as deployed protection.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, emulation_type: str) -> Response:
        """
        Analyse one emulation against the whole guardrail catalogue.

        Args:
            request:        DRF request.
            emulation_type: Registry name of the emulation.

        Returns:
            200 with the analysis, or 404 when the emulation is unknown. An
            emulation whose phases declare no actions returns 200 with
            `analysed: false`: that is "nobody has mapped this one yet", not
            "no policy can stop it", and the two must not look alike.
        """
        entry = get_emulation(emulation_type)
        if entry is None:
            return Response(
                {"detail": f"Unknown emulation '{emulation_type}'."}, status=404
            )

        manifest = entry.get("manifest", entry) or {}
        result = analyse(manifest.get("attack_path") or [], list_guardrails())
        result["emulationType"] = emulation_type
        result["displayName"] = manifest.get("display_name", emulation_type)
        result["basis"] = "catalogue"
        # The identities its phases act as, by label and kind only: which stack
        # output names a lab identity is an implementation detail of the check.
        identities = declared_identities(manifest)
        used = {who for phase in manifest.get("attack_path") or [] for who in acting_identities(phase)}
        result["identities"] = [
            {"key": key, "label": identities[key].get("label", key), "kind": identities[key].get("kind", "")}
            for key in sorted(used) if key in identities
        ]
        return Response(result)


# Stack states in which a lab's identities exist and its outputs are recorded.
_DEPLOYED = (
    Stack.Status.READY,
    Stack.Status.READY_FOR_ATTACK,
    Stack.Status.ATTACKING,
    Stack.Status.ATTACK_COMPLETE,
)


def _deployed_lab(user, emulation_type: str):
    """
    The caller's most recently created deployed lab of one emulation.

    Args:
        user:           The caller; only their own stacks are considered.
        emulation_type: Registry name of the emulation.

    Returns:
        The Stack, or None when the caller has no deployed lab of it.
    """
    return (
        Stack.objects.filter(owner=user, emulation_type=emulation_type, status__in=_DEPLOYED)
        .order_by("-created_at")
        .first()
    )


class EmulationAccountCheckView(APIView):
    """
    Ask AWS whether the caller's own policies would refuse this emulation.

    POST /api/guardrails/emulation/<emulation_type>/check/
        Optional body: {"region": "eu-west-1"}

    The catalogue endpoint above answers "a published policy would block this
    if you deployed it". This answers "your policies, as AWS evaluates them
    right now, would block this", which is a different and stronger claim. It
    performs none of the actions: AWS evaluates them and reports what would
    happen.

    Each action is judged as the identity that performs it. The connected
    role is always asked about; a lab user or role is asked about when the
    caller has a deployed lab of this emulation, found through its stack
    outputs, and that lab's region is used. Identities the attack creates, and
    requests sent with no identity, cannot be asked about and say so.

    Enterprise-gated and rate-limited. It assumes the caller's connected role
    and spends one simulation per identity it can check, so it is not
    something a stolen session should be able to run in a loop.

    What the result does not cover is stated in the response rather than left
    for a reader to assume: resource control policies and resource policies
    are invisible to the simulator.
    """

    permission_classes = [IsEnterpriseUser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "guardrail_check"

    def post(self, request: Request, emulation_type: str) -> Response:
        """
        Simulate the caller's connected role against the emulation's actions.

        Args:
            request:        DRF request, optionally carrying a region.
            emulation_type: Registry name of the emulation.

        Returns:
            200 with per-action and per-phase verdicts; 404 for an unknown
            emulation; 409 when the emulation declares no actions to check;
            422 when AWS refuses the call, including the case where the role
            is missing iam:SimulatePrincipalPolicy, which is reported as a
            permission to add rather than as a failure of the feature.
        """
        entry = get_emulation(emulation_type)
        if entry is None:
            return Response(
                {"detail": f"Unknown emulation '{emulation_type}'."},
                status=status.HTTP_404_NOT_FOUND,
            )

        manifest = entry.get("manifest", entry) or {}
        attack_path = manifest.get("attack_path") or []
        actions = emulation_actions(attack_path)
        if not actions:
            return Response(
                {"detail": "This emulation declares no AWS actions, so there is nothing to check."},
                status=status.HTTP_409_CONFLICT,
            )

        # A deployed lab lets its own identities be checked, and is the region
        # the attack would run in; without one, lab identities say so.
        lab = _deployed_lab(request.user, emulation_type)
        region = request.data.get("region") or (lab.region if lab else _DEFAULT_REGION)
        if not _REGION_RE.fullmatch(str(region)):
            return Response(
                {"detail": f"'{region}' is not an AWS region name."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        try:
            result = simulate.check_account(
                user.aws_role_arn,
                f"mayatrail-guardrail-check-{user.id}",
                emulation_type,
                manifest,
                region,
                (lab.outputs or {}) if lab else None,
            )
        except (ClientError, BotoCoreError) as exc:
            return self._aws_error(exc, user.username, emulation_type)

        summary = result["summary"]
        if summary["actionsChecked"]:
            message = (
                f"Checked {result['displayName']} against your AWS policies: "
                f"{len(summary['prevented'])} of {summary['actionsChecked']} actions would be refused."
            )
        else:
            message = (
                f"Checked {result['displayName']}: none of its actions run as your connected role, "
                "so nothing was sent to AWS."
            )
        record_activity(LogEntry.Event.GUARDRAIL_CHECK, message, actor=user)
        # The stack id only builds the "View stack" link; it is never shown.
        result["lab"] = {"stackId": str(lab.id), "deployedAt": lab.created_at.isoformat()} if lab else None
        return Response(result)

    def _aws_error(self, exc: Exception, username: str, emulation_type: str) -> Response:
        """
        Turn a botocore exception into a response a reader can act on.

        Args:
            exc:            The raised ClientError or BotoCoreError.
            username:       For the log line, never for the response.
            emulation_type: For the log line.

        Returns:
            422 with a message, and `missingPermission` set when the role
            cannot simulate, so the client can offer the fix rather than
            rendering an error.
        """
        code, message = simulate.aws_error(exc)
        logger.warning(
            "Guardrail check failed for user=%s emulation=%s: %s",
            username, emulation_type, code or exc.__class__.__name__,
        )

        # An AccessDenied naming the simulate call means the connected role
        # predates this feature. That is a one-line policy addition, not a
        # fault, so it is reported as such.
        cannot_simulate = simulate.cannot_simulate(code, message)
        return Response(
            {
                "detail": message,
                "missingPermission": "iam:SimulatePrincipalPolicy" if cannot_simulate else None,
            },
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
