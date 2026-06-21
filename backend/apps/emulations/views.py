"""
Views for the emulations app.

All endpoints require IsEnterpriseUser.

GET  /api/emulations/                              EmulationListView
GET  /api/emulations/<emulation_type>/estimate/    EmulationEstimateView
GET  /api/emulations/<emulation_type>/techniques/  EmulationTechniquesView
GET  /api/emulations/<emulation_type>/detections/  EmulationDetectionsView
GET  /api/emulations/<emulation_type>/playbook/    EmulationPlaybookView
POST /api/emulations/deploy/                       EmulationDeployView
GET  /api/emulations/<run_id>/                     EmulationRunDetailView
POST /api/emulations/<stack_id>/attack/            EmulationAttackView
POST /api/emulations/<stack_id>/destroy/           EmulationDestroyView
"""

import logging
import os
from datetime import timedelta
from pathlib import Path

from django.utils import timezone
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.infrastructure.models import Stack
from apps.infrastructure.permissions import IsEnterpriseUser

from .models import EmulationRun
from .registry import get_emulation, list_emulations
from .serializers import (
    DeployEmulationSerializer,
    EmulationRunListSerializer,
    EmulationRunSerializer,
)
from .tasks import destroy_emulation_stack, run_emulation_attack

logger = logging.getLogger(__name__)

EMULATIONS_BASE_DIR = os.environ.get("EMULATIONS_BASE_DIR", "")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _default_region() -> str:
    """
    Return the default AWS region for new stacks.

    Mirrors the Stack.region field default so cost estimates price for the same
    region a deploy would use when no explicit region is supplied.

    Returns:
        The region string (e.g. "ap-south-1").
    """
    from apps.infrastructure.models import Stack  # noqa: PLC0415
    return Stack._meta.get_field("region").default


def _manifest_to_api(entry: dict) -> dict:
    """
    Convert a registry catalogue entry to the camelCase shape expected by the
    frontend Emulation TypeScript type.

    The MANIFEST uses snake_case Python keys; the API must return camelCase so
    the frontend type definitions match without manual mapping at the call site.

    Args:
        entry: A single entry from list_emulations() / get_emulation().

    Returns:
        Dict with camelCase keys matching the frontend Emulation interface.
    """
    return {
        "id": entry.get("name"),
        "name": entry.get("display_name"),
        "description": entry.get("description"),
        "platform": entry.get("platform", "aws"),
        "added": entry.get("added"),
        "services": entry.get("services", []),
        "tier": entry.get("tier"),
        "origin": entry.get("origin", "unknown"),
        "originLabel": entry.get("origin_label", ""),
        "tags": entry.get("tags", []),
        "techniqueCount": entry.get("technique_count", 0),
        "severity": entry.get("severity", ""),
        "aliases": entry.get("aliases", ""),
        "attribution": entry.get("attribution", ""),
        "activeSince": entry.get("active_since", ""),
        "targets": entry.get("targets", ""),
        "incidents": entry.get("incidents", []),
        "attackPath": entry.get("attack_path", []),
        "mitreMappings": entry.get("mitre_mappings", []),
        "references": entry.get("references", []),
        "phaseCount": entry.get("phase_count", 0),
        "schemaVersion": entry.get("schema_version"),
    }


def _get_emulation_or_404(emulation_type: str) -> tuple[dict | None, Response | None]:
    """
    Look up an emulation entry and return a 404 Response if not found.

    Returns:
        (entry, None) on success, (None, Response) on failure.
    """
    entry = get_emulation(emulation_type)
    if entry is None:
        return None, Response(
            {"detail": f"Unknown emulation type '{emulation_type}'."},
            status=status.HTTP_404_NOT_FOUND,
        )
    return entry, None


# ── Read-only catalogue views ─────────────────────────────────────────────────

class EmulationListView(APIView):
    """
    List all available emulation packages discovered from the registry.

    GET /api/emulations/

    Returns a list of emulation catalogue entries serialised to camelCase so
    that the frontend Emulation TypeScript type is satisfied without any
    client-side mapping.  Non-enterprise users receive 403.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """
        Return all registered emulation packages in camelCase API format.

        Returns:
            200 with a list of emulation dicts.
            403 if the caller is not an enterprise user.
        """
        emulations = [_manifest_to_api(e) for e in list_emulations()]
        return Response(emulations)


class EmulationEstimateView(APIView):
    """
    Return a pre-deployment cost breakdown for a given emulation type.

    GET /api/emulations/<emulation_type>/estimate/?region=<region>

    Runs `pulumi preview --json` on the worker to enumerate the exact resources
    the deploy will create, then prices them via the live AWS Pricing API (with
    a hardcoded fallback table).  The preview runs on the worker because the
    Pulumi CLI is only installed there; this view enqueues the task and blocks
    on the result.  If the live estimate fails or times out, it falls back to
    the static MANIFEST cost figures so the endpoint always returns something.

    The frontend must show this breakdown and require confirmation before
    calling POST /api/emulations/deploy/.
    """

    permission_classes = [IsEnterpriseUser]

    # Max seconds to wait for the worker's pulumi preview before falling back.
    _ESTIMATE_TIMEOUT_SECONDS = 60

    def get(self, request: Request, emulation_type: str) -> Response:
        """
        Build and return the cost estimate for emulation_type.

        Args:
            request:        DRF request (optional ?region= query param).
            emulation_type: URL path parameter — emulation package name.

        Returns:
            200 with cost breakdown, or 404 if emulation_type is unknown.
        """
        entry, err = _get_emulation_or_404(emulation_type)
        if err:
            return err

        manifest = entry.get("manifest", entry)
        ttl_hours = manifest.get("default_ttl_hours", 4)
        region = request.query_params.get("region") or _default_region()

        live = self._live_estimate(emulation_type, region, str(request.user.id))

        if live is not None:
            hourly = live["hourlyUsd"]
            return Response({
                "emulationType": emulation_type,
                "displayName": manifest.get("display_name", emulation_type),
                "region": region,
                "source": "live-preview",
                "resources": live["breakdown"],
                "costDrivers": live["costDrivers"],
                "warnings": live["warnings"],
                "resourceCount": live["resourceCount"],
                "totalCostPerHourUsd": hourly,
                "defaultTtlHours": ttl_hours,
                "estimatedTotalUsd": round(hourly * ttl_hours, 4),
                "note": (
                    f"Live estimate from pulumi preview in {region}. "
                    f"Stack is auto-destroyed after {ttl_hours} hours."
                ),
            })

        # Fallback: static MANIFEST figures.
        cost_per_hour = manifest.get("estimated_cost_per_hour_usd", 0.0)
        return Response({
            "emulationType": emulation_type,
            "displayName": manifest.get("display_name", emulation_type),
            "region": region,
            "source": "manifest-fallback",
            "resources": manifest.get("resource_costs", []),
            "totalCostPerHourUsd": cost_per_hour,
            "defaultTtlHours": ttl_hours,
            "estimatedTotalUsd": round(cost_per_hour * ttl_hours, 4),
            "note": (
                "Live preview unavailable — showing static MANIFEST estimate. "
                f"Stack is auto-destroyed after {ttl_hours} hours."
            ),
        })

    def _live_estimate(self, emulation_type: str, region: str, user_id: str) -> dict | None:
        """
        Run the worker-side pulumi preview estimate and block on its result.

        Returns None on any failure (timeout, worker error, missing role) so the
        caller can fall back to the MANIFEST figures.

        Args:
            emulation_type: Emulation package name.
            region:         AWS region to price for.
            user_id:        Requesting user's UUID (for the STS role assumption).

        Returns:
            The estimate dict from cost_estimator, or None on failure.
        """
        from .tasks import estimate_emulation_cost  # noqa: PLC0415

        try:
            task = estimate_emulation_cost.apply_async(
                args=[emulation_type, region, user_id], queue="enterprise",
            )
            return task.get(timeout=self._ESTIMATE_TIMEOUT_SECONDS, propagate=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Live cost estimate failed for %s: %s", emulation_type, exc)
            return None


class EmulationTechniquesView(APIView):
    """
    Return the MITRE ATT&CK technique data for an emulation type.

    GET /api/emulations/<emulation_type>/techniques/

    Returns the kill-chain attack path and full MITRE mappings directly from
    the MANIFEST.  No filesystem reads — data is served from the in-memory
    registry catalogue.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, emulation_type: str) -> Response:
        """
        Return attack path and MITRE mappings for emulation_type.

        Args:
            request:        DRF request.
            emulation_type: URL path parameter — emulation package name.

        Returns:
            200 with technique data, or 404 if emulation_type is unknown.
        """
        entry, err = _get_emulation_or_404(emulation_type)
        if err:
            return err

        return Response({
            "emulationType": emulation_type,
            "displayName": entry.get("display_name", emulation_type),
            "attackPath": entry.get("attack_path", []),
            "mitreMappings": entry.get("mitre_mappings", []),
            "techniqueCount": entry.get("technique_count", 0),
        })


class EmulationDetectionsView(APIView):
    """
    Return SIGMA and KQL detection rules for an emulation type.

    GET /api/emulations/<emulation_type>/detections/

    Reads .yml (SIGMA) and .kql (KQL) files from the emulation's detections/
    subdirectory.  File contents are returned verbatim as strings — the frontend
    renders them in CodeBlock components.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, emulation_type: str) -> Response:
        """
        Read and return detection files for emulation_type.

        Args:
            request:        DRF request.
            emulation_type: URL path parameter — emulation package name.

        Returns:
            200 with sigma and kql rule lists, or 404 if emulation_type is unknown.
        """
        entry, err = _get_emulation_or_404(emulation_type)
        if err:
            return err

        detections_path = entry.get("detections_path")
        if not detections_path:
            return Response({
                "emulationType": emulation_type,
                "sigma": [],
                "kql": [],
                "totalCount": 0,
            })

        detections_dir = Path(detections_path)
        sigma_rules: list[dict] = []
        kql_rules: list[dict] = []

        for filename in sorted(entry.get("detection_files", [])):
            filepath = detections_dir / filename
            try:
                content = filepath.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning("Could not read detection file %s: %s", filepath, exc)
                continue

            rule = {"title": filename, "code": content}

            if filename.endswith(".yml"):
                sigma_rules.append(rule)
            elif filename.endswith(".kql"):
                kql_rules.append(rule)

        return Response({
            "emulationType": emulation_type,
            "displayName": entry.get("display_name", emulation_type),
            "sigma": sigma_rules,
            "kql": kql_rules,
            "totalCount": len(sigma_rules) + len(kql_rules),
            "formats": f"SIGMA ({len(sigma_rules)}) · KQL ({len(kql_rules)})",
        })


class EmulationPlaybookView(APIView):
    """
    Return the IR playbook for an emulation type.

    GET /api/emulations/<emulation_type>/playbook/

    Reads PLAYBOOK.md from the emulation package directory and returns its
    raw markdown content.  The frontend renders it as structured steps.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, emulation_type: str) -> Response:
        """
        Read and return the PLAYBOOK.md for emulation_type.

        Args:
            request:        DRF request.
            emulation_type: URL path parameter — emulation package name.

        Returns:
            200 with playbook markdown content, or 404 if not found.
        """
        entry, err = _get_emulation_or_404(emulation_type)
        if err:
            return err

        detections_path = entry.get("detections_path")
        if detections_path:
            # detections/ is one level below the package root.
            package_dir = Path(detections_path).parent
        else:
            # Fall back: derive from EMULATIONS_BASE_DIR env var.
            base = EMULATIONS_BASE_DIR
            if not base:
                return Response(
                    {"detail": "EMULATIONS_BASE_DIR is not configured on this server."},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )
            package_dir = Path(base) / emulation_type

        playbook_path = package_dir / "PLAYBOOK.md"
        if not playbook_path.exists():
            return Response(
                {"detail": f"No playbook found for '{emulation_type}'."},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            content = playbook_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Could not read playbook for %s: %s", emulation_type, exc)
            return Response(
                {"detail": "Playbook could not be read."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({
            "emulationType": emulation_type,
            "displayName": entry.get("display_name", emulation_type),
            "content": content,
        })


# ── Lifecycle views ───────────────────────────────────────────────────────────

class EmulationDeployView(APIView):
    """
    Deploy a new enterprise emulation stack.

    POST /api/emulations/deploy/
    Body: { "emulation_type": "scarleteel", "stack_name": "scarleteel-himan10" }

    Enforces one-active-stack-per-user.  Returns 409 if the user already has a
    non-terminal emulation stack.
    """

    permission_classes = [IsEnterpriseUser]

    _ACTIVE_STATUSES = [
        Stack.Status.DEPLOYING,
        Stack.Status.EC2_BOOTING,
        Stack.Status.READY_FOR_ATTACK,
        Stack.Status.ATTACKING,
        Stack.Status.ATTACK_COMPLETE,
    ]

    def post(self, request: Request) -> Response:
        """
        Validate the request, enforce concurrency limit, create a Stack,
        and enqueue the deploy Celery task.

        Args:
            request: DRF request with emulation_type and stack_name.

        Returns:
            202 Accepted with stack_id, or 400/409 on error.
        """
        serializer = DeployEmulationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        emulation_type = serializer.validated_data["emulation_type"]
        stack_name = serializer.validated_data["stack_name"]

        active = Stack.objects.filter(
            owner=request.user,
            status__in=self._ACTIVE_STATUSES,
            emulation_type__isnull=False,
        ).exclude(emulation_type="").first()

        if active:
            return Response(
                {
                    "detail": (
                        f"You already have an active emulation stack ({active.name}, "
                        f"status: {active.status}). Destroy it before deploying a new one."
                    ),
                    "stackId": str(active.id),
                },
                status=status.HTTP_409_CONFLICT,
            )

        entry = get_emulation(emulation_type)
        manifest = entry.get("manifest", entry) if entry else {}
        ttl_hours = manifest.get("default_ttl_hours", 4)

        stack = Stack.objects.create(
            name=stack_name,
            owner=request.user,
            status=Stack.Status.DEPLOYING,
            emulation_type=emulation_type,
            expires_at=timezone.now() + timedelta(hours=ttl_hours),
        )

        from .tasks import deploy_emulation_stack  # noqa: PLC0415
        task = deploy_emulation_stack.apply_async(args=[str(stack.id)], queue="enterprise")

        stack.task_id = task.id
        stack.save(update_fields=["task_id", "updated_at"])

        logger.info(
            "Emulation deploy enqueued: user=%s type=%s stack=%s task=%s",
            request.user.username, emulation_type, stack.name, task.id,
        )

        return Response(
            {"stackId": str(stack.id), "stackName": stack.name},
            status=status.HTTP_202_ACCEPTED,
        )


class EmulationRunListView(ListAPIView):
    """
    List the requesting user's emulation runs, newest first.

    GET /api/emulations/runs/?status=running,pending

    Powers the Operations pages: Active Runs requests the non-terminal statuses
    (running, pending) and Results requests the terminal ones (completed,
    failed). The optional `status` query param accepts a comma-separated list
    and filters status__in; unknown values are ignored. Results are always
    scoped to request.user so one user cannot see another user's runs.
    """

    permission_classes = [IsEnterpriseUser]
    serializer_class = EmulationRunListSerializer

    def get_queryset(self):
        """
        Return the user's runs, optionally narrowed by a status filter.

        Returns:
            EmulationRun queryset filtered to the requesting user (and to the
            requested statuses when a valid `status` param is supplied),
            ordered by the model default (-created_at).
        """
        queryset = (
            EmulationRun.objects
            .select_related("stack")
            .filter(triggered_by=self.request.user)
        )

        status_param = self.request.query_params.get("status")
        if status_param:
            valid = {choice[0] for choice in EmulationRun.Status.choices}
            statuses = [
                s.strip() for s in status_param.split(",")
                if s.strip() in valid
            ]
            if statuses:
                queryset = queryset.filter(status__in=statuses)

        return queryset


class EmulationRunDetailView(APIView):
    """
    Poll the status of an EmulationRun.

    GET /api/emulations/<run_id>/

    Returns the full EmulationRun record including phase progress and
    stdout/stderr output.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, run_id: str) -> Response:
        """
        Return the EmulationRun with the given UUID.

        Args:
            request: DRF request.
            run_id:  UUID string of the EmulationRun.

        Returns:
            200 with run data, or 404 if not found or not owned by caller.
        """
        try:
            run = EmulationRun.objects.select_related("stack").get(
                id=run_id,
                triggered_by=request.user,
            )
        except EmulationRun.DoesNotExist:
            return Response(
                {"detail": "Emulation run not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(EmulationRunSerializer(run).data)


class EmulationAttackView(APIView):
    """
    Trigger the attack phase against a ready enterprise emulation stack.

    POST /api/emulations/<stack_id>/attack/

    The stack must be in READY_FOR_ATTACK status.  Creates an EmulationRun
    record and enqueues run_emulation_attack in the enterprise queue.
    """

    permission_classes = [IsEnterpriseUser]

    def post(self, request: Request, stack_id: str) -> Response:
        """
        Validate stack state and enqueue the attack task.

        Args:
            request:  DRF request.
            stack_id: UUID string of the Stack to attack.

        Returns:
            202 Accepted with runId, or 404/409 on error.
        """
        try:
            stack = Stack.objects.get(id=stack_id, owner=request.user)
        except Stack.DoesNotExist:
            return Response(
                {"detail": "Stack not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if stack.status != Stack.Status.READY_FOR_ATTACK:
            return Response(
                {
                    "detail": (
                        f"Stack must be in 'ready_for_attack' status to trigger attack. "
                        f"Current status: {stack.status}."
                    )
                },
                status=status.HTTP_409_CONFLICT,
            )

        entry = get_emulation(stack.emulation_type)
        manifest = entry.get("manifest", entry) if entry else {}

        run = EmulationRun.objects.create(
            stack=stack,
            emulation_type=stack.emulation_type,
            status=EmulationRun.Status.PENDING,
            phase_total=manifest.get("phase_count", 0),
            triggered_by=request.user,
        )

        run_emulation_attack.apply_async(args=[str(run.id)], queue="enterprise")

        logger.info(
            "Emulation attack enqueued: user=%s stack=%s run=%s",
            request.user.username, stack_id, run.id,
        )

        return Response(
            {"runId": str(run.id), "stackId": stack_id},
            status=status.HTTP_202_ACCEPTED,
        )


class EmulationDestroyView(APIView):
    """
    Manually destroy an enterprise emulation stack before TTL expiry.

    POST /api/emulations/<stack_id>/destroy/
    """

    permission_classes = [IsEnterpriseUser]

    # Only block if already destroying — all other statuses are forcibly destroyable
    # so that users can recover from stuck deploying / attacking stacks.
    _BUSY_STATUSES = [Stack.Status.DESTROYING]

    def post(self, request: Request, stack_id: str) -> Response:
        """
        Validate stack state and enqueue destroy_emulation_stack.

        Args:
            request:  DRF request.
            stack_id: UUID string of the Stack to destroy.

        Returns:
            202 Accepted, or 404/409 on error.
        """
        try:
            stack = Stack.objects.get(id=stack_id, owner=request.user)
        except Stack.DoesNotExist:
            return Response(
                {"detail": "Stack not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if stack.status in self._BUSY_STATUSES:
            return Response(
                {"detail": f"Stack is currently {stack.status}. Wait for it to finish."},
                status=status.HTTP_409_CONFLICT,
            )

        destroy_emulation_stack.apply_async(args=[str(stack.id)], queue="enterprise")

        logger.info(
            "Emulation destroy enqueued: user=%s stack=%s",
            request.user.username, stack_id,
        )

        return Response(
            {"detail": "Destroy queued.", "stackId": stack_id},
            status=status.HTTP_202_ACCEPTED,
        )
