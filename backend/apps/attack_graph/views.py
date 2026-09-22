"""
Views for the attack_graph app.

ScoutScanTriggerView — start a scan.
ScoutScanListView    — the user's scan history.
ScoutScanDetailView  — one scan, for polling and for viewing a past result.
"""

import logging

from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ScoutScan, active_scans
from .permissions import HasScoutConnection
from .serializers import ScoutScanDetailSerializer, ScoutScanListSerializer

logger = logging.getLogger(__name__)


class ScoutScanTriggerView(APIView):
    """
    Start an Attack Graph scan.

    POST /api/attack-graph/scan/
    Returns:
      202 — { scanId: "..." }
      403 — no audit role connected
      409 — this user already has a scan in flight
    """

    permission_classes = [HasScoutConnection]

    def post(self, request: Request) -> Response:
        """
        Enforce one scan at a time, create the row, and enqueue the task.

        The enterprise worker runs two tasks at a time alongside Pulumi deploys
        that take 20-27 minutes. Without this guard, a user clicking Run Scan
        repeatedly queues a full account read per click behind them.

        active_scans() rather than a status filter: a scan whose worker was
        killed by the hard time limit never reaches a terminal status, and a
        status filter would refuse this user every future scan with no way to
        clear it. See attack_graph.models.active_scans.

        Two simultaneous POSTs can both pass this check and both create a row.
        The same read-then-create race exists in EmulationDeployView and has
        the same cost — one extra queued task, not a correctness problem — so
        it is left as it is rather than fixed differently here.
        """
        active = active_scans(request.user).first()
        if active:
            return Response(
                {
                    "detail": (
                        "A scan is already running. Wait for it to finish before "
                        "starting another."
                    ),
                    "scanId": str(active.id),
                },
                status=status.HTTP_409_CONFLICT,
            )

        scan = ScoutScan.objects.create(user=request.user)

        from .tasks import run_scout_scan  # noqa: PLC0415
        task = run_scout_scan.apply_async(args=[str(scan.id)], queue="enterprise")

        scan.task_id = task.id
        scan.save(update_fields=["task_id"])

        logger.info(
            "Attack graph scan enqueued: user=%s scan=%s task=%s",
            request.user.username, scan.id, task.id,
        )

        return Response({"scanId": str(scan.id)}, status=status.HTTP_202_ACCEPTED)


class ScoutScanListView(ListAPIView):
    """
    List the requesting user's scans, newest first.

    GET /api/attack-graph/scan/
    """

    permission_classes = [HasScoutConnection]
    serializer_class = ScoutScanListSerializer

    def get_queryset(self):
        """Return only this user's scans."""
        # Deferring the graph column: this list is unpaginated — every scan
        # the user has ever run — and get_state already forces `result` per
        # row. Without it, one history-strip load pulls every stored graph out
        # of Postgres. Keeping `graph` out of Meta.fields stops DRF
        # *rendering* it; only this stops Django *fetching* it.
        return ScoutScan.objects.filter(user=self.request.user).defer("graph")


class ScoutScanDetailView(APIView):
    """
    One scan, with its result envelope.

    GET /api/attack-graph/scan/<scan_id>/
    Returns:
      200 — the scan
      404 — no such scan belonging to this user
    """

    permission_classes = [HasScoutConnection]

    def get(self, request: Request, scan_id: str) -> Response:
        """
        Return one scan the requesting user owns.

        Scoped to the user rather than looked up globally: a 404 for someone
        else's scan is the correct answer, and it does not confirm the id exists.
        """
        # Deferring the graph column: AttackGraphHub polls this every 3s
        # while a scan runs. The graph is served by the /graph/ endpoints,
        # which fetch it deliberately and narrowly; nothing on this path
        # needs it.
        scan = (
            ScoutScan.objects.filter(id=scan_id, user=request.user)
            .defer("graph")
            .first()
        )
        if scan is None:
            return Response(
                {"detail": "No such scan."}, status=status.HTTP_404_NOT_FOUND,
            )
        return Response(ScoutScanDetailSerializer(scan).data)
