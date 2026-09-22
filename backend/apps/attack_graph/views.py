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

from . import graph_query, graph_search
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


# Why a scan has no graph, in the user's terms. All four are 404s — the
# resource genuinely is not there — but they are four different situations and
# only one of them is fixed by running a new scan. Collapsing them into one
# string would tell someone watching a scan that is running right now to go run
# a scan.
GRAPH_UNAVAILABLE = (
    "This scan has no stored graph. Scans run before this feature shipped do "
    "not have one — run a new scan to get it."
)
GRAPH_PENDING = "This scan is still running. Its graph is stored when it finishes."
GRAPH_FAILED = "This scan failed, so no graph was stored."


class _ScanGraphView(APIView):
    """
    Shared resolution for the three graph endpoints.

    One place that answers "does this user own a scan with a usable graph",
    because three copies of an ownership check is three places for one of them
    to drift into a global lookup.
    """

    permission_classes = [HasScoutConnection]

    def _resolve(self, request: Request, scan_id: str):
        """
        Returns (graph_dict, None) or (None, error Response).

        Scoped to the requesting user, matching ScoutScanDetailView: a 404 for
        someone else's scan is the correct answer and does not confirm the id
        exists. The ownership filter is inside this method and nowhere else,
        so there is one place to read to know the three endpoints are scoped.

        The graph itself comes through graph_search's LRU, so a hit skips both
        the SELECT of a multi-MB jsonb column and psycopg's parse of it. The
        status row is still read every time — it is three small columns, and
        it is what decides which of the four 404s to send.
        """
        scan = (
            ScoutScan.objects
            .filter(id=scan_id, user=request.user)
            .only("id", "status", "error_message")
            .first()
        )
        if scan is None:
            return None, Response(
                {"detail": "No such scan."}, status=status.HTTP_404_NOT_FOUND,
            )

        graph = graph_search.graph_dict_for_scan(
            str(scan_id),
            lambda: (
                ScoutScan.objects
                .filter(id=scan_id, user=request.user)
                .values_list("graph", flat=True)
                .first()
            ),
        )
        if not graph:
            if scan.status in (ScoutScan.Status.PENDING, ScoutScan.Status.RUNNING):
                detail, code = GRAPH_PENDING, "GRAPH_PENDING"
            elif scan.status == ScoutScan.Status.FAILED:
                detail = scan.error_message or GRAPH_FAILED
                code = "GRAPH_FAILED"
            else:
                detail, code = GRAPH_UNAVAILABLE, "GRAPH_UNAVAILABLE"
            return None, Response(
                {"detail": detail, "code": code},
                status=status.HTTP_404_NOT_FOUND,
            )
        return graph, None


class ScoutScanGraphNodesView(_ScanGraphView):
    """
    Search this scan's graph nodes.

    GET /api/attack-graph/scan/<scan_id>/graph/nodes/?q=<term>
    Returns:
      200 — { nodes: [...] }, at most graph_search.MAX_NODE_RESULTS
      404 — no such scan, or the scan has no stored graph
    """

    def get(self, request: Request, scan_id: str) -> Response:
        """Return matching nodes. No rehydrate — see graph_search's docstring."""
        graph, error = self._resolve(request, scan_id)
        if error is not None:
            return error
        return Response(
            {"nodes": graph_search.search_nodes(graph, request.query_params.get("q", ""))},
        )


class ScoutScanGraphEntityView(_ScanGraphView):
    """
    One entity's full record.

    GET /api/attack-graph/scan/<scan_id>/graph/entity/?id=<node id>
    Returns:
      200 — the entity
      400 — `id` missing, or not a node in this graph
      404 — no such scan, or the scan has no stored graph

    `id` is a query parameter, not a path segment: node ids contain "/" (which
    Django's default str converter excludes) and are not always ARNs at all —
    a SERVICE node is "lambda.amazonaws.com" and PUBLIC is "*".
    """

    def get(self, request: Request, scan_id: str) -> Response:
        """Return one node's record."""
        graph, error = self._resolve(request, scan_id)
        if error is not None:
            return error
        node_id = request.query_params.get("id", "")
        if not node_id:
            return Response(
                {"detail": "An 'id' query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        entity = graph_search.get_entity(graph, node_id)
        if entity is None:
            return Response(
                {"detail": f"No entity '{node_id}' in this scan's graph."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(entity)


class ScoutScanGraphPathView(_ScanGraphView):
    """
    Paths between two entities in this scan's graph.

    GET /api/attack-graph/scan/<scan_id>/graph/path/?src=<id>&dst=<id>
    Returns:
      200 — { src, dst, max_depth, edge_types, nodes, paths, truncated, search_capped }
      400 — src or dst missing, or not a node in this graph
      404 — no such scan, or the scan has no stored graph

    Exact node ids, not fuzzy tokens: both pickers are backed by
    /graph/nodes/, so the client already has an exact id. Scout's CLI-side
    token-matching helper (scout/chains/builder.py) is deliberately not
    used — its warnings are CLI copy and its suffix match is unbounded.
    """

    def get(self, request: Request, scan_id: str) -> Response:
        """Run the query and return its result, truncation flags included."""
        graph, error = self._resolve(request, scan_id)
        if error is not None:
            return error

        src = request.query_params.get("src", "")
        dst = request.query_params.get("dst", "")
        if not src or not dst:
            return Response(
                {"detail": "Both 'src' and 'dst' query parameters are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        known = graph_search.node_ids(graph)
        unknown = [i for i in (src, dst) if i not in known]
        if unknown:
            return Response(
                {"detail": f"Not an entity in this scan's graph: {', '.join(unknown)}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # iter_paths' `if node_id == dst and path` never yields a zero-length
        # path, so this would otherwise come back as an ordinary empty result
        # and the panel would say "no escalation path found from alice to
        # alice within 10 hops" — which is true, useless, and reads like a
        # finding. The pickers do not stop a user choosing the same entity
        # twice, so it is stopped here.
        if src == dst:
            return Response(
                {"detail": "Pick two different entities — a path needs somewhere to go."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(graph_query.query_paths(graph, str(scan_id), src, dst))
