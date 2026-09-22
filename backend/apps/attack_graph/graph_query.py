"""
The on-demand path query over a stored scan graph.

Scout-dependent, and therefore deliberately thin: everything that can be
decided without Scout lives in graph_search.py, which CI can import and test.
Every Scout import here is inside a function (# noqa: PLC0415), matching
tasks.py — views.py imports this module, config/urls.py imports the views, and
Django imports the URL configuration during system checks, so a module-scope
import would drag Scout into every management command and break the CI suite.

Three decisions worth knowing before changing anything here:

1. Scout's render_path() is NOT used. It emits only hop_number / mechanism /
   source_arn / target_arn / concrete_api_sequence, while envelope._step reads
   `action` and `conditional` — so a hop routed through it renders
   "deterministic" for every edge, including ones the ranked-chains view shows
   as conditional. Hops are built from the edges instead, the way
   scout/chains/builder.py:1174 does.
2. The traversed edge types are explicit. Scout's default is
   [PRIVESC_TO, CAN_ASSUME], under which any resource destination returns "no
   path found" — for every bucket, in every account — because the traversal
   never looks at a resource edge. That is a confident false statement, which
   is worse than an error.
3. Truncation is reported, and the traversal is vendored to report it.
   find_paths()/iter_paths() cap silently; a bailed-out BFS that reads as
   "nothing is reachable" is, in Scout's own words about reachable_from, "the
   worst available wrong answer here". _iter_paths_capped below is a
   line-for-line copy of iter_paths (scout/chains/builder.py:970-988) that
   additionally reports whether it exited with a non-empty queue — exactly
   what reachable_from already does for itself at :1043-1047. Copying is the
   cheap option here: inferring the same signal from a second, separate walk
   means writing a second model of iter_paths' pruning, and any divergence in
   that model (a missing depth bound, a missing dst short-circuit) shows up as
   a confident wrong answer rather than an error. IterPathsParityTests holds
   the copy to the original.
"""

import logging
from collections import OrderedDict, deque
from typing import Any

from .envelope import _step
from .graph_search import chain_nodes_for_steps, hop_dict

logger = logging.getLogger(__name__)

# Named rather than EdgeType members so this module has no import-time Scout
# dependency; resolved to real members inside the functions that traverse.
# CAN_PASS_ROLE, MEMBER_OF, DEPENDS_ON and TRIGGERS are excluded on purpose —
# see the spec's edge-type table. In short: a raw CAN_PASS_ROLE edge is added
# whenever iam:PassRole is allowed (scout/privesc/rules.py:399) while the
# PRIVESC_TO edge is added only when a launch variant is actually satisfiable
# (:431), so traversing the raw edge reports paths nobody can walk.
QUERY_EDGE_TYPE_NAMES = ["PRIVESC_TO", "CAN_ASSUME", "CAN_ACCESS_RESOURCE"]

# Matches envelope.MAX_CHAINS. iter_paths yields in BFS order, so these are
# genuinely the shortest paths and "showing the 25 shortest" is accurate.
MAX_QUERY_PATHS = 25

# Scout's own default. Carried in the response so the "within N hops" copy
# cannot drift from the value actually used.
MAX_QUERY_DEPTH = 10

# Scout's own default. The real rail — bounded by nodes visited, so a dense hub
# cannot explode regardless of how many paths are wanted.
MAX_VISITED = 50_000

# Rebuilding a multi-MB graph per request is the cost this avoids; four keeps a
# user running several queries against one scan cheap while bounding resident
# memory per worker process. Keyed on scan_id alone: a completed scan is
# immutable — nothing writes `graph` after the task sets it — so there is no
# invalidation to do and no update timestamp on ScoutScan to key on.
_GRAPH_CACHE_SIZE = 4
_graph_cache: "OrderedDict[str, Any]" = OrderedDict()


def clear_graph_cache() -> None:
    """Drop every cached graph. For tests; nothing in the request path calls it."""
    _graph_cache.clear()


def graph_for_scan(scan_id: str, graph_dict: dict[str, Any]):
    """Rehydrate this scan's graph, reusing the last few."""
    from scout.graph.schema import Graph  # noqa: PLC0415

    cached = _graph_cache.get(scan_id)
    if cached is not None:
        _graph_cache.move_to_end(scan_id)
        return cached
    graph = Graph.from_dict(graph_dict)
    _graph_cache[scan_id] = graph
    while len(_graph_cache) > _GRAPH_CACHE_SIZE:
        _graph_cache.popitem(last=False)
    return graph


def _hop_from_edge(graph, edge, hop_number: int) -> dict[str, Any]:
    """
    One hop, with the mechanism and API sequence Scout would give it.

    Dispatches on edge type because Scout renders a resource hop differently
    from an identity hop, and this query can now produce both: _mechanism_for
    has no branch for CAN_ACCESS_RESOURCE and would label it "direct_iam",
    while _concrete_api has no branch for it at all. The resource arm mirrors
    _resource_reach_chains (scout/chains/builder.py:586-597).
    """
    from scout.chains.builder import (  # noqa: PLC0415
        _concrete_api, _concrete_resource_reach, _mechanism_for,
    )
    from scout.graph.schema import EdgeType  # noqa: PLC0415

    if edge.type is EdgeType.CAN_ACCESS_RESOURCE:
        # graph.get() is None for an edge whose target was never added as a
        # node. _concrete_resource_reach guards for that itself
        # (builder.py:500), and ScoutHelperContractTests holds it to that.
        node = graph.get(edge.target)
        # The NODE's category first, the edge's only as a fallback — the same
        # precedence _resource_reach_chains uses (builder.py:581-583). This is
        # not interchangeable: ingest/resources.py sets `category` on both, but
        # attack_surface/build.py:124 adds CAN_ACCESS_RESOURCE edges carrying
        # none, and ingest/resources.py:20-32 categorises lambda/sns/ecr as
        # "compute" on the node. Reading the edge alone would label a publicly
        # exposed Lambda "resource_access" here while the ranked-chains view
        # labels the same edge "resource_control" — one grant, two
        # contradictory renderings, which is the defect class this whole
        # module's hop assembly exists to avoid.
        category = (
            (node.properties.get("category") if node is not None else None)
            or edge.properties.get("category")
            or "data"
        )
        mechanism = "resource_access" if category == "data" else "resource_control"
        api = _concrete_resource_reach(edge, node)
    else:
        mechanism = _mechanism_for(edge)
        api = _concrete_api(edge)
    return hop_dict(edge, hop_number, mechanism, api)


def _iter_paths_capped(
    graph, src: str, dst: str, *, max_depth: int, edge_types,
    max_paths: int, max_visited: int,
) -> tuple[list, bool]:
    """
    All simple paths src->dst in BFS order, plus whether the budget ran out.

    A verbatim copy of scout.chains.builder.iter_paths (:970-988) with one
    addition: the loop's exit condition is inspected afterwards, so a caller
    can tell "that is all of them" apart from "we stopped looking". This is
    what reachable_from already does for itself (`visit_capped = bool(queue)`,
    :1043-1047) and what iter_paths, returning a bare generator, cannot.

    Copied rather than wrapped because the signal depends on iter_paths' own
    pruning: it does not expand `dst`, and it stops descending at max_depth.
    A separate walk that reconstructs those rules is a second model of the
    first, and every divergence between them surfaces as a confident wrong
    answer — "we stopped looking" on a search that finished. IterPathsParity-
    Tests asserts this yields exactly what find_paths does.

    Returns (paths, search_capped). Note `produced` counts what the generator
    yielded, so a caller wanting N+1 to detect truncation gets an honest
    search_capped for that larger budget too.
    """
    queue = deque([(src, [], {src})])
    produced = visited_count = 0
    out: list = []
    while queue and produced < max_paths and visited_count < max_visited:
        node_id, path, seen = queue.popleft()
        visited_count += 1
        if node_id == dst and path:
            produced += 1
            out.append(path)
            continue
        if len(path) >= max_depth:
            continue
        for edge_type in edge_types:
            for edge in graph.out_edges(node_id, edge_type):
                if edge.target in seen:
                    continue
                queue.append((edge.target, path + [edge], seen | {edge.target}))
    # A non-empty queue means the loop exited on a budget, not on exhaustion.
    # `produced >= max_paths` is the caller's own cap and is reported as
    # `truncated` instead, so only the visit ceiling counts as capped here.
    return out, bool(queue) and visited_count >= max_visited


def query_paths(
    graph_dict: dict[str, Any],
    scan_id: str,
    src: str,
    dst: str,
    *,
    max_depth: int = MAX_QUERY_DEPTH,
    max_paths: int = MAX_QUERY_PATHS,
    max_visited: int = MAX_VISITED,
) -> dict[str, Any]:
    """
    Paths from src to dst, as steps the frontend already knows how to render.

    _iter_paths_capped rather than Scout's find_paths, for two reasons that
    both come down to a capped search being indistinguishable from a complete
    one: taking one more path than wanted tells us whether the cap or the
    graph ended the list, and the vendored loop tells us whether the visit
    budget ended the walk. The two states say different things to a user and
    only one of them is safe to phrase as "no path found".
    """
    from scout.graph.schema import EdgeType  # noqa: PLC0415

    graph = graph_for_scan(scan_id, graph_dict)
    edge_types = [EdgeType(name) for name in QUERY_EDGE_TYPE_NAMES]

    # max_paths + 1: consuming one extra distinguishes "these are all of them"
    # from "there are more". max_visited is passed through unchanged — it is
    # the budget whose exhaustion makes the answer incomplete.
    produced, search_capped = _iter_paths_capped(
        graph, src, dst, max_depth=max_depth, edge_types=edge_types,
        max_paths=max_paths + 1, max_visited=max_visited,
    )
    truncated = len(produced) > max_paths
    produced = produced[:max_paths]

    paths = []
    all_steps: list[dict[str, Any]] = []
    for edges in produced:
        steps = [_step(_hop_from_edge(graph, e, i))
                 for i, e in enumerate(edges, start=1)]
        all_steps.extend(steps)
        paths.append({"hop_count": len(steps), "steps": steps})

    return {
        "src": src,
        "dst": dst,
        "max_depth": max_depth,
        "edge_types": list(QUERY_EDGE_TYPE_NAMES),
        # Not optional: without real types the frontend's toGraph synthesizes
        # a grey "other" node for every id in the path. See
        # graph_search.chain_nodes_for_steps.
        "nodes": chain_nodes_for_steps(graph_dict, all_steps),
        "paths": paths,
        "truncated": truncated,
        "search_capped": search_capped,
    }


def reachable(graph_dict: dict[str, Any], scan_id: str, origin: str) -> dict[str, Any]:
    """
    Everything `origin` can reach — identities, then their resources.

    Not wired to any UI in this iteration. Exposed so the "what can this
    identity reach" view is additive rather than a rewrite, and so its
    visit_capped flag is carried for the same reason search_capped exists
    above.
    """
    from scout.chains.builder import reachable_from  # noqa: PLC0415
    from scout.graph.schema import EdgeType  # noqa: PLC0415

    graph = graph_for_scan(scan_id, graph_dict)
    return reachable_from(
        graph, origin,
        edge_types=[EdgeType(name) for name in QUERY_EDGE_TYPE_NAMES],
        max_visited=MAX_VISITED,
    )
