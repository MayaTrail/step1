"""
Reading the stored graph: search, entity lookup, reach, and hop assembly.

Pure on purpose. Scout runs as its own service and is never installed in
this backend, so everything here works on the plain dict Scout's
Graph.to_dict() produced and the scan task stored. reach_from answers "what can
this identity become" by walking that dict; it needs no Scout code because
Scout writes each escalation edge's API calls (and, from v0.2.0, its mechanism
name) onto the edge when it builds the graph.

Not rehydrating is part of the performance answer, not all of it.
Graph.from_dict() walks every node and edge and rebuilds two adjacency
indexes; /graph/nodes/ is an autocomplete, so doing that per keystroke would
rebuild a multi-MB graph on every character typed. Scout reached the same
conclusion for its own viewer — see scout/graph/neighborhood.py, which
traverses the serialized dict rather than the object.

The other two terms are easy to miss because they are not in this file:

- the SELECT of a multi-MB jsonb column, and psycopg deserializing it into a
  Python dict, happen per request whether or not anything rehydrates. That is
  what graph_dict_for_scan() below caches.
- search_nodes uses heapq.nsmallest, not sort. The short-query branch does not
  filter at all, and an autocomplete opened on focus sends q="" — a full sort
  there is a sort of every node in the account to return fifty of them.
"""

import heapq
import json
from collections import OrderedDict
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from .envelope import _conditional_summary, _step

# A hard cap, not a page size: this feeds a picker, not a browse view. An
# unbounded q="" on a large account is otherwise the whole node list.
MAX_NODE_RESULTS = 50

# The reach list loads every user and role once and filters in the browser,
# so this is a ceiling for unusually large accounts, not a page size.
IDENTITY_NODE_TYPES = ("IAM_USER", "IAM_ROLE")
MAX_IDENTITY_RESULTS = 2000

# The reach view walks escalation edges only, the same rule Scout's own chain
# builder follows. A CAN_ASSUME edge means only that the role's trust policy
# names the caller; when the caller may also call sts:AssumeRole, Scout adds a
# PRIVESC_TO edge of category "assume". Following CAN_ASSUME would report role
# assumptions AWS can still refuse, and CAN_PASS_ROLE alone is not a step
# anyone can take (Scout adds the PRIVESC_TO only when a launch is possible).
REACH_EDGE_TYPE = "PRIVESC_TO"

# Scout's own traversal budget. Counted in identities expanded, so a dense
# account cannot make one request expensive.
MAX_REACH_VISITED = 50_000

# Every reached identity carries its path, so the list is capped. Sorted worst
# first, so a cap drops the least severe rows.
MAX_REACH_RESULTS = 500

# How bad an identity is, from Scout's own node flags, worst first.
REACH_LEVELS = ("admin", "self", "other")

# The parsed graph dicts of the last few scans, per web process. Each can be
# several MB, so a process holds at most this many.
_DICT_CACHE_SIZE = 4
_DICT_CACHE: "OrderedDict[str, dict[str, Any]]" = OrderedDict()

# Scout's NodeType -> the lowercase vocabulary envelope._node() produces by
# parsing an ARN, which is what the frontend's NODE_CATEGORY colours on
# (AttackChainGraph.tsx). Remapping NODE_CATEGORY to Scout's names instead
# would touch the chain view for no gain, and ARN parsing cannot produce these
# at all for SERVICE ("lambda.amazonaws.com") or PUBLIC ("*") — they have no
# ARN to parse. Scout's raw NodeType travels alongside as `node_type`, because
# that is the key the icon lookup needs.
_ARN_KIND_BY_NODE_TYPE = {
    "IAM_USER": "user",
    "IAM_ROLE": "role",
    "IAM_GROUP": "group",
    "AWS_ACCOUNT": "account",
    "SERVICE": "service",
    "FEDERATED": "federated",
    "PUBLIC": "public",
    "EXTERNAL_ACCOUNT": "external",
    "RESOURCE": "resource",
    "UNKNOWN": "other",
}

# Identities sort first in a picker. A search for "alice" whose first row is an
# S3 bucket buries the identity the user is almost always after.
_SORT_RANK = {"IAM_USER": 0, "IAM_ROLE": 0, "IAM_GROUP": 0}
_DEFAULT_RANK = 1


def chain_node(node: dict[str, Any]) -> dict[str, Any]:
    """
    One graph node in the frontend's existing ChainNode shape.

    `type` stays in the ARN-parsed vocabulary so the chain view's colouring
    works unchanged; `node_type` and `name` are new optional fields carrying
    what only the real graph knows. Never returns an empty label — an
    unlabelled box is one a reader cannot act on, the same rule
    envelope._node() follows.
    """
    node_id = node.get("id") or ""
    node_type = node.get("type") or "UNKNOWN"
    name = node.get("name") or ""
    return {
        "id": node_id,
        "arn": node_id,
        "type": _ARN_KIND_BY_NODE_TYPE.get(node_type, "other"),
        "label": name or node_id or "unknown",
        "node_type": node_type,
        "name": name,
    }


def _sort_key(node: dict[str, Any]) -> tuple[int, str, str]:
    """Identities first, then by name, then by id — so the same query twice
    returns the same list. Dict insertion order is not a stable contract when
    the graph is rebuilt by a later scan."""
    return (
        _SORT_RANK.get(node.get("type") or "", _DEFAULT_RANK),
        (node.get("name") or "").lower(),
        node.get("id") or "",
    )


def search_nodes(
    graph_dict: dict[str, Any], q: str, limit: int = MAX_NODE_RESULTS,
) -> list[dict[str, Any]]:
    """
    Nodes whose id or name contains `q`, capped and deterministically ordered.

    A `q` under two characters is not an error: it returns the head of the same
    ordering. An autocomplete opened on focus sends an empty q, and answering
    that with nothing reads as "this account has no entities" rather than
    "start typing".
    """
    needle = (q or "").strip().lower()
    nodes = graph_dict.get("nodes") or []
    if len(needle) < 2:
        matched = nodes
    else:
        matched = [
            n for n in nodes
            if needle in (n.get("id") or "").lower()
            or needle in (n.get("name") or "").lower()
        ]
    # nsmallest, not sort: the short-query branch does not filter at all, so an
    # autocomplete opened on focus (q="") would otherwise fully sort every node
    # in the account to return 50 of them. nsmallest is O(n log limit) and
    # returns the same head of the same total order.
    return [chain_node(n) for n in heapq.nsmallest(limit, matched, key=_sort_key)]


def get_entity(graph_dict: dict[str, Any], node_id: str) -> dict[str, Any] | None:
    """One entity's full record, or None when the graph has no such node."""
    for node in graph_dict.get("nodes") or []:
        if node.get("id") == node_id:
            return {
                "id": node.get("id") or "",
                "type": node.get("type") or "UNKNOWN",
                "name": node.get("name") or "",
                "account_id": node.get("account_id") or "",
                "properties": dict(node.get("properties") or {}),
            }
    return None


def node_ids(graph_dict: dict[str, Any]) -> set[str]:
    """Every node id, for validating a query's src/dst before traversing."""
    return {n.get("id") or "" for n in graph_dict.get("nodes") or []}


def identity_level(node: dict[str, Any]) -> str:
    """
    How much an identity can already do, from the flags Scout sets on it.

    "admin" when it holds administrator access, "self" when it can make
    itself an administrator, otherwise "other".
    """
    properties = node.get("properties") or {}
    if properties.get("already_admin"):
        return "admin"
    if properties.get("self_escalation"):
        return "self"
    return "other"


def reach_counts(graph_dict: dict[str, Any]) -> dict[str, tuple[int, int]]:
    """
    For every node, how many identities reach_from would report it reaching,
    and how many of those are or can make themselves administrators.

    The identity list shows each identity's result before it is picked, so
    this runs for the whole graph in one pass instead of one search per
    identity. A search per identity re-walks the same edges again and again:
    on an account where many identities reach an administrator, that is
    identities times edges, which is minutes, not milliseconds.

    How: identities that can reach each other (a cycle of escalations) reach
    exactly the same set, so they are first collapsed into one group
    (Tarjan's strongly connected components). The groups form a graph with no
    cycles, and Tarjan finishes a group only after every group it points to,
    so each group's set is the union of its successors' sets, built once.
    Sets are Python ints used as bitmasks: one bit per node, so a union is a
    single `|` on big integers.

    Returns:
        {node id: (reached, reached that lead to administrator access)}. The
        counts are exact; reach_from stops at MAX_REACH_VISITED, so on an
        account beyond that budget it can list fewer.
    """
    ids: dict[str, int] = {}
    successors: list[set[int]] = []

    def index(node_id: str) -> int:
        """The node's bit position, assigned on first sight."""
        if node_id not in ids:
            ids[node_id] = len(ids)
            successors.append(set())
        return ids[node_id]

    for node in graph_dict.get("nodes") or []:
        index(node.get("id") or "")
    for edge in graph_dict.get("edges") or []:
        if edge.get("type") == REACH_EDGE_TYPE:
            source = index(edge.get("source") or "")
            successors[source].add(index(edge.get("target") or ""))

    admin_mask = 0
    for node in graph_dict.get("nodes") or []:
        if identity_level(node) != "other":
            admin_mask |= 1 << ids[node.get("id") or ""]

    # Iterative Tarjan: a recursive one overflows Python's stack on a long
    # chain of roles. `work` holds (node, iterator over its successors).
    count = len(ids)
    order = [-1] * count
    low = [0] * count
    on_stack = [False] * count
    stack: list[int] = []
    group_of = [-1] * count
    group_members: list[int] = []
    group_below: list[int] = []
    counter = 0
    for start in range(count):
        if order[start] != -1:
            continue
        work = [(start, iter(successors[start]))]
        order[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack[start] = True
        while work:
            node, pending = work[-1]
            advanced = False
            for nxt in pending:
                if order[nxt] == -1:
                    order[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack[nxt] = True
                    work.append((nxt, iter(successors[nxt])))
                    advanced = True
                    break
                if on_stack[nxt]:
                    low[node] = min(low[node], order[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] != order[node]:
                continue
            # `node` roots a finished group. Every group it points to was
            # finished before it, so their sets are already complete.
            group = len(group_members)
            popped = []
            while True:
                member = stack.pop()
                on_stack[member] = False
                group_of[member] = group
                popped.append(member)
                if member == node:
                    break
            members = 0
            below = 0
            for member in popped:
                members |= 1 << member
                for nxt in successors[member]:
                    other = group_of[nxt]
                    if other != group:
                        below |= group_members[other] | group_below[other]
            group_members.append(members)
            group_below.append(below)

    counts = {}
    for node_id, position in ids.items():
        group = group_of[position]
        members = group_members[group]
        # Everyone in a group reaches everyone else in it. reach_from never
        # lists the origin itself, so the node's own bit is cleared.
        reached = (group_below[group] | members) & ~(1 << position)
        counts[node_id] = (reached.bit_count(), (reached & admin_mask).bit_count())
    return counts


def list_identities(
    graph_dict: dict[str, Any], limit: int = MAX_IDENTITY_RESULTS,
) -> tuple[list[dict[str, Any]], bool]:
    """
    Every user and role in the graph, for the reach list.

    Returns:
        (nodes, truncated): ChainNodes in the same order search_nodes uses,
        each with its `level`, how many identities it reaches (`reaches`) and
        how many of those lead to administrator access (`reaches_admin`), and
        whether the account had more than `limit`.
    """
    identities = [
        n for n in graph_dict.get("nodes") or []
        if n.get("type") in IDENTITY_NODE_TYPES
    ]
    head = heapq.nsmallest(limit, identities, key=_sort_key)
    counts = reach_counts(graph_dict)
    nodes = []
    for n in head:
        reaches, reaches_admin = counts.get(n.get("id") or "", (0, 0))
        nodes.append({
            **chain_node(n), "level": identity_level(n),
            "reaches": reaches, "reaches_admin": reaches_admin,
        })
    return nodes, len(identities) > limit


def _is_conditional(edge: dict[str, Any]) -> bool:
    """Whether Scout found a condition that gates this edge."""
    properties = edge.get("properties") or {}
    return _conditional_summary(properties.get("conditional"))[0] == "conditional"


def _reach_step(edge: dict[str, Any], hop_number: int) -> dict[str, Any]:
    """
    One stored escalation edge as a step, the shape ranked chains use.

    Scout v0.2.0 writes the mechanism name onto the edge. A graph stored by an
    earlier release has only the category, which is the same name for most
    mechanisms; a few differ ("trust" where a chain says "trust_rewrite"), and
    the frontend names those plainly rather than with a sentence.
    """
    properties = edge.get("properties") or {}
    mechanism = properties.get("mechanism") or properties.get("category") or ""
    hop = hop_dict(
        SimpleNamespace(**edge), hop_number, mechanism,
        properties.get("concrete_api_sequence") or [],
    )
    return _step(hop)


def reach_from(
    graph_dict: dict[str, Any], origin: str, *, max_visited: int = MAX_REACH_VISITED,
) -> dict[str, Any]:
    """
    Every identity `origin` can become, each with the shortest way there.

    Breadth first, one layer of steps at a time, so an identity is always
    reached first by a shortest path. Within a layer the same identity can be
    reached over several edges; the one whose path has the fewest conditional
    steps wins, so the path shown is the easiest of the shortest. Only one path
    per identity is kept: listing every path grows combinatorially, and the
    question this answers is "what", not "in how many ways".

    Returns:
        origin / origin_level: the starting identity and its level.
        reached: {node, level, steps} per identity, worst level first, then
            fewest steps, then name. At most MAX_REACH_RESULTS.
        truncated: how many reached identities were left off the list.
        search_capped: the visit budget ran out, so the list may be missing
            identities. Never phrased as "unreachable" when true.
    """
    nodes = {n.get("id"): n for n in graph_dict.get("nodes") or []}
    out_edges: dict[str, list[dict[str, Any]]] = {}
    for edge in graph_dict.get("edges") or []:
        if edge.get("type") == REACH_EDGE_TYPE:
            out_edges.setdefault(edge.get("source") or "", []).append(edge)

    # conditional_steps doubles as the visited set: an identity in it was
    # reached in an earlier layer (or is the origin), by a shorter path.
    conditional_steps = {origin: 0}
    via: dict[str, dict[str, Any]] = {}
    frontier = [origin]
    expanded = 0
    search_capped = False
    while frontier and not search_capped:
        layer: dict[str, tuple[int, dict[str, Any]]] = {}
        for node_id in frontier:
            if expanded >= max_visited:
                search_capped = True
                break
            expanded += 1
            for edge in out_edges.get(node_id, ()):
                target = edge.get("target") or ""
                if target in conditional_steps:
                    continue
                cost = conditional_steps[node_id] + _is_conditional(edge)
                best = layer.get(target)
                if best is None or cost < best[0]:
                    layer[target] = (cost, edge)
        for target, (cost, edge) in layer.items():
            conditional_steps[target] = cost
            via[target] = edge
        # Sorted so the same graph always yields the same paths.
        frontier = sorted(layer)

    reached = []
    for target in via:
        edges = []
        node_id = target
        while node_id in via:
            edges.append(via[node_id])
            node_id = via[node_id].get("source") or ""
        edges.reverse()
        node = nodes.get(target) or {"id": target, "type": "UNKNOWN"}
        reached.append({
            "node": chain_node(node),
            "level": identity_level(node),
            "steps": [_reach_step(e, i) for i, e in enumerate(edges, start=1)],
        })
    reached.sort(key=lambda r: (
        REACH_LEVELS.index(r["level"]), len(r["steps"]),
        r["node"]["label"].lower(), r["node"]["id"],
    ))

    origin_node = nodes.get(origin) or {"id": origin, "type": "UNKNOWN"}
    return {
        "origin": chain_node(origin_node),
        "origin_level": identity_level(origin_node),
        "reached": reached[:MAX_REACH_RESULTS],
        "truncated": max(0, len(reached) - MAX_REACH_RESULTS),
        "search_capped": search_capped,
    }


def chain_nodes_for_steps(
    graph_dict: dict[str, Any], steps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    A ChainNode for every id the given steps reference.

    Without this the frontend's toGraph synthesizes {type: 'other', label: id}
    for any id it sees only inside a step (chainGraph.ts) — which, for a query
    result, is every id. The whole path then renders grey and labelled with raw
    ARNs. An id the graph does not carry still gets a node rather than being
    dropped: a missing endpoint is a hole in the picture, which is worse than
    an unstyled box.
    """
    by_id = {n.get("id"): n for n in graph_dict.get("nodes") or []}
    wanted: list[str] = []
    for step in steps:
        for key in ("from", "to"):
            node_id = step.get(key)
            if node_id and node_id not in wanted:
                wanted.append(node_id)
    return [
        chain_node(by_id.get(node_id) or {"id": node_id, "type": "UNKNOWN"})
        for node_id in wanted
    ]


def hop_dict(
    edge: Any, hop_number: int, mechanism: str, concrete_api_sequence: list[str],
) -> dict[str, Any]:
    """
    One hop, in the shape envelope._step consumes.

    Takes the edge duck-typed (.source / .target / .method / .properties) and
    the already-computed mechanism and API sequence, because deciding those two
    needs Scout and the rest does not — that split is what lets the certainty
    regression test run in CI.

    Field-for-field identical to the Hop scout/chains/builder.py builds at
    :1174. Carrying `action` and `conditional` is the entire point: Scout's
    render_path() emits neither, so a hop routed through it reaches _step with
    no method and no gating and renders "deterministic" even when the
    ranked-chains view shows the same edge as conditional.

    Note that only six of these keys survive: envelope._step emits exactly
    from / to / mechanism / action / concrete_api_sequence / detail /
    certainty / conditional_reason, so hop_number, catalog_path_ids,
    granted_by, granted_by_overflow and bounded_by are dropped one call later
    and never cross the wire. They are kept because full Hop parity is what
    makes this swappable for Scout's own Hop.to_dict(), and because a `_step`
    that carries provenance is the obvious next change — not because anything
    reads them today.

    Read-only on `edge.properties`, and it has to stay that way: unlike
    Node.to_dict(), Edge.to_dict() hands out the live dict by reference
    (scout/graph/schema.py:78), so mutating it here would edit the cached
    Graph that every later query on this scan reuses.
    """
    properties = getattr(edge, "properties", None) or {}
    return {
        "hop_number": hop_number,
        "mechanism": mechanism,
        "action": getattr(edge, "method", "") or "",
        "source_arn": getattr(edge, "source", "") or "",
        "target_arn": getattr(edge, "target", "") or "",
        "concrete_api_sequence": list(concrete_api_sequence or []),
        "catalog_path_ids": list(properties.get("path_ids") or []),
        "conditional": properties.get("conditional"),
        "granted_by": properties.get("granted_by") or [],
        "granted_by_overflow": properties.get("granted_by_overflow", 0),
        "bounded_by": properties.get("bounded_by"),
    }


def graph_dict_for_scan(scan_id: str, load: Callable[[], dict[str, Any] | None]):
    """
    This scan's stored graph dict, reusing the last few.

    `load` is called only on a miss, so a cache hit skips the SELECT as well
    as the parse. Both matter, and the parse is the one that is easy to miss:
    the column is jsonb, so psycopg deserializes the whole blob into a Python
    dict on every fetch — comparable to Graph.from_dict(), and paid by
    /graph/nodes/, which is an autocomplete, so without the cache the search
    path would pay that price per keystroke.

    Keyed on scan_id alone: a completed scan is immutable — nothing writes
    `graph` after the task sets it — so there is nothing to invalidate.

    A miss that loads None is NOT cached: that is the "scan has no graph yet"
    state, which for a running scan stops being true without anything here
    hearing about it.
    """
    cached = _DICT_CACHE.get(scan_id)
    if cached is not None:
        _DICT_CACHE.move_to_end(scan_id)
        return cached
    loaded = load()
    if loaded:
        _DICT_CACHE[scan_id] = loaded
        while len(_DICT_CACHE) > _DICT_CACHE_SIZE:
            _DICT_CACHE.popitem(last=False)
    return loaded


def clear_graph_dict_cache() -> None:
    """Drop every cached dict. For tests; nothing in the request path calls it."""
    _DICT_CACHE.clear()


def payload_bytes(graph_dict: dict[str, Any]) -> int:
    """
    Serialized size of a stored graph — the storage measurement from Task 0.

    Scout has its own (scout/viz.py:66) against an 8MB ceiling; this one
    exists so the number can be taken from a stored row without Scout.
    """
    return len(json.dumps(graph_dict))
