"""
Reading the stored graph — search, entity lookup, and hop assembly.

Pure on purpose. config/settings/ci.py installs six packages and Scout is not
one of them, so a module that imports scout.chains.builder is a module CI
cannot load and therefore cannot defend. Everything here works on the plain
dict Graph.to_dict() produced; graph_query.py holds the half that needs a real
scout.graph.Graph and defers its imports.

Not rehydrating is part of the performance answer, not all of it.
Graph.from_dict() walks every node and edge and rebuilds two adjacency
indexes; /graph/nodes/ is an autocomplete, so doing that per keystroke would
rebuild a multi-MB graph on every character typed. Scout reached the same
conclusion for its own viewer — see scout/graph/neighborhood.py, which
traverses the serialized dict rather than the object.

The other two terms are easy to miss because they are not in this file:

- the SELECT of a multi-MB jsonb column, and psycopg deserializing it into a
  Python dict, happen per request whether or not anything rehydrates. That is
  what graph_dict_for_scan() below caches, and why the cache lives here rather
  than only in graph_query.
- search_nodes uses heapq.nsmallest, not sort. The short-query branch does not
  filter at all, and an autocomplete opened on focus sends q="" — a full sort
  there is a sort of every node in the account to return fifty of them.
"""

import heapq
import json
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

# A hard cap, not a page size: this feeds a picker, not a browse view. An
# unbounded q="" on a large account is otherwise the whole node list.
MAX_NODE_RESULTS = 50

# Matches graph_query._GRAPH_CACHE_SIZE, and the two caches are deliberately
# separate: this one holds the parsed dict (what search and entity lookup
# read), that one holds the rehydrated Graph (what the traversal needs). A
# worker running against four scans therefore holds up to four of each —
# budget for both, not one.
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
    /graph/nodes/, which is an autocomplete. Caching only the rehydrated Graph
    (graph_query.graph_for_scan) would leave the search path paying full price
    per keystroke while appearing to be "the cheap one".

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

    Here rather than in graph_query.py because it needs no Scout, and the
    split in this app is "stdlib goes in the file CI can import". Scout has
    its own (scout/viz.py:66) against an 8MB ceiling; this one exists so the
    number can be taken from a stored row without importing Scout at all.
    """
    return len(json.dumps(graph_dict))
