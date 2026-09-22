"""
The path query, against a real scout.graph.Graph.

Gated: Scout is not installed under config.settings.ci, so this module runs
locally (backend/venv-dev) and skips in CI — the same arrangement
apps/emulations/tests/test_access_contract.py:103 uses for DRF. What CI *can*
hold about this feature lives in test_graph_search.py, deliberately, including
the certainty regression; nothing load-bearing is only here.
"""

import unittest

from django.test import SimpleTestCase

try:
    from scout.graph.schema import Edge, EdgeType, Graph, Node, NodeType
    HAS_SCOUT = True
except ImportError:  # Scout is not installed under config.settings.ci
    HAS_SCOUT = False

from apps.attack_graph import graph_query

ALICE = "arn:aws:iam::123456789012:user/alice"
DEPLOY = "arn:aws:iam::123456789012:role/deploy"
ADMIN = "arn:aws:iam::123456789012:role/admin"
BUCKET = "arn:aws:s3:::secrets"
FUNC = "arn:aws:lambda:ap-south-1:123456789012:function:billing"
ISLAND = "arn:aws:iam::123456789012:role/island"


def _graph_dict():
    """
    alice -> deploy -> admin -> {(s3) secrets, (lambda) billing}, plus an
    unreachable role.

    The lambda leg is not decoration: its node carries category "compute"
    (what ingest/resources.py:240 writes for a lambda) while its edge carries
    no category at all (what attack_surface/build.py:124 emits). That is the
    exact shape where reading the category off the edge instead of the node
    silently downgrades the hop to "resource_access".
    """
    g = Graph()
    g.add_node(Node(id=ALICE, type=NodeType.IAM_USER, name="alice",
                    account_id="123456789012"))
    g.add_node(Node(id=DEPLOY, type=NodeType.IAM_ROLE, name="deploy",
                    account_id="123456789012"))
    g.add_node(Node(id=ADMIN, type=NodeType.IAM_ROLE, name="admin",
                    account_id="123456789012"))
    g.add_node(Node(id=ISLAND, type=NodeType.IAM_ROLE, name="island",
                    account_id="123456789012"))
    g.add_node(Node(id=BUCKET, type=NodeType.RESOURCE, name="secrets",
                    account_id="123456789012",
                    properties={"resource_type": "s3", "category": "data"}))
    g.add_node(Node(id=FUNC, type=NodeType.RESOURCE, name="billing",
                    account_id="123456789012",
                    properties={"resource_type": "lambda",
                                "category": "compute"}))
    g.add_edge(Edge(ALICE, DEPLOY, EdgeType.CAN_ASSUME, "sts:AssumeRole"))
    g.add_edge(Edge(DEPLOY, ADMIN, EdgeType.PRIVESC_TO, "PassRole+lambda",
                    properties={"category": "passrole", "service": "lambda",
                                "conditional": {"gating": [
                                    {"klass": "deny_may_apply"}]}}))
    g.add_edge(Edge(ADMIN, BUCKET, EdgeType.CAN_ACCESS_RESOURCE,
                    "s3:GetObject", properties={"category": "data"}))
    # No `category` on the edge — the attack-surface shape.
    g.add_edge(Edge(ADMIN, FUNC, EdgeType.CAN_ACCESS_RESOURCE,
                    "lambda:UpdateFunctionCode",
                    properties={"kind": "public_policy", "via": "resource_policy"}))
    return g.to_dict()


def _two_path_graph_dict():
    """alice reaches admin two ways: directly, and via deploy."""
    g = Graph.from_dict(_graph_dict())
    g.add_edge(Edge(ALICE, ADMIN, EdgeType.CAN_ASSUME, "sts:AssumeRole"))
    return g.to_dict()


@unittest.skipUnless(HAS_SCOUT, "scout is not installed under config.settings.ci")
class QueryPathsTests(SimpleTestCase):
    def setUp(self):
        graph_query.clear_graph_cache()
        self.graph = _graph_dict()

    def test_it_finds_an_identity_to_identity_path(self):
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ADMIN)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["hop_count"], 2)

    def test_it_finds_a_path_that_ends_at_a_resource(self):
        # The default edge-type list is [PRIVESC_TO, CAN_ASSUME], under which
        # this returns nothing and the UI says "no path found" — a false
        # statement, since the traversal never looked at a resource edge.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["steps"][-1]["to"], BUCKET)

    def test_a_resource_hop_gets_scouts_resource_mechanism(self):
        # _mechanism_for has no branch for CAN_ACCESS_RESOURCE and would label
        # it "direct_iam"; _resource_reach_chains uses these instead.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET)
        self.assertEqual(result["paths"][0]["steps"][-1]["mechanism"],
                         "resource_access")

    def test_the_resource_category_is_read_off_the_node_not_the_edge(self):
        # The lambda edge carries no `category` (the attack_surface/build.py
        # shape) while its node says "compute". Reading the edge alone yields
        # the "data" default and labels this "resource_access", while the
        # ranked-chains view — which reads the node, builder.py:581-583 —
        # labels the same edge "resource_control". One grant rendering two
        # ways is the defect this asserts against; note that an assertion
        # built on a "data" fixture cannot detect it, because "data" is also
        # the fallback.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, FUNC)
        self.assertEqual(result["paths"][0]["steps"][-1]["mechanism"],
                         "resource_control")

    def test_a_conditional_hop_survives_the_real_traversal(self):
        # The CI-side version of this is in test_graph_search.py. This one
        # proves the wiring, end to end, with a real Scout edge.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ADMIN)
        hop = result["paths"][0]["steps"][1]
        self.assertEqual(hop["certainty"], "conditional")
        self.assertEqual(hop["action"], "PassRole+lambda")

    def test_no_path_is_an_empty_list_with_the_flags_clear(self):
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ISLAND)
        self.assertEqual(result["paths"], [])
        self.assertFalse(result["truncated"])
        self.assertFalse(result["search_capped"])

    def test_the_response_names_what_was_traversed(self):
        # "No path found" is only true of the edge types actually followed, so
        # the UI has to be able to say which.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ISLAND)
        self.assertEqual(result["edge_types"], graph_query.QUERY_EDGE_TYPE_NAMES)
        self.assertEqual(result["max_depth"], graph_query.MAX_QUERY_DEPTH)

    def test_nodes_cover_every_id_the_steps_reference(self):
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET)
        referenced = set()
        for path in result["paths"]:
            for step in path["steps"]:
                referenced |= {step["from"], step["to"]}
        self.assertTrue(referenced <= {n["id"] for n in result["nodes"]})

    def test_the_nodes_carry_real_types_not_the_grey_fallback(self):
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET)
        by_id = {n["id"]: n for n in result["nodes"]}
        self.assertEqual(by_id[ALICE]["type"], "user")
        self.assertEqual(by_id[ALICE]["node_type"], "IAM_USER")

    def test_search_capped_is_reported_when_the_budget_ends_the_search(self):
        # A bailed-out BFS that looks like "nothing is reachable" is the worst
        # available wrong answer — scout/chains/builder.py:1043 says so about
        # its own reachable_from, and this endpoint must not reintroduce it.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ISLAND,
                                         max_visited=1)
        self.assertTrue(result["search_capped"])

    def test_search_capped_is_false_when_a_bounded_search_simply_finished(self):
        # The inverse, and the one that matters in practice: this graph is
        # exhausted long before the budget, so claiming otherwise would put a
        # permanent "there may be paths we did not find" banner on an answer
        # that is complete. An over-eager capping signal is a quieter bug than
        # a missing one and lasts longer.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ISLAND)
        self.assertFalse(result["search_capped"])

    def test_search_capped_is_reported_even_when_paths_were_found(self):
        # Finding some paths says nothing about whether the walk completed —
        # the budget runs out one dequeue after the bucket is reached, with
        # the lambda still queued. The old "infer it from a second walk"
        # approach could not report this case at all: it only asked the
        # question when fewer paths than the cap came back.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET,
                                         max_visited=4)
        self.assertEqual(len(result["paths"]), 1)
        self.assertTrue(result["search_capped"])

    def test_truncated_is_reported_when_more_paths_exist_than_are_returned(self):
        # Two real paths, one asked for — not max_paths=0, which would assert
        # truncation against an empty list and a UI string ("showing the 0
        # shortest") that has no meaning.
        result = graph_query.query_paths(_two_path_graph_dict(), "scan-2",
                                         ALICE, ADMIN, max_paths=1)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["paths"]), 1)
        # BFS order, so the one kept is the shortest — which is what the
        # panel's "showing the N shortest" claims.
        self.assertEqual(result["paths"][0]["hop_count"], 1)

    def test_the_cache_returns_the_same_graph_object_for_one_scan(self):
        first = graph_query.graph_for_scan("scan-1", self.graph)
        second = graph_query.graph_for_scan("scan-1", self.graph)
        self.assertIs(first, second)

    def test_the_cache_evicts_beyond_its_size(self):
        first = graph_query.graph_for_scan("scan-1", self.graph)
        for i in range(2, 7):
            graph_query.graph_for_scan(f"scan-{i}", self.graph)
        self.assertIsNot(graph_query.graph_for_scan("scan-1", self.graph), first)


@unittest.skipUnless(HAS_SCOUT, "scout is not installed under config.settings.ci")
class IterPathsParityTests(SimpleTestCase):
    """
    _iter_paths_capped is a copy of Scout's iter_paths. Hold it to the original.

    Copying was the deliberate choice (see the module docstring): the capping
    signal depends on iter_paths' own pruning, so re-deriving it from a
    separate walk means maintaining a second model of rules that live
    upstream. The cost of copying is drift, and this is what catches it — a
    Scout release that changes the traversal fails here, by name, rather than
    on a user's query.
    """

    def setUp(self):
        self.graph = Graph.from_dict(_two_path_graph_dict())
        self.edge_types = [EdgeType(n) for n in graph_query.QUERY_EDGE_TYPE_NAMES]

    def _find_paths(self, **kwargs):
        from scout.chains.builder import find_paths  # noqa: PLC0415
        return find_paths(self.graph, ALICE, ADMIN, edge_types=self.edge_types,
                          **kwargs)

    def test_it_yields_exactly_what_find_paths_yields(self):
        mine, _ = graph_query._iter_paths_capped(
            self.graph, ALICE, ADMIN, max_depth=10, edge_types=self.edge_types,
            max_paths=50, max_visited=50_000)
        theirs = self._find_paths(max_depth=10, max_paths=50, max_visited=50_000)
        self.assertEqual([[e.key() for e in p] for p in mine],
                         [[e.key() for e in p] for p in theirs])

    def test_it_prunes_at_max_depth_the_same_way(self):
        # The divergence that matters most: without the depth prune the copy
        # visits states the original never does, and every extra visit pushes
        # the capping signal toward a false positive.
        mine, _ = graph_query._iter_paths_capped(
            self.graph, ALICE, ADMIN, max_depth=1, edge_types=self.edge_types,
            max_paths=50, max_visited=50_000)
        theirs = self._find_paths(max_depth=1, max_paths=50, max_visited=50_000)
        self.assertEqual(len(mine), len(theirs))
        self.assertEqual(len(mine), 1)

    def test_it_stops_at_max_paths_the_same_way(self):
        mine, _ = graph_query._iter_paths_capped(
            self.graph, ALICE, ADMIN, max_depth=10, edge_types=self.edge_types,
            max_paths=1, max_visited=50_000)
        self.assertEqual(len(mine), 1)


@unittest.skipUnless(HAS_SCOUT, "scout is not installed under config.settings.ci")
class ScoutHelperContractTests(SimpleTestCase):
    """
    The three private helpers this module borrows from Scout.

    Underscore-private in scout/chains/builder.py, so a Scout upgrade can
    rename them. Failing here names the cause; failing at runtime happens on a
    user's query.
    """

    def test_the_helpers_are_importable(self):
        from scout.chains.builder import (  # noqa: PLC0415
            _concrete_api, _concrete_resource_reach, _mechanism_for,
        )
        self.assertTrue(callable(_mechanism_for))
        self.assertTrue(callable(_concrete_api))
        self.assertTrue(callable(_concrete_resource_reach))

    def test_concrete_resource_reach_tolerates_a_missing_node(self):
        # _hop_from_edge passes graph.get(edge.target) straight through, which
        # is None for an edge whose target was never added as a node.
        from scout.chains.builder import _concrete_resource_reach  # noqa: PLC0415
        from apps.attack_graph.tests.test_graph_search import _FakeEdge  # noqa: PLC0415
        self.assertIsInstance(
            _concrete_resource_reach(_FakeEdge(ALICE, BUCKET, "s3:GetObject", {}), None),
            list,
        )
