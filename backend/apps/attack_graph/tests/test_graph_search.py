"""
The stored graph's search, entity lookup and hop assembly.

Pure by design, and that is the point: config/settings/ci.py installs six
packages and Scout is not one of them. Everything a user can get wrong about
this feature — a search that returns a different list twice, a query result
whose nodes render as grey "other" boxes, a conditional hop that reports
itself as deterministic — is decided here, where CI can hold it.

The conditional-certainty test is the load-bearing one. The defect it guards
against (see the 2026-09-22 spec review) was exactly a hop losing its
`conditional` data on the way to _step and every query hop then rendering as
deterministic, contradicting the ranked-chains view about the same edge. A
skipUnless-gated test would reproduce the original silence, so hop_dict takes
a duck-typed edge and this runs with a four-line fake.
"""

import json

from django.test import SimpleTestCase

from apps.attack_graph.envelope import _step
from apps.attack_graph.graph_search import (
    _DICT_CACHE,
    MAX_NODE_RESULTS,
    chain_node,
    chain_nodes_for_steps,
    clear_graph_dict_cache,
    get_entity,
    graph_dict_for_scan,
    hop_dict,
    node_ids,
    payload_bytes,
    search_nodes,
)

ALICE = "arn:aws:iam::123456789012:user/alice"
DEPLOY = "arn:aws:iam::123456789012:role/deploy"
BUCKET = "arn:aws:s3:::alice-backups"
LAMBDA = "lambda.amazonaws.com"

GRAPH = {
    "nodes": [
        {"id": BUCKET, "type": "RESOURCE", "name": "alice-backups",
         "account_id": "123456789012", "properties": {"resource_type": "s3"}},
        {"id": LAMBDA, "type": "SERVICE", "name": "lambda.amazonaws.com",
         "account_id": "", "properties": {}},
        {"id": ALICE, "type": "IAM_USER", "name": "alice",
         "account_id": "123456789012", "properties": {"tags": {"team": "eng"}}},
        {"id": DEPLOY, "type": "IAM_ROLE", "name": "deploy",
         "account_id": "123456789012",
         "properties": {"trust_policy": {"Version": "2012-10-17"}}},
    ],
    "edges": [],
}


class _FakeEdge:
    """Anything with these four attributes is an edge as far as hop_dict cares."""

    def __init__(self, source, target, method, properties):
        self.source = source
        self.target = target
        self.method = method
        self.properties = properties


class ChainNodeTests(SimpleTestCase):
    def test_an_iam_user_maps_to_the_type_the_frontend_colours_on(self):
        # NODE_CATEGORY in AttackChainGraph.tsx keys on "user"/"role"/"group",
        # the lowercase vocabulary envelope._node() produces from an ARN. Scout
        # says IAM_USER. If this mapping is wrong the node renders grey.
        self.assertEqual(chain_node(GRAPH["nodes"][2])["type"], "user")

    def test_an_iam_role_maps_to_role(self):
        self.assertEqual(chain_node(GRAPH["nodes"][3])["type"], "role")

    def test_a_service_node_keeps_scouts_type_for_the_icon_lookup(self):
        node = chain_node(GRAPH["nodes"][1])
        self.assertEqual(node["node_type"], "SERVICE")
        self.assertEqual(node["type"], "service")

    def test_the_label_is_the_name_not_the_raw_id(self):
        self.assertEqual(chain_node(GRAPH["nodes"][0])["label"], "alice-backups")

    def test_a_nameless_node_falls_back_to_its_id(self):
        node = chain_node({"id": "*", "type": "PUBLIC", "name": "",
                           "account_id": "", "properties": {}})
        self.assertEqual(node["label"], "*")


class SearchNodesTests(SimpleTestCase):
    def test_it_matches_on_id_and_on_name(self):
        found = {n["id"] for n in search_nodes(GRAPH, "alice")}
        self.assertEqual(found, {ALICE, BUCKET})

    def test_it_is_case_insensitive(self):
        self.assertEqual(len(search_nodes(GRAPH, "ALICE")), 2)

    def test_identities_sort_before_everything_else(self):
        # A picker whose first row is an S3 bucket buries the identity the user
        # is almost always looking for.
        self.assertEqual(search_nodes(GRAPH, "alice")[0]["id"], ALICE)

    def test_the_order_is_the_same_twice(self):
        self.assertEqual(search_nodes(GRAPH, ""), search_nodes(GRAPH, ""))

    def test_a_short_query_returns_the_head_of_the_list_not_an_error(self):
        # An autocomplete opened on focus sends q="". Returning nothing there
        # reads as "this account has no entities".
        self.assertEqual(len(search_nodes(GRAPH, "")), 4)

    def test_it_caps_results(self):
        big = {"nodes": [
            {"id": f"arn:aws:iam::123456789012:role/r{i}", "type": "IAM_ROLE",
             "name": f"r{i}", "account_id": "1", "properties": {}}
            for i in range(200)
        ], "edges": []}
        self.assertEqual(len(search_nodes(big, "r")), MAX_NODE_RESULTS)

    def test_it_survives_a_scan_whose_graph_has_no_nodes_key(self):
        self.assertEqual(search_nodes({}, "alice"), [])


class GetEntityTests(SimpleTestCase):
    def test_it_returns_the_full_record(self):
        entity = get_entity(GRAPH, DEPLOY)
        self.assertEqual(entity["type"], "IAM_ROLE")
        self.assertEqual(entity["name"], "deploy")
        self.assertEqual(entity["account_id"], "123456789012")
        self.assertIn("trust_policy", entity["properties"])

    def test_an_unknown_id_is_none_not_an_exception(self):
        self.assertIsNone(get_entity(GRAPH, "arn:aws:iam::1:role/nope"))

    def test_node_ids_is_the_validation_set_for_a_query(self):
        self.assertEqual(node_ids(GRAPH), {ALICE, DEPLOY, BUCKET, LAMBDA})


class ChainNodesForStepsTests(SimpleTestCase):
    def test_every_id_a_step_references_gets_a_node(self):
        # Without this the frontend's toGraph synthesizes
        # {type: 'other', label: id} for each one and the whole path renders
        # grey, labelled with raw ARNs.
        steps = [{"from": ALICE, "to": DEPLOY}, {"from": DEPLOY, "to": BUCKET}]
        self.assertEqual({n["id"] for n in chain_nodes_for_steps(GRAPH, steps)},
                         {ALICE, DEPLOY, BUCKET})

    def test_an_id_absent_from_the_graph_still_gets_a_usable_node(self):
        steps = [{"from": ALICE, "to": "arn:aws:iam::1:role/ghost"}]
        nodes = {n["id"]: n for n in chain_nodes_for_steps(GRAPH, steps)}
        self.assertEqual(nodes["arn:aws:iam::1:role/ghost"]["label"],
                         "arn:aws:iam::1:role/ghost")


class HopDictTests(SimpleTestCase):
    def test_a_conditional_edge_stays_conditional_through_step(self):
        # THE regression test. render_path dropped `conditional`, so every
        # query hop rendered "deterministic" while the ranked-chains view
        # showed the same edge as conditional.
        edge = _FakeEdge(ALICE, DEPLOY, "PassRole+lambda",
                         {"conditional": {"gating": [{"klass": "deny_may_apply"}]}})
        step = _step(hop_dict(edge, 1, "passrole_service", ["iam:PassRole"]))
        self.assertEqual(step["certainty"], "conditional")
        self.assertEqual(step["conditional_reason"],
                         "a conditional Deny may block this")

    def test_the_edge_method_survives_as_the_step_action(self):
        # render_path dropped this too; without it `detail` degrades from
        # "PassRole+lambda (passrole_service)" to the bare mechanism.
        edge = _FakeEdge(ALICE, DEPLOY, "PassRole+lambda", {})
        step = _step(hop_dict(edge, 1, "passrole_service", []))
        self.assertEqual(step["action"], "PassRole+lambda")
        self.assertEqual(step["detail"], "PassRole+lambda (passrole_service)")

    def test_an_ungated_edge_is_deterministic(self):
        edge = _FakeEdge(ALICE, DEPLOY, "sts:AssumeRole", {})
        self.assertEqual(_step(hop_dict(edge, 1, "assume_role", []))["certainty"],
                         "deterministic")

    def test_the_hop_has_full_parity_with_scouts_own_hop(self):
        # These five keys do NOT reach the response — _step drops them. The
        # parity is what makes hop_dict swappable for Hop.to_dict() and what
        # makes carrying provenance a later one-line change to _step rather
        # than a re-plumbing. Asserted at this level, not at the endpoint,
        # because the endpoint genuinely does not carry them.
        edge = _FakeEdge(ALICE, DEPLOY, "sts:AssumeRole",
                         {"granted_by": [{"action": "sts:AssumeRole"}],
                          "granted_by_overflow": 3,
                          "bounded_by": {"boundary": "arn:aws:iam::1:policy/b"}})
        hop = hop_dict(edge, 2, "assume_role", [])
        self.assertEqual(hop["hop_number"], 2)
        self.assertEqual(hop["granted_by_overflow"], 3)
        self.assertEqual(hop["bounded_by"]["boundary"], "arn:aws:iam::1:policy/b")
        self.assertNotIn("granted_by", _step(hop))


class PayloadBytesTests(SimpleTestCase):
    def test_it_measures_the_serialized_size(self):
        self.assertEqual(payload_bytes(GRAPH), len(json.dumps(GRAPH)))


class GraphDictCacheTests(SimpleTestCase):
    def setUp(self):
        clear_graph_dict_cache()

    def test_a_hit_does_not_call_the_loader(self):
        # The loader is the DB read plus the jsonb parse. This is the whole
        # point of the cache: /graph/nodes/ is an autocomplete, and without it
        # every debounced keystroke pays both.
        calls = []

        def load():
            calls.append(1)
            return GRAPH

        graph_dict_for_scan("scan-1", load)
        graph_dict_for_scan("scan-1", load)
        self.assertEqual(len(calls), 1)

    def test_it_evicts_beyond_its_size(self):
        for i in range(6):
            graph_dict_for_scan(f"scan-{i}", lambda: GRAPH)
        self.assertEqual(len(_DICT_CACHE), 4)

    def test_an_absent_graph_is_not_cached(self):
        # A running scan's graph is None and stops being None without anything
        # here being told. Caching that would pin "no graph" for this worker
        # until eviction.
        calls = []

        def load():
            calls.append(1)
            return None

        graph_dict_for_scan("scan-x", load)
        graph_dict_for_scan("scan-x", load)
        self.assertEqual(len(calls), 2)
