"""
What one identity can become, read from a scan's stored graph.

The search is pure, so these run in CI. Each graph is written out by hand, so
each test states exactly which edges exist and the rule under test is the only
thing that can change the answer.
"""

import random
import unittest
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from apps.attack_graph.graph_search import (
    MAX_REACH_RESULTS,
    clear_graph_dict_cache,
    list_identities,
    reach_counts,
    reach_from,
)
from apps.attack_graph.models import ScoutScan

try:
    from rest_framework.test import APIClient
    HAS_DRF = True
except ImportError:  # DRF is not installed under config.settings.ci
    HAS_DRF = False

ACCOUNT = "111122223333"


def _arn(kind, name):
    """An IAM ARN in the test account."""
    return f"arn:aws:iam::{ACCOUNT}:{kind}/{name}"


CI = _arn("role", "ci-deploy")
BUILD = _arn("role", "build-runner")
SIGNER = _arn("role", "artifact-signer")
OPS = _arn("user", "ops-admin")
REPORTING = _arn("user", "svc-reporting")


def _node(arn, node_type="IAM_ROLE", **properties):
    """A stored graph node."""
    return {"id": arn, "type": node_type, "name": arn.rsplit("/", 1)[-1],
            "account_id": ACCOUNT, "properties": properties}


def _edge(source, target, method, category, edge_type="PRIVESC_TO", conditional=None, mechanism=None):
    """A stored edge, with the properties Scout writes onto an escalation edge."""
    properties = {"category": category, "concrete_api_sequence": [f"{method}(x)"]}
    if mechanism:
        properties["mechanism"] = mechanism
    if conditional:
        properties["conditional"] = conditional
    return {"source": source, "target": target, "type": edge_type, "method": method,
            "properties": properties}


GATED = {"gating": [{"key": "aws:SourceIp", "klass": "deny_may_apply"}]}


def _graph(nodes, edges):
    """A stored graph dict."""
    return {"nodes": nodes, "edges": edges}


class ReachTests(SimpleTestCase):
    """reach_from's rules: what it follows, which path it shows, how it ranks."""

    def test_each_identity_comes_with_its_shortest_path(self):
        graph = _graph(
            [_node(CI), _node(BUILD), _node(OPS, "IAM_USER", already_admin=True)],
            [
                _edge(CI, BUILD, "sts:AssumeRole", "assume", mechanism="assume_role"),
                _edge(BUILD, OPS, "iam:CreateAccessKey", "credential", mechanism="credential"),
            ],
        )
        result = reach_from(graph, CI)
        by_id = {r["node"]["id"]: r for r in result["reached"]}
        ops = by_id[OPS]
        self.assertEqual(ops["level"], "admin")
        self.assertEqual([(s["from"], s["to"]) for s in ops["steps"]], [(CI, BUILD), (BUILD, OPS)])
        self.assertEqual([s["mechanism"] for s in ops["steps"]], ["assume_role", "credential"])
        self.assertEqual(ops["steps"][1]["concrete_api_sequence"], ["iam:CreateAccessKey(x)"])
        self.assertEqual(result["origin"]["id"], CI)
        self.assertNotIn(CI, by_id)

    def test_only_escalation_edges_are_followed(self):
        graph = _graph(
            [_node(CI), _node(BUILD), _node(SIGNER)],
            [
                _edge(CI, BUILD, "sts:AssumeRole", "", edge_type="CAN_ASSUME"),
                _edge(CI, SIGNER, "iam:PassRole", "", edge_type="CAN_PASS_ROLE"),
            ],
        )
        self.assertEqual(reach_from(graph, CI)["reached"], [])

    def test_a_shorter_path_wins_over_a_longer_one(self):
        graph = _graph(
            [_node(CI), _node(BUILD), _node(OPS, "IAM_USER")],
            [
                _edge(CI, BUILD, "sts:AssumeRole", "assume"),
                _edge(BUILD, OPS, "iam:CreateAccessKey", "credential"),
                _edge(CI, OPS, "iam:UpdateLoginProfile", "credential"),
            ],
        )
        ops = next(r for r in reach_from(graph, CI)["reached"] if r["node"]["id"] == OPS)
        self.assertEqual([s["action"] for s in ops["steps"]], ["iam:UpdateLoginProfile"])

    def test_among_equally_short_paths_the_one_with_fewer_conditions_wins(self):
        graph = _graph(
            [_node(CI), _node(BUILD), _node(SIGNER), _node(OPS, "IAM_USER")],
            [
                _edge(CI, BUILD, "sts:AssumeRole", "assume", conditional=GATED),
                _edge(CI, SIGNER, "sts:AssumeRole", "assume"),
                _edge(BUILD, OPS, "iam:CreateAccessKey", "credential"),
                _edge(SIGNER, OPS, "iam:CreateAccessKey", "credential"),
            ],
        )
        ops = next(r for r in reach_from(graph, CI)["reached"] if r["node"]["id"] == OPS)
        self.assertEqual([s["to"] for s in ops["steps"]], [SIGNER, OPS])
        self.assertEqual({s["certainty"] for s in ops["steps"]}, {"deterministic"})

    def test_a_conditional_step_says_so(self):
        graph = _graph([_node(CI), _node(BUILD)], [_edge(CI, BUILD, "iam:UpdateAssumeRolePolicy", "trust", conditional=GATED)])
        step = reach_from(graph, CI)["reached"][0]["steps"][0]
        self.assertEqual(step["certainty"], "conditional")

    def test_graphs_stored_before_scout_named_mechanisms_fall_back_to_the_category(self):
        graph = _graph([_node(CI), _node(BUILD)], [_edge(CI, BUILD, "iam:UpdateAssumeRolePolicy", "trust")])
        self.assertEqual(reach_from(graph, CI)["reached"][0]["steps"][0]["mechanism"], "trust")

    def test_worst_first_then_fewest_steps(self):
        graph = _graph(
            [_node(CI), _node(BUILD), _node(SIGNER), _node(REPORTING, "IAM_USER", self_escalation=True),
             _node(OPS, "IAM_USER", already_admin=True, self_escalation=True)],
            [
                _edge(CI, BUILD, "sts:AssumeRole", "assume"),
                _edge(CI, REPORTING, "iam:UpdateLoginProfile", "credential"),
                _edge(BUILD, SIGNER, "sts:AssumeRole", "assume"),
                _edge(SIGNER, OPS, "iam:CreateAccessKey", "credential"),
            ],
        )
        reached = reach_from(graph, CI)["reached"]
        self.assertEqual([r["node"]["id"] for r in reached], [OPS, REPORTING, BUILD, SIGNER])
        self.assertEqual([r["level"] for r in reached], ["admin", "self", "other", "other"])

    def test_cycles_end(self):
        graph = _graph(
            [_node(CI), _node(BUILD)],
            [_edge(CI, BUILD, "sts:AssumeRole", "assume"), _edge(BUILD, CI, "sts:AssumeRole", "assume")],
        )
        self.assertEqual([r["node"]["id"] for r in reach_from(graph, CI)["reached"]], [BUILD])

    def test_an_already_admin_origin_is_reported_as_such(self):
        graph = _graph([_node(OPS, "IAM_USER", already_admin=True)], [])
        result = reach_from(graph, OPS)
        self.assertEqual(result["origin_level"], "admin")
        self.assertEqual(result["reached"], [])
        self.assertFalse(result["search_capped"])

    def test_an_exhausted_budget_is_reported_not_hidden(self):
        graph = _graph(
            [_node(CI), _node(BUILD), _node(SIGNER)],
            [_edge(CI, BUILD, "sts:AssumeRole", "assume"), _edge(BUILD, SIGNER, "sts:AssumeRole", "assume")],
        )
        result = reach_from(graph, CI, max_visited=1)
        self.assertTrue(result["search_capped"])
        self.assertEqual([r["node"]["id"] for r in result["reached"]], [BUILD])

    def test_the_list_is_capped_and_says_by_how_much(self):
        extra = 3
        roles = [_arn("role", f"r{i:04d}") for i in range(MAX_REACH_RESULTS + extra)]
        graph = _graph([_node(CI)] + [_node(r) for r in roles],
                       [_edge(CI, r, "sts:AssumeRole", "assume") for r in roles])
        result = reach_from(graph, CI)
        self.assertEqual(len(result["reached"]), MAX_REACH_RESULTS)
        self.assertEqual(result["truncated"], extra)


class ListIdentitiesTests(SimpleTestCase):
    """The reach picker's options."""

    def test_users_and_roles_only_each_with_its_level(self):
        graph = _graph(
            [_node(CI), _node(OPS, "IAM_USER", already_admin=True), _node("lambda.amazonaws.com", "SERVICE"),
             _node(_arn("group", "devs"), "IAM_GROUP")],
            [],
        )
        nodes, truncated = list_identities(graph)
        self.assertEqual({n["id"]: n["level"] for n in nodes}, {CI: "other", OPS: "admin"})
        self.assertFalse(truncated)

    def test_each_identity_says_what_it_reaches_before_it_is_picked(self):
        graph = _graph(
            [_node(CI), _node(BUILD), _node(OPS, "IAM_USER", already_admin=True), _node(SIGNER)],
            [_edge(CI, BUILD, "sts:AssumeRole", "assume"), _edge(BUILD, OPS, "iam:CreateAccessKey", "credential")],
        )
        nodes, _ = list_identities(graph)
        self.assertEqual(
            {n["id"]: (n["reaches"], n["reaches_admin"]) for n in nodes},
            {CI: (2, 1), BUILD: (1, 1), OPS: (0, 0), SIGNER: (0, 0)},
        )

    def test_a_larger_account_is_cut_and_says_so(self):
        graph = _graph([_node(CI), _node(BUILD), _node(SIGNER)], [])
        nodes, truncated = list_identities(graph, limit=2)
        self.assertEqual(len(nodes), 2)
        self.assertTrue(truncated)


class ReachCountsTests(SimpleTestCase):
    """reach_counts must agree with reach_from, which the identity list promises."""

    def test_counts_match_a_search_from_every_node(self):
        rng = random.Random(7)
        for _ in range(40):
            names = [_arn("role", f"r{i}") for i in range(rng.randint(1, 14))]
            nodes = [
                _node(n, already_admin=rng.random() < 0.15, self_escalation=rng.random() < 0.1)
                for n in names
            ]
            # Dense enough for cycles, self-loops and identities reaching each other.
            edges = [
                _edge(a, b, "sts:AssumeRole", "assume")
                for a in names for b in names if rng.random() < 0.18
            ]
            edges.append(_edge(names[0], names[-1], "iam:PassRole", "pass", edge_type="CAN_PASS_ROLE"))
            graph = _graph(nodes, edges)
            counts = reach_counts(graph)
            for name in names:
                reached = reach_from(graph, name)["reached"]
                admin = sum(1 for r in reached if r["level"] != "other")
                self.assertEqual(counts[name], (len(reached), admin), name)

    def test_a_long_chain_does_not_exhaust_the_stack(self):
        roles = [_arn("role", f"r{i:05d}") for i in range(5000)]
        graph = _graph([_node(r) for r in roles],
                       [_edge(a, b, "sts:AssumeRole", "assume") for a, b in zip(roles, roles[1:])])
        self.assertEqual(reach_counts(graph)[roles[0]], (len(roles) - 1, 0))


@unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")
class ReachEndpointTests(TestCase):
    """GET /graph/reach/: validation, ownership and the linked emulations."""

    GRAPH = _graph(
        [_node(CI), _node(OPS, "IAM_USER", already_admin=True)],
        [_edge(CI, OPS, "iam:CreateAccessKey", "credential", mechanism="credential")],
    )

    def setUp(self):
        clear_graph_dict_cache()
        users = get_user_model().objects
        self.user = users.create_user(
            username="auditor", email="auditor@example.com", password="x",
            aws_audit_role_arn=_arn("role", "scout-audit"),
        )
        self.scan = ScoutScan.objects.create(user=self.user, status=ScoutScan.Status.COMPLETED, graph=self.GRAPH)
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def _get(self, params):
        return self.client.get(f"/api/attack-graph/scan/{self.scan.id}/graph/reach/", params)

    @mock.patch("apps.attack_graph.related.list_detection_summaries", return_value=[])
    @mock.patch("apps.attack_graph.related.list_emulations", return_value=[{
        "name": "backdoor_user", "display_name": "Backdoor User", "tier": "atomic", "platform": "aws",
        "attack_path": [{"aws_actions": ["iam:CreateAccessKey"]}],
    }])
    def test_reached_identities_carry_their_linked_emulations(self, _emulations, _detections):
        response = self._get({"from": CI})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual([r["node"]["id"] for r in body["reached"]], [OPS])
        self.assertEqual([e["id"] for e in body["related"][OPS]["emulations"]], ["backdoor_user"])

    def test_from_is_required_and_must_be_in_the_graph(self):
        self.assertEqual(self._get({}).status_code, 400)
        self.assertEqual(self._get({"from": _arn("role", "nobody")}).status_code, 400)

    def test_someone_elses_scan_is_not_found(self):
        other = get_user_model().objects.create_user(
            username="other", email="other@example.com", password="x",
            aws_audit_role_arn=_arn("role", "scout-audit"),
        )
        self.client.force_authenticate(other)
        self.assertEqual(self._get({"from": CI}).status_code, 404)

    def test_the_identity_list_for_the_picker(self):
        response = self.client.get(f"/api/attack-graph/scan/{self.scan.id}/graph/nodes/", {"kind": "identity"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual({n["id"]: n["level"] for n in body["nodes"]}, {CI: "other", OPS: "admin"})
        self.assertFalse(body["truncated"])
