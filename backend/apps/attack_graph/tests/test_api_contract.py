"""
The scan endpoints gate on the right connection.

HasAWSConnection is the obvious import and the wrong one: it keys on
is_verified, which the emulation role's verification sets. An organisation
that provisioned only the read-only auditor role would be refused its own
scan, and the failure would look like a bug in the connector rather than a
gate reading the wrong field. DRF is not installed in CI, so this reads the
source rather than exercising the view.
"""

import pathlib

from django.test import SimpleTestCase

BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[3]


class ScanPermissionTests(SimpleTestCase):
    """Which permission class the scan endpoints use."""

    def _source(self, relative):
        path = BACKEND_ROOT / relative
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_the_scan_views_use_the_scout_gate(self):
        source = self._source("apps/attack_graph/views.py")
        self.assertIn("HasScoutConnection", source)

    def test_they_do_not_gate_on_the_emulation_connection(self):
        source = self._source("apps/attack_graph/views.py")
        self.assertNotIn("HasAWSConnection", source)

    def test_the_gate_reads_the_audit_role(self):
        source = self._source("apps/attack_graph/permissions.py")
        self.assertIn("aws_audit_role_arn", source)
        self.assertNotIn("is_verified", source)

    def test_the_trigger_refuses_a_second_concurrent_scan(self):
        # Ten clicks are otherwise ten concurrent GAAD collections on a worker
        # that runs two at a time alongside 20-27 minute Pulumi deploys.
        source = self._source("apps/attack_graph/views.py")
        self.assertIn("HTTP_409_CONFLICT", source)

    def test_both_409_guards_read_the_same_staleness_rule(self):
        # The trigger and the audit disconnect both refuse while a scan is in
        # flight, and both must agree on when a scan has stopped being in
        # flight. A status-only filter in either one is a permanent lockout
        # after a worker crash: the hard time_limit kills the process, so the
        # row never reaches a terminal status and nothing clears it.
        for module in ("apps/attack_graph/views.py", "apps/connectors/views.py"):
            source = self._source(module)
            self.assertIn("active_scans", source, module)
            self.assertNotIn("status__in=ACTIVE_SCAN_STATUSES", source, module)


class ScanTaskStoresTheGraphTests(SimpleTestCase):
    """
    The task keeps Scout's graph instead of discarding it.

    pipeline.run() has always returned (report, graph) and the task bound the
    second value to `_graph` — the underscore that says "intentionally
    unused". Reading the source rather than running the task: tasks.py imports
    boto3 and Scout, neither of which is installed under config.settings.ci.
    """

    def _tasks_source(self):
        path = BACKEND_ROOT / "apps/attack_graph/tasks.py"
        return path.read_text(encoding="utf-8")

    def test_the_graph_return_value_is_no_longer_discarded(self):
        source = self._tasks_source()
        self.assertNotIn("report, _graph = pipeline.run", source)
        self.assertIn("report, graph = pipeline.run", source)

    def test_the_completion_update_writes_the_graph(self):
        source = self._tasks_source()
        self.assertIn("graph=graph.to_dict()", source)


class GraphEndpointContractTests(SimpleTestCase):
    """
    What the three graph endpoints must and must not do.

    Source-reading, like the rest of this file: DRF is not installed under
    config.settings.ci, so the views cannot be exercised. These hold the
    decisions that are expensive to get wrong and cheap to check textually.
    """

    def _source(self, relative):
        path = BACKEND_ROOT / relative
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def _class_body(self, source, name):
        """
        One class's source, from its `class X` line to the next top-level one.

        Needed because a substring search over a whole file cannot tell "the
        new views do this" from "some view in this file already did this" —
        which is how an assertion about a new class ends up passing off an old
        one and never failing again.
        """
        start = source.index(f"class {name}")
        rest = source[start + 1:]
        end = rest.find("\nclass ")
        return rest if end == -1 else rest[:end]

    GRAPH_VIEWS = (
        "_ScanGraphView",
        "ScoutScanGraphNodesView",
        "ScoutScanGraphEntityView",
        "ScoutScanGraphPathView",
    )

    def test_node_ids_travel_as_query_parameters_not_path_segments(self):
        # arn:aws:iam::1:role/foo contains a slash, which Django's default str
        # converter excludes, and a PUBLIC node's id is literally "*". A path
        # segment cannot carry either.
        urls = self._source("apps/attack_graph/urls.py")
        self.assertIn("graph/entity/", urls)
        self.assertNotIn("graph/entity/<", urls)
        self.assertNotIn("<str:arn>", urls)
        self.assertNotIn("<path:arn>", urls)

    def test_all_three_routes_are_registered(self):
        urls = self._source("apps/attack_graph/urls.py")
        for route in ("graph/nodes/", "graph/entity/", "graph/path/"):
            self.assertIn(route, urls)

    def test_the_graph_views_use_the_scout_gate(self):
        # Asserted positively, on the base class. The earlier draft of this
        # test asserted `assertNotIn("HasAWSConnection", views)` — an
        # identifier that exists nowhere in this repo, so it could not fail
        # and checked nothing.
        views = self._source("apps/attack_graph/views.py")
        for name in self.GRAPH_VIEWS[1:]:
            self.assertIn(f"class {name}", views)
        self.assertIn(
            "permission_classes = [HasScoutConnection]",
            self._class_body(views, "_ScanGraphView"),
        )
        for name in self.GRAPH_VIEWS[1:]:
            self.assertIn("(_ScanGraphView)", self._class_body(views, name))

    def test_they_scope_the_lookup_to_the_requesting_user(self):
        # Someone else's scan is a 404, which is the correct answer and does
        # not confirm the id exists.
        #
        # Scoped to _ScanGraphView's own body, not the whole file: a plain
        # `assertIn("user=request.user", views)` passes off ScoutScanDetail-
        # View, which has contained that string since before this feature
        # existed — so it would keep passing if all three new views did a
        # global ScoutScan.objects.filter(id=scan_id). A cross-user access
        # check that cannot detect its own absence is worse than none, because
        # it reads like coverage.
        views = self._source("apps/attack_graph/views.py")
        body = self._class_body(views, "_ScanGraphView")
        self.assertEqual(body.count("user=request.user"), 2)   # row + graph loader
        # And nothing else in the three subclasses queries the model at all:
        # one resolver is the point.
        for name in self.GRAPH_VIEWS[1:]:
            self.assertNotIn("ScoutScan.objects", self._class_body(views, name))

    def test_the_four_reasons_a_graph_is_missing_are_told_apart(self):
        # "Run a new scan to get it" is wrong advice for a scan that is
        # running right now, and for one that failed. All four are 404s; only
        # one of them is the pre-feature scan.
        views = self._source("apps/attack_graph/views.py")
        body = self._class_body(views, "_ScanGraphView")
        for code in ("GRAPH_UNAVAILABLE", "GRAPH_PENDING", "GRAPH_FAILED"):
            self.assertIn(code, body)
        self.assertIn("No such scan.", body)

    def test_the_graph_column_is_read_narrowly_and_through_the_cache(self):
        # The counterpart to test_model's deferral test, which owns the "the
        # polled paths must not fetch it" half — not repeated here, because
        # two copies of one string count in two files is two numbers to keep
        # in step. This half: the one path that *does* fetch it pulls the
        # column alone, through the LRU, so a cache hit skips the SELECT and
        # the jsonb parse rather than only the rehydrate.
        body = self._class_body(
            self._source("apps/attack_graph/views.py"), "_ScanGraphView",
        )
        self.assertIn('values_list("graph", flat=True)', body)
        self.assertIn("graph_search.graph_dict_for_scan", body)

    def test_a_query_to_the_same_entity_is_rejected(self):
        # iter_paths never yields a zero-length path, so without this the
        # answer is an empty result rendered as "no escalation path found from
        # alice to alice" — which reads like a finding.
        body = self._class_body(
            self._source("apps/attack_graph/views.py"), "ScoutScanGraphPathView",
        )
        self.assertIn("src == dst", body)

    def test_render_path_is_never_used(self):
        # It drops `action` and `conditional`; every query hop would then
        # render deterministic. See graph_query's module docstring.
        self.assertNotIn("render_path", self._source("apps/attack_graph/graph_query.py"))
        self.assertNotIn("render_path", self._source("apps/attack_graph/views.py"))

    def test_resolve_arn_tokens_is_never_used(self):
        # Its warnings are Scout CLI copy ("--foothold/--target ... matched
        # zero nodes") and its matching is unbounded. The pickers submit exact
        # ids; an unknown one is a 400.
        self.assertNotIn("resolve_arn_tokens",
                         self._source("apps/attack_graph/graph_query.py"))
        self.assertNotIn("resolve_arn_tokens", self._source("apps/attack_graph/views.py"))

    def test_scout_is_not_imported_at_module_scope_in_the_query_module(self):
        # views.py imports graph_query, config/urls.py imports the views, and
        # Django imports the URLconf during system checks. A module-scope Scout
        # import breaks every management command and the CI suite.
        source = self._source("apps/attack_graph/graph_query.py")
        head = source.split("def ", 1)[0]
        self.assertNotIn("from scout", head)
        self.assertNotIn("import scout", head)
