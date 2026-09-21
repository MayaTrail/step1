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
