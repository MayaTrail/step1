"""Unit tests for the manifest-driven readiness helper (pure, no Django/DB)."""

import unittest

from apps.emulations.readiness import (
    DEFAULT_READINESS,
    requires_http_probe,
    resolve_readiness,
)


class ReadinessTests(unittest.TestCase):
    def test_absent_readiness_defaults_to_ec2_http(self):
        r = resolve_readiness({})
        self.assertEqual(r, DEFAULT_READINESS)
        self.assertEqual(r["ip_output"], "vuln_instance_ip")
        self.assertTrue(requires_http_probe(r))

    def test_none_readiness_skips_probe(self):
        r = resolve_readiness({"readiness": {"type": "none"}})
        self.assertEqual(r["type"], "none")
        self.assertFalse(requires_http_probe(r))

    def test_custom_ec2_http_readiness_passthrough(self):
        custom = {"type": "ec2_http", "ip_output": "web_ip", "port": 9000, "path": "/ready"}
        r = resolve_readiness({"readiness": custom})
        self.assertEqual(r, custom)
        self.assertTrue(requires_http_probe(r))


if __name__ == "__main__":
    unittest.main()
