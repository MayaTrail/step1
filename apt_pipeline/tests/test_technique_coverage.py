"""Tests for validators.validate_technique_coverage.

Locks in two recent fixes:
  - MED-4: case-insensitive technique ID matching (lowercase t1078 counts)
  - MED-7: phishing_attack excluded from coverage expectations (documented-only)
"""
from validators import validate_technique_coverage


def _plan(*steps):
    return {"attack_chain": [
        {"technique_id": tid, "execution_context": ctx} for tid, ctx in steps
    ]}


class TestMED4CaseInsensitive:
    def test_uppercase_reference_counts(self):
        r = validate_technique_coverage("# T1078 done", _plan(("T1078", "api_attack")))
        assert r["coverage_pct"] == 100.0

    def test_lowercase_reference_counts(self):
        r = validate_technique_coverage("# t1078 done", _plan(("T1078", "api_attack")))
        assert r["coverage_pct"] == 100.0

    def test_subtechnique_case_insensitive(self):
        r = validate_technique_coverage(
            "# t1110.001 covered",
            _plan(("T1110.001", "api_attack")))
        assert r["coverage_pct"] == 100.0

    def test_mixed_case(self):
        plan = _plan(("T1078", "api_attack"), ("T1110", "api_attack"))
        r = validate_technique_coverage("# T1078 and t1110 both handled", plan)
        assert r["coverage_pct"] == 100.0


class TestMED7PhishingSkipped:
    def test_phishing_not_counted_as_missing(self):
        plan = _plan(
            ("T1078", "api_attack"),
            ("T1566", "phishing_attack"),
        )
        r = validate_technique_coverage("# T1078 done", plan)
        assert r["coverage_pct"] == 100.0
        assert r["missing"] == []
        assert r["valid"]

    def test_all_phishing_is_100_pct(self):
        plan = _plan(
            ("T1566", "phishing_attack"),
            ("T1621", "phishing_attack"),
        )
        r = validate_technique_coverage("", plan)
        assert r["coverage_pct"] == 100.0
        assert r["valid"]
        # Warning names both skipped techniques
        joined = " ".join(r["warnings"])
        assert "T1566" in joined and "T1621" in joined

    def test_phishing_and_host_both_skipped(self):
        plan = _plan(
            ("T1078", "api_attack"),
            ("T1566", "phishing_attack"),
            ("T1486", "host_attack"),
        )
        r = validate_technique_coverage("# T1078", plan)
        assert r["coverage_pct"] == 100.0
        joined = " ".join(r["warnings"])
        assert "phishing_attack" in joined
        assert "host_attack" in joined


class TestCoverageErrors:
    def test_missing_api_technique_errors(self):
        plan = _plan(("T1078", "api_attack"), ("T1110", "api_attack"))
        r = validate_technique_coverage("# only T1078", plan)
        assert r["coverage_pct"] == 50.0
        assert r["missing"] == ["T1110"]
        assert not r["valid"]
        assert any("T1110" in e for e in r["errors"])

    def test_empty_plan_passes(self):
        r = validate_technique_coverage("", {"attack_chain": []})
        assert r["valid"]
        assert r["coverage_pct"] == 100.0
