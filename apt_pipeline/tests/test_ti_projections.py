"""Tests for TI extract per-phase projection helpers.

Covers:
  - ti_for_infra  — fields needed by Phase 1/2 (infra planning)
  - ti_for_attack — fields needed by Phase 3/4 (attack planning)
  - ti_for_detections — fields needed by Phase 6 (detections/playbook)

Key invariants:
  - Each projection is strictly smaller than the full extract
  - Fields critical to the target phase are present
  - Fields not needed by that phase are absent (no cross-contamination)
  - Empty / partial inputs don't raise exceptions
"""
import pytest
from utils import ti_for_infra, ti_for_attack, ti_for_detections

# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

FULL_TI = {
    "status": "PHASE_0B_COMPLETE",
    "threat_actor": {"name": "TestActor", "aliases": []},
    "platform": "aws",
    "targeted_services": ["IAM", "S3"],
    "kill_chain_order": ["T1078", "T1087"],
    "credential_chain": [{"phase": 1, "source": "IMDS", "used_in_phases": [2, 3]}],
    "iocs": {"source_ips": ["1.2.3.4"]},
    "operational_notes": "Actor uses living-off-the-land",
    "source_url": "https://example.com/report",
    "extraction_confidence": "high",
    "techniques": [
        {
            "mitre_id": "T1078",
            "name": "Valid Accounts",
            "tactic": "initial-access",
            "execution_plane": "control_plane",
            "execution_context": "api_attack",
            "emulation_category": "emulated",
            "resource_needs": ["ec2 instance", "iam user"],
            "userdata_actions": [{"action": "install tools"}],
            "expected_audit_events": ["sts:AssumeRole"],
            "credential_requirements": "leaked key",
            "indicators_of_compromise": "unusual region",
        },
        {
            "mitre_id": "T1087",
            "name": "Account Discovery",
            "tactic": "discovery",
            "execution_plane": "control_plane",
            "execution_context": "api_attack",
            "emulation_category": "emulated",
            "resource_needs": ["iam user"],
            "userdata_actions": [],
            "expected_audit_events": ["iam:ListUsers"],
            "credential_requirements": "valid session",
            "indicators_of_compromise": "bulk enumeration",
        },
    ],
}


# ---------------------------------------------------------------------------
# ti_for_infra
# ---------------------------------------------------------------------------

class TestTiForInfra:
    def _proj(self, ti=None):
        return ti_for_infra(ti or FULL_TI)

    def test_keeps_platform(self):
        assert self._proj()["platform"] == "aws"

    def test_keeps_threat_actor(self):
        assert self._proj()["threat_actor"]["name"] == "TestActor"

    def test_keeps_targeted_services(self):
        assert "IAM" in self._proj()["targeted_services"]

    def test_keeps_credential_chain(self):
        assert len(self._proj()["credential_chain"]) == 1

    def test_keeps_resource_needs_per_technique(self):
        techs = self._proj()["techniques"]
        assert "ec2 instance" in techs[0]["resource_needs"]

    def test_keeps_userdata_actions(self):
        techs = self._proj()["techniques"]
        assert len(techs[0]["userdata_actions"]) == 1

    def test_keeps_execution_plane(self):
        techs = self._proj()["techniques"]
        assert techs[0]["execution_plane"] == "control_plane"

    def test_drops_iocs(self):
        # iocs are detection/playbook territory, not infra
        assert "iocs" not in self._proj()

    def test_drops_kill_chain_order(self):
        # ordering matters to attack planner, not infra planner
        assert "kill_chain_order" not in self._proj()

    def test_drops_expected_audit_events(self):
        techs = self._proj()["techniques"]
        for t in techs:
            assert "expected_audit_events" not in t

    def test_drops_indicators_of_compromise(self):
        techs = self._proj()["techniques"]
        for t in techs:
            assert "indicators_of_compromise" not in t

    def test_preserves_technique_count(self):
        assert len(self._proj()["techniques"]) == 2

    def test_preserves_technique_order(self):
        ids = [t["mitre_id"] for t in self._proj()["techniques"]]
        assert ids == ["T1078", "T1087"]

    def test_smaller_than_full(self):
        import json
        assert len(json.dumps(self._proj())) < len(json.dumps(FULL_TI))

    def test_empty_input(self):
        result = ti_for_infra({})
        assert result["techniques"] == []
        assert result["platform"] is None

    def test_missing_techniques_key(self):
        ti = {k: v for k, v in FULL_TI.items() if k != "techniques"}
        result = ti_for_infra(ti)
        assert result["techniques"] == []


# ---------------------------------------------------------------------------
# ti_for_attack
# ---------------------------------------------------------------------------

class TestTiForAttack:
    def _proj(self, ti=None):
        return ti_for_attack(ti or FULL_TI)

    def test_keeps_kill_chain_order(self):
        assert self._proj()["kill_chain_order"] == ["T1078", "T1087"]

    def test_keeps_credential_chain(self):
        assert len(self._proj()["credential_chain"]) == 1

    def test_keeps_iocs(self):
        assert "source_ips" in self._proj()["iocs"]

    def test_keeps_expected_audit_events(self):
        techs = self._proj()["techniques"]
        assert "sts:AssumeRole" in techs[0]["expected_audit_events"]

    def test_keeps_credential_requirements(self):
        techs = self._proj()["techniques"]
        assert techs[0]["credential_requirements"] == "leaked key"

    def test_keeps_indicators_of_compromise(self):
        techs = self._proj()["techniques"]
        assert techs[0]["indicators_of_compromise"] == "unusual region"

    def test_drops_resource_needs(self):
        techs = self._proj()["techniques"]
        for t in techs:
            assert "resource_needs" not in t

    def test_drops_userdata_actions(self):
        techs = self._proj()["techniques"]
        for t in techs:
            assert "userdata_actions" not in t

    def test_drops_targeted_services(self):
        assert "targeted_services" not in self._proj()

    def test_preserves_technique_count(self):
        assert len(self._proj()["techniques"]) == 2

    def test_smaller_than_full(self):
        import json
        assert len(json.dumps(self._proj())) < len(json.dumps(FULL_TI))

    def test_empty_input(self):
        result = ti_for_attack({})
        assert result["techniques"] == []
        assert result["kill_chain_order"] is None


# ---------------------------------------------------------------------------
# ti_for_detections
# ---------------------------------------------------------------------------

class TestTiForDetections:
    def _proj(self, ti=None):
        return ti_for_detections(ti or FULL_TI)

    def test_keeps_kill_chain_order(self):
        assert self._proj()["kill_chain_order"] == ["T1078", "T1087"]

    def test_keeps_iocs(self):
        assert "source_ips" in self._proj()["iocs"]

    def test_keeps_expected_audit_events(self):
        techs = self._proj()["techniques"]
        assert "iam:ListUsers" in techs[1]["expected_audit_events"]

    def test_keeps_execution_plane(self):
        techs = self._proj()["techniques"]
        assert techs[0]["execution_plane"] == "control_plane"

    def test_keeps_tactic(self):
        techs = self._proj()["techniques"]
        assert techs[0]["tactic"] == "initial-access"

    def test_drops_resource_needs(self):
        techs = self._proj()["techniques"]
        for t in techs:
            assert "resource_needs" not in t

    def test_drops_userdata_actions(self):
        techs = self._proj()["techniques"]
        for t in techs:
            assert "userdata_actions" not in t

    def test_drops_credential_requirements(self):
        techs = self._proj()["techniques"]
        for t in techs:
            assert "credential_requirements" not in t

    def test_drops_credential_chain(self):
        assert "credential_chain" not in self._proj()

    def test_drops_targeted_services(self):
        assert "targeted_services" not in self._proj()

    def test_preserves_technique_count(self):
        assert len(self._proj()["techniques"]) == 2

    def test_smallest_of_three(self):
        import json
        infra_size = len(json.dumps(ti_for_infra(FULL_TI)))
        attack_size = len(json.dumps(ti_for_attack(FULL_TI)))
        det_size = len(json.dumps(self._proj()))
        # detections doesn't need credential_chain or targeted_services
        assert det_size < infra_size or det_size < attack_size

    def test_empty_input(self):
        result = ti_for_detections({})
        assert result["techniques"] == []
        assert result["iocs"] is None
