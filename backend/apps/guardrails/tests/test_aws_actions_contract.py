"""
Tests for the aws_actions contract (apps/guardrails/matching.validate_aws_actions).

Two layers, as in apps/emulations/tests/test_readiness.py:

  * Unit tests for the validator on hand-built manifests.
  * A discovery test over every emulation the registry finds, with a ratchet.
    PENDING_AWS_ACTIONS names the emulations still waiting for their
    annotations. Every AWS emulation not on it must comply, so a new emulation
    cannot ship without aws_actions. Every emulation on it must still be
    missing them, so annotating one fails this test until its name is removed.
    The list can only shrink.
"""

from __future__ import annotations

import os
from pathlib import Path

from django.test import SimpleTestCase

from apps.emulations import registry as registry_wrapper
from apps.guardrails.matching import validate_aws_actions

# backend/apps/guardrails/tests/<this file> -> repo root (step1) is parents[4].
_REPO_ROOT = Path(__file__).resolve().parents[4]
_FALLBACK_EMULATIONS_DIR = _REPO_ROOT / "emulations"

# Emulations whose phases do not declare aws_actions yet, recorded on
# 2026-10-01. Remove a name once its MANIFEST is annotated; never add one.
PENDING_AWS_ACTIONS = frozenset({
    "aws_credential_access_ec2_get_password_data",
    "aws_credential_access_ec2_steal_instance_credentials",
    "aws_credential_access_secretsmanager_batch_retrieve_secrets",
    "aws_credential_access_secretsmanager_retrieve_secrets",
    "aws_credential_access_ssm_retrieve_securestring_parameters",
    "aws_defense_evasion_dns_delete_logs",
    "aws_defense_evasion_elbv2_listener_auth_bypass_rule",
    "aws_defense_evasion_rds_modify_public_access",
    "aws_defense_evasion_vpc_remove_flow_logs",
    "aws_defense_evasion_wafv2_disable_web_acl",
    "aws_discovery_ec2_download_user_data",
    "aws_discovery_ec2_enumerate_from_instance",
    "aws_discovery_ses_enumerate",
    "aws_execution_codepipeline_inject_stage",
    "aws_execution_ec2_launch_unusual_instances",
    "aws_execution_ec2_user_data",
    "aws_execution_sagemaker_update_lifecycle_config",
    "aws_execution_ssm_send_command",
    "aws_execution_ssm_start_session",
    "aws_exfiltration_dynamodb_export_to_s3",
    "aws_exfiltration_ec2_security_group_open_port_22_ingress",
    "aws_exfiltration_rds_share_snapshot",
    "aws_exfiltration_sns_external_subscription",
    "aws_impact_bedrock_invoke_model",
    "aws_initial_access_cognito_identity_pool_unauth_creds",
    "aws_initial_access_console_login_without_mfa",
    "aws_lateral_movement_ec2_instance_connect",
    "aws_lateral_movement_ec2_serial_console_send_ssh_public_key",
    "aws_persistence_iam_backdoor_role",
    "aws_persistence_iam_backdoor_user",
    "aws_persistence_iam_create_admin_user",
    "aws_persistence_iam_create_backdoor_role",
    "aws_persistence_iam_create_user_login_profile",
    "aws_persistence_lambda_backdoor_function",
    "aws_persistence_lambda_layer_extension",
    "aws_persistence_lambda_overwrite_code",
    "aws_persistence_rolesanywhere_create_trust_anchor",
    "aws_persistence_sqs_open_queue_policy",
    "aws_persistence_sts_federation_token",
    "aws_privilege_escalation_iam_update_user_login_profile",
})


def _resolve_emulations_dir() -> Path:
    """Prefer EMULATIONS_BASE_DIR (Docker); fall back to the repo emulations/ dir."""
    env_dir = os.environ.get("EMULATIONS_BASE_DIR", "")
    if env_dir and Path(env_dir).is_dir():
        return Path(env_dir)
    return _FALLBACK_EMULATIONS_DIR


def _load_emulations(base_dir: Path):
    """Point the registry at base_dir and return the discovered catalogue."""
    os.environ["EMULATIONS_BASE_DIR"] = str(base_dir)
    registry_wrapper.reset_cache()
    return registry_wrapper.list_emulations()


def _manifest(**phase_overrides):
    """A one-phase AWS manifest whose phase carries the given fields."""
    phase = {"phase": 1, "name": "Impact", "techniques": [{"id": "T1485"}]}
    phase.update(phase_overrides)
    return {"name": "sample", "platform": "aws", "attack_path": [phase]}


class ValidateAwsActionsTests(SimpleTestCase):
    """The rule itself, on hand-built manifests."""

    def test_declared_actions_pass(self):
        """A phase listing the calls it makes complies."""
        self.assertEqual(validate_aws_actions(_manifest(aws_actions=["s3:DeleteObject", "iam:PassRole"])), [])

    def test_an_empty_list_is_a_valid_declaration(self):
        """It records a phase that makes no IAM-authorised call, which is a finding."""
        self.assertEqual(validate_aws_actions(_manifest(aws_actions=[])), [])

    def test_a_missing_field_is_reported(self):
        """Absent means unanalysed, which prevention analysis cannot judge."""
        errors = validate_aws_actions(_manifest())
        self.assertEqual(len(errors), 1)
        self.assertIn("phase 1 has no 'aws_actions'", errors[0])

    def test_every_phase_is_checked(self):
        """One missing phase in a multi-phase emulation is still reported."""
        manifest = _manifest(aws_actions=["s3:GetObject"])
        manifest["attack_path"].append({"phase": 2, "name": "Impact", "techniques": []})
        errors = validate_aws_actions(manifest)
        self.assertEqual(len(errors), 1)
        self.assertIn("phase 2", errors[0])

    def test_a_non_list_value_is_rejected(self):
        """A bare string would be read as a list of characters elsewhere."""
        errors = validate_aws_actions(_manifest(aws_actions="s3:GetObject"))
        self.assertEqual(len(errors), 1)
        self.assertIn("must be a list", errors[0])

    def test_wildcards_and_malformed_actions_are_rejected(self):
        """A phase declares the exact calls it makes, spelled as IAM spells them."""
        for bad in ("s3:*", "DeleteObject", "S3:DeleteObject", "s3:deleteObject", 7):
            errors = validate_aws_actions(_manifest(aws_actions=[bad]))
            self.assertEqual(len(errors), 1, bad)

    def test_other_platforms_are_skipped(self):
        """Kubernetes emulations are not governed by AWS policies."""
        manifest = _manifest()
        manifest["platform"] = "k8s"
        self.assertEqual(validate_aws_actions(manifest), [])

    def test_a_registry_entry_is_unwrapped(self):
        """The registry nests the MANIFEST under 'manifest'."""
        self.assertEqual(len(validate_aws_actions({"manifest": _manifest()})), 1)


class DiscoveredEmulationsAwsActionsTests(SimpleTestCase):
    """Every registered AWS emulation declares aws_actions, or is listed as pending."""

    @classmethod
    def setUpClass(cls):
        """Load the catalogue once for all checks."""
        super().setUpClass()
        cls.emulations = _load_emulations(_resolve_emulations_dir())
        cls.names = {(entry.get("manifest", entry) or {}).get("name") for entry in cls.emulations}

    def test_at_least_one_emulation_discovered(self):
        """An empty catalogue would make every other check pass vacuously."""
        self.assertGreater(len(self.emulations), 0, "No emulations discovered")

    def test_every_emulation_off_the_list_complies(self):
        """New emulations must ship with aws_actions on every phase."""
        errors: list[str] = []
        for entry in self.emulations:
            if (entry.get("manifest", entry) or {}).get("name") not in PENDING_AWS_ACTIONS:
                errors.extend(validate_aws_actions(entry))
        self.assertEqual(
            errors,
            [],
            "Emulation(s) violate the aws_actions contract:\n  - " + "\n  - ".join(errors),
        )

    def test_every_listed_emulation_still_needs_annotations(self):
        """Annotating a listed emulation means removing it from the list."""
        done = sorted(
            (entry.get("manifest", entry) or {}).get("name")
            for entry in self.emulations
            if (entry.get("manifest", entry) or {}).get("name") in PENDING_AWS_ACTIONS
            and not validate_aws_actions(entry)
        )
        self.assertEqual(
            done,
            [],
            "Now annotated, so remove from PENDING_AWS_ACTIONS:\n  - " + "\n  - ".join(done),
        )

    def test_every_listed_name_exists(self):
        """A renamed or deleted emulation must not linger on the list."""
        stale = sorted(PENDING_AWS_ACTIONS - self.names)
        self.assertEqual(stale, [], "Not in the catalogue, so remove from PENDING_AWS_ACTIONS: " + ", ".join(stale))
