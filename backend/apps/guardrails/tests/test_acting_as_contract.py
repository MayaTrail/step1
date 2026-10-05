"""
Tests for the acting_as contract (apps/guardrails/matching.validate_acting_as).

The account check judges each action against the identity that performs it.
Before this contract existed it assumed the connected role for everything, so
for emulations that act as a stolen user or a lab role it gave a confident
answer about the wrong identity. Every AWS emulation now declares who performs
each action, and the discovery test keeps it that way: a new emulation cannot
ship an action without naming its identity.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

from apps.guardrails.matching import (
    BUILT_IN_PLACEHOLDERS,
    acting_identities,
    declared_identities,
    phase_resources,
    placeholders,
    validate_acting_as,
    validate_resources,
)

from .test_aws_actions_contract import _load_emulations, _resolve_emulations_dir


def _manifest(identities=None, **phase_overrides):
    """A one-phase AWS manifest whose phase carries the given fields."""
    phase = {"phase": 1, "name": "Impact", "aws_actions": ["s3:GetObject", "s3:DeleteObject"]}
    phase.update(phase_overrides)
    manifest = {"name": "sample", "platform": "aws", "attack_path": [phase]}
    if identities is not None:
        manifest["identities"] = identities
    return manifest


STOLEN = {"stolen_user": {"kind": "lab_user", "label": "The lab's stolen user", "output": "victim_user_name"}}


class ValidateActingAsTests(SimpleTestCase):
    """The rule itself, on hand-built manifests."""

    def test_a_built_in_identity_for_the_whole_phase_passes(self):
        """The common case: every action runs as the connected role."""
        self.assertEqual(validate_acting_as(_manifest(acting_as="connected_role")), [])

    def test_a_mapping_covering_every_action_passes(self):
        """A phase that switches identity names who performs each action."""
        manifest = _manifest(STOLEN, acting_as={"anonymous": ["s3:GetObject"], "stolen_user": ["s3:DeleteObject"]})
        self.assertEqual(validate_acting_as(manifest), [])

    def test_two_identities_may_perform_the_same_action(self):
        """An action is listed under each identity that performs it."""
        manifest = _manifest(
            STOLEN,
            acting_as={"connected_role": ["s3:GetObject"], "stolen_user": ["s3:GetObject", "s3:DeleteObject"]},
        )
        self.assertEqual(validate_acting_as(manifest), [])

    def test_a_missing_acting_as_is_reported(self):
        """Nothing is assumed: actions without an identity fail."""
        errors = validate_acting_as(_manifest())
        self.assertEqual(len(errors), 1)
        self.assertIn("acting_as", errors[0])

    def test_a_phase_without_actions_needs_no_identity(self):
        """An exploit over HTTP makes no IAM call, so there is nobody to name."""
        self.assertEqual(validate_acting_as(_manifest(aws_actions=[])), [])

    def test_an_uncovered_action_is_reported(self):
        """Every declared action needs an identity."""
        errors = validate_acting_as(_manifest(acting_as={"connected_role": ["s3:GetObject"]}))
        self.assertTrue(any("s3:DeleteObject" in error for error in errors), errors)

    def test_an_action_not_in_aws_actions_is_reported(self):
        """The mapping cannot invent actions the phase does not declare."""
        errors = validate_acting_as(
            _manifest(acting_as={"connected_role": ["s3:GetObject", "s3:DeleteObject", "s3:PutObject"]})
        )
        self.assertTrue(any("s3:PutObject" in error for error in errors), errors)

    def test_an_unknown_identity_is_reported(self):
        """A typo in an identity name must not pass silently."""
        errors = validate_acting_as(_manifest(acting_as="stolen_usr"))
        self.assertTrue(any("stolen_usr" in error for error in errors), errors)

    def test_a_lab_identity_needs_its_output(self):
        """Without the output naming it, a lab identity could never be found."""
        identities = {"stolen_user": {"kind": "lab_user", "label": "The lab's stolen user"}}
        errors = validate_acting_as(_manifest(identities, acting_as="stolen_user"))
        self.assertTrue(any("output" in error for error in errors), errors)

    def test_an_attack_created_identity_has_no_output(self):
        """It only exists during the attack, so no stack output can name it."""
        identities = {"backdoor": {"kind": "attack_created", "label": "A backdoor user", "output": "x"}}
        errors = validate_acting_as(_manifest(identities, acting_as="backdoor"))
        self.assertTrue(any("created by the attack" in error for error in errors), errors)

    def test_an_identity_needs_a_known_kind_and_a_label(self):
        """The label is what a reader sees; the kind decides whether it can be checked."""
        errors = validate_acting_as(_manifest({"thief": {"kind": "stolen"}}, acting_as="thief"))
        self.assertTrue(any("'kind'" in error for error in errors), errors)
        self.assertTrue(any("label" in error for error in errors), errors)

    def test_a_built_in_identity_cannot_be_redeclared(self):
        """Redeclaring the connected role could make it something it is not."""
        identities = {"connected_role": {"kind": "lab_user", "label": "x", "output": "y"}}
        errors = validate_acting_as(_manifest(identities, acting_as="connected_role"))
        self.assertTrue(any("built in" in error for error in errors), errors)

    def test_an_unused_identity_is_reported(self):
        """A declared identity no phase acts as is usually a typo elsewhere."""
        errors = validate_acting_as(_manifest(STOLEN, acting_as="connected_role"))
        self.assertTrue(any("stolen_user" in error for error in errors), errors)

    def test_other_platforms_are_skipped(self):
        """Kubernetes emulations are not governed by AWS policies."""
        manifest = _manifest()
        manifest["platform"] = "kubernetes"
        self.assertEqual(validate_acting_as(manifest), [])


class ActingIdentitiesTests(SimpleTestCase):
    """Reading a phase's declaration into {identity: [actions]}."""

    def test_a_single_identity_covers_every_action(self):
        """A string names the identity of the whole phase."""
        phase = {"aws_actions": ["s3:GetObject", "s3:DeleteObject"], "acting_as": "connected_role"}
        self.assertEqual(acting_identities(phase), {"connected_role": ["s3:GetObject", "s3:DeleteObject"]})

    def test_no_declaration_assumes_nobody(self):
        """An undeclared phase returns nothing rather than the connected role."""
        self.assertEqual(acting_identities({"aws_actions": ["s3:GetObject"]}), {})

    def test_built_in_identities_are_always_known(self):
        """The connected role and anonymous need no declaration."""
        identities = declared_identities({"identities": STOLEN})
        self.assertEqual(set(identities), {"connected_role", "anonymous", "stolen_user"})


class ValidateResourcesTests(SimpleTestCase):
    """Lab-identity actions must name the resource the attack really targets."""

    def _phase(self, **overrides):
        """A one-phase manifest whose actions run as a lab user."""
        phase = {"phase": 1, "name": "Collect", "aws_actions": ["s3:GetObject", "s3:ListAllMyBuckets"],
                 "acting_as": "stolen_user"}
        phase.update(overrides)
        return _manifest(STOLEN, **phase)

    def test_a_resource_or_an_explicit_star_per_action_passes(self):
        """A scoped ARN for the object read, "*" for an action AWS only allows on everything."""
        manifest = self._phase(aws_resources={"s3:GetObject": "arn:aws:s3:::{target_bucket_name}/*",
                                              "s3:ListAllMyBuckets": "*"})
        self.assertEqual(validate_resources(manifest), [])

    def test_a_lab_identity_action_without_a_resource_is_reported(self):
        """Leaving it out is what judged a bucket-scoped policy against "*"."""
        errors = validate_resources(self._phase(aws_resources={"s3:ListAllMyBuckets": "*"}))
        self.assertTrue(any("s3:GetObject" in error for error in errors), errors)

    def test_the_connected_role_also_needs_a_resource(self):
        """The connected role's own policy is scoped too, so its actions name their resource."""
        manifest = _manifest(aws_actions=["s3:GetObject"], acting_as="connected_role")
        self.assertTrue(any("s3:GetObject" in error for error in validate_resources(manifest)))

    def test_the_connected_role_with_a_resource_passes(self):
        """A named resource (or an explicit "*") satisfies the connected role."""
        manifest = _manifest(aws_actions=["s3:GetObject"], acting_as="connected_role",
                             aws_resources={"s3:GetObject": "arn:aws:s3:::{target_bucket_name}/*"})
        self.assertEqual(validate_resources(manifest), [])

    def test_a_resource_for_an_undeclared_action_is_reported(self):
        """The map cannot invent actions the phase does not make."""
        manifest = self._phase(aws_resources={"s3:GetObject": "*", "s3:ListAllMyBuckets": "*", "s3:PutObject": "*"})
        self.assertTrue(any("s3:PutObject" in error for error in validate_resources(manifest)))

    def test_a_malformed_resource_is_reported(self):
        """A bare bucket name is not an ARN, and AWS would not match it."""
        manifest = self._phase(aws_resources={"s3:GetObject": "my-bucket", "s3:ListAllMyBuckets": "*"})
        self.assertTrue(any("my-bucket" in error for error in validate_resources(manifest)))

    def test_placeholders_are_read_from_a_template(self):
        """The names a template needs filled, in order."""
        self.assertEqual(placeholders("arn:aws:lambda:{region}:{account_id}:function:x"), ["region", "account_id"])


class DiscoveredEmulationsActingAsTests(SimpleTestCase):
    """Every registered AWS emulation names who performs each of its actions."""

    @classmethod
    def setUpClass(cls):
        """Load the catalogue once for all checks."""
        super().setUpClass()
        cls.emulations = _load_emulations(_resolve_emulations_dir())

    def test_at_least_one_emulation_discovered(self):
        """An empty catalogue would make the check pass vacuously."""
        self.assertGreater(len(self.emulations), 0, "No emulations discovered")

    def test_every_emulation_complies(self):
        """New emulations must declare acting_as on every phase with actions."""
        errors: list[str] = []
        for entry in self.emulations:
            errors.extend(validate_acting_as(entry))
        self.assertEqual(
            errors,
            [],
            "Emulation(s) violate the acting_as contract:\n  - " + "\n  - ".join(errors),
        )

    def test_every_emulation_declares_its_lab_resources(self):
        """Every lab-identity action names its resource, or "*" on purpose."""
        errors: list[str] = []
        for entry in self.emulations:
            errors.extend(validate_resources(entry))
        self.assertEqual(errors, [], "\n  - ".join(errors))

    def test_every_resource_placeholder_is_an_export(self):
        """A placeholder the lab does not export could never be filled, so the check would say redeploy forever."""
        missing: list[str] = []
        for entry in self.emulations:
            manifest = entry.get("manifest", entry) or {}
            infra = Path(entry["module"].__file__).parent / "infra" / "__main__.py"
            if not infra.is_file():
                continue
            exported = set(re.findall(r"""pulumi\.export\(\s*["']([A-Za-z0-9_]+)["']""", infra.read_text()))
            for phase in manifest.get("attack_path") or []:
                for action, templates in phase_resources(phase).items():
                    for template in templates:
                        missing += [
                            f"{manifest.get('name')}: phase {phase.get('phase')} {action} needs {{{name}}}, which infra does not export"
                            for name in placeholders(template)
                            if name not in exported and name not in BUILT_IN_PLACEHOLDERS
                        ]
        self.assertEqual(missing, [], "\n  - ".join(missing))

    def test_every_lab_identity_is_exported_by_its_infra(self):
        """
        A lab identity is found through the stack output its declaration names.

        If the emulation's infrastructure never exports that output, every
        deployed lab says "redeploy to check" forever, so the export is checked
        here, by reading the Pulumi program, rather than discovered after a
        deploy.
        """
        missing: list[str] = []
        for entry in self.emulations:
            manifest = entry.get("manifest", entry) or {}
            labs = {
                key: value["output"]
                for key, value in (manifest.get("identities") or {}).items()
                if isinstance(value, dict) and value.get("kind") in ("lab_user", "lab_role")
            }
            if not labs:
                continue
            infra = Path(entry["module"].__file__).parent / "infra" / "__main__.py"
            exported = set(re.findall(r"""pulumi\.export\(\s*["']([A-Za-z0-9_]+)["']""", infra.read_text()))
            missing += [
                f"{manifest.get('name')}: identity {key!r} needs output {output!r}, which infra does not export"
                for key, output in labs.items()
                if output not in exported
            ]
        self.assertEqual(missing, [], "\n  - ".join(missing))
