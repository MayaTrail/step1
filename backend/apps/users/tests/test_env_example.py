"""
The env template and the settings modules have to agree.

Every setting read with config() is something a deployment may need to supply,
and .env.example is the only place an operator sees that it exists. A key with
an empty default is the dangerous case: the app boots without it and fails
later, when the feature is first used. WORKFLOW_FERNET_KEY was exactly that,
absent from the template while being required for the alert webhook, so a run
scored every rule as not_integrated with nothing explaining why.

Deliberately one-directional. The reverse check, "the template documents
something nothing reads", was tried and removed: .env.example legitimately
carries AWS_ACCESS_KEY_ID, PULUMI_CONFIG_PASSPHRASE and the POSTGRES_* family,
which the backend passes through to Pulumi, boto3 and Compose rather than
reading as Django settings. Distinguishing those needs an allowlist that would
rot, and a test nobody trusts gets deleted.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

# backend/apps/users/tests/ -> backend/
_BACKEND = Path(__file__).resolve().parents[3]
_SETTINGS_DIR = _BACKEND / "config" / "settings"
_TEMPLATE = _BACKEND / ".env.example"

# config("KEY") and config('KEY'), the only way this project reads settings
# from the environment.
_READS = re.compile(r'config\(\s*["\']([A-Z][A-Z0-9_]{2,})["\']')

# Supplied by the container image or the process, never by an operator editing
# .env, so their absence from the template is correct.
_RUNTIME_SUPPLIED = {"DJANGO_SETTINGS_MODULE"}


def _settings_keys() -> set[str]:
    """Every environment key read across config/settings/."""
    found: set[str] = set()
    for path in sorted(_SETTINGS_DIR.glob("*.py")):
        found |= set(_READS.findall(path.read_text()))
    return found - _RUNTIME_SUPPLIED


def _template_keys() -> set[str]:
    """Every key assigned in .env.example, ignoring comments and blanks."""
    keys = set()
    for line in _TEMPLATE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        keys.add(line.split("=", 1)[0].strip())
    return keys


class EnvExampleContractTests(SimpleTestCase):
    """.env.example documents every setting the code reads."""

    def test_the_template_is_not_empty(self):
        """Guards the parser: a silent parse failure would pass every check."""
        self.assertGreater(len(_template_keys()), 10)
        self.assertGreater(len(_settings_keys()), 10)

    def test_every_setting_is_documented(self):
        """
        A setting the code reads but the template omits is invisible to whoever
        has to deploy this.
        """
        missing = sorted(_settings_keys() - _template_keys())
        self.assertEqual(
            missing,
            [],
            "read by config/settings/ but absent from backend/.env.example: "
            f"{missing}. Add each with a comment saying what it does and "
            "whether it is required.",
        )
