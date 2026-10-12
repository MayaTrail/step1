"""
Severity must read the same wherever the product shows it.

An emulation's severity appears in two places an analyst sees side by side: the
`severity` field of its MANIFEST (dashboard badge, attack surface panel) and the
`Severity` row of the PLAYBOOK.md Classification table (playbook page). They were
authored at different times by different hands and drifted apart, which reads as
an unfinished product. This test folds the comparison over every emulation the
repository ships so the drift cannot return.

The playbook cell may carry escalation conditions after its headline
("High. Raise to Critical when ..."); only the leading level is compared, because
that is the baseline severity of the emulated technique. The rubric that decides
the level lives in docs/emulation-severity-rubric.md.
"""

import os
import re
from pathlib import Path

from django.test import SimpleTestCase

LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEVERITY_ROW = re.compile(r"\|\s*Severity\s*\|\s*([^|]+)\|")
_HEADLINE = re.compile(r"^\W*(Critical|High|Medium|Low)\b", re.IGNORECASE)


def _emulations_dir() -> Path:
    configured = os.environ.get("EMULATIONS_BASE_DIR", "")
    if configured:
        return Path(configured)
    # backend/apps/emulations/tests/<this file> -> repo root is parents[4]
    return Path(__file__).resolve().parents[4] / "emulations"


def _manifest_severity(manifest_path: Path) -> str:
    namespace: dict = {}
    exec(compile(manifest_path.read_text(encoding="utf-8"), str(manifest_path), "exec"), namespace)
    return str(namespace["MANIFEST"].get("severity", "")).upper()


class SeverityAlignmentTests(SimpleTestCase):
    def test_manifest_and_playbook_agree_on_severity(self):
        problems = []
        checked = 0
        for folder in sorted(_emulations_dir().iterdir()):
            manifest_path = folder / "MANIFEST.py"
            if not folder.is_dir() or folder.name.startswith("_") or not manifest_path.exists():
                continue
            severity = _manifest_severity(manifest_path)
            if severity not in LEVELS:
                problems.append(f"{folder.name}: manifest severity {severity!r} is not one of {LEVELS}")
                continue
            playbook = folder / "PLAYBOOK.md"
            if not playbook.exists():
                continue
            row = _SEVERITY_ROW.search(playbook.read_text(encoding="utf-8"))
            if not row:
                problems.append(f"{folder.name}: PLAYBOOK.md has no Severity row in its Classification table")
                continue
            headline = _HEADLINE.match(row.group(1).replace("*", "").strip())
            if not headline:
                problems.append(f"{folder.name}: playbook severity {row.group(1).strip()[:40]!r} does not open with a level")
            elif headline.group(1).upper() != severity:
                problems.append(
                    f"{folder.name}: manifest says {severity}, playbook says {headline.group(1).upper()}"
                )
            checked += 1
        self.assertGreater(checked, 0, "no playbooks found; EMULATIONS_BASE_DIR is probably wrong")
        self.assertEqual(problems, [], "Severity differs between manifest and playbook:\n  " + "\n  ".join(problems))
