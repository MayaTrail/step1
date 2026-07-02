"""
Detection rule parsing and per-rule detail assembly.

Detection artifacts live as flat files under each emulation's detections/
directory: Sigma rules (sigma_<technique>.yml), KQL queries
(kql_<technique>.kql), and detection notes (detection_note_<technique>.md).

This module groups those files by their technique id, parses the Sigma
frontmatter into the structured fields the detection detail page renders,
and folds in the emulation-level context (threat actor, coverage, related
techniques) drawn from the MANIFEST.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_SIGMA_PREFIX = "sigma_"
_KQL_PREFIX = "kql_"
_NOTE_PREFIX = "detection_note_"


def _technique_key(filename: str) -> str | None:
    """
    Derive the technique grouping key from a detection filename.

    The key pairs the three file kinds that describe one technique:
        sigma_t1098.001.yml        -> t1098.001
        kql_t1098.001.kql          -> t1098.001
        detection_note_t1098.001.md -> t1098.001

    Path.stem drops only the final extension, so the dotted sub-technique
    id (t1098.001) is preserved. Returns None for files that do not follow
    the naming convention.
    """
    stem = Path(filename).stem
    for prefix in (_NOTE_PREFIX, _SIGMA_PREFIX, _KQL_PREFIX):
        if stem.startswith(prefix):
            return stem[len(prefix):]
    return None


def _group_by_technique(detection_files: list[str]) -> dict[str, dict[str, str]]:
    """
    Group detection filenames by technique key.

    Returns a mapping of technique key to the filenames that describe it,
    e.g. {"t1098.001": {"sigma": "sigma_t1098.001.yml", "kql": "kql_...",
    "note": "detection_note_..."}}.
    """
    groups: dict[str, dict[str, str]] = {}
    for filename in detection_files:
        key = _technique_key(filename)
        if key is None:
            continue
        group = groups.setdefault(key, {})
        if filename.startswith(_SIGMA_PREFIX):
            group["sigma"] = filename
        elif filename.startswith(_KQL_PREFIX):
            group["kql"] = filename
        elif filename.startswith(_NOTE_PREFIX):
            group["note"] = filename
    return groups


def parse_sigma(text: str) -> dict[str, Any]:
    """
    Parse a Sigma rule file into a dict.

    The leading "# FILE:" line is a YAML comment and is ignored by the
    loader. Returns an empty dict when the content is not valid YAML so a
    single malformed rule cannot break the detail view.
    """
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        logger.warning("Could not parse Sigma rule: %s", exc)
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _read(detections_dir: Path, filename: str | None) -> str | None:
    """Read a detection file's contents, or return None if absent/unreadable."""
    if not filename:
        return None
    try:
        return (detections_dir / filename).read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not read detection file %s: %s", filename, exc)
        return None


def _technique_meta(manifest: dict, technique_id: str) -> dict[str, str]:
    """
    Look up a technique's name and tactic from the MANIFEST mappings.

    Falls back to the bare id when the technique is not mapped, so the page
    always has something to show.
    """
    for mapping in manifest.get("mitre_mappings", []):
        if str(mapping.get("id", "")).upper() == technique_id:
            return {
                "id": technique_id,
                "name": mapping.get("name", ""),
                "tactic": mapping.get("tactic", ""),
            }
    return {"id": technique_id, "name": "", "tactic": ""}


def _coverage(manifest: dict, groups: dict[str, dict[str, str]]) -> dict[str, int]:
    """
    Compute emulation-level detection coverage from the MANIFEST and the
    grouped detection files.

    A technique counts as covered when it ships at least one Sigma or KQL
    rule (a note alone does not count). A phase counts as covered when any
    of its techniques is covered.
    """
    covered_ids = {
        key.upper()
        for key, files in groups.items()
        if "sigma" in files or "kql" in files
    }

    attack_path = manifest.get("attack_path", [])
    phases_total = len(attack_path)
    phases_covered = 0
    for phase in attack_path:
        phase_ids = {str(t.get("id", "")).upper() for t in phase.get("techniques", [])}
        if phase_ids & covered_ids:
            phases_covered += 1

    techniques_total = manifest.get("technique_count") or len(manifest.get("mitre_mappings", []))

    return {
        "techniquesCovered": len(covered_ids),
        "techniquesTotal": techniques_total,
        "phasesCovered": phases_covered,
        "phasesTotal": phases_total,
    }


def list_detection_summaries(entry: dict) -> list[dict[str, Any]]:
    """
    Return a per-rule summary list for the detection library.

    Each item groups the Sigma and KQL variants for one technique and
    carries the light metadata the master-detail rail renders (title,
    severity, log source, formats) plus both code bodies, so selecting a
    rule needs no follow-up request. Rules with only a detection note (no
    Sigma or KQL) are skipped.
    """
    groups = _group_by_technique(entry.get("detection_files", []))
    detections_dir = Path(entry["detections_path"]) if entry.get("detections_path") else None
    manifest = entry.get("manifest", entry)

    summaries: list[dict[str, Any]] = []
    for rule_id, files in sorted(groups.items()):
        if "sigma" not in files and "kql" not in files:
            continue
        sigma_text = _read(detections_dir, files.get("sigma")) if detections_dir else None
        kql_text = _read(detections_dir, files.get("kql")) if detections_dir else None
        sigma = parse_sigma(sigma_text) if sigma_text else {}
        technique = _technique_meta(manifest, rule_id.upper())
        summaries.append({
            "ruleId": rule_id,
            "technique": technique,
            "title": sigma.get("title") or technique.get("name") or rule_id.upper(),
            "severity": sigma.get("level", ""),
            "logSource": sigma.get("logsource", {}) or {},
            "formats": {"sigma": bool(sigma_text), "kql": bool(kql_text)},
            "sigma": sigma_text,
            "kql": kql_text,
        })
    return summaries


def build_detection_detail(entry: dict, rule_id: str) -> dict[str, Any] | None:
    """
    Assemble the full detail payload for a single detection rule.

    Args:
        entry:   Registry catalogue entry for the emulation.
        rule_id: Technique grouping key, e.g. "t1098.001".

    Returns:
        A camelCase detail dict, or None if the emulation ships no rule for
        rule_id.
    """
    groups = _group_by_technique(entry.get("detection_files", []))
    files = groups.get(rule_id)
    if not files or ("sigma" not in files and "kql" not in files):
        return None

    detections_dir = Path(entry["detections_path"])
    sigma_text = _read(detections_dir, files.get("sigma"))
    kql_text = _read(detections_dir, files.get("kql"))
    note_text = _read(detections_dir, files.get("note"))

    sigma = parse_sigma(sigma_text) if sigma_text else {}
    manifest = entry.get("manifest", entry)
    technique_id = rule_id.upper()

    # references in Sigma frontmatter are a plain list of URLs.
    references = sigma.get("references") or []
    if not isinstance(references, list):
        references = [references]

    related = [
        {"id": m.get("id"), "name": m.get("name")}
        for m in manifest.get("mitre_mappings", [])
        if str(m.get("id", "")).upper() != technique_id
    ]

    playbook_exists = (detections_dir.parent / "PLAYBOOK.md").exists()

    return {
        "emulationType": entry.get("name"),
        "displayName": entry.get("display_name", entry.get("name")),
        "ruleId": rule_id,
        "technique": _technique_meta(manifest, technique_id),
        "title": sigma.get("title", ""),
        "description": sigma.get("description", ""),
        "status": sigma.get("status", ""),
        "severity": sigma.get("level", ""),
        "logSource": sigma.get("logsource", {}) or {},
        "tags": sigma.get("tags", []) or [],
        "author": sigma.get("author", ""),
        "date": sigma.get("date", ""),
        "falsePositives": sigma.get("falsepositives", []) or [],
        "references": references,
        "note": note_text,
        "threatActor": manifest.get("attribution", ""),
        "hasPlaybook": playbook_exists,
        "relatedTechniques": related,
        "services": manifest.get("services", []) or [],
        "coverage": _coverage(manifest, groups),
        "formats": {"sigma": bool(sigma_text), "kql": bool(kql_text)},
        "sigma": sigma_text,
        "kql": kql_text,
    }
