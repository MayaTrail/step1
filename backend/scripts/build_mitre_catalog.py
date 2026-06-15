#!/usr/bin/env python3
"""
Generate the bundled MITRE ATT&CK technique catalogue used as the denominator
for the dashboard's APT Coverage Score and as the row/column structure for the
MITRE coverage heatmap.

The catalogue is intentionally checked in (apps/metrics/mitre/catalog.json) so
the backend has zero network dependency at runtime and the coverage denominator
is deterministic and reviewable.  Re-run this script to upgrade to a newer
ATT&CK release; commit the regenerated JSON.

Granularity: TECHNIQUE-LEVEL.  Sub-techniques (e.g. T1552.005) are excluded
from the catalogue — they roll up to their parent (T1552) at scoring time.
This matches the product decision that the denominator is the ~200 parent
Enterprise techniques, not the ~600 parent+sub IDs.

Source:
    MITRE ATT&CK STIX 2.1 bundle, enterprise-attack domain, published at
    https://github.com/mitre-attack/attack-stix-data

Usage:
    # Use a locally downloaded bundle:
    python scripts/build_mitre_catalog.py --src /tmp/enterprise-attack.json

    # Or let the script fetch the latest bundle over the network:
    python scripts/build_mitre_catalog.py --fetch

Revoked techniques:
    MITRE periodically revokes/replaces techniques (e.g. v19 revoked T1562
    "Impair Defenses" in favour of T1685).  Revoked techniques are excluded
    from the `techniques` list, but a transitive `revoked_map` (old_id ->
    current_id) is emitted so emulation manifests authored against an older
    ATT&CK version still resolve to a live technique at scoring time.

Output shape (catalog.json):
    {
      "attack_version": "<x_mitre_version of the marking>",
      "generated_from": "enterprise-attack",
      "tactics": [{"id": "TA0001", "shortname": "initial-access",
                   "name": "Initial Access"}, ...],
      "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                      "tactics": ["initial-access"]}, ...],
      "revoked_map": {"T1562": "T1685", ...},
      "technique_count": 203
    }
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# Repo-relative output path: backend/apps/metrics/mitre/catalog.json
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "apps" / "metrics" / "mitre" / "catalog.json"


def _load_bundle(src: str | None, fetch: bool) -> dict[str, Any]:
    """Load the STIX bundle from a local file or by fetching it over HTTP."""
    if fetch or src is None:
        print(f"Fetching ATT&CK bundle from {BUNDLE_URL} ...", file=sys.stderr)
        with urllib.request.urlopen(BUNDLE_URL, timeout=60) as resp:  # noqa: S310
            return json.load(resp)
    print(f"Reading ATT&CK bundle from {src} ...", file=sys.stderr)
    return json.loads(Path(src).read_text(encoding="utf-8"))


def _build(bundle: dict[str, Any]) -> dict[str, Any]:
    """Reduce a STIX bundle to a compact technique-level catalogue."""
    objects = bundle.get("objects", [])

    # Tactics are STIX x-mitre-tactic objects; preserve matrix order via the
    # bundle's x-mitre-matrix tactic_refs when available.
    tactics_by_id: dict[str, dict[str, str]] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        ext = _external_id(obj)
        tactics_by_id[obj["id"]] = {
            "id": ext,
            "shortname": obj.get("x_mitre_shortname", ""),
            "name": obj.get("name", ""),
        }

    matrix_order: list[str] = []
    for obj in objects:
        if obj.get("type") == "x-mitre-matrix":
            matrix_order = obj.get("tactic_refs", [])
            break
    ordered_tactics = [tactics_by_id[ref] for ref in matrix_order if ref in tactics_by_id]
    if not ordered_tactics:  # fall back to insertion order
        ordered_tactics = list(tactics_by_id.values())

    techniques: list[dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("x_mitre_is_subtechnique"):  # technique-level only
            continue
        ext = _external_id(obj)
        if not ext:
            continue
        tactic_shortnames = [
            kc["phase_name"]
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append(
            {"id": ext, "name": obj.get("name", ""), "tactics": tactic_shortnames}
        )

    techniques.sort(key=lambda t: t["id"])

    live_ids = {t["id"] for t in techniques}
    revoked_map = _build_revoked_map(objects, live_ids)

    return {
        "attack_version": _bundle_version(objects),
        "generated_from": "enterprise-attack",
        "tactics": ordered_tactics,
        "techniques": techniques,
        "revoked_map": revoked_map,
        "technique_count": len(techniques),
    }


def _build_revoked_map(objects: list[dict[str, Any]], live_ids: set[str]) -> dict[str, str]:
    """
    Build a transitive old_id -> current_id map from STIX 'revoked-by' edges.

    Only technique-level IDs (no sub-technique suffix) are mapped.  Chains are
    followed until they reach a non-revoked technique that is present in the
    catalogue; entries whose final target is not a live catalogue technique are
    dropped so callers never resolve to a dangling ID.

    Args:
        objects:  All STIX objects from the bundle.
        live_ids: The set of technique IDs kept in the catalogue.

    Returns:
        Mapping of revoked technique ID -> current replacement technique ID.
    """
    sid_to_ext = {
        obj["id"]: _external_id(obj)
        for obj in objects
        if obj.get("type") == "attack-pattern"
    }

    # Direct old -> new edges, technique-level only.
    direct: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "revoked-by":
            continue
        old = sid_to_ext.get(obj.get("source_ref", ""), "")
        new = sid_to_ext.get(obj.get("target_ref", ""), "")
        if old and new and "." not in old and "." not in new:
            direct[old] = new

    resolved: dict[str, str] = {}
    for old in direct:
        seen = {old}
        target = direct[old]
        while target in direct and target not in seen:
            seen.add(target)
            target = direct[target]
        if target in live_ids:
            resolved[old] = target

    return resolved


def _external_id(obj: dict[str, Any]) -> str:
    """Pull the ATT&CK external_id (Txxxx / TAxxxx) from a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _bundle_version(objects: list[dict[str, Any]]) -> str:
    """Best-effort ATT&CK spec version from the bundle's marking definition."""
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version", "unknown")
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--src", help="Path to a local enterprise-attack.json STIX bundle")
    parser.add_argument("--fetch", action="store_true", help="Fetch the latest bundle over HTTP")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output catalog.json path")
    args = parser.parse_args()

    bundle = _load_bundle(args.src, args.fetch)
    catalog = _build(bundle)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(
        f"Wrote {catalog['technique_count']} techniques across "
        f"{len(catalog['tactics'])} tactics (ATT&CK {catalog['attack_version']}) "
        f"to {out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
