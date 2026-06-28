"""
The dashboard contract for emulation manifests.

The redesigned dashboard derives every security metric by folding over the
emulation registry.  For that to work, each emulation's MANIFEST must carry a
small set of fields in a known shape.  This module defines that contract in one
place and provides a validator used by:

  * the contract test (apps/metrics/tests/test_contracts.py), which fails CI if
    any discovered emulation is non-compliant, and
  * optionally, startup/diagnostic checks.

Keeping the contract here — rather than scattered through the aggregation views —
means a new emulation lights up the whole dashboard the moment it satisfies this
single, testable specification, with no dashboard code changes.

Contract (schema_version >= 2):
  * name, display_name : non-empty strings (identity; also required by the
    registry itself).
  * platform           : one of SUPPORTED_PLATFORMS (drives Platform Coverage).
  * origin, attribution: non-empty strings (drive Threat Coverage grouping).
  * severity           : non-empty string.
  * mitre_mappings     : non-empty list; each entry has a `id` that resolves to
    a live catalogue technique (via normalize_technique) and a non-empty `name`.
    This list is the canonical technique source for the coverage score and the
    MITRE heatmap.
  * references         : non-empty list; each entry must carry a verified `url`
    (an http/https link). Guarantees the References tab links out for every
    source and prevents shipping an emulation whose links would have to be
    researched and back-filled later.

Optional (forward-compat, not enforced):
  * added : "YYYY-MM" month the emulation was added — reserved for the future
    Coverage Trend section; absence is allowed.
"""

from __future__ import annotations

from typing import Any

from apps.metrics.mitre import catalog

# Platform identifiers shared with the frontend PlatformId union
# ('aws' | 'azure' | 'gcp' | 'k8s' | 'ai').
SUPPORTED_PLATFORMS = frozenset({"aws", "azure", "gcp", "k8s", "ai"})

# Minimum manifest schema version that carries the full dashboard contract.
MIN_SCHEMA_VERSION = 2


def validate_manifest(entry: dict[str, Any]) -> list[str]:
    """
    Validate a single registry catalogue entry against the dashboard contract.

    Args:
        entry: A catalogue dict as returned by emulations.registry.discover()
               (i.e. the MANIFEST contents plus registry-injected keys).

    Returns:
        A list of human-readable error strings.  An empty list means the entry
        is fully dashboard-compliant.  The function never raises so callers can
        aggregate errors across every emulation in one pass.
    """
    errors: list[str] = []
    name = entry.get("name") or "<unnamed>"

    schema_version = entry.get("schema_version")
    if not isinstance(schema_version, int) or schema_version < MIN_SCHEMA_VERSION:
        errors.append(
            f"{name}: schema_version must be an int >= {MIN_SCHEMA_VERSION} "
            f"(got {schema_version!r})"
        )

    for field in ("name", "display_name", "origin", "attribution", "severity"):
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{name}: field '{field}' must be a non-empty string")

    platform = entry.get("platform")
    if platform not in SUPPORTED_PLATFORMS:
        errors.append(
            f"{name}: 'platform' must be one of {sorted(SUPPORTED_PLATFORMS)} "
            f"(got {platform!r})"
        )

    errors.extend(_validate_mitre_mappings(name, entry.get("mitre_mappings")))
    errors.extend(_validate_references(name, entry.get("references")))

    return errors


def _validate_mitre_mappings(name: str, mappings: Any) -> list[str]:
    """Validate the mitre_mappings list of a manifest. Returns error strings."""
    if not isinstance(mappings, list) or not mappings:
        return [f"{name}: 'mitre_mappings' must be a non-empty list"]

    errors: list[str] = []
    for index, mapping in enumerate(mappings):
        if not isinstance(mapping, dict):
            errors.append(f"{name}: mitre_mappings[{index}] must be an object")
            continue

        technique_id = mapping.get("id")
        if not isinstance(technique_id, str) or not technique_id.strip():
            errors.append(f"{name}: mitre_mappings[{index}].id must be a non-empty string")
        elif not catalog.is_known(technique_id):
            errors.append(
                f"{name}: mitre_mappings[{index}].id '{technique_id}' does not "
                f"resolve to a known ATT&CK {catalog.attack_version()} technique"
            )

        mapping_name = mapping.get("name")
        if not isinstance(mapping_name, str) or not mapping_name.strip():
            errors.append(f"{name}: mitre_mappings[{index}].name must be a non-empty string")

    return errors


def _validate_references(name: str, references: Any) -> list[str]:
    """
    Validate the references list of a manifest. Returns error strings.

    Every emulation must ship a non-empty references list, and every reference
    must carry a verified outbound `url` (an http/https link). This is what the
    References tab links to; enforcing it here means a missing or unlinked
    reference fails CI instead of shipping and needing to be researched later.
    """
    if not isinstance(references, list) or not references:
        return [f"{name}: 'references' must be a non-empty list"]

    errors: list[str] = []
    for index, ref in enumerate(references):
        if not isinstance(ref, dict):
            errors.append(f"{name}: references[{index}] must be an object")
            continue

        title = ref.get("title", "?")
        url = ref.get("url")
        if not isinstance(url, str) or not url.strip():
            errors.append(f"{name}: references[{index}] ('{title}') is missing a 'url'")
        elif not url.startswith(("http://", "https://")):
            errors.append(
                f"{name}: references[{index}] ('{title}') 'url' must be an "
                f"http(s) link (got {url!r})"
            )

    return errors
