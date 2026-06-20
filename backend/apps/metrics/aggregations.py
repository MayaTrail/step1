"""
Dashboard metric aggregations.

Every function here is a pure read-only fold over the emulation registry plus,
where runtime facts are needed, the EmulationRun table.  No metric is stored;
all are computed on request so they are always current and so a newly added
emulation contributes automatically.

Definitions (locked with the product owner):

  * APT Coverage Score — distinct parent ATT&CK techniques covered across all
    emulations, divided by the technique-level catalogue size (the denominator
    bundled in apps/metrics/mitre/catalog.json).  Sub-techniques roll up to
    their parent and revoked IDs forward-resolve, both handled by
    catalog.normalize_technique().

  * Threat Coverage — one row per emulation (each emulation emulates one APT
    campaign / actor).  Each row's coverage_pct uses the same catalogue
    denominator as the headline score, so the figures are consistent across the
    dashboard.

  * MITRE Coverage — the full catalogue matrix (tactics x techniques) with a
    `covered` flag per technique, for the heatmap.  Tactic placement is read
    from the catalogue, never from manifest labels.

  * Platform Coverage — per platform, the number of emulations, playbooks
    (a PLAYBOOK.md counts as one), and detection rules (files under detections/).

The canonical technique source for an emulation is its `mitre_mappings` list.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from apps.emulations.registry import list_emulations
from apps.metrics.contracts import SUPPORTED_PLATFORMS
from apps.metrics.mitre import catalog

# Recognises ATT&CK technique IDs in either dotted ("T1552.005") or underscored
# ("t1552_005") form — the conventions used by detection filenames and playbook
# prose, from which we derive which techniques each content type backs.
_TECHNIQUE_PATTERN = re.compile(r"[Tt](\d{4})(?:[._](\d{3}))?")

# Human-friendly labels for the supported platform identifiers.
PLATFORM_LABELS = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "k8s": "Kubernetes",
    "ai": "AI / LLM",
}

# Colour used to mark covered techniques in the exported ATT&CK Navigator layer
# (matches the dashboard's "safe" green).
NAVIGATOR_COVERED_COLOR = "#5fc992"


def _emulation_technique_ids(entry: dict[str, Any]) -> set[str]:
    """
    Return the set of normalised, catalogue-known parent technique IDs an
    emulation covers, derived from its mitre_mappings.

    IDs that do not resolve to a live catalogue technique are dropped so they
    never inflate coverage.
    """
    covered: set[str] = set()
    for mapping in entry.get("mitre_mappings", []) or []:
        technique_id = mapping.get("id") if isinstance(mapping, dict) else None
        if isinstance(technique_id, str) and catalog.is_known(technique_id):
            covered.add(catalog.normalize_technique(technique_id))
    return covered


def _covered_technique_ids(entries: list[dict[str, Any]]) -> set[str]:
    """Return the union of covered technique IDs across the given emulations."""
    covered: set[str] = set()
    for entry in entries:
        covered |= _emulation_technique_ids(entry)
    return covered


def _detection_count(entry: dict[str, Any]) -> int:
    """Return the number of detection rule files an emulation ships."""
    return len(entry.get("detection_files", []) or [])


def _playbook_path(entry: dict[str, Any]) -> Path | None:
    """Return the path to the emulation's PLAYBOOK.md, or None if absent."""
    module = entry.get("module")
    module_file = getattr(module, "__file__", None)
    if not module_file:
        return None
    path = Path(module_file).parent / "PLAYBOOK.md"
    return path if path.is_file() else None


def _has_playbook(entry: dict[str, Any]) -> bool:
    """Return True if the emulation package contains a PLAYBOOK.md."""
    return _playbook_path(entry) is not None


def _techniques_from_text(text: str) -> set[str]:
    """
    Extract normalised, catalogue-known parent technique IDs referenced in text.

    Used to derive which techniques a piece of content backs, from sources that
    already encode technique IDs by convention: detection filenames
    (e.g. "sigma_t1190.yml") and playbook prose (e.g. "T1552.005").  IDs that do
    not resolve to a live catalogue technique are ignored.
    """
    found: set[str] = set()
    for major, minor in _TECHNIQUE_PATTERN.findall(text):
        technique_id = f"T{major}" + (f".{minor}" if minor else "")
        if catalog.is_known(technique_id):
            found.add(catalog.normalize_technique(technique_id))
    return found


def _detection_technique_ids(entry: dict[str, Any]) -> set[str]:
    """Return the techniques an emulation's detection rules cover (by filename)."""
    return _techniques_from_text(" ".join(entry.get("detection_files", []) or []))


def _playbook_technique_ids(entry: dict[str, Any]) -> set[str]:
    """Return the techniques referenced in an emulation's PLAYBOOK.md."""
    path = _playbook_path(entry)
    if path is None:
        return set()
    try:
        return _techniques_from_text(path.read_text(encoding="utf-8"))
    except OSError:
        return set()


def _platform_of(entry: dict[str, Any]) -> str | None:
    """Return the emulation's declared platform, or None if unset/unsupported."""
    platform = entry.get("platform")
    return platform if platform in SUPPORTED_PLATFORMS else None


def _pct(part: int, whole: int) -> float:
    """Return part/whole as a percentage rounded to one decimal place."""
    if whole <= 0:
        return 0.0
    return round(100.0 * part / whole, 1)


def coverage_summary() -> dict[str, Any]:
    """
    Compute the four KPI-card figures.

    Returns:
        Dict with the APT coverage score, total emulation executions, total
        detection rule count, and the most recent successful run timestamp
        (ISO 8601 string, or None if there has been no successful run).
    """
    # Imported lazily so this module stays importable without Django app config
    # (e.g. from standalone tooling) and to avoid an import cycle at app load.
    from apps.emulations.models import EmulationRun  # noqa: PLC0415

    entries = list_emulations()
    covered = _covered_technique_ids(entries)
    total = catalog.technique_count()

    last_success = (
        EmulationRun.objects.filter(status=EmulationRun.Status.COMPLETED)
        .order_by("-completed_at")
        .values_list("completed_at", flat=True)
        .first()
    )

    return {
        "aptCoverageScore": _pct(len(covered), total),
        "coveredTechniques": len(covered),
        "totalTechniques": total,
        "attackVersion": catalog.attack_version(),
        "emulationsExecuted": EmulationRun.objects.count(),
        "detectionCoverage": sum(_detection_count(e) for e in entries),
        "lastSuccessfulRun": last_success.isoformat() if last_success else None,
    }


# Coverage-status thresholds for a tactic's percentage (drives green/amber/red).
_STATUS_COVERED_MIN = 67  # >= this percent is "covered" (green)


def _tactic_status(pct: float) -> str:
    """Map a tactic coverage percentage to a status: covered / partial / none."""
    if pct >= _STATUS_COVERED_MIN:
        return "covered"
    if pct > 0:
        return "partial"
    return "none"


def _filtered_emulations(
    platform: str | None = None,
    actor: str | None = None,
    emulation: str | None = None,
) -> list[dict[str, Any]]:
    """
    Return the emulation entries matching the given coverage filters.

    Args:
        platform:  Restrict to a single platform id.
        actor:     Restrict to a single threat-origin value (case-insensitive).
        emulation: Restrict to a single emulation by name/id.
    """
    entries = list_emulations()
    if platform:
        entries = [e for e in entries if _platform_of(e) == platform]
    if actor:
        entries = [e for e in entries if (e.get("origin") or "").lower() == actor.lower()]
    if emulation:
        entries = [e for e in entries if e.get("name") == emulation]
    return entries


def _techniques_by_tactic() -> dict[str, list[dict[str, Any]]]:
    """Group catalogue techniques under each tactic shortname (matrix columns)."""
    grouped: dict[str, list[dict[str, Any]]] = {t["shortname"]: [] for t in catalog.tactics()}
    for technique in catalog.techniques():
        for shortname in technique["tactics"]:
            if shortname in grouped:
                grouped[shortname].append(technique)
    return grouped


def _tactic_rows(covered_ids: set[str]) -> list[dict[str, Any]]:
    """Build the per-tactic coverage summary rows (no per-technique lists)."""
    grouped = _techniques_by_tactic()
    rows: list[dict[str, Any]] = []
    for tactic in catalog.tactics():
        techniques = grouped[tactic["shortname"]]
        total = len(techniques)
        covered = sum(1 for t in techniques if t["id"] in covered_ids)
        pct = _pct(covered, total)
        uncovered = total - covered
        rows.append(
            {
                "id": tactic["id"],
                "shortname": tactic["shortname"],
                "name": tactic["name"],
                "techniqueCount": total,
                "coveredCount": covered,
                "pct": pct,
                "status": _tactic_status(pct),
                "insight": "Fully covered" if uncovered == 0 else f"{uncovered} uncovered",
            }
        )
    return rows


def _highlight(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Reduce a tactic row to the {shortname, name, pct} highlight shape, or None."""
    if row is None:
        return None
    return {"shortname": row["shortname"], "name": row["name"], "pct": row["pct"]}


def _coverage_insights(
    rows: list[dict[str, Any]], covered_total: int, total: int, entry_count: int
) -> list[dict[str, str]]:
    """
    Derive up to three actionable, truthful insights from the tactic rows.

    Prioritises the lowest non-zero coverage tactic and the largest absolute gap,
    then an overall summary line.  All figures come from the data — no estimates.
    """
    insights: list[dict[str, str]] = []
    with_techniques = [r for r in rows if r["techniqueCount"] > 0]

    partial = [r for r in with_techniques if 0 < r["pct"] < _STATUS_COVERED_MIN]
    if partial:
        weakest = min(partial, key=lambda r: r["pct"])
        insights.append(
            {"severity": "high", "text": f"{weakest['name']} coverage is only {weakest['pct']}%."}
        )

    biggest_gap = max(
        with_techniques,
        key=lambda r: r["techniqueCount"] - r["coveredCount"],
        default=None,
    )
    if biggest_gap is not None:
        gap = biggest_gap["techniqueCount"] - biggest_gap["coveredCount"]
        if gap > 0:
            insights.append(
                {
                    "severity": "medium",
                    "text": f"{gap} uncovered techniques exist under {biggest_gap['name']}.",
                }
            )

    insights.append(
        {
            "severity": "info",
            "text": (
                f"{covered_total} / {total} techniques covered "
                f"across {entry_count} {'emulation' if entry_count == 1 else 'emulations'}."
            ),
        }
    )
    return insights


def _available_filters() -> dict[str, Any]:
    """Return the filter options the frontend dropdowns should offer."""
    entries = list_emulations()
    platforms = sorted({p for e in entries if (p := _platform_of(e))})
    actors = sorted({(e.get("origin") or "unknown") for e in entries})
    return {
        "platforms": [{"id": p, "label": PLATFORM_LABELS.get(p, p.upper())} for p in platforms],
        "actors": [{"id": a, "label": a.replace("-", " ").title()} for a in actors],
        "emulations": [
            {"id": e["name"], "label": e.get("display_name", e["name"])} for e in entries
        ],
        "tactics": [{"id": t["shortname"], "label": t["name"]} for t in catalog.tactics()],
    }


def mitre_coverage(
    platform: str | None = None,
    actor: str | None = None,
    emulation: str | None = None,
) -> dict[str, Any]:
    """
    Build the redesigned MITRE ATT&CK coverage payload: an executive summary, a
    per-tactic coverage list (status + percentage, no tiny per-technique cells),
    derived insights, and the available filter options.

    Coverage is computed over the emulation subset matching the filters, so the
    whole view re-scopes by platform / threat actor / emulation.
    """
    entries = _filtered_emulations(platform, actor, emulation)
    covered_ids = _covered_technique_ids(entries)
    rows = _tactic_rows(covered_ids)

    total = catalog.technique_count()
    covered_total = len(covered_ids)

    distribution = {"covered": 0, "partial": 0, "none": 0}
    for row in rows:
        distribution[row["status"]] += 1

    sortable = [r for r in rows if r["techniqueCount"] > 0]
    most = max(sortable, key=lambda r: r["pct"], default=None)
    # Least covered = lowest percentage, breaking ties toward the largest gap.
    least = min(
        sortable,
        key=lambda r: (r["pct"], -(r["techniqueCount"] - r["coveredCount"])),
        default=None,
    )

    return {
        "summary": {
            "coveredTechniques": covered_total,
            "totalTechniques": total,
            "pct": _pct(covered_total, total),
            "attackVersion": catalog.attack_version(),
            "distribution": distribution,
            "mostCovered": _highlight(most),
            "leastCovered": _highlight(least),
            "trendAvailable": False,
        },
        "tactics": rows,
        "insights": _coverage_insights(rows, covered_total, total, len(entries)),
        "filters": _available_filters(),
    }


def tactic_detail(
    shortname: str,
    platform: str | None = None,
    actor: str | None = None,
    emulation: str | None = None,
) -> dict[str, Any] | None:
    """
    Build the drill-down payload for a single tactic: covered and missing
    techniques, the emulations/playbooks/detections related to it, and a
    recommendation.  Honours the same filters as mitre_coverage.

    Returns None if shortname is not a known tactic.
    """
    tactic = next((t for t in catalog.tactics() if t["shortname"] == shortname), None)
    if tactic is None:
        return None

    techniques = _techniques_by_tactic().get(shortname, [])
    tactic_ids = {t["id"] for t in techniques}

    entries = _filtered_emulations(platform, actor, emulation)
    covered_ids = _covered_technique_ids(entries) & tactic_ids

    covered = [{"id": t["id"], "name": t["name"]} for t in techniques if t["id"] in covered_ids]
    missing = [{"id": t["id"], "name": t["name"]} for t in techniques if t["id"] not in covered_ids]

    related_emulations: list[dict[str, str]] = []
    detections = 0
    playbooks = 0
    for entry in entries:
        if _emulation_technique_ids(entry) & tactic_ids:
            related_emulations.append(
                {"id": entry["name"], "name": entry.get("display_name", entry["name"])}
            )
            detections += len(_detection_technique_ids(entry) & tactic_ids)
            if _playbook_technique_ids(entry) & tactic_ids:
                playbooks += 1

    pct = _pct(len(covered), len(techniques))
    if missing:
        recommendation = (
            f"Add an emulation covering {missing[0]['name']} ({missing[0]['id']}) "
            f"to improve {tactic['name']} coverage."
        )
    else:
        recommendation = f"{tactic['name']} is fully covered — maintain its detections."

    return {
        "tactic": {
            "shortname": shortname,
            "name": tactic["name"],
            "pct": pct,
            "coveredCount": len(covered),
            "techniqueCount": len(techniques),
        },
        "covered": covered,
        "missing": missing,
        "relatedEmulations": related_emulations,
        "relatedPlaybooks": playbooks,
        "relatedDetections": detections,
        "recommendation": recommendation,
    }


def navigator_layer() -> dict[str, Any]:
    """
    Build a MITRE ATT&CK Navigator layer (layer format 4.5) for the techniques
    Mayatrail covers, so users can open the full official matrix preloaded with
    our coverage.

    Technique IDs are normalised to live catalogue parents (the same technique
    level the dashboard scores against), guaranteeing every entry is a valid
    technique in the bundled ATT&CK version.  Each entry's comment lists the
    emulations that exercise it.

    Returns:
        A dict matching the Navigator layer schema, ready to be serialised to
        JSON and loaded via the Navigator's "Open Existing Layer" flow.
    """
    coverage: dict[str, set[str]] = {}
    for entry in list_emulations():
        label = entry.get("display_name") or entry.get("name") or "Unknown"
        for mapping in entry.get("mitre_mappings", []) or []:
            technique_id = mapping.get("id") if isinstance(mapping, dict) else None
            if isinstance(technique_id, str) and catalog.is_known(technique_id):
                coverage.setdefault(catalog.normalize_technique(technique_id), set()).add(label)

    techniques = [
        {
            "techniqueID": technique_id,
            "score": 1,
            "color": NAVIGATOR_COVERED_COLOR,
            "comment": "Covered by: " + ", ".join(sorted(labels)),
            "enabled": True,
        }
        for technique_id, labels in sorted(coverage.items())
    ]

    # The Navigator's "attack" version is the major release (e.g. "19").
    attack_major = catalog.attack_version().split(".", 1)[0]

    return {
        "name": "Mayatrail Coverage",
        "versions": {"attack": attack_major, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "MITRE ATT&CK techniques emulated and validated by Mayatrail. "
            "Generated from the live emulation registry."
        ),
        "techniques": techniques,
        "gradient": {"colors": ["#101111", NAVIGATOR_COVERED_COLOR], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "Covered by Mayatrail", "color": NAVIGATOR_COVERED_COLOR}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#101111",
        "selectTechniquesAcrossTactics": True,
        "hideDisabled": False,
    }


def threat_coverage() -> dict[str, Any]:
    """
    Build per-emulation (per threat-actor campaign) coverage rows.

    Each emulation emulates one campaign, so one row per emulation matches the
    PRD's actor-oriented view (APT29, Lazarus, ...).  Rows are sorted by
    coverage descending so the strongest coverage surfaces first.
    """
    catalogue_total = catalog.technique_count()
    rows: list[dict[str, Any]] = []
    for entry in list_emulations():
        techniques = _emulation_technique_ids(entry)
        total = len(techniques)
        detections_backed = len(techniques & _detection_technique_ids(entry))
        playbook_backed = len(techniques & _playbook_technique_ids(entry))

        rows.append(
            {
                "id": entry.get("name"),
                "name": entry.get("display_name", entry.get("name")),
                "origin": entry.get("origin", "unknown"),
                "originLabel": entry.get("origin_label", ""),
                "attribution": entry.get("attribution", ""),
                "severity": entry.get("severity", ""),
                "techniqueCount": total,
                "coveragePct": _pct(total, catalogue_total),
                # Per content type: how many of this actor's techniques are
                # backed by that content.  An emulation backs all of its own
                # techniques by definition.
                "coverageByContent": {
                    "emulations": _content_coverage(total, total),
                    "playbooks": _content_coverage(playbook_backed, total),
                    "detections": _content_coverage(detections_backed, total),
                },
            }
        )

    rows.sort(key=lambda r: r["coveragePct"], reverse=True)
    return {"totalTechniques": catalogue_total, "actors": rows}


def _content_coverage(covered: int, total: int) -> dict[str, Any]:
    """Build a {covered, total, pct} block for a content type's technique backing."""
    return {"covered": covered, "total": total, "pct": _pct(covered, total)}


def platform_coverage(platform: str | None = None) -> dict[str, Any]:
    """
    Build content-depth counts per platform.

    Args:
        platform: If given, restrict the result to this platform identifier.

    Returns:
        Dict with a `platforms` list; each entry has the platform id, label,
        and counts of emulations, playbooks, and detection rules.  Supported
        platforms with no content are included with zero counts so the dropdown
        and donut always show the full platform set.
    """
    entries = list_emulations()
    requested = (
        [platform] if platform in SUPPORTED_PLATFORMS else sorted(SUPPORTED_PLATFORMS)
    )

    payload: list[dict[str, Any]] = []
    for plat in requested:
        plat_entries = [e for e in entries if _platform_of(e) == plat]
        payload.append(
            {
                "platform": plat,
                "label": PLATFORM_LABELS.get(plat, plat.upper()),
                "emulations": len(plat_entries),
                "playbooks": sum(1 for e in plat_entries if _has_playbook(e)),
                "detections": sum(_detection_count(e) for e in plat_entries),
            }
        )

    return {"platforms": payload}
