"""
Compile shipped Sigma rules into a customer's SIEM dialect.

sigma_convert.py does the compiling, one file at a time. This assembles those
results into something a detection engineer can actually take away: a bundle of
queries for a whole emulation, or - the case worth building for - only the rules
that a run proved were not working.

A run ends with a verdict per rule: fired, silent, or no_logs. "Silent" means
the activity happened, the logs arrived, and the rule did not match. That is the
finding, and the next thing the engineer wants is that rule in the language
their SIEM speaks. Exporting exactly those closes the loop between "here is your
gap" and "here is the fix".

Rules that a target cannot express are reported, never dropped. A bundle that
silently omitted three correlations would be worse than useless: the engineer
would deploy it believing they had coverage they do not have.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .detections import build_detection_detail
from .sigma_convert import (
    TARGETS,
    BackendUnavailable,
    ConversionResult,
    available_targets,
    convert,
)

logger = logging.getLogger(__name__)


@dataclass
class ExportBundle:
    """Every rule requested, compiled for one target."""

    target: str
    label: str
    output_format: str
    emulation_type: str
    queries: list[dict[str, str]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    # Rule ids asked for that the catalogue does not have, or that carry no
    # Sigma at all. Distinct from `skipped`, which is "the backend cannot
    # express this".
    missing: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """Serialise for the API."""
        return {
            "target": self.target,
            "label": self.label,
            "format": self.output_format,
            "emulationType": self.emulation_type,
            "queries": self.queries,
            "skipped": self.skipped,
            "missing": self.missing,
            "counts": {
                "converted": len(self.queries),
                "skipped": len(self.skipped),
                "missing": len(self.missing),
            },
        }


def _header(bundle: ExportBundle, note: str = "") -> list[str]:
    """Provenance comment at the top of a downloaded bundle."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# MayaTrail detection export - {bundle.label}",
        f"# Emulation: {bundle.emulation_type}",
        f"# Generated: {stamp}",
        f"# Converted: {len(bundle.queries)}"
        f"  Skipped: {len(bundle.skipped)}"
        f"  Missing: {len(bundle.missing)}",
    ]
    if note:
        lines.append(f"# {note}")
    if bundle.skipped:
        lines.append("#")
        lines.append("# NOT INCLUDED - this target cannot express these rules.")
        lines.append("# You do not have coverage for them from this file:")
        for item in bundle.skipped:
            lines.append(f"#   {item['ruleId']}: {item['reason']}")
    if bundle.missing:
        lines.append("#")
        lines.append("# NOT FOUND in the catalogue: " + ", ".join(bundle.missing))
    lines.append("")
    return lines


def bundle_to_text(bundle: ExportBundle, note: str = "") -> str:
    """
    Render a bundle as a downloadable text file.

    Each query is preceded by its title and rule id, so a query pasted into a
    SIEM can still be traced back to the rule it came from.
    """
    lines = _header(bundle, note)
    for item in bundle.queries:
        trace = item["ruleId"]
        if item.get("sigmaId"):
            trace += f" / {item['sigmaId']}"
        lines.append(f"# {item['title']}  [{trace}]")
        lines.append(item["query"])
        lines.append("")
    return "\n".join(lines)


def _absorb(bundle: ExportBundle, result: ConversionResult, rule_id: str) -> None:
    """
    Fold one file's conversion result into the bundle.

    Two identifiers travel together and they are not interchangeable. `ruleId`
    is the technique grouping key the caller asked for and the UI addresses
    ("t1496"); `sigmaId` is the rule document's own UUID. One file can hold
    several Sigma rules, so a single requested ruleId legitimately produces
    several queries with different sigmaIds - collapsing them into one field
    would make a multi-rule file look like a duplicate.
    """
    if not result.ok:
        # The file could not be compiled at all. That is a skip with the
        # compiler's own reason, not a silent loss.
        bundle.skipped.append(
            {
                "ruleId": rule_id,
                "sigmaId": "",
                "title": rule_id,
                "reason": result.error or "unknown error",
            }
        )
        return
    for query in result.queries:
        bundle.queries.append(
            {
                "ruleId": rule_id,
                "sigmaId": query.rule_id or "",
                "title": query.title,
                "query": query.query,
            }
        )
    for skip in result.skipped:
        bundle.skipped.append(
            {
                "ruleId": rule_id,
                "sigmaId": skip.rule_id or "",
                "title": skip.title,
                "reason": skip.reason,
            }
        )


def export_rules(
    entry: dict,
    rule_ids: list[str],
    target: str,
    output_format: str = "default",
) -> ExportBundle:
    """
    Compile a set of an emulation's rules for one target.

    Args:
        entry: The emulation's registry catalogue entry.
        rule_ids: Rule ids to compile.
        target: A key of TARGETS.
        output_format: A member of that target's output_formats.

    Returns:
        The assembled bundle.

    Raises:
        BackendUnavailable: the target's backend is not installed.
        KeyError: unknown target name.
    """
    spec = TARGETS[target]
    bundle = ExportBundle(
        target=target,
        label=spec.label,
        output_format=output_format,
        emulation_type=entry.get("name", ""),
    )

    for rule_id in rule_ids:
        detail = build_detection_detail(entry, rule_id)
        sigma_text = (detail or {}).get("sigma")
        if not sigma_text:
            bundle.missing.append(rule_id)
            continue
        try:
            result = convert(sigma_text, target, output_format)
        except BackendUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - one bad rule must not sink the bundle
            logger.exception("Converting %s for %s failed", rule_id, target)
            bundle.skipped.append(
                {
                    "ruleId": rule_id,
                    "sigmaId": "",
                    "title": rule_id,
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        _absorb(bundle, result, rule_id)

    return bundle


def target_catalogue() -> list[dict[str, Any]]:
    """
    Every conversion target, and whether this deployment can serve it.

    Reported rather than filtered: a UI that silently omits Splunk when the
    backend is missing leaves the operator wondering whether the product
    supports it at all. Saying "installed: false" is a deployment problem with
    an obvious fix.
    """
    installed = set(available_targets())
    return [
        {
            "name": name,
            "label": spec.label,
            "formats": list(spec.output_formats),
            "installed": name in installed,
            "install": spec.install,
        }
        for name, spec in TARGETS.items()
    ]
