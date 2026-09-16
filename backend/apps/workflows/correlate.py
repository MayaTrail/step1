"""
Matching a client's SIEM alerts against the detections an emulation expects.

The question this answers is the reason the workflow exists: of the detections
that should have caught this attack, which ones did the client's SIEM actually
report? An emulation on its own tells a client nothing; the SIEM's response to
it is the finding.

Matching runs down a ladder, because we do not control whose detections the
client runs:

    exact       the alert names a Sigma rule id we ship. The client deployed
                MayaTrail's rules, so this is an identity match, not a guess.
    technique   the alert carries the ATT&CK technique the rule maps. The
                client wrote their own rule and it covers this technique.
    weak        an alert arrived inside the run's window and matched neither.
                Reported so the reader can see it, never counted as a pass.

The tiers exist because a wrong verdict here is expensive in a way a missing
one is not. This feature grades a client's own detection engineering; telling a
team their SIEM missed something it caught, or that it caught something it did
not, is the kind of error that ends the conversation. So the ladder is
precision-first and every verdict carries the alert that produced it.

Pure functions over dicts: no models, no network, no settings, so the rules are
testable without a database.
"""

from __future__ import annotations

import re
from typing import Any

# Alerts name a technique in many shapes: "T1098.001", "attack.t1098.001",
# "MITRE T1098.001". Pulling the id out of whatever arrived is more reliable
# than asking every SIEM to agree on a format.
_TECHNIQUE_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b", re.IGNORECASE)

MATCH_EXACT = "exact"
MATCH_TECHNIQUE = "technique"
MATCH_WEAK = "weak"

# Ordering used when one rule is reached by more than one alert, and to order
# what a reader sees.
_TIER_RANK = {MATCH_EXACT: 0, MATCH_TECHNIQUE: 1, MATCH_WEAK: 2}

# Verdicts a rule can end a run with.
FIRED = "fired"
SILENT = "silent"
NOT_INTEGRATED = "not_integrated"


def normalise_technique(value: str | None) -> str:
    """
    Reduce any technique spelling to a canonical ATT&CK id.

    Args:
        value: Free text that may contain a technique id, in any of the shapes
            SIEMs emit ("attack.t1098.001", "T1098.001", "MITRE T1098.001").

    Returns:
        The id upper-cased, for example "T1098.001", or an empty string when
        the text names no technique.
    """
    if not value:
        return ""
    match = _TECHNIQUE_RE.search(value)
    if not match:
        return ""
    base, sub = match.group(1), match.group(2)
    return f"T{base}.{sub}" if sub else f"T{base}"


def _rule_techniques(rule: dict[str, Any]) -> set[str]:
    """
    Collect the ATT&CK ids a detection rule claims to cover.

    Args:
        rule: A detection summary from list_detection_summaries.

    Returns:
        Canonical technique ids, possibly empty.
    """
    technique = rule.get("technique") or {}
    candidates = [technique.get("id") if isinstance(technique, dict) else technique]
    candidates.append(rule.get("ruleId"))
    return {t for t in (normalise_technique(str(c or "")) for c in candidates) if t}


def _rule_sigma_ids(rule: dict[str, Any]) -> set[str]:
    """
    Collect the Sigma document ids a detection rule ships.

    Every rule MayaTrail ships carries a unique Sigma UUID, so an alert naming
    one is an identity match rather than an inference.

    Args:
        rule: A detection summary carrying a `sigmaIds` list.

    Returns:
        Lower-cased ids, possibly empty.
    """
    return {str(value).strip().lower() for value in rule.get("sigmaIds", []) if value}


def _alert_technique(alert: dict[str, Any]) -> str:
    """
    Resolve the technique an alert refers to.

    Reads the dedicated field first, then falls back to the rule name, since
    many teams put the technique in the title rather than in a tag.

    Args:
        alert: A normalised alert.

    Returns:
        A canonical technique id, or an empty string.
    """
    return normalise_technique(alert.get("technique")) or normalise_technique(alert.get("ruleName"))


def match_alerts(
    rules: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Decide which expected detections the client's SIEM reported.

    Args:
        rules: The emulation's detection summaries, each with a ruleId, title
            and optionally sigmaIds and technique.
        alerts: Alerts attributed to the run's window, each a dict with
            ruleId, ruleName, technique and an id for evidence.

    Returns:
        Dict with `rules` (one verdict per expected detection, carrying the
        matching alert when there is one) and `unmatched` (alerts that arrived
        in the window but map to no expected detection). Verdicts are `fired`
        or `silent` only; deciding that nothing is integrated needs to know
        whether the endpoint has ever received anything, which is not a fact
        about this run, so scoring.py makes that call.
    """
    by_sigma_id: dict[str, list[int]] = {}
    by_technique: dict[str, list[int]] = {}
    for index, rule in enumerate(rules):
        for sigma_id in _rule_sigma_ids(rule):
            by_sigma_id.setdefault(sigma_id, []).append(index)
        for technique in _rule_techniques(rule):
            by_technique.setdefault(technique, []).append(index)

    best: dict[int, tuple[str, dict[str, Any]]] = {}
    claimed: set[str] = set()

    def record(index: int, tier: str, alert: dict[str, Any]) -> None:
        """Keep the highest-precision alert that reached a given rule."""
        claimed.add(str(alert.get("id")))
        current = best.get(index)
        if current is None or _TIER_RANK[tier] < _TIER_RANK[current[0]]:
            best[index] = (tier, alert)

    for alert in alerts:
        rule_id = str(alert.get("ruleId") or "").strip().lower()
        targets = by_sigma_id.get(rule_id, []) if rule_id else []
        if targets:
            for index in targets:
                record(index, MATCH_EXACT, alert)
            continue

        technique = _alert_technique(alert)
        targets = by_technique.get(technique, []) if technique else []
        if targets:
            for index in targets:
                record(index, MATCH_TECHNIQUE, alert)

    verdicts = []
    for index, rule in enumerate(rules):
        hit = best.get(index)
        verdicts.append({
            "ruleId": rule.get("ruleId", ""),
            "title": rule.get("title", ""),
            "severity": rule.get("severity", ""),
            "technique": (rule.get("technique") or {}).get("id", "")
            if isinstance(rule.get("technique"), dict)
            else "",
            "verdict": FIRED if hit else SILENT,
            "matchTier": hit[0] if hit else "",
            "evidence": _evidence(hit[1]) if hit else None,
        })

    # An alert that reached no rule is still worth showing: it may be the
    # client's own coverage of something we did not expect, or noise from real
    # activity during the window. Either way it is not a pass.
    unmatched = [
        _evidence(alert) for alert in alerts if str(alert.get("id")) not in claimed
    ]

    return {"rules": verdicts, "unmatched": unmatched}


def _evidence(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Reduce an alert to the fields a reader needs to judge a verdict.

    Args:
        alert: A normalised alert.

    Returns:
        The identifying fields only. The full payload stays on IngestedAlert,
        reachable from the alert id, rather than being copied into every report.
    """
    return {
        "alertId": str(alert.get("id", "")),
        "ruleId": alert.get("ruleId", ""),
        "ruleName": alert.get("ruleName", ""),
        "technique": _alert_technique(alert),
        "severity": alert.get("severity", ""),
        "firedAt": alert.get("firedAt"),
        "receivedAt": alert.get("receivedAt"),
    }
