"""
The scan result contract between Scout and this product.

Scout lives in its own repository and ranks chains in its own shape. Handing
that shape to the frontend would make every Scout upgrade a frontend
deployment, so the task serializes into the versioned envelope built here and
the graph component reads nothing else.

This module imports Django and the standard library only — no boto3, no
Scout, no DRF — because it holds the decisions that must not regress and the
test suite runs without those packages installed (see config/settings/ci.py).

Field names follow Scout's real output, verified in Task 1 against the pinned
commit (see docs/superpowers/specs/2026-09-21-attack-graph-integration-design.md,
"Assumptions to verify" and the envelope field-mapping table) — not the
pre-verification guess. In particular: a chain's `hops` (not `steps`) carry no
per-hop `technique` or `condition`; `mitre_techniques` is attached once, on
the chain; and both endpoints and every hop are plain IAM ARN strings, with no
separate node-id space to reconcile.
"""

from datetime import datetime
from typing import Any

# Bumped when the envelope's shape changes in a way the frontend must notice.
# The frontend refuses to render a version it does not know rather than
# drawing a half-empty graph.
SCHEMA_VERSION = 1

# The ranked chains kept per scan. Scout ranks descending, so this is the top
# of the list; `truncated` records that there were more.
MAX_CHAINS = 25

# The evaluator the scan runs. Recorded in the envelope because it is what
# makes the SCP caveat true: the effective evaluator applies permission
# boundaries from the GAAD but no AWS Organizations policies, so a chain it
# reports may in fact be blocked by an SCP the scan never fetched.
#
# Verified in Task 1: pipeline.run()'s evaluator=None default resolves
# internally to scout.eval.effective.EffectivePermissionEvaluator, but the
# report itself carries no field naming which evaluator ran — this literal is
# the task's own claim, made true by Task 9 passing evaluator explicitly
# rather than relying on the default.
EVALUATOR = "effective"

# What `mode` says when Scout reported none.
#
# Not "self". A scan is classified "partial" whenever mode is anything other
# than "account", so the safe classification does not need this value to lie —
# and "self" is a specific claim the UI turns into specific advice ("the audit
# role's policy no longer grants iam:GetAccountAuthorizationDetails, reconnect
# it"). Writing that word in when Scout said nothing at all would have the
# product assert a cause it never observed. That is the same failure as a
# false all-clear, moved up a level: a confident explanation of something that
# did not happen. Fail safe on the state; stay honest about the reason.
UNKNOWN_MODE = "unknown"


def serialize_scan(
    report: dict[str, Any],
    collection: dict[str, Any],
    account_id: str,
    scanned_at: datetime,
    regions: list[str] | None = None,
) -> dict[str, Any]:
    """
    Turn a Scout report into the envelope stored on ScoutScan.result.

    Args:
        report: Scout's pipeline output; `report["chains"]` is ranked descending
            by risk_score.
        collection: Scout's collection metadata; `collection["mode"]` is
            "account" when account-wide IAM was readable and "self" when it
            fell back to enumerating only the assumed role.
        account_id: The AWS account the scan ran against.
        scanned_at: When the scan completed, timezone-aware.
        regions: Which regions resource collection covered (User.aws_audit_regions
            at scan time), tenant-declared rather than auto-detected. Empty or
            omitted means the scan was IAM-only — no EC2/Lambda/S3/etc. resources
            were collected, so a chain through an actual resource anywhere could
            not be found, only identities that already hold an impact directly.
            Recorded so the UI can say so the same way it states the SCP caveat:
            a scan is not "the whole account" merely by completing.

    Returns:
        A plain-JSON envelope. `mode` is Scout's value verbatim, or UNKNOWN_MODE
        when it reported none — see the constant for why it is not silently
        rewritten to "self".
    """
    chains = list(report.get("chains") or [])
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "mode": collection.get("mode") or UNKNOWN_MODE,
        "account_id": account_id,
        "scanned_at": scanned_at.isoformat(),
        # v1 runs Scout's effective evaluator with no AWS Organizations
        # policies fetched, so a reported chain may be blocked by an SCP this
        # scan never saw. Recorded here so the UI can say so.
        "evaluator": EVALUATOR,
        "regions": list(regions or []),
        "truncated": len(chains) > MAX_CHAINS,
        "chains": [
            _chain(raw, rank)
            for rank, raw in enumerate(chains[:MAX_CHAINS], start=1)
        ],
    }
    envelope["state"] = result_state(envelope)
    return envelope


def result_state(envelope: dict[str, Any]) -> str:
    """
    Classify a scan result for display.

    Returns:
        "partial" — the scan did not demonstrably read account-wide IAM,
            whatever it found. This is checked first and on purpose: a
            self-scoped scan finds nothing because it could not look, and
            rendering that as an account with no privilege-escalation paths is
            a false all-clear from a security product.
        "clean" — a full scan that found no chains.
        "findings" — a full scan with ranked chains.

    The check is a whitelist of the one mode that earns a verdict, not a
    blacklist of the degraded ones. A mode Scout invents in a future release
    then lands on the cautious side of the line without this function being
    edited — which is the only way a rule like this survives a dependency
    that is maintained elsewhere.
    """
    if envelope.get("mode") != "account":
        return "partial"
    return "findings" if envelope.get("chains") else "clean"


def _chain(raw: dict[str, Any], rank: int) -> dict[str, Any]:
    """
    Normalise one ranked chain.

    `id` is always serializer-assigned (`chain-{rank}`), never Scout's own
    `chain_id`: that id is opaque and not guaranteed stable across scans, so
    surfacing it — even only as a fallback — would start leaking it silently
    the day Scout's shape changes to make the fallback trigger.
    """
    hops = sorted(raw.get("hops") or [], key=lambda hop: hop.get("hop_number", 0))
    terminal_props = raw.get("terminal_props") or {}
    # scout.reason.engine.reason() (called in tasks.py before serialize_scan)
    # stamps this in-place on the raw chain; absent on any report produced
    # without that step (e.g. an older stored scan, or a report built
    # directly in a test) — treated as "no analysis available", not an error.
    analysis = raw.get("analysis") or {}
    return {
        "id": f"chain-{rank}",
        "rank": rank,
        "score": raw.get("risk_score"),
        "source": _node(str(raw.get("origin_identity_arn") or "")),
        "target": _node(str(raw.get("terminal_target_arn") or "")),
        # Chain-level, not per-hop: Scout does not attach a technique to an
        # individual hop (verified in Task 1).
        "mitre_techniques": list(raw.get("mitre_techniques") or []),
        "steps": [_step(hop) for hop in hops],
        # Scout reports a chain with zero hops when an identity already holds
        # this impact directly — no escalation step exists to draw. Without
        # this field the frontend has no way to tell "already privileged"
        # apart from "found nothing to say about this node"; both would
        # otherwise render as an isolated box with a number next to it.
        # Optional: older stored scans and any future Scout release that
        # drops the field both read as None, which the frontend treats as
        # "unknown impact" rather than raising.
        "terminal_impact": raw.get("terminal_impact"),
        # Scout's chain builder collapses near-duplicate chains (same source
        # and target, different mechanism) into one representative chain and
        # lists the merged-away routes here (chains/builder.py's
        # _collapse_by_mechanism). Without this field those routes are simply
        # gone from the product's view, not merely unranked — the account
        # genuinely has more than one way in, and only one shows.
        "alternate_mechanisms": list(terminal_props.get("mechanisms") or []),
        # Plain-English "how this works", plus one detection and remediation
        # idea, from Scout's own (offline, no-LLM-by-default) reasoning
        # engine. Empty strings, never omitted, when no analysis was run —
        # the frontend can render "no explanation available" without a
        # presence check on three separate keys.
        "narrative": analysis.get("narrative") or "",
        "detection": analysis.get("detection") or "",
        "remediation": analysis.get("remediation") or "",
    }


def _node(arn: str) -> dict[str, Any]:
    """
    Normalise one identity endpoint.

    Scout gives no node id, type or label anywhere in the chain output — only
    an ARN (verified in Task 1). `id` is the ARN itself: it is the only
    identifier space Scout uses, at every level, so there is no id/ARN join to
    normalise. `type` is derived by parsing the ARN's resource segment
    (`user/`, `role/`, ...) since Scout does not provide one.
    """
    resource = arn.rsplit(":", 1)[-1] if arn else ""
    kind, _, name = resource.partition("/")
    return {
        "id": arn,
        "arn": arn,
        "type": kind or "other",
        # The graph renders this, so never leave it empty: an unlabelled node
        # is a box a reader cannot act on.
        "label": name or arn or "unknown",
    }


def _step(hop: dict[str, Any]) -> dict[str, Any]:
    """
    Normalise one hop of a chain.

    No `technique` field: Scout attaches none per hop (a chain's MITRE
    technique ids are chain-level — see `_chain`). `mechanism`/`action` are
    Scout's own hop fields, carried through verbatim.

    `certainty`/`conditional_reason` come from `hop["conditional"]`
    (`{"gating": [...]}` or null) — see `_conditional_summary`.
    """
    mechanism = hop.get("mechanism") or ""
    action = hop.get("action") or ""
    certainty, conditional_reason = _conditional_summary(hop.get("conditional"))
    return {
        "from": str(hop.get("source_arn") or ""),
        "to": str(hop.get("target_arn") or ""),
        "mechanism": mechanism,
        "action": action,
        "concrete_api_sequence": list(hop.get("concrete_api_sequence") or []),
        "detail": f"{action} ({mechanism})" if action and mechanism else (action or mechanism),
        "certainty": certainty,
        "conditional_reason": conditional_reason,
    }


# Scout's evaluator (scout/eval/conditional.py) tags each gating key with a
# `klass` describing why the grant isn't unconditional. `attacker_controllable`
# is rendered from the gate's own key/operator/values so the reason names the
# actual condition; the rest are fixed phrasing. SCP/permission-boundary
# denial is deliberately absent here: Scout's own evaluator does not evaluate
# those (see EVALUATOR above) — inventing a "blocked" phrase for a klass Scout
# doesn't emit would assert a diagnosis this scan never made.
_GATING_KLASS_PHRASES: dict[str, str] = {
    "deny_may_apply": "a conditional Deny may block this",
    "unknown_key": "an unresolved condition applies",
    "unknown_operator": "an unresolved condition applies",
    "parse_error": "an unresolved condition applies",
}
_GENERIC_GATING_REASON = "a condition applies"


def _gating_reason(gate: dict[str, Any]) -> str:
    """Plain-English reason for one gating key. Falls back rather than
    raising on a klass this module has never seen — a future Scout release
    must still read as conditional, with some explanation, not crash."""
    klass = gate.get("klass") or ""
    if klass == "attacker_controllable":
        key = str(gate.get("key") or "").strip()
        operator = str(gate.get("operator") or "").strip()
        values = ", ".join(str(v) for v in (gate.get("values") or []))
        parts = [p for p in (key, operator, values) if p]
        return f"requires {' '.join(parts)}" if parts else _GENERIC_GATING_REASON
    return _GATING_KLASS_PHRASES.get(klass, _GENERIC_GATING_REASON)


def _conditional_summary(conditional: dict[str, Any] | None) -> tuple[str, str]:
    """
    (certainty, conditional_reason) for one hop.

    "conditional" iff Scout's evaluator actually attached gating keys —
    `conditional` can be present but carry an empty `gating` list, which
    still means nothing gates the grant. Reasons are de-duplicated: several
    gates commonly share the same klass (e.g. two Deny statements that may
    both apply), and repeating the same sentence twice would read as two
    findings instead of one.
    """
    gating = (conditional or {}).get("gating") or []
    if not gating:
        return "deterministic", ""
    reasons: list[str] = []
    for gate in gating:
        reason = _gating_reason(gate)
        if reason not in reasons:
            reasons.append(reason)
    return "conditional", "; ".join(reasons)
