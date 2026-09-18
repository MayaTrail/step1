"""
AI-assisted Sigma detection validation.

Synthesizes labeled CloudTrail events from a Sigma rule through the user's LLM
connector, evaluates the rule against them with the in-process Sigma evaluator,
scores a fidelity number, and asks the model for improvements grounded in
whatever failed. Everything here is ephemeral; nothing is persisted.

The fidelity number reflects rule logic against synthetic events (does the rule
fire on the activity it claims to and stay quiet on benign look-alikes), not
production noise. Callers should present it as such.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from apps.emulations.sigma_eval import SigmaUnsupported, evaluate

from .prompts import (
    SUGGESTIONS_SYSTEM_PROMPT,
    SYNTHESIS_SYSTEM_PROMPT,
    build_suggestions_prompt,
    build_synthesis_prompt,
)
from .providers import STREAM_ERROR_PREFIX, stream_chat

logger = logging.getLogger(__name__)

POSITIVE_COUNT = 4
BENIGN_COUNT = 3
EVASION_COUNT = 4

# Eleven full CloudTrail records (4 positive, 3 benign, 4 evasion). A real
# record carries userIdentity, ARNs, sourceIPAddress, requestParameters and
# eventID, which is roughly 450 tokens each, so 2200 truncated the response
# three quarters of the way through and the JSON parse rejected the fragment.
# Measured: a complete synthesis for this prompt runs to about 5,100 characters.
_SYNTHESIS_MAX_TOKENS = 8000

# Synthesis asks for eleven labelled CloudTrail events as JSON, and a provider on
# a free tier buffers the whole response rather than streaming it, so the read
# timeout is effectively "time to first byte". Gemini Flash measured 44.5s for
# this prompt, which the 60s default clears only on a good run. 100s leaves
# headroom inside gunicorn's 120s worker timeout.
_SYNTHESIS_TIMEOUT_S = 100
_SUGGESTIONS_MAX_TOKENS = 700

# Expected verdict per label: positives and evasion variants SHOULD trigger the
# rule (an evasion that slips past is a miss); benign activity should not.
_SHOULD_MATCH = {"positive": True, "evasion": True, "benign": False}


# Hosted models, free tiers especially, return transient 503 (overloaded) and
# 429 (rate limited) that clear on a retry. Without this, validation fails where
# generation (which already retries) would have ridden through - and validation
# makes two model calls, so it is twice as likely to hit a transient blip.
_RETRY_ATTEMPTS = 3
_RETRY_BACKOFF_S = (2, 5)


def _is_retryable(detail: str) -> bool:
    """True when a provider error is a transient overload worth retrying."""
    text = (detail or "").lower()
    return "503" in text or "429" in text or "overload" in text or "rate limit" in text


def _complete(
    provider: str, creds: dict, model: str, system: str, user: str, max_tokens: int,
    timeout: int = 60,
) -> tuple[str | None, str | None]:
    """
    Run one non-streaming completion by collecting the streamed deltas, retrying
    on transient provider errors.

    Returns (text, None) on success or (None, error_detail) on a provider error.
    """
    last_error: str | None = None
    for attempt in range(_RETRY_ATTEMPTS):
        chunks: list[str] = []
        error: str | None = None
        for chunk in stream_chat(
            provider, creds, model, system,
            [{"role": "user", "content": user}], max_tokens=max_tokens,
            timeout=timeout,
        ):
            if chunk.startswith(STREAM_ERROR_PREFIX):
                error = chunk[len(STREAM_ERROR_PREFIX):]
                break
            chunks.append(chunk)
        if error is None:
            return "".join(chunks).strip(), None
        last_error = error
        if not _is_retryable(error) or attempt == _RETRY_ATTEMPTS - 1:
            break
        time.sleep(_RETRY_BACKOFF_S[min(attempt, len(_RETRY_BACKOFF_S) - 1)])
    return None, last_error


_PY_LITERALS = {"True": "true", "False": "false", "None": "null"}

# Value position only: after a colon, comma or opening bracket, so a quoted
# "True" in a field value is left alone.
_PY_LITERAL_RE = re.compile(r"(?<=[:\[,])(\s*)\b(True|False|None)\b")


def _extract_json(text: str) -> Any:
    """
    Parse a JSON object from a model response.

    Models wrap JSON in code fences, prefix it with prose, and sometimes close
    it with one brace too many. The last of those is what made this fail about
    one run in five: an outermost-brace slice takes the final `}` in the string,
    so an unbalanced tail is included and the parse fails exactly as it would
    have without the fallback.

    So the object is decoded from its opening brace with `raw_decode`, which
    reads one complete value and reports where it ended, leaving whatever
    follows to be discarded. Truncation is still a genuine failure and still
    raises: a half-written event is missing data, and inventing the rest would
    put a fabricated CloudTrail record into a detection's evidence.

    Args:
        text: The raw model response.

    Returns:
        The decoded object.

    Raises:
        ValueError: When no complete JSON object can be read.
    """
    try:
        return json.loads(text)
    except ValueError:
        pass

    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object found in model response")

    try:
        obj, _ = json.JSONDecoder().raw_decode(text, start)
        return obj
    except ValueError:
        pass

    # Models trained largely on Python emit its literals: {"isLogging": True}
    # rather than true. Observed from Gemini Flash on roughly one synthesis in
    # four. Rewritten only in value position, immediately after a colon, comma
    # or bracket, so a quoted "True" inside a field stays untouched.
    repaired = _PY_LITERAL_RE.sub(lambda m: m.group(1) + _PY_LITERALS[m.group(2)], text)
    if repaired != text:
        try:
            obj, _ = json.JSONDecoder().raw_decode(repaired, repaired.find("{"))
            return obj
        except ValueError:
            pass

    # Last resort for a fence that swallowed the opening brace's context.
    end = text.rfind("}")
    if end > start:
        return json.loads(text[start:end + 1])
    raise ValueError("no JSON object found in model response")


def _verdict(label: str, matched: bool) -> str:
    """Map (label, matched) to a human-readable verdict."""
    if label == "benign":
        return "quiet" if not matched else "false positive"
    if label == "evasion":
        return "caught" if matched else "missed"
    return "matched" if matched else "missed"


def _score(scenarios: list[dict]) -> dict[str, Any]:
    """
    Compute per-bucket fractions and a blended fidelity score.

    Fidelity is the equal-weight mean of the positive-hit, benign-quiet, and
    evasion-caught rates, over whichever buckets have events, scaled to 0-100.
    """
    buckets: dict[str, list[dict]] = {"positive": [], "benign": [], "evasion": []}
    for scenario in scenarios:
        buckets.setdefault(scenario["label"], []).append(scenario)

    def frac(label: str, good) -> tuple[str, float | None]:
        items = buckets.get(label, [])
        if not items:
            return "0/0", None
        hits = sum(1 for s in items if good(s))
        return f"{hits}/{len(items)}", hits / len(items)

    pos_text, pos_rate = frac("positive", lambda s: s["matched"])
    ben_text, ben_rate = frac("benign", lambda s: not s["matched"])
    eva_text, eva_rate = frac("evasion", lambda s: s["matched"])

    present = [r for r in (pos_rate, ben_rate, eva_rate) if r is not None]
    fidelity = round(sum(present) / len(present) * 100) if present else 0

    return {
        "fidelity": fidelity,
        "summary": {
            "positiveHit": pos_text,
            "benignQuiet": ben_text,
            "evasionCaught": eva_text,
        },
    }


def _suggestions(
    provider: str, creds: dict, model: str, rule_text: str, failures: list[dict]
) -> list[str]:
    """
    Ask the model for improvements grounded in the failed scenarios.

    Returns a list of suggestion strings, or an empty list when there were no
    failures or the output could not be parsed. Suggestions are advisory, so a
    parse failure here must not fail the whole validation.
    """
    if not failures:
        return []
    user = build_suggestions_prompt(rule_text, failures)
    raw, error = _complete(
        provider, creds, model, SUGGESTIONS_SYSTEM_PROMPT, user, _SUGGESTIONS_MAX_TOKENS
    )
    if error or not raw:
        return []
    try:
        items = _extract_json(raw).get("suggestions", [])
    except (ValueError, AttributeError):
        return []
    return [str(item) for item in items if isinstance(item, str)][:8]


def run_validation(
    provider: str, creds: dict, model: str, rule_text: str, sigma_rule: dict
) -> dict[str, Any]:
    """
    Run one ephemeral validation pass for a Sigma rule.

    Args:
        provider:   LLM provider key (from the user's connector).
        creds:      provider credentials from build_credentials.
        model:      provider model id.
        rule_text:  the raw Sigma YAML (sent to the model).
        sigma_rule: the parsed Sigma dict (evaluated locally).

    Returns:
        On success {evaluable, fidelity, summary, scenarios, suggestions}; on a
        provider or parse failure {error}. Assumes the rule is evaluable
        (gate with sigma_eval.is_evaluable first).
    """
    user = build_synthesis_prompt(rule_text, POSITIVE_COUNT, BENIGN_COUNT, EVASION_COUNT)
    raw, error = _complete(
        provider, creds, model, SYNTHESIS_SYSTEM_PROMPT, user, _SYNTHESIS_MAX_TOKENS,
        timeout=_SYNTHESIS_TIMEOUT_S,
    )
    if error:
        return {"error": error}

    try:
        raw_scenarios = _extract_json(raw)["scenarios"]
    except (ValueError, KeyError, TypeError) as exc:
        logger.info("Detection validation: unparseable synthesis output: %s", exc)
        return {"error": "The model returned malformed synthesis output. Try again."}

    scenarios: list[dict] = []
    for item in raw_scenarios:
        label = item.get("label") if isinstance(item, dict) else None
        event = item.get("event") if isinstance(item, dict) else None
        if label not in _SHOULD_MATCH or not isinstance(event, dict):
            continue
        try:
            result = evaluate(sigma_rule, event)
        except SigmaUnsupported:
            continue
        matched = result["matched"]
        scenarios.append({
            "label": label,
            "rationale": item.get("rationale", ""),
            "event": event,
            "expected": _SHOULD_MATCH[label],
            "matched": matched,
            "verdict": _verdict(label, matched),
            "firedSelections": result["firedSelections"],
        })

    if not scenarios:
        return {"error": "The model did not return any usable test events. Try again."}

    scored = _score(scenarios)
    failures = [
        {"label": s["label"], "rationale": s["rationale"], "event": s["event"]}
        for s in scenarios
        if s["verdict"] in ("missed", "false positive")
    ]

    return {
        "evaluable": True,
        "fidelity": scored["fidelity"],
        "summary": scored["summary"],
        "scenarios": scenarios,
        "suggestions": _suggestions(provider, creds, model, rule_text, failures),
    }
