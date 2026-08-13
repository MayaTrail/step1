"""
Minimal in-process Sigma rule evaluator.

Evaluates a single Sigma rule against a single log event, so detection rules
can be tested against synthetic events without compiling to a SIEM query
language. It supports the subset of Sigma that MayaTrail's own rules use:

    - plain field equality (case-insensitive, per Sigma default),
    - the |contains, |startswith, |endswith, |re, |exists and |all field
      modifiers,
    - list-of-values (OR by default, AND with |all),
    - nested dotted field paths (userIdentity.type, requestParameters.roleArn),
    - list-of-maps selections (OR of the maps),
    - boolean conditions over named selections (and / or / not / parentheses).

Aggregation and correlation conditions cannot be judged from one event: the
Sigma pipe form (`selection | count() by field > N`) and folded multi-line
conditions need many events grouped over time. Those raise SigmaUnsupported so
callers can fall back to AI assessment instead of guessing a verdict.
"""

from __future__ import annotations

import json
import re
from typing import Any

_SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "all", "exists"})
_CONDITION_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*.]+")


class SigmaUnsupported(Exception):
    """Raised when a rule uses a Sigma construct this evaluator cannot judge."""


def _get_field(event: dict, path: str) -> Any:
    """
    Resolve a field from an event by dotted path.

    Tries the literal flattened key first (events may carry "userIdentity.type"
    as one key), then walks the path as nested dicts. Returns None if absent.
    """
    if path in event:
        return event[path]
    current: Any = event
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _as_text(value: Any) -> str:
    """Coerce a field value to text; dicts and lists serialise to JSON."""
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def _compare(actual: Any, expected: Any, modifier: str | None) -> bool:
    """Compare one actual value against one expected value under a modifier."""
    if actual is None:
        return False
    if modifier == "re":
        return re.search(str(expected), _as_text(actual)) is not None
    actual_text = _as_text(actual).lower()
    expected_text = str(expected).lower()
    if modifier == "contains":
        return expected_text in actual_text
    if modifier == "startswith":
        return actual_text.startswith(expected_text)
    if modifier == "endswith":
        return actual_text.endswith(expected_text)
    return actual_text == expected_text


def _match_field(field_spec: str, expected: Any, event: dict) -> bool:
    """
    Evaluate one "field|modifiers: value(s)" predicate against an event.

    A list of expected values is OR by default, or AND when |all is present.
    """
    path, *modifiers = field_spec.split("|")
    modifier: str | None = None
    require_all = False
    for mod in modifiers:
        if mod == "all":
            require_all = True
        elif mod in _SUPPORTED_MODIFIERS:
            modifier = mod
        else:
            raise SigmaUnsupported(f"unsupported field modifier '|{mod}'")

    actual = _get_field(event, path)

    # |exists asks whether the path resolves at all, so it cannot go through
    # _compare, which treats an absent field as a non-match by definition.
    if modifier == "exists":
        return (actual is not None) is bool(expected)

    values = expected if isinstance(expected, list) else [expected]
    results = [_compare(actual, value, modifier) for value in values]
    return all(results) if require_all else any(results)


def _match_selection(selection: Any, event: dict) -> bool:
    """
    Evaluate one selection against an event.

    A dict selection matches when every field predicate matches (AND). A list
    selection is OR of its member maps.

    Both branches build a list rather than pass a generator to any()/all().
    Short-circuiting would stop at the first decisive predicate, so an
    unsupported modifier later in the same block would never raise and
    is_evaluable would wrongly pass the rule. Every predicate is evaluated.
    """
    if isinstance(selection, list):
        return any([_match_selection(member, event) for member in selection])
    if not isinstance(selection, dict):
        raise SigmaUnsupported("selection is neither a map nor a list of maps")
    return all([_match_field(field, expected, event) for field, expected in selection.items()])


def _eval_condition(condition: str, selection_matches: dict[str, bool]) -> bool:
    """
    Evaluate a boolean Sigma condition over precomputed selection results.

    Supports and / or / not and parentheses over selection names. Raises
    SigmaUnsupported for aggregation pipes and quantifier forms (1 of them,
    all of them) that a single-event evaluator cannot decide.
    """
    if "|" in condition:
        raise SigmaUnsupported("aggregation/correlation condition")

    tokens = _CONDITION_TOKEN.findall(condition)
    if any(token == "of" or "*" in token for token in tokens):
        raise SigmaUnsupported("quantifier condition (e.g. '1 of them')")

    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def advance() -> str:
        nonlocal pos
        token = tokens[pos]
        pos += 1
        return token

    def parse_or() -> bool:
        value = parse_and()
        while peek() == "or":
            advance()
            value = parse_and() or value
        return value

    def parse_and() -> bool:
        value = parse_not()
        while peek() == "and":
            advance()
            value = parse_not() and value
        return value

    def parse_not() -> bool:
        if peek() == "not":
            advance()
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        token = peek()
        if token == "(":
            advance()
            value = parse_or()
            if peek() != ")":
                raise SigmaUnsupported("unbalanced parentheses in condition")
            advance()
            return value
        if token is None or token == ")":
            raise SigmaUnsupported("malformed condition")
        name = advance()
        if name not in selection_matches:
            raise SigmaUnsupported(f"unknown selection '{name}' in condition")
        return selection_matches[name]

    result = parse_or()
    if pos != len(tokens):
        raise SigmaUnsupported("trailing tokens in condition")
    return result


def _selections(rule: dict) -> dict[str, Any]:
    """Return the detection block's selections (every key except condition)."""
    detection = rule.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaUnsupported("rule has no detection block with a condition")
    condition = detection["condition"]
    if not isinstance(condition, str):
        raise SigmaUnsupported("condition is not a single expression")
    return {key: value for key, value in detection.items() if key != "condition"}


def is_evaluable(rule: dict) -> tuple[bool, str]:
    """
    Report whether this evaluator can execute the rule.

    Dry-runs the condition parser and the selection modifiers against an empty
    event to surface unsupported constructs without needing a real event.
    Returns (True, "") when evaluable, or (False, reason) otherwise.
    """
    try:
        selections = _selections(rule)
        for selection in selections.values():
            _match_selection(selection, {})
        _eval_condition(rule["detection"]["condition"], dict.fromkeys(selections, False))
        return True, ""
    except SigmaUnsupported as exc:
        return False, str(exc)


def evaluate(rule: dict, event: dict) -> dict[str, Any]:
    """
    Evaluate a Sigma rule against a single event.

    Returns {"matched": bool, "firedSelections": [names that matched]}.
    Raises SigmaUnsupported when the rule uses a construct outside the
    supported subset; callers should gate on is_evaluable first.
    """
    selections = _selections(rule)
    matches = {name: _match_selection(selection, event) for name, selection in selections.items()}
    matched = _eval_condition(rule["detection"]["condition"], matches)
    fired = [name for name, hit in matches.items() if hit]
    return {"matched": matched, "firedSelections": fired}
