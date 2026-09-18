"""
Compiling the detections a client's SIEM missed.

This is where the validation loop closes. A workflow ends with a verdict per
expected detection - fired, silent, or not_integrated - and "two rules stayed
silent" is a finding with no action attached. Handing back exactly those two
rules, compiled for the SIEM the client actually runs, is the action.

Only `silent` is offered. A rule that fired needs nothing, and `not_integrated`
means no alert route existed, so the rule was never exercised and shipping a
query for it would assert a gap that was never measured.

The conversion itself belongs to the emulations app; this module only decides
which rules to ask for.
"""

from __future__ import annotations

from typing import Any

# The verdict meaning "this detection was expected and your SIEM did not report
# it", which is the only one a query can close.
SILENT = "silent"


def silent_rule_ids(score: dict[str, Any] | None) -> list[str]:
    """
    Rule ids a workflow found silent, in the order the score reported them.

    Args:
        score: The workflow's stored score payload, or None for a run that
            never settled.

    Returns:
        Rule ids whose verdict is `silent`. Empty when the run did not settle,
        when nothing was silent, or when no endpoint was integrated, since in
        that last case every verdict was rewritten to not_integrated and no
        claim about the client's rules was ever made.
    """
    if not score:
        return []
    return [
        rule["ruleId"]
        for rule in score.get("rules", []) or []
        if rule.get("verdict") == SILENT and rule.get("ruleId")
    ]
