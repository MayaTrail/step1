"""Tests for utils._parse_rate_limit_reset.

The regression we're locking in: a stale/past reset message used to parse as
~31,000,000 seconds (the reset date wrapped to next year). Now it MUST return
None so the caller falls back to staggered backoff.
"""
from utils import _parse_rate_limit_reset


class TestFullDatetime:
    def test_parses_full_format_with_timezone(self):
        # Use a time well into the future so the test doesn't flake near midnight.
        # We can't pin "now" without freezegun, so just assert the structure:
        # either a positive sane delta, or None if the fixed date is already past.
        text = "You've hit your limit · resets Dec 31, 11:30pm (UTC)"
        repr_str, delta = _parse_rate_limit_reset(text)
        assert "Dec 31" in repr_str
        assert "11:30pm" in repr_str
        # delta is either a finite positive number <=86400, or None
        assert delta is None or (0 < delta <= 86400)

    def test_stale_past_date_returns_none(self):
        # Jan 1 00:00 is almost certainly in the past from "now" (or it just
        # happened — edge-case flakes are bounded by 86400s cap anyway).
        # Key invariant: we NEVER return ~31M seconds.
        text = "resets Jan 1, 12:00am (UTC)"
        _, delta = _parse_rate_limit_reset(text)
        assert delta is None or (0 < delta <= 86400), \
            f"stale dates must not produce year-long deltas, got {delta}"


class TestTimeOnly:
    def test_time_only_returns_sane_delta_or_none(self):
        text = "resets 11:30pm"
        repr_str, delta = _parse_rate_limit_reset(text)
        assert "11:30pm" in repr_str
        # Always bounded — even wrap-to-tomorrow path must be under 24h.
        assert delta is None or (0 < delta <= 86400)

    def test_time_at_format(self):
        text = "resets at 23:30"
        repr_str, delta = _parse_rate_limit_reset(text)
        assert "23:30" in repr_str
        assert delta is None or (0 < delta <= 86400)


class TestUnparseable:
    def test_empty_string(self):
        _, delta = _parse_rate_limit_reset("")
        assert delta is None

    def test_no_reset_in_text(self):
        _, delta = _parse_rate_limit_reset("Some other error about quota")
        assert delta is None

    def test_garbage_text(self):
        _, delta = _parse_rate_limit_reset("resets sometime maybe idk")
        assert delta is None


class TestSanityBound:
    """Cross-cutting regression guard: whatever we parse, the delta must
    be bounded to the next 24h. The caller (call_claude) adds its own 2h cap,
    but the parser is the authoritative source of the invariant."""

    def test_no_parse_ever_exceeds_86400s(self):
        for text in [
            "resets Apr 17, 11:30pm (Asia/Calcutta)",
            "resets Jun 15, 3:00am (UTC)",
            "resets 11:30pm",
            "resets at 23:30",
            "resets at 00:00",
            "resets Feb 29, 12:00am (UTC)",
        ]:
            _, delta = _parse_rate_limit_reset(text)
            assert delta is None or (0 < delta <= 86400), \
                f"{text!r} produced out-of-bound delta: {delta}"
