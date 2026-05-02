"""Tests for utils.extract_json — the LLM-output JSON salvager.

Coverage priorities (in order of importance):
  1. Truncation refusal — returning a fragment from a truncated response
     would poison downstream phases. This is the CRIT-2 guardrail.
  2. Raw, fenced, prose-wrapped inputs — the three normal shapes.
  3. Multiple blocks — we return the largest.
"""
from utils import extract_json


class TestRawParse:
    def test_plain_object(self):
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_array_top_level_returns_none(self):
        # The function is typed -> Optional[dict]; arrays are not dicts.
        # json.loads succeeds on `[1,2,3]` but the signature implies dict.
        # Current behaviour: it returns the list (loose typing). Lock that in.
        assert extract_json("[1,2,3]") == [1, 2, 3]


class TestFencedJson:
    def test_json_fence(self):
        assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}

    def test_fence_with_prose(self):
        text = 'Here you go:\n```json\n{"ok": true}\n```\nThanks!'
        assert extract_json(text) == {"ok": True}

    def test_multiple_fences_returns_largest(self):
        text = (
            '```json\n{"small": 1}\n```\n'
            'and also\n'
            '```json\n{"big": {"a": 1, "b": 2, "c": 3}}\n```'
        )
        assert extract_json(text) == {"big": {"a": 1, "b": 2, "c": 3}}


class TestProseBraceMatching:
    def test_prose_wrapped_object(self):
        text = 'Based on the article, here is the JSON: {"actor": "LUCR-3"}'
        assert extract_json(text) == {"actor": "LUCR-3"}

    def test_string_aware_does_not_split_on_escaped_quotes(self):
        # The brace matcher must track string state so a `}` inside a string
        # doesn't prematurely close the object.
        text = 'Prose. {"k": "value with } brace"}'
        assert extract_json(text) == {"k": "value with } brace"}


class TestTruncationRefusal:
    """CRIT-2 guardrail — if the response looks truncated, return None
    rather than a partial fragment. A downstream phase operating on a
    fragment is worse than a loud failure."""

    def test_unclosed_object_returns_none(self):
        # depth>0 at EOF → refuse
        text = '{"a": 1, "b": {"nested":'
        assert extract_json(text) is None

    def test_leading_comma_fragment_returns_none(self):
        # first non-whitespace char is `,` → response starts mid-value
        text = ', "techniques": [{"id": "T1078"}]}'
        assert extract_json(text) is None

    def test_leading_closing_bracket_fragment_returns_none(self):
        text = ']}'
        assert extract_json(text) is None


class TestNoJson:
    def test_pure_prose_returns_none(self):
        assert extract_json("I cannot help with that request.") is None

    def test_empty_string_returns_none(self):
        assert extract_json("") is None
