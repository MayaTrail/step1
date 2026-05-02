"""Tests for utils.count_tokens (MED-1 — tiktoken hard-required).

These tests are tiny by design: if tiktoken regresses or the encoder name
changes, we want a loud import-time failure, not a silent drift in token
estimates downstream."""
from utils import count_tokens


def test_empty_string_is_zero():
    assert count_tokens("") == 0


def test_nonempty_string_is_positive():
    assert count_tokens("hello world") > 0


def test_returns_int():
    assert isinstance(count_tokens("some text"), int)


def test_monotonic_with_length():
    # Longer text has at least as many tokens. Strict `<` can flake on
    # repeated-char sequences that collapse in BPE; `<=` is the invariant.
    short = count_tokens("hello")
    long = count_tokens("hello world this is a longer test string")
    assert short <= long


def test_diverges_from_old_heuristic():
    # Regression guard for MED-1: tiktoken and `len//3` give materially
    # different answers on repeated content (where BPE compresses heavily but
    # the heuristic is blind). If this test passes with tk == heuristic, the
    # `len//3` fallback has snuck back in.
    repeated = "x" * 10_000
    tk = count_tokens(repeated)
    heuristic = len(repeated) // 3
    # On repeated chars, tiktoken is ~1/8 of len//3. We only need to prove
    # they're not the same function — >20% relative difference is plenty.
    rel_diff = abs(tk - heuristic) / heuristic
    assert rel_diff > 0.2, \
        f"tiktoken={tk}, len//3={heuristic} — too close; is the fallback back?"
