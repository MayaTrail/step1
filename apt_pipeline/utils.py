"""
MayaTrail APT Pipeline v2 — Core Utilities
==========================================
Handles Claude CLI invocation, logging, file I/O, human gates,
review loops, token tracking, and manifest management.

Changes from v1:
- JSON extraction handles nested fences and multi-block responses
- Review loop tracks sub-phase iteration in manifest for resumability
- Token cost estimates updated for current Claude pricing
- Article fetching uses Claude for HTML → clean text extraction
"""

import os
import sys
import json
import time
import tempfile
import subprocess
import re
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Tuple

# ── Force UTF-8 for stdout/stderr on Windows ────────────────────────────
# Windows consoles default to cp1252 which cannot encode emojis / Unicode.
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Model Constants ──────────────────────────────────────────────────────
SONNET = "claude-sonnet-4-6"
OPUS = "claude-opus-4-6"

# ── Token Cost Estimates (USD per 1K tokens, April 2026) ─────────────────
COST_PER_1K = {
    SONNET: {"input": 0.003, "output": 0.015},
    OPUS:   {"input": 0.015, "output": 0.075},
}

# ── Global Token Tracker ─────────────────────────────────────────────────
_token_log: list[dict] = []
_token_lock = threading.Lock()       # guards _token_log appends from parallel phases
_manifest_lock = threading.Lock()    # guards run_manifest.json read-modify-write

# ── CLI concurrency cap ──────────────────────────────────────────────────
# Phases 5+6 can run in parallel, each fanning out to 2-3 subprocess calls,
# giving up to 5 concurrent `claude --print` processes on a single host —
# the fastest way to exhaust a rate-limited account. This semaphore gates
# the real subprocess path (not the fixture replay path). Default 2; tune
# via PIPELINE_MAX_CONCURRENCY. See MED-3 in PIPELINE_GAP_ANALYSIS_V3.md.
try:
    _CLAUDE_MAX_CONCURRENCY = max(1, int(os.getenv("PIPELINE_MAX_CONCURRENCY", "1")))
except ValueError:
    _CLAUDE_MAX_CONCURRENCY = 2
_claude_concurrency_sem = threading.Semaphore(_CLAUDE_MAX_CONCURRENCY)

# ── Fixture Harness (record/replay for offline iteration) ────────────────
# Set PIPELINE_FIXTURE_MODE=record to capture every Claude response to disk.
# Set PIPELINE_FIXTURE_MODE=replay to short-circuit call_claude with saved
# responses — no subprocess, no API cost. See tests/fixtures/ for layout.
_FIXTURE_MODE = os.getenv("PIPELINE_FIXTURE_MODE", "").strip().lower()
_FIXTURE_DIR = Path(os.getenv("PIPELINE_FIXTURE_DIR", "tests/fixtures/current"))
_fixture_call_counts: dict[str, int] = {}
_fixture_lock = threading.Lock()


class PipelineError(Exception):
    """Raised when a pipeline phase fails unrecoverably."""
    pass


# ══════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════

_COLORS = {
    "info":  "\033[36m",   # cyan
    "ok":    "\033[32m",   # green
    "warn":  "\033[33m",   # yellow
    "err":   "\033[31m",   # red
    "dim":   "\033[90m",   # gray
    "reset": "\033[0m",
    "bold":  "\033[1m",
}


def log(phase: str, msg: str, level: str = "info"):
    """Print a colored, timestamped log line."""
    ts = datetime.now().strftime("%H:%M:%S")
    c = _COLORS.get(level, _COLORS["info"])
    r = _COLORS["reset"]
    d = _COLORS["dim"]
    b = _COLORS["bold"]
    print(f"{d}{ts}{r} {b}[{phase}]{r} {c}{msg}{r}", flush=True)


# ══════════════════════════════════════════════════════════════════════════
# FILE I/O
# ══════════════════════════════════════════════════════════════════════════

def save(path: Path, content: str):
    """Write content to file, creating parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    log("IO", f"Saved → {path}", "dim")


def save_json(path: Path, data: dict):
    """Write dict as pretty JSON."""
    save(path, json.dumps(data, indent=2, default=str))


def load_json(path: Path) -> dict:
    """Load JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))


def load_agent(agents_dir: Path, name: str) -> str:
    """Read an agent .md file."""
    agent_path = agents_dir / f"{name}.md"
    if not agent_path.exists():
        raise PipelineError(f"Agent file not found: {agent_path}")
    content = agent_path.read_text(encoding="utf-8")
    log("AGENT", f"Loaded {name} ({len(content)} chars)", "dim")
    return content


# ══════════════════════════════════════════════════════════════════════════
# TOKEN COUNTING
# ══════════════════════════════════════════════════════════════════════════
# tiktoken is a hard requirement (checked in validate_environment). We use
# cl100k_base because Anthropic doesn't publish a tokenizer and cl100k_base
# is a close-enough BPE approximation for budget/context warnings. The
# authoritative count is the API's `usage` field — see CRIT-1 in
# PIPELINE_GAP_ANALYSIS_V3.md for the follow-up to consume it.

import tiktoken

_ENCODER = tiktoken.get_encoding("cl100k_base")


def count_tokens(text: str) -> int:
    """Return the tiktoken cl100k_base token count for `text`."""
    return len(_ENCODER.encode(text))


# ══════════════════════════════════════════════════════════════════════════
# FIXTURE HARNESS (record / replay of Claude calls)
# ══════════════════════════════════════════════════════════════════════════
# Each invocation of `call_claude(label=X)` maps to the Nth fixture file
# named `{X}_{N}.json` under _FIXTURE_DIR, where N is the 1-indexed count
# of calls with that label in this process. Labels that appear in review
# loops (PHASE-2-REDRAFT, PHASE-4-REDRAFT) will naturally occupy indices
# 1..3 across iterations.

def _next_call_index(label: str) -> int:
    with _fixture_lock:
        _fixture_call_counts[label] = _fixture_call_counts.get(label, 0) + 1
        return _fixture_call_counts[label]


def _fixture_path(label: str, index: int) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_\-]", "_", label)
    return _FIXTURE_DIR / f"{safe}_{index}.json"


def _load_fixture(label: str, index: int) -> Optional[Tuple[str, dict]]:
    path = _fixture_path(label, index)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["response"], data["token_info"]


def _save_fixture(label: str, index: int, system_prompt: str, user_prompt: str,
                  response: str, token_info: dict):
    path = _fixture_path(label, index)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "label": label,
        "call_index": index,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "response": response,
        "token_info": token_info,
    }, indent=2), encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════
# CLAUDE CLI INVOCATION
# ══════════════════════════════════════════════════════════════════════════

def _parse_rate_limit_reset(text: str) -> Tuple[str, Optional[float]]:
    """Parse Claude Code's rate-limit reset string.

    The CLI typically prints:
        "You've hit your limit · resets Apr 17, 11:30pm (Asia/Calcutta)"

    Returns (human_repr, seconds_until_reset) where `seconds_until_reset` is
    None if we couldn't pin the reset to a concrete future time. The caller
    is expected to fall back to staggered backoff when None.

    We try, in order:
      1. Full datetime with timezone — most precise.
      2. Time-only — assume today's local date; wrap to tomorrow if past.
      3. Nothing — return ("unknown", None).

    We keep the parser intentionally forgiving: on ANY exception we degrade
    to the time-only or staggered path. Sleeping until a misparsed reset
    is strictly worse than a short retry, so the cap in the caller (2h)
    backstops us.
    """
    # Pattern 1: "Apr 17, 11:30pm (Asia/Calcutta)"
    full_match = re.search(
        r"resets?\s+"
        r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}),\s*"
        r"(?P<hm>\d{1,2}:\d{2})\s*(?P<ampm>am|pm)?\s*"
        r"\((?P<tz>[^)]+)\)",
        text, re.IGNORECASE,
    )
    if full_match:
        repr_str = (
            f"{full_match.group('mon')} {full_match.group('day')}, "
            f"{full_match.group('hm')}{full_match.group('ampm') or ''} "
            f"({full_match.group('tz')})"
        )
        try:
            from datetime import datetime
            try:
                from zoneinfo import ZoneInfo
                tz = ZoneInfo(full_match.group("tz"))
            except Exception:
                tz = None
            now = datetime.now(tz) if tz else datetime.now()
            fmt = "%Y %b %d %I:%M%p" if full_match.group("ampm") else "%Y %b %d %H:%M"
            target_str = (
                f"{now.year} {full_match.group('mon')} {full_match.group('day')} "
                f"{full_match.group('hm')}{(full_match.group('ampm') or '').lower()}"
            )
            target = datetime.strptime(target_str, fmt).replace(tzinfo=tz)
            delta = (target - now).total_seconds()
            # Rate limits reset within hours, never a year later. If the
            # parsed target is in the past, we're looking at a stale message
            # (the limit may have reset already, or year rolled over) — bail
            # to staggered backoff instead of sleeping for ~365 days.
            if 0 < delta <= 86400:  # sane window: up to 24h ahead
                return repr_str, delta
        except Exception:
            pass  # fall through to time-only
        return repr_str, None

    # Pattern 2: time-only — "resets 11:30pm" or "resets at 23:30"
    time_match = re.search(
        r"resets?\s+(?:at\s+)?(?P<hm>\d{1,2}:\d{2})\s*(?P<ampm>am|pm)?",
        text, re.IGNORECASE,
    )
    if time_match:
        hm = time_match.group("hm")
        ampm = (time_match.group("ampm") or "").lower()
        repr_str = f"{hm}{ampm}"
        try:
            from datetime import datetime, timedelta
            fmt = "%I:%M%p" if ampm else "%H:%M"
            now = datetime.now()
            target = datetime.strptime(f"{hm}{ampm}", fmt).replace(
                year=now.year, month=now.month, day=now.day
            )
            # Wrap past-times to tomorrow.
            if (target - now).total_seconds() < 0:
                target += timedelta(days=1)
            return repr_str, (target - now).total_seconds()
        except Exception:
            return repr_str, None

    return "unknown", None


def call_claude(
    model: str,
    system_prompt: str,
    user_prompt: str,
    label: str,
    max_retries: int = 2,
    timeout: int = 600,
    json_schema: Optional[dict] = None,
    fallback_model: Optional[str] = None,
    max_budget_usd: Optional[float] = None,
) -> Tuple[str, dict]:
    """
    Invoke Claude via the CLI (`claude --print`).

    Combines system_prompt (agent instructions) and user_prompt (task context)
    into a single stdin payload.

    When `json_schema` is provided, the call uses `--output-format json
    --json-schema <schema>` so the CLI returns a JSON envelope containing
    both authoritative `usage` counts and a `structured_output` object that
    matches the schema. The returned `response` string is the JSON-stringified
    `structured_output`, so downstream `extract_json(response)` yields the
    schema-enforced dict directly — no brace-matching salvage path.

    Returns: (response_text, token_info_dict)
    """
    full_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}" if system_prompt else user_prompt

    # ── Fixture replay: skip the subprocess entirely ────────────────────
    # In replay mode every call_claude invocation must have a matching
    # fixture — a missing fixture is an error, not a silent fall-through,
    # so we don't spend money or mask stale test data.
    call_index = _next_call_index(label) if _FIXTURE_MODE in ("record", "replay") else 0
    if _FIXTURE_MODE == "replay":
        fixture = _load_fixture(label, call_index)
        if fixture is None:
            raise PipelineError(
                f"{label}: PIPELINE_FIXTURE_MODE=replay but no fixture at "
                f"{_fixture_path(label, call_index)} (call #{call_index})"
            )
        response, token_info = fixture
        _track_tokens(label, token_info)
        log(label, f"Replayed fixture #{call_index} "
                   f"(~{token_info['input_tokens'] + token_info['output_tokens']} tokens)",
            "dim")
        return response, token_info

    # Pre-flight: warn if prompt likely exceeds model context window.
    # Sonnet/Opus context is ~200K tokens.
    est_input_tokens = count_tokens(full_prompt)
    MODEL_CONTEXT_LIMIT = 180_000  # conservative (leaves room for output)
    if est_input_tokens > MODEL_CONTEXT_LIMIT:
        log(label,
            f"PROMPT SIZE WARNING: ~{est_input_tokens:,} tokens "
            f"(limit ~{MODEL_CONTEXT_LIMIT:,}). Response may be truncated or fail. "
            f"Prompt is {len(full_prompt):,} chars.", "err")
    elif est_input_tokens > MODEL_CONTEXT_LIMIT * 0.8:
        log(label,
            f"Prompt is large: ~{est_input_tokens:,} tokens "
            f"({int(est_input_tokens / MODEL_CONTEXT_LIMIT * 100)}% of context). "
            f"Monitor for truncation.", "warn")

    for attempt in range(1, max_retries + 2):
        log(label, f"[{model}] attempt {attempt}/{max_retries + 1}…")

        # ── CLI concurrency cap (MED-3) ──
        # Gate here so a queued call logs the attempt immediately, then
        # notes it's waiting. Blocking is counted toward overall elapsed
        # time below (captured from `start = time.time()` *after* acquire).
        if not _claude_concurrency_sem.acquire(blocking=False):
            log(label,
                f"Waiting for concurrency slot "
                f"(cap={_CLAUDE_MAX_CONCURRENCY})…", "dim")
            _claude_concurrency_sem.acquire(blocking=True)
        start = time.time()

        # ── Split system vs user for proper prompt caching ──
        # The Anthropic API caches the `system` field independently of user
        # messages. Passing the agent markdown via --append-system-prompt-file
        # keeps it stable across iterations (review loops, retries), which
        # means cache hits for each subsequent call on the same agent.
        # --exclude-dynamic-system-prompt-sections moves per-machine sections
        # (cwd, env, git status) into the first user message so they don't
        # invalidate the cache key.
        sys_tmp = None
        user_tmp = None
        try:
            cmd = [
                "claude", "--print",
                "--dangerously-skip-permissions",
                "--no-session-persistence",
                "--exclude-dynamic-system-prompt-sections",
                "--model", model,
            ]
            # Fallback model: if Opus is overloaded, downgrade to Sonnet
            # rather than failing. Set by the caller on non-critical calls
            # (review passes etc.). See HIGH-2 in PIPELINE_GAP_ANALYSIS_V3.md.
            if fallback_model:
                cmd.extend(["--fallback-model", fallback_model])
            # Budget cap: per-call ceiling. Default-sourced from env so
            # a runaway session can be capped without touching code.
            effective_budget = max_budget_usd
            if effective_budget is None:
                env_budget = os.getenv("PIPELINE_MAX_BUDGET_USD")
                if env_budget:
                    try:
                        effective_budget = float(env_budget)
                    except ValueError:
                        log(label,
                            f"PIPELINE_MAX_BUDGET_USD={env_budget!r} is not a "
                            f"number — ignoring.", "warn")
            if effective_budget is not None:
                cmd.extend(["--max-budget-usd", str(effective_budget)])
            if json_schema is not None:
                # Structured output: CLI returns `{..., "result": "...",
                # "structured_output": {...}, "usage": {...}, "stop_reason": ...}`.
                # The `structured_output` object is validated against the schema.
                cmd.extend([
                    "--output-format", "json",
                    "--json-schema", json.dumps(json_schema),
                ])
            if system_prompt:
                sys_tmp = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".md", encoding="utf-8", delete=False
                )
                sys_tmp.write(system_prompt)
                sys_tmp.close()
                cmd.extend(["--append-system-prompt-file", sys_tmp.name])

            user_tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", encoding="utf-8", delete=False
            )
            user_tmp.write(user_prompt)
            user_tmp.close()

            with open(user_tmp.name, "r", encoding="utf-8") as stdin_file:
                result = subprocess.run(
                    cmd,
                    stdin=stdin_file,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=timeout,
                )
        except subprocess.TimeoutExpired:
            log(label, f"Timeout after {timeout}s — retrying…", "warn")
            continue
        except FileNotFoundError:
            raise PipelineError(
                "claude CLI not found on PATH. Install Claude Code: "
                "https://docs.anthropic.com/en/docs/claude-code"
            )
        finally:
            for t in (sys_tmp, user_tmp):
                if t and os.path.exists(t.name):
                    try:
                        os.unlink(t.name)
                    except OSError:
                        pass  # Windows may hold the handle briefly
            # Always release — even on timeout/failure — so a retry re-acquires
            # cleanly and other threads can proceed.
            _claude_concurrency_sem.release()

        elapsed = round(time.time() - start, 1)

        if result.returncode == 0 and result.stdout.strip():
            raw_stdout = result.stdout.strip()

            if json_schema is not None:
                # ── Parse CLI envelope ──
                # With --output-format json, stdout is a single JSON object with
                # `structured_output` (schema-validated), `result` (text), `usage`
                # (authoritative counts) and `stop_reason` (truncation signal).
                try:
                    envelope = json.loads(raw_stdout)
                except json.JSONDecodeError as e:
                    log(label,
                        f"--output-format json: envelope parse failed at char {e.pos}: "
                        f"{e.msg}. Raw stdout preview: {raw_stdout[:200]!r}", "err")
                    continue

                if envelope.get("is_error"):
                    err_msg = envelope.get("result", "unknown") or envelope.get("subtype", "unknown")
                    log(label, f"CLI returned is_error=True: {err_msg}", "err")
                    continue

                stop_reason = envelope.get("stop_reason", "unknown")
                if stop_reason == "max_tokens":
                    log(label,
                        "RESPONSE TRUNCATED (stop_reason=max_tokens). Retrying…", "err")
                    continue

                structured = envelope.get("structured_output")
                if structured is None:
                    log(label,
                        f"No structured_output in envelope (schema enforcement "
                        f"may have failed). Falling back to `result` field. "
                        f"stop_reason={stop_reason}", "warn")
                    response = envelope.get("result", "") or ""
                else:
                    # Stringify so callers can `extract_json(response)` uniformly.
                    response = json.dumps(structured)

                usage = envelope.get("usage", {}) or {}
                # Authoritative: input includes cache-creation + cache-read + fresh
                # input. This is what the API/CLI actually billed, not an estimate.
                input_tokens = (
                    (usage.get("input_tokens") or 0)
                    + (usage.get("cache_creation_input_tokens") or 0)
                    + (usage.get("cache_read_input_tokens") or 0)
                )
                output_tokens = usage.get("output_tokens") or 0
                token_info = {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "model": model,
                    "elapsed_s": elapsed,
                    "cost_usd": envelope.get("total_cost_usd"),
                    "stop_reason": stop_reason,
                    "source": "envelope",
                }
            else:
                response = raw_stdout
                input_tokens = count_tokens(full_prompt)
                output_tokens = count_tokens(response)
                token_info = {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "model": model,
                    "elapsed_s": elapsed,
                    "source": "tiktoken",
                }

            _track_tokens(label, token_info)
            log(label, f"Done in {elapsed}s (~{input_tokens + output_tokens} tokens)", "ok")
            if _FIXTURE_MODE == "record":
                _save_fixture(label, call_index, system_prompt, user_prompt,
                              response, token_info)
                log(label, f"Recorded fixture → {_fixture_path(label, call_index)}", "dim")
            return response, token_info

        # ── Failure handling — distinguish failure modes ──
        stderr = result.stderr.strip()[:500] if result.stderr else ""
        stdout_preview = result.stdout.strip()[:300] if result.stdout else ""
        combined = f"{stdout_preview} {stderr}".lower()

        # Rate limit detection.
        # Claude Code CLI typical format: "You've hit your limit · resets Apr 17, 11:30pm (Asia/Calcutta)"
        # Older/alternative formats may just say "You've hit your limit" or include only a time.
        rate_limit_hit = any(
            phrase in combined for phrase in
            ("hit your limit", "rate limit", "rate-limit", "too many requests", "429")
        )
        if rate_limit_hit:
            reset_repr, wait_until_reset_s = _parse_rate_limit_reset(combined)
            log(label, f"RATE LIMITED — resets at {reset_repr}", "err")
            # If the wait is long (>30 min), sleeping would let the OAuth token
            # expire and all retries wake up to 401s. Exit cleanly instead so
            # the user can restart after the reset — phases 0-4 will be skipped
            # and Phase 5+ will resume from where it left off.
            _LONG_WAIT_THRESHOLD = 1800  # 30 minutes
            if wait_until_reset_s is not None and wait_until_reset_s > _LONG_WAIT_THRESHOLD:
                log(label,
                    f"Rate limit wait is {int(wait_until_reset_s)}s — too long to sleep "
                    f"(OAuth token would expire). Exiting. Restart after {reset_repr}.",
                    "err")
                raise PipelineError(
                    f"RATE_LIMIT_EXIT: resets at {reset_repr} "
                    f"(~{int(wait_until_reset_s)}s). Re-run the pipeline after that time."
                )
            if attempt <= max_retries:
                # Short wait (≤30 min): sleep through it and retry.
                if wait_until_reset_s is not None:
                    wait = wait_until_reset_s + 10  # parser already caps at 86400s
                    log(label,
                        f"Sleeping {wait}s until reset (+10s buffer)…", "warn")
                else:
                    wait = 60 + (attempt * 30)
                    log(label,
                        f"Reset time unparseable — staggered backoff {wait}s…",
                        "warn")
                time.sleep(wait)
            continue

        # Other failures: log and use standard backoff
        log(label, f"Failed (exit {result.returncode}): {stderr or 'no stderr'}", "warn")
        if stdout_preview:
            log(label, f"stdout: {stdout_preview[:150]}", "dim")

        if attempt <= max_retries:
            wait = min(2 ** attempt * 5, 60)  # 5s, 10s, 20s, 40s, 60s
            log(label, f"Waiting {wait}s before retry…", "dim")
            time.sleep(wait)

    raise PipelineError(f"{label}: All {max_retries + 1} attempts exhausted.")


# ══════════════════════════════════════════════════════════════════════════
# JSON / CODE EXTRACTION FROM LLM OUTPUT
# ══════════════════════════════════════════════════════════════════════════

def extract_json(text: str) -> Optional[dict]:
    """
    Extract a JSON object from LLM output. Handles:
    - Raw JSON
    - JSON in ```json fences (including ```json5, unclosed fences)
    - JSON embedded in prose (string-aware brace matching)
    - Multiple JSON blocks (returns the largest)
    - Truncation detection (unmatched braces at EOF)
    """
    text = text.strip()

    # ── 1. Try raw parse ──
    if text.startswith("{") or text.startswith("["):
        try:
            result = json.loads(text)
            log("JSON-EXTRACT", "Parsed raw JSON directly", "dim")
            return result
        except json.JSONDecodeError as e:
            log("JSON-EXTRACT", f"Raw parse failed at char {e.pos}: {e.msg}", "dim")

    # ── 2. Try code fences (broader pattern: ```json*, unclosed fence fallback) ──
    candidates = []
    fence_pattern = r"```json\w*\s*\n(.*?)(?:\n```|$)"
    for match in re.finditer(fence_pattern, text, re.DOTALL):
        inner = match.group(1).strip()
        if not inner:
            continue
        try:
            parsed = json.loads(inner)
            candidates.append(parsed)
        except json.JSONDecodeError as e:
            log("JSON-EXTRACT", f"Fence block ({len(inner)} chars) failed at char {e.pos}: {e.msg}", "dim")

    if candidates:
        best = max(candidates, key=lambda c: len(json.dumps(c)))
        log("JSON-EXTRACT", f"Found {len(candidates)} fenced block(s), returning largest ({len(json.dumps(best))} chars)", "dim")
        return best

    # ── 3. String-aware brace matching ──
    # Tracks depth while skipping characters inside JSON strings to avoid
    # false matches on escaped braces like {"key": "test\"}"}
    depth = 0
    start_idx = None
    brace_candidates = []
    in_string = False
    escape_next = False
    for i, ch in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"' and not escape_next:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            if depth == 0:
                start_idx = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start_idx is not None:
                try:
                    parsed = json.loads(text[start_idx : i + 1])
                    brace_candidates.append(parsed)
                except json.JSONDecodeError:
                    pass
                start_idx = None

    if brace_candidates:
        # ── Guardrail: refuse to return a fragment from a truncated response ──
        # The brace-matching fallback was built to handle prose-wrapped JSON
        # ("Here is the JSON: {...}"), not to salvage fragments from a broken
        # response. Two signals say the root envelope is missing:
        #   1. depth>0 at EOF — top-level object never closed.
        #   2. first non-whitespace char is `,` / `]` / `}` — text starts
        #      mid-value (the LUCR-3 failure mode: the tail of a large object
        #      survived but the opening brace didn't).
        # Prose prefixes are NOT a truncation signal — "Based on the article, here
        # is the JSON: {...}" is the normal LLM output pattern.
        stripped = text.lstrip()
        first_char = stripped[0] if stripped else ""
        looks_truncated = depth > 0 or first_char in (",", "]", "}")
        sizes = sorted([len(json.dumps(c)) for c in brace_candidates], reverse=True)

        if looks_truncated:
            log("JSON-EXTRACT",
                f"REFUSING fragment: response appears truncated "
                f"(first char={first_char!r}, depth_at_eof={depth}). "
                f"Found {len(brace_candidates)} nested block(s) sizes={sizes[:5]} "
                f"but returning None rather than a fragment. "
                f"Raw response starts with: {stripped[:120]!r}", "err")
            return None

        best = max(brace_candidates, key=lambda c: len(json.dumps(c)))
        log("JSON-EXTRACT", f"Found {len(brace_candidates)} brace block(s), sizes: {sizes[:5]}", "dim")
        return best

    # ── 4. Truncation detection ──
    # After section 3's loop, `depth > 0` means the LAST opening brace was
    # never closed (truncated mid-object). `start_idx is not None` is always
    # True when depth > 0 because section 3 only resets start_idx to None
    # on a depth-0 closing brace — so this branch is equivalent to `depth > 0`
    # alone. Both conditions are kept for explicitness (LOW-4).
    if depth > 0 and start_idx is not None:
        truncated_len = len(text) - start_idx
        log("JSON-EXTRACT",
            f"TRUNCATED JSON detected — unclosed braces (depth={depth}) "
            f"starting at char {start_idx}, {truncated_len} chars of incomplete JSON. "
            f"Claude likely hit output token limit.", "err")
    else:
        log("JSON-EXTRACT",
            f"No valid JSON found in {len(text)} chars of response. "
            f"Response starts with: {text[:120]!r}", "warn")
    return None


def extract_code_blocks(text: str, lang: str = "python") -> list[Tuple[str, str]]:
    """
    Extract named code blocks from LLM output.

    Looks for:
      ```python
      # FILE: 01_initial_access.py
      ...
      ```

    Returns: list of (filename, code_content)
    """
    # Match both exact lang and lang with additional text (e.g., ```python3)
    pattern = rf"```{lang}\w*\s*\n(.*?)```"
    blocks = re.findall(pattern, text, re.DOTALL)

    results = []
    for block in blocks:
        block = block.strip()
        lines = block.split("\n")
        first_line = lines[0] if lines else ""
        filename = None

        # Try FILE: marker
        for marker in ["# FILE:", "# file:", "# Filename:", "# filename:", "## FILE:"]:
            if marker in first_line:
                raw_name = first_line.split(marker, 1)[1].strip()
                # Sanitize: take only the filename (stop at whitespace, #, or quotes)
                filename = re.split(r'[\s#"\']', raw_name, maxsplit=1)[0].strip()
                # Remove the FILE: line from content
                block = "\n".join(lines[1:]).strip()
                break

        if not filename:
            # Infer from content
            if "Pulumi.yaml" in first_line:
                filename = "Pulumi.yaml"
            elif "__main__" in first_line:
                filename = "__main__.py"
            elif "requirements" in first_line.lower():
                filename = "requirements.txt"
            elif "def run(" in block[:200]:
                # Try to find a MANIFEST dict for the module name
                manifest_match = re.search(r'"name"\s*:\s*"([^"]+)"', block[:500])
                if manifest_match:
                    filename = f"{manifest_match.group(1)}.py"
                else:
                    filename = f"module_{len(results):02d}.py"
            else:
                filename = f"block_{len(results):02d}.{lang if lang != 'text' else 'txt'}"

        results.append((filename, block))

    return results


def extract_all_code_blocks(text: str) -> list[Tuple[str, str, str]]:
    """
    Extract ALL code blocks regardless of language.
    Returns: list of (filename, content, language)
    Warns on duplicate filenames (last write wins on disk, so flag it).
    """
    results = []
    seen_names: dict[str, int] = {}
    for lang in ["python", "python3", "yaml", "yml", "bash", "sh", "text", "json", "kql"]:
        for filename, content in extract_code_blocks(text, lang):
            norm_lang = lang.replace("python3", "python").replace("yml", "yaml").replace("sh", "bash")
            if filename in seen_names:
                seen_names[filename] += 1
                deduped = f"{Path(filename).stem}_{seen_names[filename]}{Path(filename).suffix}"
                log("CODE-EXTRACT", f"Duplicate filename '{filename}' — renaming to '{deduped}'", "warn")
                filename = deduped
            else:
                seen_names[filename] = 1
            results.append((filename, content, norm_lang))
    return results


# ══════════════════════════════════════════════════════════════════════════
# HUMAN GATES
# ══════════════════════════════════════════════════════════════════════════

def human_gate(gate_id: str, display_content: str, prompt_text: str) -> str:
    """
    Display content and wait for human approval.
    Returns: "APPROVED", "OVERRIDE", "ABORT", or "SKIP"
    """
    sep = "═" * 60
    print(f"\n{_COLORS['bold']}{sep}{_COLORS['reset']}")
    print(f"{_COLORS['bold']}⛔ HUMAN GATE — {gate_id}{_COLORS['reset']}")
    print(f"{sep}\n")

    lines = display_content.strip().split("\n")
    max_display = 40
    if len(lines) > max_display:
        for line in lines[:20]:
            print(f"  {line}")
        print(f"  {_COLORS['dim']}... ({len(lines) - max_display} lines omitted — see output files) ...{_COLORS['reset']}")
        for line in lines[-20:]:
            print(f"  {line}")
    else:
        for line in lines:
            print(f"  {line}")

    print(f"\n{sep}")
    print(f"{_COLORS['bold']}{prompt_text}{_COLORS['reset']}")
    print(f"{sep}\n")

    while True:
        try:
            response = input(">>> ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            return "ABORT"
        if response in ("APPROVED", "APPROVE", "YES", "Y"):
            return "APPROVED"
        elif response in ("OVERRIDE", "FORCE"):
            return "OVERRIDE"
        elif response in ("ABORT", "QUIT", "EXIT", "N", "NO"):
            return "ABORT"
        elif response in ("SKIP",):
            return "SKIP"
        else:
            print("  Valid responses: APPROVED | OVERRIDE | ABORT | SKIP")


# ══════════════════════════════════════════════════════════════════════════
# REVIEW LOOP (Opus review → Sonnet redraft)
# ══════════════════════════════════════════════════════════════════════════

def review_loop(
    reviewer_agent: str,
    drafter_fn,
    initial_draft: str,
    base_context: str,
    loop_label: str,
    out_dir: Path,
    max_iterations: int = 3,
) -> Tuple[str, dict]:
    """
    Generic review-and-revise loop with JSON envelope verdict parsing.

    reviewer_agent : str       — Opus reviewer agent prompt
    drafter_fn     : callable  — fn(context, feedback) → (draft_str, token_info)
    initial_draft  : str       — first Sonnet output
    base_context   : str       — canonical context (ti_extract etc.)
    max_iterations : int       — hard cap

    Returns: (approved_draft_str, review_envelope_dict)
    """
    current_draft = initial_draft
    iter_dir = out_dir / f"{loop_label}_iterations"
    iter_dir.mkdir(exist_ok=True)
    last_envelope = {}

    for i in range(1, max_iterations + 1):
        log(loop_label, f"Review iteration {i}/{max_iterations}…")

        # Track sub-phase for resumability
        update_manifest(out_dir, f"{loop_label}_iter_{i}", "in_progress")

        # Opus reviews
        review_prompt = (
            f"## Context\n{base_context}\n\n"
            f"## Content to Review\n{current_draft}"
        )
        # Opus reviews are non-critical — on overload, degrade to Sonnet
        # rather than failing the whole run. See HIGH-2.
        review_text, _ = call_claude(
            OPUS, reviewer_agent, review_prompt, f"{loop_label}-REVIEW-{i}",
            fallback_model="sonnet",
        )
        save(iter_dir / f"iter{i}_review.md", review_text)

        # Extract verdict — try JSON first, then text fallback
        envelope = extract_json(review_text)
        verdict = None
        _VALID_VERDICTS = {"APPROVED", "REVISION_REQUIRED"}

        if envelope:
            raw_verdict = str(envelope.get("verdict", "")).upper().replace(" ", "_")
            if raw_verdict in _VALID_VERDICTS:
                verdict = raw_verdict
            elif raw_verdict:
                log(loop_label, f"Unknown verdict '{raw_verdict}' — treating as revision needed", "warn")
                verdict = "REVISION_REQUIRED"
            last_envelope = envelope

        if not verdict:
            upper = review_text.upper()
            if "VERDICT: APPROVED" in upper or '"APPROVED"' in upper:
                verdict = "APPROVED"
            elif "REVISION" in upper:
                verdict = "REVISION_REQUIRED"
            else:
                log(loop_label, f"Could not determine verdict from review — treating as revision needed", "warn")
                verdict = "REVISION_REQUIRED"

        if verdict == "APPROVED":
            log(loop_label, f"Approved after {i} iteration(s)", "ok")
            update_manifest(out_dir, f"{loop_label}_iter_{i}", "approved")
            return current_draft, last_envelope or {"verdict": "APPROVED"}

        # Revision needed
        log(loop_label, f"Revision required — re-drafting…", "warn")
        update_manifest(out_dir, f"{loop_label}_iter_{i}", "revision_required")

        feedback = review_text
        if envelope:
            issues = envelope.get("issues") or envelope.get("gaps") or []
            if issues:
                feedback = json.dumps(issues, separators=(",", ":"))
                if len(feedback) > 5000:
                    feedback = feedback[:5000] + "\n... (truncated)"

        current_draft, _ = drafter_fn(base_context, feedback)
        save(iter_dir / f"iter{i}_revision.md", current_draft)

    # Max iterations exhausted
    log(loop_label, f"Max iterations ({max_iterations}) reached without approval", "err")
    decision = human_gate(
        f"{loop_label}-MAXITER",
        current_draft[:2000],
        f"Opus did not approve after {max_iterations} iterations.\n"
        f"Last review saved to {iter_dir}\n"
        f"Type OVERRIDE to proceed anyway, or ABORT to stop."
    )
    if decision == "OVERRIDE":
        log(loop_label, "Operator overrode iteration limit", "warn")
        return current_draft, last_envelope or {"verdict": "OVERRIDE"}

    raise PipelineError(f"Pipeline aborted at {loop_label} — max iterations exceeded.")


# ══════════════════════════════════════════════════════════════════════════
# TOKEN TRACKING
# ══════════════════════════════════════════════════════════════════════════

def _track_tokens(label: str, info: dict):
    with _token_lock:
        _token_log.append({
            "label": label,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **info,
        })


def get_token_summary() -> dict:
    with _token_lock:
        snapshot = list(_token_log)  # consistent snapshot for summation

    total_input = sum(e["input_tokens"] for e in snapshot)
    total_output = sum(e["output_tokens"] for e in snapshot)

    est_cost = 0.0
    per_model: dict[str, dict] = {}
    for entry in snapshot:
        model = entry.get("model", SONNET)
        rates = COST_PER_1K.get(model, COST_PER_1K[SONNET])
        entry_cost = ((entry["input_tokens"] / 1000) * rates["input"]
                      + (entry["output_tokens"] / 1000) * rates["output"])
        est_cost += entry_cost

        if model not in per_model:
            per_model[model] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
        per_model[model]["calls"] += 1
        per_model[model]["input_tokens"] += entry["input_tokens"]
        per_model[model]["output_tokens"] += entry["output_tokens"]
        per_model[model]["cost_usd"] = round(per_model[model]["cost_usd"] + entry_cost, 4)

    return {
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_tokens": total_input + total_output,
        "estimated_cost_usd": round(est_cost, 2),
        "calls": len(snapshot),
        "per_model": per_model,
        "breakdown": snapshot,
    }


# ══════════════════════════════════════════════════════════════════════════
# MANIFEST (Run State Tracking + Resumability)
# ══════════════════════════════════════════════════════════════════════════

def update_manifest(out_dir: Path, phase: str, status: str, metadata: Optional[dict] = None):
    with _manifest_lock:
        manifest_path = out_dir / "run_manifest.json"
        if manifest_path.exists():
            manifest = load_json(manifest_path)
        else:
            manifest = {
                "run_id": out_dir.name,
                "start_time": datetime.now(timezone.utc).isoformat(),
                "phases": {},
            }

        # Merge into the existing phase entry so prior fields (e.g. "input",
        # "mode") are preserved when a later update changes only "status".
        existing = manifest["phases"].get(phase, {})
        manifest["phases"][phase] = {
            **existing,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        }
        manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        save_json(manifest_path, manifest)


def load_manifest(out_dir: Path) -> Optional[dict]:
    manifest_path = out_dir / "run_manifest.json"
    return load_json(manifest_path) if manifest_path.exists() else None


def is_phase_complete(out_dir: Path, phase: str) -> bool:
    """Check if a phase already completed (for --resume support)."""
    manifest = load_manifest(out_dir)
    if not manifest:
        return False
    phase_data = manifest.get("phases", {}).get(phase, {})
    return phase_data.get("status") == "complete"


# ══════════════════════════════════════════════════════════════════════════
# ARTICLE FETCHING
# ══════════════════════════════════════════════════════════════════════════

_NAV_MARKERS = (
    "back to blog", "related articles", "subscribe", "sign up",
    "cookie policy", "privacy policy", "terms of service", "all rights reserved",
    "follow us", "share this", "read more", "trending now",
)


def _looks_like_article(text: str) -> Tuple[bool, str]:
    """Structural heuristic: does this text smell like a real article body?

    Catches the failure mode where HTML extraction returned nav/menu chrome
    (50 lines × 15 chars each = trivially passes len>=500 gate) instead of
    the article. We reject if:
      - fewer than 3 paragraph-length (>100 char) lines exist
      - long lines make up < 10 % of non-empty lines (menu-heavy pages)
      - fewer than 5 sentence terminators across the first 20 long lines
        (articles have sentences; nav doesn't)
    """
    lines = [l.strip() for l in text.split("\n") if l.strip()]
    if not lines:
        return False, "empty"
    long_lines = [l for l in lines if len(l) > 100]
    if len(long_lines) < 3:
        return False, f"only {len(long_lines)} paragraph-length lines; likely nav/chrome"
    if len(long_lines) / len(lines) < 0.10:
        return False, (
            f"{len(long_lines)}/{len(lines)} ({int(100 * len(long_lines)/len(lines))}%) "
            f"of lines are paragraph-length — likely menu-heavy page"
        )
    head = " ".join(long_lines[:20])
    terminators = head.count(".") + head.count("!") + head.count("?")
    if terminators < 5:
        return False, f"only {terminators} sentence terminators in first 20 paragraphs"
    return True, "ok"


def fetch_article(url: str) -> str:
    """Fetch article and extract clean text locally (no LLM call needed).

    Uses trafilatura for extraction — it handles article/amp/main tag
    detection, JS-rendered boilerplate, and paywalls better than regex. We
    follow up with a structural heuristic that rejects nav/menu-like output
    that passed the length gate but isn't really article content. See HIGH-3
    in PIPELINE_GAP_ANALYSIS_V3.md for the incident that motivated this.
    """
    log("FETCH", f"Downloading: {url}")

    try:
        import requests as _req
        resp = _req.get(url, timeout=30, headers={
            # Current Chrome 124 UA — reduces Cloudflare/Akamai bot-detection
            # hits compared to the old fragment-only string (LOW-6).
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        })
        resp.raise_for_status()
        raw_html = resp.text
    except Exception as e:
        raise PipelineError(f"Failed to fetch article: {e}")

    log("FETCH", f"Downloaded {len(raw_html)} chars of HTML")

    import trafilatura
    # favor_precision=True: prefers leaving doubtful content out. Better to
    # fail loudly on a sparse extract than to silently pass nav/menu text.
    text = trafilatura.extract(
        raw_html, url=url,
        favor_precision=True,
        include_comments=False,
        include_tables=True,
        no_fallback=False,
    ) or ""
    text = text.strip()
    log("FETCH", f"Extracted {len(text)} chars via trafilatura", "ok")

    # Length gate — cheap first-pass check.
    if len(text) < 500:
        raise PipelineError(
            f"Article text too short ({len(text)} chars). "
            f"The page may be behind a login wall, CAPTCHA, or paywall, or "
            f"trafilatura may not have found an article body. "
            f"Preview: {text[:200]!r}"
        )

    # Structural heuristic — catches nav/menu passing the length gate.
    ok, reason = _looks_like_article(text)
    if not ok:
        raise PipelineError(
            f"Extracted content doesn't look like an article: {reason}. "
            f"URL: {url}. Preview: {text[:300]!r}. "
            f"If this is a false positive, inspect the page and consider "
            f"passing the article body directly via --article <path>."
        )

    # Soft checks — warn but don't halt. These may appear legitimately
    # mid-body (e.g. a "subscribe" CTA inside a real article).
    text_head_lower = text[:3000].lower()
    for blocker in ("sign in to continue", "please log in", "access denied",
                    "captcha", "enable javascript", "403 forbidden", "page not found"):
        if blocker in text_head_lower:
            log("FETCH", f"Possible access wall detected: '{blocker}' in first 3000 chars", "warn")
            break
    nav_hits = sum(1 for m in _NAV_MARKERS if m in text_head_lower)
    if nav_hits >= 4:
        log("FETCH",
            f"{nav_hits} nav markers found in first 3000 chars — extract "
            f"may include site chrome. Check article.txt before trusting Phase 0B.",
            "warn")

    return text


# ══════════════════════════════════════════════════════════════════════════
# ENVIRONMENT VALIDATION
# ══════════════════════════════════════════════════════════════════════════

def validate_environment() -> dict:
    """Check required tools are available.

    Python check tries multiple common launcher names so the pipeline works on
    Windows (where `python3` usually doesn't exist — only `python` or `py`).

    Returns a ``{tool: version_string}`` dict for stamping into the manifest
    (LOW-3 — callers that don't need versions can ignore the return value).
    """
    versions: dict = {}

    # tiktoken: Python library, checked by import (not subprocess).
    try:
        import tiktoken  # noqa: F401
        log("ENV", f"✅ tiktoken: {tiktoken.__version__}", "ok")
        versions["tiktoken"] = tiktoken.__version__
    except ImportError as e:
        raise PipelineError(
            "tiktoken not installed — required for accurate token counting. "
            "Install with: pip install -r requirements.txt "
            f"(ImportError: {e})"
        )

    # trafilatura: Python library, checked by import (not subprocess).
    # Required for article extraction — the regex fallback silently produced
    # nav/menu content on some sites, which then poisoned Phase 0B. See HIGH-3.
    try:
        import trafilatura  # noqa: F401
        log("ENV", f"✅ trafilatura: {trafilatura.__version__}", "ok")
        versions["trafilatura"] = trafilatura.__version__
    except ImportError as e:
        raise PipelineError(
            "trafilatura not installed — required for article extraction. "
            "Install with: pip install -r requirements.txt "
            f"(ImportError: {e})"
        )

    # Each entry: (logical name, list of command alternatives to try in order)
    checks = [
        ("claude", [["claude", "--version"]]),
        ("pulumi", [["pulumi", "version"]]),
        ("python", [
            ["python3", "--version"],   # Unix / some Windows installs
            ["python", "--version"],    # Windows / Anaconda / venv
            ["py", "-3", "--version"],  # Windows py launcher
        ]),
    ]

    for name, cmd_alternatives in checks:
        found = False
        last_err = None
        for cmd in cmd_alternatives:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=10)
                if result.returncode == 0:
                    version = result.stdout.strip().split("\n")[0] or result.stderr.strip().split("\n")[0]
                    log("ENV", f"✅ {name}: {version} (via {cmd[0]})", "ok")
                    versions[name] = version
                    found = True
                    break
                last_err = f"{cmd[0]} exited {result.returncode}: {result.stderr.strip()[:100]}"
            except FileNotFoundError:
                last_err = f"{cmd[0]} not on PATH"
                continue
        if not found:
            raise PipelineError(f"{name} not available — tried {[c[0] for c in cmd_alternatives]}. Last error: {last_err}")

    # AWS — optional warning
    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity"],
            capture_output=True, text=True, encoding="utf-8", timeout=30
        )
        if result.returncode == 0:
            identity = json.loads(result.stdout)
            log("ENV", f"✅ AWS: {identity.get('Arn', 'authenticated')}", "ok")
            versions["aws_arn"] = identity.get("Arn", "authenticated")
        else:
            log("ENV", "⚠  AWS credentials not configured (optional for authoring-only mode)", "warn")
    except FileNotFoundError:
        log("ENV", "⚠  AWS CLI not found (optional)", "warn")
    except subprocess.TimeoutExpired:
        log("ENV", "⚠  AWS STS call timed out (continuing anyway)", "warn")

    return versions


# ══════════════════════════════════════════════════════════════════════════
# TI EXTRACT PROJECTIONS — per-phase field filters
# Each helper returns only the fields a given phase actually needs,
# reducing the token payload injected into prompts by 40-60%.
# ══════════════════════════════════════════════════════════════════════════

def ti_for_infra(ti_extract: dict) -> dict:
    """Fields needed by Phase 1 (infra planning) and Phase 2 (infra review).

    Keeps platform, targeted_services, credential_chain and the per-technique
    fields that determine what resources to provision.  Drops expected_audit_events,
    indicators_of_compromise, and other fields irrelevant to infra design.
    """
    return {
        "threat_actor": ti_extract.get("threat_actor"),
        "platform": ti_extract.get("platform"),
        "targeted_services": ti_extract.get("targeted_services"),
        "credential_chain": ti_extract.get("credential_chain"),
        "operational_notes": ti_extract.get("operational_notes"),
        "techniques": [
            {
                "mitre_id": t.get("mitre_id"),
                "name": t.get("name"),
                "tactic": t.get("tactic"),
                "execution_plane": t.get("execution_plane"),
                "emulation_category": t.get("emulation_category"),
                "resource_needs": t.get("resource_needs"),
                "userdata_actions": t.get("userdata_actions"),
                "execution_context": t.get("execution_context"),
            }
            for t in ti_extract.get("techniques", [])
        ],
    }


def ti_for_attack(ti_extract: dict) -> dict:
    """Fields needed by Phase 3 (attack planning) and Phase 4 (attack review).

    Keeps kill_chain_order, credential_chain, and the per-technique fields
    that determine how to chain API calls.  Drops resource_needs and
    userdata_actions which are infra concerns.
    """
    return {
        "threat_actor": ti_extract.get("threat_actor"),
        "platform": ti_extract.get("platform"),
        "kill_chain_order": ti_extract.get("kill_chain_order"),
        "credential_chain": ti_extract.get("credential_chain"),
        "operational_notes": ti_extract.get("operational_notes"),
        "iocs": ti_extract.get("iocs"),
        "techniques": [
            {
                "mitre_id": t.get("mitre_id"),
                "name": t.get("name"),
                "tactic": t.get("tactic"),
                "execution_plane": t.get("execution_plane"),
                "execution_context": t.get("execution_context"),
                "emulation_category": t.get("emulation_category"),
                "expected_audit_events": t.get("expected_audit_events"),
                "credential_requirements": t.get("credential_requirements"),
                "indicators_of_compromise": t.get("indicators_of_compromise"),
            }
            for t in ti_extract.get("techniques", [])
        ],
    }


def ti_for_detections(ti_extract: dict) -> dict:
    """Fields needed by Phase 6 (detections, playbook, guardrails).

    Keeps audit event names, IoCs, and tactic context.  Drops resource_needs,
    userdata_actions, and credential_requirements which are irrelevant here.
    """
    return {
        "threat_actor": ti_extract.get("threat_actor"),
        "platform": ti_extract.get("platform"),
        "kill_chain_order": ti_extract.get("kill_chain_order"),
        "iocs": ti_extract.get("iocs"),
        "techniques": [
            {
                "mitre_id": t.get("mitre_id"),
                "name": t.get("name"),
                "tactic": t.get("tactic"),
                "execution_plane": t.get("execution_plane"),
                "execution_context": t.get("execution_context"),
                "expected_audit_events": t.get("expected_audit_events"),
                "indicators_of_compromise": t.get("indicators_of_compromise"),
            }
            for t in ti_extract.get("techniques", [])
        ],
    }


def infra_for_attack(infra_plan: dict) -> dict:
    """Fields needed by Phase 3 (attack planning) and Phase 4 (attack review).

    Drops Pulumi-specific fields (pulumi_type, depends_on, cleanup_method,
    estimated_cost_usd_hr, configuration_notes) that are only relevant to the
    IaC implementor.  The attack planner only needs resource names, categories,
    purposes, and which techniques each resource serves.

    Savings vs full infra_plan: ~65% fewer chars (~2.5K tokens per call;
    compounds over Phase 4 review iterations).
    """
    keep = {"name", "resource_category", "purpose", "techniques_served"}
    return {
        "resources": [
            {k: v for k, v in r.items() if k in keep}
            for r in infra_plan.get("resources", [])
        ],
        **({"userdata_actions": infra_plan["userdata_actions"]}
           if infra_plan.get("userdata_actions") else {}),
    }


def attack_for_detections(attack_plan: dict) -> dict:
    """Fields needed by Phase 6 (detections, playbook, guardrails).

    Drops implementation details that are only needed by the attack script
    generator (Phase 5B): implementation, cleanup_actions, operational_tempo,
    risk_level, script_manifest, cleanup_manifest.

    Savings vs full attack plan: ~28% fewer chars (~2.75K tokens per call;
    sent to 3 Phase 6 sub-tasks = ~8K tokens total).
    """
    drop_step = {"implementation", "cleanup_actions", "operational_tempo", "risk_level", "phase"}
    drop_top  = {"script_manifest", "cleanup_manifest",
                 "dwell_time_recommendation_seconds", "total_techniques",
                 "total_attack_steps"}
    return {
        k: (
            [{fk: fv for fk, fv in step.items() if fk not in drop_step}
             for step in v]
            if k == "attack_chain" else v
        )
        for k, v in attack_plan.items()
        if k not in drop_top
    }


def _load_implementor(agents_dir: Path, task: str, platform: str = "aws") -> str:
    """Compose the implementor system prompt: base compat rules + task overlay.

    Optionally appends a platform-specific compatibility overlay if one exists
    (e.g. agents/opus_implementor_compat_azure.md for Azure runs).

    Args:
        agents_dir: Path to the agents/ directory.
        task:       One of infra | attack | detections | playbook | guardrails.
        platform:   Platform string from ti_extract (aws, azure, gcp, …).

    Returns:
        Combined system prompt string ready to pass as the agent argument.
    """
    base = (agents_dir / "opus_implementor_base.md").read_text(encoding="utf-8")
    task_overlay = (agents_dir / f"opus_implementor_{task}.md").read_text(encoding="utf-8")

    # Optional platform-specific compat overlay (only exists for non-AWS once added)
    platform_path = agents_dir / f"opus_implementor_compat_{platform}.md"
    platform_overlay = (
        platform_path.read_text(encoding="utf-8") if platform_path.exists() else ""
    )

    parts = [base]
    if platform_overlay:
        parts.append(platform_overlay)
    parts.append(task_overlay)
    return "\n\n---\n\n".join(parts)
