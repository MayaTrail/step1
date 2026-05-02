# Pipeline Gap Analysis v3 — LUCR-3 Live Test
## Observed failures running pipeline.py against the Permiso LUCR-3 article

> **STATUS: CRITICAL.** The pipeline is currently non-functional end-to-end. The
> test run against the LUCR-3 (Scattered Spider) article from Permiso produced a
> ti_extract.json containing a single `cannot_safely_emulate` entry — 228 bytes
> of data where 30-50 KB was expected. Phase 1 then "succeeded" by designing
> infrastructure for a SINGLE technique (T1090.002 residential proxies) instead
> of the 19-technique LUCR-3 kill chain.
>
> This analysis documents what went wrong, the root causes, and the minimum fix
> set required before the pipeline can produce a usable LUCR-3 emulation.

---

## TL;DR — The Three Compounding Bugs

The LUCR-3 run revealed three bugs that compound catastrophically:

1. **Silent output truncation.** Claude Sonnet's Phase 0B response was truncated
   to only its tail (~6.4 KB of what should have been ~30+ KB compact JSON). The
   file saved to `phase0b_raw.md` starts mid-JSON with `,"opsec_notes":"..."` —
   no opening `{`, no `status` field, no `threat_actor` field, and the first
   ~16 technique objects are missing entirely.

2. **`extract_json` silently picks the wrong JSON.** When the raw response is
   malformed, the brace-matching fallback finds nested `{...}` objects inside
   arrays (e.g., individual `cannot_safely_emulate` entries) and returns "the
   largest one" (216 bytes). It reports success — no warning that the envelope
   is missing.

3. **Schema validation is advisory, not blocking.** Phase 0B logged `Schema issues:
   ["Missing top-level field: 'status'", "Missing top-level field: 'techniques'",
   ...]` then printed `✅ Unknown: 0 techniques` and continued. Phase 1 happily
   designed infrastructure from a ti_extract that had ZERO techniques.

If any ONE of these were fixed, the failure would be caught. All three failing
together produces silent, confident, completely wrong output — the worst
possible failure mode for a content-authoring pipeline.

---

## CRITICAL — Pipeline cannot produce a correct LUCR-3 emulation without these fixes

### CRIT-1 — Phase 0B response is truncated (only the tail survives)

**Observed:** `phase0b_raw.md` is 6458 bytes and begins with `,"opsec_notes":...`,
which is mid-field inside a technique object. The file ends correctly with
`"extraction_confidence":"high"}`. Between the truncation point and the end,
the `kill_chain_order` lists 19 techniques — but only 3 technique objects
appear in the `techniques` array. Approximately 16 technique objects and all
top-level metadata (`status`, `threat_actor`, `targeted_services`, `platform`)
are missing from the start of the response.

**Root cause:** Two contributing factors:

  a. The Sonnet TI extractor emits a very large single-blob JSON (~30-50 KB
     for a 19-technique actor) in one response. This pushes close to output
     token limits and makes streaming fragile.

  b. The `claude --print --output-format text` invocation used by the pipeline
     doesn't provide any integrity signal — truncation (from any source:
     pipe buffer overrun on Windows, Claude CLI's internal display limits,
     model output token cap) is invisible to the caller.

**Fixes (in order of impact):**

1. **Use `--output-format json --json-schema <schema>`.** The Claude CLI supports
   structured-output validation natively (see `claude --help`). Passing a JSON
   Schema forces the model to produce a valid object and the CLI to return
   `{"result": {...}}` that can be parsed deterministically. This alone
   eliminates 90 % of the extraction pain.

2. **Split Phase 0B into two calls.** Call 1 returns the top-level metadata
   (threat_actor, platform, kill_chain_order, credential_chain, iocs,
   operational_notes) — small, fits easily. Call 2 returns the techniques
   array — can be paginated if the actor has > N techniques. Re-assemble in
   Python. Halves the per-call output size and gives natural retry points.

3. **Stream the response with `--output-format stream-json`.** The pipeline can
   detect truncation at the point it happens (stream closes mid-token) rather
   than after the fact. Lets us retry the same call with the partial content
   as context ("continue from here").

4. **Detect truncation in `extract_json`.** Today the function only flags
   truncation when the brace count is still positive at EOF. Add a symmetric
   "starts mid-value" check — if the first non-whitespace char isn't `{` or
   `[` AND no code fence was found, log ERROR and return `None`. Do NOT fall
   back to nested-brace matching on clearly malformed input.

### CRIT-2 — `extract_json` returns the wrong JSON on malformed input

**Observed:** Given a response whose outer envelope is missing, the function
scanned for balanced `{...}` blocks inside the tail, found 17 small nested
objects (sizes `[216, 190, 187, 174, 170]`), and returned the largest one
(216 bytes) as "the JSON". The returned object was a single
`{"technique":"T1090.002","reason":"Residential VPN...","simulation":"..."}`
entry plucked from the `cannot_safely_emulate` array.

The log line that "found 17 brace blocks" was emitted at `dim` level and did
not surface to the user as a problem.

**Root cause:** The brace-matching fallback was designed to handle LLM output
with prose around a JSON block. It was never meant to salvage JSON fragments
from a broken response. The "largest wins" tiebreaker is catastrophic when
the true root object is missing: every child object becomes a candidate.

**Fix:** In `utils.extract_json`:

```python
# After step 3 (brace matching), sanity-check the winning candidate.
if brace_candidates:
    best = max(brace_candidates, key=lambda c: len(json.dumps(c)))

    # Guardrail: if the ORIGINAL text had unbalanced braces at EOF OR
    # the response starts with ',' / ']' / '}' (mid-value), the "winning"
    # candidate is probably a nested fragment, not the envelope.
    stripped = text.lstrip()
    looks_truncated = (
        depth > 0 or
        (stripped and stripped[0] in ",]}")
    )
    if looks_truncated:
        log("JSON-EXTRACT",
            f"Response appears truncated (starts with {stripped[:20]!r}). "
            f"Found {len(brace_candidates)} nested blocks but REFUSING to "
            f"return a fragment. Treat as extraction failure.", "err")
        return None
    return best
```

### CRIT-3 — Phase 0B doesn't halt on empty/invalid TI extract

**Observed:** Phase 0B logged schema errors (`Missing top-level field: 'status'`,
`Missing top-level field: 'techniques'`, etc.), printed a green
`✅ Unknown: 0 techniques (control:0 data:0 host:0)`, wrote a 228-byte
ti_extract.json, and moved on to Phase 1 with a zero-technique extract.

**Root cause:** `phase_0b_ti_extraction` treats `validate_json_schema` as
informational. The validation result is logged but never checked before
returning.

**Fix:** In `pipeline.phase_0b_ti_extraction`, hard-fail on critical schema
violations:

```python
validation = validate_json_schema(ti_data, "ti_extract")
if not validation["valid"]:
    # Don't poison downstream phases with a bad TI extract.
    # The caller is expected to retry or abort.
    raise PipelineError(
        f"Phase 0B produced invalid TI extract. "
        f"Schema errors: {validation['errors']}. "
        f"Raw output saved to {out_dir / 'phase0b_raw.md'} for inspection. "
        f"Techniques extracted: {len(ti_data.get('techniques', []))}."
    )

# Also refuse to proceed with zero techniques:
if not ti_data.get("techniques"):
    raise PipelineError(
        "Phase 0B returned zero techniques. Cannot plan infrastructure. "
        "Check article.txt quality and phase0b_raw.md."
    )
```

The same gate is needed in Phases 1, 3 (infra_plan and attack_plan can be
similarly malformed).

---

## HIGH — These cause correctness or cost problems even when the pipeline "works"

### HIGH-1 — Phase 0B runs for 485 s on a single call

The LUCR-3 Phase 0B call took 8 minutes. This is:
- Close to the 900 s timeout, with no margin.
- Expensive — a single Sonnet call with ~9500 tokens total.
- Single point of failure — if this times out or rate-limits, the entire run
  is lost. There's no intra-phase checkpointing.

**Fix:** Same as CRIT-1 fix #2 — split into two calls. Each call completes in
~3-4 min, with natural save points between them. Gives us a cheaper retry unit.

### HIGH-2 — Hit rate limit after ~5 Claude calls

On line 44 of the run log: `PHASE-2-REDRAFT ... RATE LIMITED — resets at unknown`.
The pipeline was at Phase 2 redraft iteration 1 when it hit the daily limit.
Total calls consumed before the limit: **five** (Phase 0B, Phase 1, Phase 2 review,
Phase 2 redraft attempt, failed retry).

Five calls is nowhere near enough for a full LUCR-3 emulation. The pipeline
reasonably needs:

| Phase | Calls (min) | Calls (worst case w/ 3x review) |
|-------|-------------|----------------------------------|
| 0B    | 1           | 2 (on retry)                     |
| 1     | 1           | 1                                |
| 2     | 2 (review + redraft x1) | 6 (review+redraft x3)      |
| 3     | 1           | 1                                |
| 4     | 2           | 6                                |
| 5A + 5B | 2         | 2 (parallel, counts as 2)        |
| 6A + 6B + 6C | 3     | 3                                |
| **Total** | **12**   | **21**                           |

**Fixes:**

1. **`--fallback-model` flag.** `claude --print --fallback-model sonnet` on
   Opus calls will downgrade to Sonnet if Opus is overloaded instead of
   dying. Worth it for non-critical review passes.

2. **`--max-budget-usd`.** Pass the user's budget cap so the CLI refuses
   spend past a threshold — no more surprise bills.

3. **Prompt cache reuse.** Opus reviewer prompts repeat the ti_extract JSON
   for each iteration. If we stop concatenating system+user prompts and pass
   the agent markdown via `--append-system-prompt` AND use
   `--exclude-dynamic-system-prompt-sections`, the Claude cache hits across
   iterations and drops costs significantly. Today we inline everything into
   stdin, so every call is a cache miss.

4. **Parse the rate-limit reset time.** The regex in `call_claude` today
   fails to match Claude Code CLI's actual output format and shows
   `RATE LIMITED — resets at unknown`. Improve to match the CLI's current
   wording (`"You've hit your limit · resets Apr 17, 11:30pm (Asia/Calcutta)"`)
   and sleep until that timestamp instead of an arbitrary 90 s.

### HIGH-3 — Article fetch silently returns non-content

The `fetch_article` function uses regex HTML stripping. On the LUCR-3 URL it
produced 16 279 chars of legible article body — good. But in a prior run
(`20260411_171836/article.txt`), the regex only captured the site header/nav,
and no article text at all. Downstream, Claude Sonnet was given a prompt that
asked it to extract TI from a few kilobytes of navigation markup, and it
responded with an LLM-reconstructed "article" from its training data — a
hallucinated threat report masquerading as extracted content.

The pipeline has no defense against this. The quality gate
(`len(text) < 500` raises) is trivially satisfied by any page's header.

**Fix:**

1. **Content heuristics.** After extraction, check for article-like markers
   (multiple `<p>`-derived paragraphs, at least one long sentence, presence
   of body-level punctuation diversity). If the extracted "article" has 50
   lines that are all under 80 chars, it's probably nav/menu, not content.

2. **Reject obvious site chrome.** If >60 % of extracted lines match nav
   patterns (`BACK TO BLOGS`, `Subscribe`, `Related Articles`, etc.), warn.

3. **Optional LLM sanity pass.** Before Phase 0B, do a cheap Haiku/Sonnet
   call: "Is this a threat intelligence article about a specific actor, or
   is it navigation/login/paywall content? Reply one word." If not an
   article, abort with a clear error rather than producing hallucinated TI.

4. **Prefer trafilatura/readability-lxml** over regex tag stripping. These
   libraries are battle-tested for article extraction and handle edge cases
   (JS-rendered pages, AMP, article tag detection) far better.

### HIGH-4 — `call_claude` concatenates system + user into stdin

Current code:

```python
full_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}" if system_prompt else user_prompt
# ... written to temp file, passed via stdin
```

This loses the system/user distinction. The Claude CLI supports
`--append-system-prompt <text>` and `--append-system-prompt-file <path>`,
which keep the separation and let the model's training on system prompts
work properly. It also improves prompt caching across calls that share a
system prompt.

**Fix:** Use `--append-system-prompt-file` for the agent.md and pass the
user prompt as stdin (or via `-p <prompt>`). This is a one-line change with
measurable quality and cost improvements.

### HIGH-5 — Python version check is Unix-only

`validate_environment` runs `python3 --version`. On Windows this command
often doesn't exist (only `python` does). The LUCR-3 run succeeded only
because the user happens to have `python3.exe` installed — many Windows
environments don't.

**Fix:** Try `python3`, fall back to `python`, and on Windows prefer `py -3`.

---

## MEDIUM — Quality-of-life improvements

### MED-1 — Token cost estimates are rough (off by ~50 %)

`len(text) // 3` is used as the token estimator. For dense JSON, the real
ratio is closer to 3.5-4 chars/token; for English prose it's 4-5. The
summary `$X estimated cost` at the end of a run will be systematically
inaccurate by 30-50 %.

**Fix:** Use `tiktoken` (if installed) or accept the token counts from
`--output-format json` which returns usage data directly from the API.

### MED-2 — No content-hash caching

The pipeline stores `article.txt` but re-runs Phase 0B against the same URL
every time (no `--resume` flag). If a user wants to regenerate just the
detections section, they pay for Phase 0B again. Detect identical
`article.txt` hash between runs and reuse `ti_extract.json`.

### MED-3 — Parallel Phase 5/6 executes 5 concurrent Claude calls

Phase 5 runs 5A || 5B, and when the top-level `run_pipeline` launches Phase
5 and Phase 6 in parallel, Phase 6's 6A || 6B || 6C adds three more, giving
**five simultaneous Claude calls**. On a rate-limited account this is the
fastest way to exhaust quota. Either serialize 5+6 (simpler, slightly
slower) or gate concurrency behind a `--max-concurrency` flag that defaults
to 2.

### MED-4 — `validate_technique_coverage` matches technique IDs case-insensitively

`re.findall(r'T\d{4}(?:\.\d{3})?', code)` — this matches any `T` followed
by 4 digits. That's fine for well-formed ATT&CK IDs, but won't match lower-case
`t1078` references in a variable name or comment. Consider whether `re.I` should
be set, or whether to also match technique names (`"Valid Accounts"`) as evidence
of coverage. Today a perfectly correct script that uses `TID_1078 = "..."` as
a variable will score 100 % while `tid_1078` will score 0 %.

### MED-5 — `infra_plan_approved.json` can silently equal `infra_plan.json`

When the review-loop fallback triggers (Opus approved but the approved draft
can't be parsed as JSON), the pipeline reuses the original, un-revised plan.
This can hide that the reviewer actually asked for changes and the redraft
failed. The fallback is logged but no warning escalates to the run summary.

**Fix:** Add a `"fallback_count"` field to the final summary and log it at
`warn` level when non-zero.

### MED-6 — No "dry run" for the actual emulation scripts

The pipeline generates `attack.py` and validates syntax/imports/boto3 calls
— but never actually imports or executes the module. A missing function
definition, a call to an undefined helper, or a logic bug passes validation
cleanly. Adding a `python -c "import importlib.util; s=importlib.util.spec_from_file_location('m','attack.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"`
step would catch a large class of bugs at ~0 cost.

### MED-7 — `schema.valid_execution_contexts` out of sync with agent prompts

`validators.SCHEMAS["attack_plan"]["valid_execution_contexts"]` lists:
`api_attack, host_attack, container_attack, sso_attack, saas_attack,
idp_attack, phishing_attack, lateral_movement`.

The `sonnet_ti_extractor.md` agent lists the same values. But `phase_5_code_generation`
in pipeline.py only handles: `container_attack, api_attack, sso_attack, saas_attack,
idp_attack, lateral_movement`. **Missing handlers:** `host_attack` (partially — it's
"pre-deployed in UserData") and `phishing_attack` (no implementation guidance at all).

A phishing-heavy threat actor like LUCR-3 (step 1 is SIM swap/push fatigue)
will produce `phishing_attack` steps that have no code-gen guidance in the
Phase 5 prompt. The Opus implementor will improvise — probably with
placeholder or simulated code — and the user won't know.

**Fix:** Either remove `phishing_attack` from the enum (with guidance to map
to `saas_attack` / `idp_attack` with a `simulated` emulation_category), or add
explicit handling.

### MED-8 — No dedicated LUCR-3 test fixture

Every test run costs ~$5-10 and 20+ minutes. A fixture that saves a real
(known-good) Claude response for each phase and replays it would let us
iterate on pipeline code (error handling, extraction, validation) in seconds
for $0. `pytest` + `pytest-vcr` or a simple JSON replay harness in
`tests/fixtures/lucr3/` would pay for itself after the third iteration.

---

## LOW — Polish

### LOW-1 — Green checkmark on zero-technique extract
The log `✅ Unknown: 0 techniques (control:0 data:0 host:0)` uses the "ok"
color. Any zero-count summary should be "warn" or "err".

### LOW-2 — Hardcoded `inter_phase_delay_seconds: [300, 3600]`
The LUCR-3 operational_notes in the broken ti_extract says phases are
5 min – 1 hour apart. For a test emulation, this is too slow. The attack
planner/implementor should offer a "test_mode" with shorter delays.

### LOW-3 — `run_manifest.json` doesn't record the tool versions
The environment check logs claude/pulumi/python versions but doesn't persist
them in the manifest. Reproducibility suffers.

### LOW-4 — `extract_json` has dead `depth>0` branch in Section 4
Section 4 checks `depth > 0 and start_idx is not None` AFTER section 3 has
already iterated to EOF and reset start_idx on every closing brace. The
branch fires only if the LAST opening brace never closes. Works, but the
logic reads like a leftover — worth documenting or simplifying.

### LOW-5 — Windows console UTF-8 reconfigure is Python 3.7+ only
`sys.stdout.reconfigure(...)` was added in 3.7. Pipeline probably only
supports 3.8+ anyway, but worth adding an explicit version check in
`validate_environment`.

### LOW-6 — `fetch_article` sets a fake Windows user-agent
Some sites return different content to what they think is a browser vs a
bot. The current UA string `Mozilla/5.0 (Windows NT 10.0; Win64; x64)
AppleWebKit/537.36` is old and fragment-y (no version number, no browser
name). Update to a current Chrome/Firefox UA, or respect the site's
`robots.txt`. For permiso.io specifically this doesn't matter — the page
served is complete — but for sites with CF/Akamai bot detection this
matters a lot.

---

## Summary of Recommended Fix Order

If you only fix three things, fix CRIT-1 (response truncation + structured
output), CRIT-2 (`extract_json` refuses fragments), and CRIT-3 (schema
validation halts the pipeline). Those three alone turn the current run
from "silently wrong" into "correctly fails fast" — which is infinitely
more actionable.

After those, HIGH-1 (split Phase 0B) and HIGH-4 (use --append-system-prompt-file)
are the biggest cost/performance wins for ~30 minutes of work each.

Everything in MEDIUM and LOW is polish — valuable, but not blocking a
working LUCR-3 emulation.

---

## Concrete LUCR-3 Emulation Expectations (for verification)

Once the pipeline works, a correct LUCR-3 emulation should produce:

- **19 techniques** in the kill chain (T1589.001 → T1213.003, see the
  broken run's accidentally-captured `kill_chain_order`).
- **5 credential-chain phases**: dark-web creds → IDP session token →
  SecretsManager → IAM access key → SaaS API tokens.
- **Multi-platform infra**: Okta/Azure AD/PingOne (identity), AWS (S3,
  IAM, Secrets Manager, CloudTrail, GuardDuty), M365/Graph API, GitHub/GitLab.
- **~7 `cannot_safely_emulate` entries** (dark web creds, real push fatigue,
  disabling real CloudTrail/GuardDuty, real exfil, real repo cloning,
  residential proxies).
- **SIGMA/KQL rules for every control_plane technique**: ~12 of the 19
  techniques are control_plane (API-observable), the rest are
  data_plane/host_plane (documented-only in the extract).
- **Platform-specific guardrails**: Okta MFA/sign-on policies, Azure
  Conditional Access, AWS SCP + IAM boundaries, GitHub OAuth app restrictions.

This is the yardstick for "did the pipeline work on LUCR-3?" — not whether
it produced *any* ti_extract, but whether it produced *this* ti_extract.
