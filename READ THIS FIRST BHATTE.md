# Read this first, Bhatte

This branch adds a batch of work that was built off `main` at **`d95a669`
(PR #68, 3 Sep)** and has been merged up to your current `main` (`4631a24`,
14 Sep). **Nothing of yours has been removed** — your playbook library, threat
intel, connectors and workflows are all still here. Where we both touched the
same file, your version was kept and our additions were placed alongside it.

The one-line summary of what this adds: `main` already runs an attack and checks
which rules fired. This turns that single verdict into a **loop** — convert the
rules into the customer's SIEM, watch coverage over time, catch regressions, hand
over an evidence packet, and let users write the missing rules and playbooks
in-product.

Deeper reference for all of it, with the reasoning behind each decision, is in
**`docs/NEW_FEATURES.md`**. This file is the tour.

---

## 1. Detection conversion module — Sigma → SIEM

**`backend/apps/emulations/sigma_convert.py`** (+ `detection_export.py` for the
HTTP surface)

Compiles our shipped Sigma rules into the customer's SIEM query language using
**pySigma** with one backend per target. It's the official implementation, not a
translator we wrote.

| Target | Backend class | Output formats |
|---|---|---|
| `splunk` | `SplunkBackend` | `default`, `savedsearches` |
| `opensearch` | `OpensearchLuceneBackend` | `default`, `dsl_lucene` |

`savedsearches` emits a real `savedsearches.conf` stanza — droppable into a
Splunk app, not just a query to paste.

```
GET /api/emulations/detection-targets/
GET /api/emulations/<emulation_type>/detections/export/?target=splunk
GET /api/emulations/<run_id>/detections/export/?verdict=silent&target=splunk
```

**The run-scoped one is the whole point.** "2 rules stayed silent" is a finding
with no action attached. Handing back exactly those two rules, compiled for their
SIEM, is the action. In the UI it's a **"Close the gap"** panel on the run
coverage page, shown only when there's something to fix — fired rules need
nothing, and `no_logs` is a telemetry gap no query closes.

**Four things that will bite you if you touch this:**

- **Backends import lazily.** The module is Django-free on purpose, so the
  validator and the CLI can import it with no settings, DB or AWS creds, and so
  it stays importable in the runtime image where pySigma isn't installed.
- **The query param is `output_format`, not `format`.** DRF reserves `?format=`
  for content negotiation and 404s in the renderer before the view even runs.
- **Route order:** `<str:emulation_type>` happily matches a UUID, so the
  `<uuid:run_id>` export route must be declared **first** or every run export
  404s with "unknown emulation &lt;uuid&gt;". Four tests pin this.
- **Rules a target can't express are reported, never dropped** (`SkippedRule`,
  with a reason). Splunk implements `event_count` and `value_count` but not
  `temporal_ordered`; OpenSearch Lucene implements no correlations at all. A
  bundle that silently swallowed three correlations would be worse than useless —
  the engineer deploys it believing they have coverage they don't have.

**Don't "clean up" the dependency duplication.** pySigma and both backends are
pinned in `requirements.txt` *and* `requirements-dev.txt`, and CI fails if the
two pin sets drift. Otherwise CI would validate the rule corpus against a
different compiler than the one serving customers.

---

## 2. Report and compare — the evidence packet

**`backend/apps/emulations/reporting.py`**, `coverage_history.compare_runs()`,
and `frontend/UI/src/components/reports/`

`/reports` was a `ComingSoon` stub in the sidebar while the product promised "a
signed evidence packet" as the deliverable of every run. This is that packet.

```
GET /api/emulations/<run_id>/report/
GET /api/emulations/compare/?a=<run_id>&b=<run_id>
```

- **`build_report()` is a pure assembly over data already stored** — verdicts
  from the run's `detection_check`, the change report from `coverage_history`,
  technique metadata from the registry. It's an assembly, never a second opinion,
  so **a report can never disagree with the run page it came from.**
- **`compare_runs(a, b)` answers a different question from `compare()`.**
  `compare()` answers "what regressed". `compare_runs` answers "I changed
  something — did it work?", so every rule is on the table with both runs' figures
  side by side, classified regressed / improved / changed / unchanged / added /
  removed. A rule present in only one run is added-or-removed, never scored as a
  regression, because the rule set itself moved.
- The compare view **normalises argument order by completion time**, so passing
  the two runs the wrong way round still reads correctly. 400 on missing,
  identical or non-UUID ids; 404 on a run the caller doesn't own.

**The honest part, which is the reason the feature exists.**
`reporting._uncovered()` lists techniques the campaign declares in its attack
path that **no rule in our pack looks for**, and reports them *separately* from
rules that ran and stayed silent — because those are two different failures. One
is the customer's detection gap; the other is ours. For AMBERSQUID that's
`T1204.003` and `T1496`, and the report says so in as many words: *"This is a gap
in MayaTrail's content, not in your detection stack."*

Coverage is always phrased **"n of m rules evaluated"**, never a bare score, and
the page states outright that uncovered techniques are excluded from it. Please
keep that phrasing — it's the product argument, not house style.

Export is print / save-PDF (a `@media print` block drops the app chrome) and
download-JSON. Route order gotcha: `reports/compare` must be declared **before**
`reports/:runId` or the param route swallows it.

---

## 3. Playbook draft feature — `apps/playbooks`

Note this is a **different feature from your playbooks-as-documentation**, and
they currently share a hub. See the open question at the bottom.

Yours ships playbooks to *read*. This lets a user *write* one: model, 7
endpoints, owner-only writes, path-traversal validation on the fork parameter, a
512 KB body cap.

- **Stored as Markdown, not HTML**, even though the editor is a rich-text
  surface. Our shipped playbooks are Markdown, so a fork is lossless in and an
  export is lossless out — verified by forking AMBERSQUID and exporting it back
  byte-identical to `emulations/ambersquid/PLAYBOOK.md`. Every renderer already
  reads Markdown, and storing user HTML to render back would be a stored-XSS
  surface.
- The editor is **block-based** — phases, steps, commands, decisions, notes —
  serialising to the exact `## Phase` / `#### Step N -` conventions the existing
  reader already parses. All 46 shipped playbooks round-trip markdown → blocks →
  markdown with zero lost phases, steps or commands.
- Decisions are **If/Then rows, not a node graph**, because a true branching
  canvas can't round-trip with the shipped files.
- The reader reuses the **same parser and `PlaybookSection` component** as the
  shipped playbooks, so an authored playbook gets phase tabs, checkable steps and
  copyable commands like any other.
- Every new user is seeded two examples via a `post_save` signal. Idempotent and
  best-effort: a user who already has any playbook is skipped, so deleted
  examples never come back, and a seeding failure never costs a signup.
- **AI drafting** reuses the existing connector and shares the `ai_chat` throttle.

**One trap worth knowing.** Trimming "unused" toolbar code once removed the
TipTap table extensions. ProseMirror **silently drops nodes its schema doesn't
know**, and AMBERSQUID opens with a classification table — so opening that
playbook would have deleted a table the author never touched. The schema is now
deliberately wider than the toolbar. Please leave it that way.

---

## 4. Everything else in this branch

**Continuous assurance** — `coverage_history.py` (trend + regressions) and
`scheduling.py` (`ScheduledRun`, cadence maths, a Beat task every 15 min that
mirrors the deploy path and respects one-active-stack). Endpoints:
`coverage-trend/`, `<run_id>/regressions/`, `assurance/`, `schedules/`.
**fired → silent is a regression; no_logs → silent is not** — deliberately, so we
don't cry wolf when telemetry merely came back. Scheduled runs only actually
execute where Beat, Redis and AWS are live; the logic is unit-tested without any
of that. Regression alerts are **pull-only** today (a banner) — push to
Slack/email/Jira is the obvious next step and no notification plumbing exists.

**Detection studio** — `apps/authored_detections`: write or AI-generate a Sigma
rule, **validate whether it actually fires** against synthetic CloudTrail events
(reusing `apps/ai/detection_validation.py`), then export it to a SIEM. The
generate → validate → export loop, in-product. Sigma is stored as YAML so it
validates, exports and renders through the existing paths.

**Dashboard command center** — one call to `assurance/`. The headline percentage
is **`fired ÷ ruleCount`** across the latest completed run of each emulation.
No weighting, no model, no invented score. `no_logs` sits in the denominator on
purpose: a rule you can't judge isn't coverage. Heads-up on a naming collision —
the trend code calls this same ratio `fidelity`, the dashboard calls it `pct`.

**Plain-language UI mode** — `context/UiModeContext.tsx`, a global
Technical/Simple toggle stored at `mt:ui-mode`, **defaulting to `classic`**.
Classic is byte-identical to the old UI, so this rolls back by toggle, not by
revert. **Nobody has reviewed it in a browser yet** — `tsc -b` and `npm run build`
are clean and the API was smoke-tested on seeded data, but treat the visuals as
unverified.

**Gemini support** in the AI connector via its OpenAI-compatible endpoint, which
makes AI drafting usable on a free key. Saving a connector needs
`LLM_FERNET_KEY` set — it encrypts the stored key, so Test passes without it but
Save 503s.

**Run recordings** — `manage.py export_run_recording <run_id>` turns a real run
into a replayable recording for the marketing site. **Allowlist, not scrub:**
every field is constructed by name and no CloudTrail dict is ever copied, so an
event carries exactly `{eventSource, eventName, t_offset_s}`. Account ids, ARNs,
session names (often a human's email), source IPs and request parameters have no
path out. Three independent checks guard that boundary.

---

## What I need from you

**One product decision, not a merge conflict:** `PlaybooksHub.tsx` now hosts two
different features — your playbooks-as-documentation and this branch's
user-authored playbooks. They coexist in this branch but nobody has designed how
they should sit together. Worth a short conversation before this merges to
`main`.

**Two things to know about the merge:**

- The merge commit on this branch is where `main`'s 14 Sep state was brought in.
  Conflicts were resolved by **keeping your code and adding ours next to it** —
  worth a skim of the merge commit if you want to check my work.
- This repo has paths too long for Windows defaults (the
  `playbooks/secretsmanager.privilege-escalation...` directories). If you clone on
  Windows, run `git config --global core.longpaths true` first or the checkout
  silently half-fails.

**Not included on purpose:** an alternative "contact sheet" UI experiment lives
outside this branch. It's parked and shouldn't go anywhere near `main`.

**State before pushing:** backend **229 tests passing**, detection validator
**87/87 files**, `npx tsc -b` and `npm run build` clean. Two UI lint rules fire
codebase-wide (`tailwindcss/no-arbitrary-value`, the `font-display font-[800]`
page-header idiom) and both pre-date this work.
