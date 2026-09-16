# New features — detection loop, assurance, reports, authoring

Everything in this document is **additive work that is not yet on `main`**. It was
built against `d95a669` (PR #68, 2026-09-03) and has since diverged; see
"Merging this" at the bottom before opening a PR.

The theme running through all of it: `main` already runs an attack and checks
which rules fired. This work turns that single verdict into a **loop** — convert
the rules to the customer's SIEM, watch coverage over time, catch regressions,
hand over an evidence packet, and let users author the missing rules and
playbooks in-product.

---

## 1. Sigma → SIEM conversion (`apps/emulations/sigma_convert.py`)

Compiles the shipped Sigma rules into the query language of the customer's SIEM
using **pySigma** and one backend per target — the official implementation, not a
hand-rolled translator.

| Target | Label | Backend class | Output formats |
|---|---|---|---|
| `splunk` | Splunk (SPL) | `SplunkBackend` | `default`, `savedsearches` |
| `opensearch` | OpenSearch / Wazuh Indexer (Lucene) | `OpensearchLuceneBackend` | `default`, `dsl_lucene` |

The non-`default` formats are deployable artefacts, not just queries — the
`savedsearches` output is a stanza you can drop straight into a Splunk app.

**Endpoints** (`apps/emulations/detection_export.py`):

```
GET /api/emulations/detection-targets/
GET /api/emulations/<emulation_type>/detections/export/?target=splunk&output_format=default
GET /api/emulations/<run_id>/detections/export/?verdict=silent&target=splunk
```

The **run-scoped** one is the point of the feature. "2 rules stayed silent" is a
finding with no action attached; handing back exactly those two, compiled for
their SIEM, is the action. It surfaces as a **"Close the gap"** panel on the run
coverage page, and only when there is something to fix — fired rules need
nothing, and `no_logs` is a telemetry gap no query closes.

Four things that will bite whoever touches this next:

- **Backends are imported lazily.** `sigma_convert` is Django-free and must stay
  importable in the runtime image where pySigma is not installed. `available_targets()`
  probes which backends actually import; `BackendUnavailable` explains the install.
- **`?format=` is reserved by DRF** for content negotiation and 404s in the
  renderer before the view runs. The parameter is **`output_format`**.
- **Route order matters.** `<str:emulation_type>` matches a UUID perfectly well,
  so the `<uuid:run_id>` export route must be declared first or every run export
  404s with "unknown emulation &lt;uuid&gt;". Four route-resolution tests pin this.
- **Rules a target cannot express are reported, never dropped** (`SkippedRule`,
  with a reason). Splunk's backend implements `event_count` and `value_count` but
  not `temporal_ordered`; the OpenSearch Lucene backend implements no
  correlations at all. A bundle that silently omitted three correlations is worse
  than useless — the engineer deploys it believing they have coverage they don't.

pySigma and both backends moved from `requirements-dev.txt` into
`requirements.txt` (they now serve customer traffic). They stay pinned in **both**
files, and CI fails if the two pin sets drift — otherwise CI would validate the
rule corpus against a different compiler than the one serving customers. **Do not
tidy that duplication away.**

There is also a standalone CLI, `scripts/convert_detections.py`, running the same
module.

---

## 2. Continuous assurance — trend, regressions, schedules

Turns a point-in-time assessment into something that holds over time. All of it
reads the run history already stored on `EmulationRun.detection_check`; no new
data collection.

**`apps/emulations/coverage_history.py`** (pure functions, no ORM writes):

- `snapshot(run)` — one trend point: the three verdict counts, `ruleCount`, and
  `fidelity` = fired / rules-evaluated.
- `coverage_trend(runs)` — those points over time.
- `compare()` / `compare_to_previous()` — **fired → silent is a regression;
  no_logs → silent is not**, deliberately, to avoid crying wolf when telemetry
  merely came back.
- `compare_runs(earlier, later)` — the full side-by-side. `compare()` answers
  "what regressed"; this answers "I changed something, did it work?", so every
  rule is on the table. A rule present in only one run is classified
  added-or-removed rather than scored as a regression, because the rule set moved.
- `build_assurance()` — the portfolio roll-up behind the dashboard (see §5).

**`ScheduledRun`** (model + `apps/emulations/scheduling.py`) — cadence maths:
`next_after()` and an `advance()` that keeps cadence phase and catches up without
bursting. The Beat task `run_scheduled_emulations` is registered every 15 minutes
in `CELERY_BEAT_SCHEDULE`, mirrors the deploy path, and respects
one-active-stack.

```
GET  /api/emulations/coverage-trend/?emulation_type=<type>
GET  /api/emulations/<run_id>/regressions/
GET  /api/emulations/assurance/
CRUD /api/emulations/schedules/
```

**Frontend:** `CoverageHistory.tsx` (regression banner + trend bars) on the run
coverage page, `ScheduleControl.tsx` in the emulation overview's Detection
Readiness card, `SchedulesPage.tsx` under Operations.

**What needs the worker + AWS:** the Beat task fires real deploy/attack/destroy,
so schedules only execute where Celery Beat, Redis and AWS are live. The
selection and advance logic and the whole analytics layer are unit-tested without
any of that. **Regression alerts are currently pull-only** — a banner. Push
(Slack / email / Jira) is the obvious next feature and no notification plumbing
exists yet.

---

## 3. Evidence packet + run comparison (`apps/emulations/reporting.py`)

`/reports` was a `ComingSoon` stub in the sidebar while the product promised "a
signed evidence packet" as the deliverable of every run. This is that packet.

- `build_report(run, entry, previous_run, trend_points)` is a **pure assembly
  over data already stored** — verdicts from the run's `detection_check`, the
  change report from `coverage_history`, technique metadata from the registry. It
  is an assembly, never a second opinion, so **a report cannot disagree with the
  run page it came from**.
- `GET /api/emulations/<run_id>/report/` and `GET /api/emulations/compare/?a=&b=`.
  The compare view normalises argument order by completion time, so passing the
  runs the wrong way round still reads correctly; 400 on missing, identical or
  non-UUID ids, 404 on a run the caller does not own.

**The honest part, which is the whole point.** `reporting._uncovered()` lists
techniques the campaign declares in its attack path that **no rule in the pack
looks for**, reported *separately* from rules that ran and stayed silent —
because those are different failures. One is the customer's detection gap; the
other is ours. For AMBERSQUID that is `T1204.003` and `T1496`, and the report
says so in as many words: *"This is a gap in MayaTrail's content, not in your
detection stack."* Coverage is always stated as "n of m rules evaluated", never
as a bare score, and the page says outright that uncovered techniques are
excluded from it.

**Frontend:** `components/reports/` — `ReportsPage` (run list, tick two to
compare), `RunReportPage` (the packet), `RunComparePage` (headline sentence, both
runs' figures, delta in points, verdict-change table), and `reportHelpers.tsx`,
which owns the verdict vocabulary and follows the global UI mode so a report
words a verdict exactly as the coverage page does. Export is **print / save PDF**
(a `@media print` block drops the app chrome and prints on white) and
**download JSON**.

Route order: `reports/compare` must be declared **before** `reports/:runId`, or
the param route swallows it.

---

## 4. Authoring — playbooks and detections

### `apps/playbooks` — user-authored playbooks

Model, 7 endpoints, owner-only writes, path-traversal validation on the fork
parameter, a 512 KB body cap.

- **Stored as Markdown, not HTML**, even though the editor is a rich-text
  surface. The shipped playbooks are Markdown, so a fork is lossless in and an
  export is lossless out (verified: fork AMBERSQUID, export, byte-identical to
  `emulations/ambersquid/PLAYBOOK.md`); every renderer already reads Markdown;
  and storing user HTML to render back is a stored-XSS surface.
- The editor is **block-based** — phases, steps, commands, decisions, notes —
  serialising to the exact `## Phase` / `#### Step N -` conventions the existing
  reader parses. All 46 shipped playbooks round-trip markdown → blocks → markdown
  with zero lost phases, steps or commands. Decisions are If/Then rows rather
  than a node graph, because a branching canvas cannot round-trip with the
  shipped files.
- The reader reuses the **same parser and `PlaybookSection` component** as the
  shipped playbooks, so an authored playbook gets phase tabs, checkable steps and
  copyable commands like any other.
- Every new user is seeded two examples via a `post_save` signal — an annotated
  template and a real fork. Idempotent and best-effort: a user who has any
  playbook is skipped (so deleted examples never come back), and a seeding
  failure never costs a signup.
- **A near-miss worth remembering:** trimming unused toolbar code once removed
  the TipTap table extensions. ProseMirror **silently drops nodes its schema does
  not know**, and AMBERSQUID opens with a classification table — so opening that
  playbook would have deleted a table the author never touched. The schema is now
  deliberately wider than the toolbar. Don't "clean it up".

### `apps/authored_detections` — the writable counterpart to shipped rules

Write or AI-generate a Sigma rule, **validate whether it actually fires** against
synthetic CloudTrail events (reusing `apps/ai/detection_validation.py`), and
export it to a SIEM: generate → validate → export, in-product.

`AuthoredDetection` model + migration, CRUD, `generate/`, ad-hoc `validate/`,
saved `<id>/validate/` (stores `last_fidelity`), `<id>/export/`. Sigma is stored
as YAML so it validates, exports and renders through the existing paths.
Frontend: `DetectionStudioPage` at `/detections/studio/new` and `/:id`, plus a
"Your detections" shelf on `DetectionsHub`. 16 tests.

### Shared stance across both

**Reference URLs are cited, never fetched.** A backend holding an EC2 role
fetching user-supplied URLs is an SSRF primitive aimed at instance metadata —
the exact target SCARLETEEL goes after in this very catalogue. Pasted text is
fenced and labelled data-not-instructions. Generation never auto-publishes;
drafts carry review notes.

**Known smell, deliberately deferred:** the retry + `_complete` streaming helper
now exists in three places (`playbooks/generation.py`,
`authored_detections/generation.py`, `ai/detection_validation.py`). It should be
hoisted into `apps/ai/providers.py` as one `collect_stream(..., retries=)`; it
was left alone to avoid churning three working modules at once. Note the retry
was also added to the shared `detection_validation._complete`, which fixes the
pre-existing emulation detection-validator too — it previously had none.

---

## 5. Dashboard command center and the coverage score

`CommandCenter.tsx` answers "is my detection posture holding?" in one call to
`GET /api/emulations/assurance/`.

**The headline percentage is `fired ÷ ruleCount`. No weighting, no model, no
invented score.** It is computed in `coverage_history.build_assurance()` and
accumulated across **the latest completed run of each emulation** (grouped by
`emulation_type`, sorted by `completed_at`, only runs whose
`detection_check.status == "ok"`), so it reads as current posture, not a lifetime
average.

Per-run figures come from `detection_check.py`, where every rule with Sigma text
lands in exactly one verdict:

| Verdict | Meaning | Numerator | Denominator |
|---|---|---|---|
| `fired` | Rule matched real logged activity | ✅ | ✅ |
| `silent` | Activity happened, rule did not catch it — the customer's gap | — | ✅ |
| `no_logs` | Rule could not be judged; telemetry missing | — | ✅ |

`no_logs` therefore **drags the number down**, intentionally: a rule you cannot
judge is not coverage.

The UI states it two ways, always together — the plain sentence *"Your defences
caught N% of the attacks we simulated"* and, under it, the denominator: *"{fired}
of {total} checks fired across your latest test of {emulationsScored} attacks."*
A `postureWord()` band (≥85% Strong, ≥60% Holding, ≥40% Patchy, else Weak) drives
the gauge colour only; it feeds nothing back.

**Two caveats that must survive any rewrite:**

1. **Techniques with no rule at all are excluded from the denominator** — they
   never enter `ruleCount`, so a missing rule cannot lower the score. The
   evidence report lists them separately for exactly this reason; the dashboard
   gauge does not yet carry that caveat.
2. **Never render it as a bare score.** Coverage is always "n of m rules
   evaluated". That phrasing is the product argument, not house style.

One naming collision to be aware of: `snapshot()` and the trend chart call this
same ratio **`fidelity`**, while the dashboard calls it **`pct`**. Same formula,
two names. (`readiness.py` is unrelated to both — it is the deploy-time health
probe.)

---

## 6. Plain-language UI mode (`context/UiModeContext.tsx`)

A global Technical/Simple toggle, stored at `mt:ui-mode`, **defaulting to
`classic`**. Classic is byte-identical to the previous UI, so this ships safely
and rolls back by toggle rather than by revert. Every changed surface is gated on
Simple mode. The switch lives in the sidebar footer and the dashboard header,
kept in sync.

Shipped under it: the command-center dashboard, a plain-language vocabulary
layer, a nav IA collapse into five groups (Overview / Run / Coverage / Library /
Settings, children expanding only inside a group), consistent KPI drill-down cues
on `MetricCard`, a de-densified `PlatformHealth`, and named dashboard bands.

A real bug was fixed on the way: `UiModeContext.toggle` read `localStorage`
instead of current state, so it stuck on one mode where storage is blocked.

**Not yet reviewed in a browser by anyone.** `tsc -b` and `npm run build` are
clean and the API was smoke-tested on seeded data, but treat the visuals as
unverified.

---

## 7. Also included

- **Gemini** added to the AI connector via its OpenAI-compatible endpoint
  (`apps/ai`), which makes AI drafting usable on a free key. Saving a connector
  requires `LLM_FERNET_KEY` in the environment — it encrypts the stored key; Test
  passes without it, Save 503s.
- **Run recordings** — `manage.py export_run_recording <run_id>` turns a real run
  into a replayable recording for the marketing site's run page. **Allowlist, not
  scrub:** every field is constructed by name, no CloudTrail dict is ever copied,
  so an event carries exactly `{eventSource, eventName, t_offset_s}`. Account
  ids, ARNs, session names, source IPs and request parameters have no path out.
  Three independent checks guard the boundary. Two narrow exemptions, each
  justified: AWS-managed policy ARNs and non-routable IPs (169.254.169.254 is
  IMDS).

---

## Merging this

**Base:** `d95a669` (PR #68, 2026-09-03). `main` has moved on since — PR #69
(playbooks-as-doc + connector revamp), #70 (threat intel), #72 (emulations
workflow).

This work is **overwhelmingly additive**: two new Django apps, seven new modules
under `apps/emulations`, and ~30 new frontend files, none of which exist on
`main`. The overlap is small and concentrated in registration points:

- `backend/apps/emulations/urls.py`, `views.py`, `tasks.py` — new routes and
  views alongside `main`'s new `library/` routes. **`main`'s `library.py` and its
  three `PlaybookLibrary*` routes do not exist in this tree and must not be lost
  in the merge.**
- `backend/config/urls.py`, `settings/base.py`, `settings/ci.py` — app
  registration.
- `frontend/UI/src/App.tsx`, `Sidebar.tsx` — routes and nav entries.
- `PlaybooksHub.tsx` — needs real reconciliation, not a mechanical merge:
  `main` now has playbooks-as-documentation, and this tree adds user-authored
  playbooks. They are different features that share a hub.

**Do not merge by overwriting files.** Apply the additions onto current `main`.

**Green before pushing:** backend 229 passing, detection validator 87/87,
`npx tsc -b` and `npm run build` clean. Two pre-existing UI lint rules fire
codebase-wide (`tailwindcss/no-arbitrary-value`, the `font-display font-[800]`
page-header idiom) and are not from this work.
