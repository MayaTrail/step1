# Attack Graph (Scout Integration) — Design Spec

Date: 2026-09-21
Branch: `feat/scout-integration`
Status: Approved for planning

## Goal

Give MayaTrail users a native "Attack Graph" tab that runs a read-only IAM
privilege-escalation scan against their connected AWS account (via
[mayatrail-scout](https://github.com/MayaTrail/scout), the standalone Scout
engine) and renders the top ranked attack chains as an interactive graph,
styled to match the rest of the product rather than looking like an embedded
third-party tool.

v1 scope is deliberately narrow: trigger a scan on demand, compute chains
with Scout's `effective` evaluator, and render them. No resource collection,
no SCP/RCP org-policy awareness, no iamspy, no auto-scheduling, no
chain-to-guardrail or chain-to-emulation linking. Those are explicit
non-goals for this iteration, revisited once v1 ships.

## Why

MayaTrail's product goals (`project_goal.txt`) include "graphical
representation of attack emulation" and "guardrails to block threat actors."
Scout already solves the IAM-privesc-graph half of that (identity graph,
ranked attack chains, SCP/RCP-aware evaluation) as a separate, independently
maintained tool. Rather than reimplementing that inside MayaTrail, this
spec integrates Scout as a backend dependency behind a MayaTrail-native UI.

## Non-goals (v1)

- AWS Organizations SCP/RCP fetch (evaluator still runs, just without org
  policies applied — permission boundaries from the GAAD itself still are).
- iamspy/Z3 evaluator tier (confirmed installable on Python 3.14 in a
  standalone test, but not proven end-to-end against a real GAAD; deferred
  to a later iteration once needed).
- Resource collection, Access Advisor, GuardDuty, Access Analyzer inputs.
- Linking a chain to a specific emulation or guardrail suggestion.
- Multi-account scanning (the connectors app supports exactly one connected
  role per user today; this spec doesn't change that).

## Architecture

A new isolated Django app, `apps/attack_graph`, following the same shape as
`emulations`/`infrastructure`: one model, one Celery task, two views. On the
frontend: one new Sidebar entry under "Security Content", one new route, one
Hub-style page, and one graph component structurally cloned from
`InfraGraphView.tsx`'s dagre+SVG approach.

```
User clicks "Run Scan" (Attack Graph page)
  -> POST /api/attack-graph/scan/                [ScoutScanTriggerView]
       -> creates ScoutScan(status="pending")
       -> attack_graph.tasks.run_scout_scan.delay(scan_id)   [queue="enterprise"]
       -> returns 202 { scan_id }
  -> frontend polls GET /api/attack-graph/scan/<id>/         [ScoutScanDetailView]
  -> frontend lists GET /api/attack-graph/scan/              [ScoutScanListView, history]

Celery task (run_scout_scan):
  1. creds = _assume_user_role(user)            # reused from emulations/tasks.py
  2. session = boto3.Session(**creds)
  3. gaad, account_id, collection = scout.aws.collect.gaad.collect(session.client)
  4. report, graph = scout.pipeline.run(
         gaad=gaad, account_id=account_id,
         evaluator=EffectivePermissionEvaluator(...),
     )
  5. top_chains = report["chains"][:25]          # already ranked by chains.py
  6. ScoutScan.objects.filter(id=scan_id).update(
         status="succeeded", result=top_chains, completed_at=now(),
     )
```

On any exception in steps 1-5, the task catches it, sets
`status="failed"`, and stores a human-readable `error_message` (mirrors how
`deploy_emulation_stack` handles failures today).

## Backend components

### `ScoutScan` model (`apps/attack_graph/models.py`)

| field | type | notes |
|---|---|---|
| `id` | UUID/PK | |
| `user` | FK to User | who triggered the scan |
| `status` | CharField, enum | `pending` / `running` / `succeeded` / `failed` — same shape as `EmulationRun.status` |
| `result` | JSONField, nullable | the top-N ranked chains; small (no resource data collected) |
| `error_message` | TextField, blank | populated on failure |
| `created_at` | DateTimeField(auto_now_add) | |
| `completed_at` | DateTimeField, nullable | set when the task reaches a terminal status |

History is kept: every scan is its own row, listed newest-first (mirrors
`EmulationRunListView`). No latest-only overwrite.

### Credential path

No new AssumeRole code. `_assume_user_role(user)` already exists in
`backend/apps/emulations/tasks.py:173` and returns
`{AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN}` from an STS
AssumeRole against the user's stored `aws_role_arn`. The implementation
plan will decide whether to import it directly or lift it into a small
shared helper (e.g. `apps/connectors/aws.py`) — a duplication-vs-coupling
call left to planning, not architecturally significant.

### GAAD collection

`scout.aws.collect.gaad.collect(session.client, self_only=False)` —
confirmed to take a `ClientFactory`, which a plain
`boto3.Session(...).client` bound method satisfies directly. No Scout CLI
profile files, no subprocess.

Required permissions on the connected role: `iam:GetAccountAuthorizationDetails`,
`sts:GetCallerIdentity`. If the role lacks account-wide IAM read, `collect()`
**automatically falls back** to `self_enum.synthesize_gaad()` — a
self-scoped enumeration of the caller's own identity — rather than hard
failing. The task does not need to special-case this; Scout already
degrades gracefully. The `collection` dict returned (`{"mode":
"account"|"self", ...}`) should be surfaced in the scan result so the
frontend can show the user which mode ran (e.g. a small "self-scoped scan —
grant broader IAM read for a full account view" notice).

### Evaluator

`EffectivePermissionEvaluator` — `scout.pipeline.run()`'s own default.
No AWS Organizations policy fetch in v1 (see Non-goals).

### Dependency

Add `mayatrail-scout[aws]` to `backend/requirements.txt`, pinned to a
specific version/commit. Core Scout is stdlib-only; the `aws` extra adds
`boto3`, which is already a direct dependency of step1's backend.

## API surface (`apps/attack_graph/urls.py`)

| method | path | view | purpose |
|---|---|---|---|
| POST | `/api/attack-graph/scan/` | `ScoutScanTriggerView` | kick off a new scan, 202 + `scan_id` |
| GET | `/api/attack-graph/scan/` | `ScoutScanListView` | history, newest-first |
| GET | `/api/attack-graph/scan/<id>/` | `ScoutScanDetailView` | status + result (for polling and for viewing a past scan) |

All views `IsAuthenticated`, scoped to `request.user`'s own scans.

## Frontend components

- **Sidebar** (`components/layout/Sidebar.tsx`): one new `NavItem` under the
  "Security Content" section, label **"Attack Graph"**, route
  `/attack-graph`. (User-facing label deliberately avoids the "Scout" engine
  name — see Naming below.)
- **Route** (`App.tsx`): `<Route path="attack-graph" element={<AttackGraphHub />} />`.
- **`AttackGraphHub.tsx`** (new, `components/attack-graph/`) — Hub-page
  header (eyebrow + title, same pattern as `EmulationsHub`), gated by the
  existing `useAWSConnection`/`ConnectGate` hook, a "Run Scan" button, a
  scan-history strip (status + timestamp per past `ScoutScan`, click to
  view), and the graph for the selected/latest scan. Uses `ComingSoon`
  styling for the zero-scans-yet state (matches the "honest placeholder"
  convention already used elsewhere).
- **`AttackChainGraph.tsx`** (new) — structurally a clone of
  `InfraGraphView.tsx`: `dagre` layout, hand-rolled SVG nodes/edges,
  category-colored node cards (identity/role/resource, reusing the existing
  `net/compute/data/iam/other` palette where it maps — `iam` amber for
  identity nodes), arrow-marker edges highlighting on selection, click-to-open
  detail side panel (mirrors `DetailPanel`'s pattern, here showing the chain
  step's technique/condition detail from Scout's chain data), legend, empty
  state.
- **Polling** — a small hook for scan-status polling; the implementation
  plan will confirm and reuse whatever existing hook pattern
  `EmulationDeployView`'s frontend consumer already uses, rather than
  inventing a new one.

## Naming

User-facing label: **"Attack Graph"**. Internal code (Django app name,
model name, Python package) keeps the `scout`/`attack_graph` naming — only
the label a user sees changes. This matches the existing nav convention
(plain descriptive words: Emulations, Detections, Guardrails — not tool
brand names).

## Data flow diagram

```
[MayaTrail user] --click "Run Scan"--> [AttackGraphHub]
      |
      v
[POST /api/attack-graph/scan/] --> [ScoutScan row: pending] --> [Celery: enterprise queue]
      |                                                              |
      |                                                    _assume_user_role(user)
      |                                                              |
      |                                                    boto3.Session(**creds)
      |                                                              |
      |                                                    scout.aws.collect.gaad.collect(session.client)
      |                                                              |
      |                                                    scout.pipeline.run(gaad=..., evaluator=effective)
      |                                                              |
      |                                                    ScoutScan row: succeeded, result=top_chains
      v                                                              |
[GET /api/attack-graph/scan/<id>/] <----------------------------------
      |
      v
[AttackChainGraph renders result]
```

## Error handling

- **STS AssumeRole failure** (expired/revoked role) — task catches, sets
  `status=failed`, `error_message` from the botocore exception (same pattern
  `AWSConnectorView` already uses for surfacing STS errors).
- **IAM read access denied** — handled by Scout's own fallback to
  self-scoped enumeration (see GAAD collection above); not a task failure.
- **Empty result** (zero chains found — a well-locked-down account) — not an
  error; the frontend shows a positive empty state ("no privilege-escalation
  paths found in this scan"), not `ComingSoon`.
- **Celery task never completes** (worker crash) — out of scope for v1;
  same exposure the existing `emulations` tasks already have, no new
  mitigation invented here.

## Testing

- Backend: model + view tests fully offline, mocking `collect()` and
  `pipeline.run()` — matches how `emulations` tests mock Pulumi/boto3, and
  Scout's own test suite is fully offline too, so fixtures are easy to
  share/adapt from `scout/tests/fixtures/`.
- Frontend: a component test for `AttackChainGraph` given a fixed
  chain-JSON fixture, asserting layout/node/edge counts — same pattern as
  any existing graph/list component test in this repo.
- No live-AWS test in CI, matching the repo's existing convention of
  skipping live tests by default.

## Open items for the implementation plan (not blocking this spec)

- Exact shared-helper vs. import decision for `_assume_user_role`.
- Exact polling hook to reuse from the emulations frontend flow.
- Whether `ScoutScan.result` needs a max-size guard (unlikely at 25 chains,
  but worth a sanity check against a real large-account scan once available).
