# Scout Integration — Attack Graph

Branch: `feat/scout-integration`
Plan: `docs/superpowers/plans/2026-09-21-attack-graph-integration.md`
Design spec: `docs/superpowers/specs/2026-09-21-attack-graph-integration-design.md`

This document records what was built, in what order, and what still needs
attention before this ships. It is a companion to the plan file above, not a
replacement for it — the plan has the full task-by-task detail (files,
interfaces, TDD steps); this is the narrative summary plus the gaps found
while verifying against a real AWS account.

## What this feature is

A read-only "Attack Graph" page that runs an IAM privilege-escalation scan
(via the `mayatrail-scout` engine) against a **second, separate AWS role** —
the "Scout audit role" — and renders the ranked attack chains as a graph.

It is deliberately a second connection, not a reuse of the existing emulation
role:

- The **emulation role** (`aws_role_arn`) grants the writes emulations need.
- The **Scout audit role** (`aws_audit_role_arn`) grants exactly one read:
  `iam:GetAccountAuthorizationDetails`.

A security team can grant, review, and revoke the audit role independently of
the emulation connection. Connecting one does not require or affect the
other.

## Architecture

```
Django REST API ──> Celery (queue: enterprise) ──> Scout (in-process, boto3)
      │
      └── apps/attack_graph/  (new, isolated Django app)
            constants.py   timing constants shared by tasks.py and models.py
            models.py      ScoutScan, active_scans() — "is a scan in flight"
            envelope.py    pure serialize_scan()/result_state() — no boto3/DRF
            tasks.py       run_scout_scan — orchestration only, no decisions
            permissions.py HasScoutConnection
            views.py/urls.py/serializers.py   3 endpoints
```

Every security-relevant decision (what counts as a "clean" result, what
"partial" means, which evaluator ran) lives in `envelope.py`, a pure module
with no boto3/Scout/DRF imports — CI can import and test it directly even
though DRF and boto3 are not installed in CI (`config/settings/ci.py`).

`ScoutScan` never stores Scout's own objects. `tasks.py` serializes Scout's
report into a versioned envelope (`envelope.serialize_scan`) before it ever
reaches the database or the frontend — Scout is maintained in a separate
repository and its internal shape is not a contract this product can be held
to.

## What was built, in order

### Phase 1 — the Scout audit connection

| Commit | What |
|---|---|
| `2e6bb87` | Design spec written and reviewed first |
| `8f9c6db` | **Task 1** — Scout dependency spike: installed `mayatrail-scout[aws]` in a throwaway Python 3.12 venv, ran it against Scout's own offline fixtures, recorded the real `collect()`/`pipeline.run()` signatures and chain/step field names in the spec, saved a real (not hand-written) fixture at `backend/apps/attack_graph/tests/fixtures/scout_report.json`, pinned the dependency by commit SHA in `requirements.txt` |
| `1bbc08d` | **Task 2** — `apps/connectors/aws.py`: one shared `assume_role_arn()` / `probe_account_authorization_details()` helper. `apps/emulations/tasks.py`'s `_assume_user_role` now delegates to it instead of calling `sts.assume_role` directly — a source-scan test (`test_credentials.py`) asserts only this one file ever calls `.assume_role(` |
| `c0bb555` | **Task 3** — `User.aws_audit_role_arn` field, exposed on `GET /api/auth/me/` |
| `e82679e` | **Task 4** — `AWSAuditConnectorView` (`POST`/`DELETE /api/connectors/aws/audit/`): assumes the role, then **probes** `iam:GetAccountAuthorizationDetails` before saving — a role that's merely assumable but can't read IAM would otherwise produce a scan that finds nothing and reads as a clean account. Also refuses to connect an audit role in a different AWS account than the connected emulation role |
| `2437dee` | **Task 5** — Frontend: `hasAuditRole` on `User`, `useScoutConnection()` hook, `ConnectScoutRoleDialog`, a second "Scout Audit Role" card on the Profile page, `ConnectPrompt`'s `cta` made overridable so the Attack Graph page can point at the audit-role dialog instead of the emulation one |

Phase 1 is independently mergeable but not independently releasable — shipped
alone, the profile advertises a connection nothing consumes yet.

### Phase 2 — the `attack_graph` backend

| Commit | What |
|---|---|
| `05f7ea0` | **Task 6** — the `attack_graph` Django app, `ScoutScan` model (status vocabulary matches `EmulationRun`'s: `pending`/`running`/`completed`/`failed`), `active_scans()` — the one definition of "a scan is in flight," shared by the 409 guards on both the disconnect endpoint and the scan trigger. `SCAN_STALE_AFTER_SECONDS` survives a worker crash (Celery's hard `time_limit` kills the process outright, so a crashed scan never reaches a terminal status on its own) |
| `2dce30a` | **Task 7** — `envelope.py`: `serialize_scan()` and `result_state()`. A **self-scoped scan is never reported clean** — `collection["mode"] == "self"` forces `state: "partial"`, because a role that can only see itself finding no escalation paths says nothing about the rest of the account |
| `c610ce1` | **Task 8** — three `LogEntry.Event` members (`SCAN_STARTED`/`SCAN_COMPLETED`/`SCAN_FAILED`) so scans show up in the existing activity trail |
| `e93de9c` | **Task 9** — `run_scout_scan` Celery task on the `enterprise` queue: assumes the audit role, calls `gaad.collect()`, runs `pipeline.run()`, serializes the result. **Shipped with a bug** — see "Bug found and fixed" below |
| `6199159` | **Task 10** — the three endpoints (trigger / status / list), gated on `HasScoutConnection` |

### Phase 3 — the `attack_graph` frontend

| Commit | What |
|---|---|
| `2318e46` | **Task 11–12** — `attackGraph.service.ts` (3 API calls), `attackGraph.ts` types mirroring `envelope.py`, `chainGraph.ts` (envelope → `{nodes, edges}`, pure, no React — written this way so a test runner can be added later without touching the component) |
| `6909176` | **Task 13** — `AttackChainGraph.tsx`: dagre layout + SVG rendering |
| `d497745` | **Task 14/15** — `AttackGraphHub.tsx` (page, gating, polling, the honest result states below), route + sidebar nav entry (`IconBroadcast`, labeled "Attack Graph" — never "Scout," which means nothing to a user) |

### Post-merge fix

| Commit | What |
|---|---|
| `b47d15a` | `run_scout_scan` called `EffectivePermissionEvaluator()` with no arguments; that class requires an `AccountModel` that only `pipeline.run()` builds internally. Every real scan crashed. Fixed by passing `evaluator=None` and letting `pipeline.run()` build its own default evaluator, which is the same class. Found by running a real scan end to end — see below |

## The four result states the page must get right

This is the part of the design the plan calls out as the actual point of the
feature, so it's worth restating here:

| `state` | `mode` | Meaning | UI must show |
|---|---|---|---|
| `findings` | `account` | Real chains found, full account read | the graph, chains, SCP caveat line |
| `clean` | `account` | No chains, full account read | positive copy, no warning styling |
| `partial` | `self` | Audit role can only see itself (missing `iam:GetAccountAuthorizationDetails`) | **warning** styling, names the missing permission, reconnect link |
| `partial` | `unknown` | Scout didn't report how much it could read | **warning** styling, generic "not treated as complete" copy, **no** reconnect link, **no** claim about a specific permission |

The two `partial` rows must never render as `clean`, and must not be
confused with each other — `self` names a fixable cause and offers a fix;
`unknown` doesn't invent one. This was verified by hand against a real
account (below) and both render correctly.

## Bug found and fixed (post-merge)

`run_scout_scan` (Task 9) constructed the evaluator itself:

```python
from scout.eval.effective import EffectivePermissionEvaluator
...
report, _graph = pipeline.run(gaad=raw_gaad, account_id=account_id,
                               evaluator=EffectivePermissionEvaluator())
```

`EffectivePermissionEvaluator.__init__(self, model: AccountModel)` requires
the model Scout builds internally from the GAAD collection — `tasks.py` has
no way to construct one before calling `pipeline.run()`. Every real scan
raised `TypeError: EffectivePermissionEvaluator.__init__() missing 1
required positional argument: 'model'`, caught by the task's own
`except Exception`, and silently surfaced to the user as "The scan failed
unexpectedly."

Fix: pass `evaluator=None`. `pipeline.run()`'s own default already resolves
to `EffectivePermissionEvaluator(model)` internally (confirmed in Task 1's
spike and asserted in `envelope.py`'s `EVALUATOR = "effective"` literal) — so
the task doesn't need to build one at all. See commit `b47d15a`.

This shipped in the original Task 9 commit and was **not** caught by the
existing test suite, because no test in this plan can import `boto3`/`scout`
(CI has neither installed) — it can only be caught by actually running a
scan. That's exactly what Task 9 Step 5 / Task 10 Step 8 / Task 15 Step 5 in
the plan call for ("verify against a real account"), and is how this was
found.

## Verified against a real AWS account

Account `940482414561`, role `scout-security-audit` (managed policy
`SecurityAudit` attached), platform identity `user/mayatrail`.

- **Trust policy**: the role's trust policy only allowed `user/admin`; the
  backend actually runs as `user/mayatrail`. Updated the trust policy to add
  `user/mayatrail` as a trusted principal (real AWS change, done with
  explicit confirmation).
- **Connect flow** (Task 4/5): happy path (200), probe rejection with the
  policy detached (422 naming the missing action), short `MaxSessionDuration`
  (see correction below), cross-account refusal, persistence across
  sign-out/sign-in — all pass.
- **Scan flow** (Task 9/10/15, after the evaluator fix): queued → scanning →
  completed with real ranked chains; failed state with a generic message
  (not a raw traceback); `partial`/`self` and `partial`/`unknown` both render
  correctly and distinctly; unconnected state says "Connect a Scout audit
  role," not "Connect AWS account"; scan history switching works.
- Not exercised: the `clean` result (this test account has real IAM roles,
  not a locked-down one) and the staleness escape hatch (Task 9 Step 5's
  "kill the worker mid-scan" scenario).

### Correction to the plan

Task 4 Step 7 says to set the role's `MaxSessionDuration` to "900 (the AWS
console's minimum)" to verify a short-session role still connects. The real
IAM API minimum for `MaxSessionDuration` is **3600 seconds**; `900` is only
the minimum for an individual `AssumeRole` call's `DurationSeconds`, which is
always legal regardless of the role's cap. Verified against 3600 (the true
floor) instead — the point of the test (a tight cap doesn't block the
connector's 900s verify request) still holds, since no legally configured
role can have a smaller cap.

## Known gaps / not yet done

- **CI/Docker build cannot install `mayatrail-scout` without a GitHub
  credential.** It's a private repo pinned by commit SHA
  (`backend/requirements.txt`). `backend/Dockerfile` and
  `backend/Dockerfile.worker` already document the `--secret
  id=github_token` build invocation needed, but **`.github/workflows/
  backend-tests.yml`'s install step and any CI image build still need that
  secret wired in** — this was not done as part of this branch. Local
  verification in this session worked around it by copying the package from
  a venv where it was already installed directly into the running
  containers, which is not a substitute for a real image build.
- **Task 14 (optional frontend test runner)** was explicitly skipped per the
  plan — it's a repo-wide decision (there are currently zero `.test.tsx`
  files anywhere), not specific to this feature.
- **The staleness escape hatch** (a scan stuck at `running` after a worker
  crash, and the `SCAN_STALE_AFTER_SECONDS` cutoff that recovers from it) is
  covered by unit tests but was not exercised by actually killing a worker
  mid-scan against a real account.
- **The `clean` result state** was not observed against a real account in
  this session (would need a genuinely locked-down test account).

## Local dev notes

- The worker container needs the exact same file set as the backend
  container — `apps/connectors/aws.py` (Task 2) is easy to miss if you're
  patching a running container by hand rather than rebuilding the image, and
  its absence crashes the worker at import time (Django loads
  `config.urls` → `connectors.urls` → `connectors.views` on worker startup
  too, not just in the API process).
- `apps/attack_graph`'s migration is `0001_initial.py`; `apps/logs` gained
  `0004_alter_logentry_event.py` for the three new `Event` members. Both
  must be applied (`python manage.py migrate`) before the endpoints will
  work — a missing migration surfaces as `ProgrammingError` at first use, not
  at Django boot.
