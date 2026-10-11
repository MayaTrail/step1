# Attack Graph (Scout Integration) — Design Spec

Date: 2026-09-21 (revised 2026-09-21 after design review)
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

Two things are **not** negotiable inside that narrow scope. Scout gets its own
connection — a dedicated read-only auditor role the org provisions for it,
separate from the emulation role — rather than widening what MayaTrail asks
for the emulation role. And a scan that could not read the account must never
look like a scan that found nothing. See
[The Scout audit connection](#the-scout-audit-connection) and
[Scan fidelity](#scan-fidelity).

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
  A chain we report may in fact be blocked by an SCP we never fetched, so the
  UI states that caveat rather than implying the chains are confirmed
  exploitable.
- iamspy/Z3 evaluator tier (deferred to a later iteration once needed).
- Resource collection, Access Advisor, GuardDuty, Access Analyzer inputs.
- Linking a chain to a specific emulation or guardrail suggestion.
- Multi-account scanning (the connectors app supports exactly one connected
  role per user today — `User.aws_role_arn`, `apps/users/models.py:38`; this
  spec doesn't change that).

## The Scout audit connection

The obvious way to give Scout the IAM read it needs is to add
`iam:GetAccountAuthorizationDetails` to the policy MayaTrail already asks
users to attach (`SCOPED_POLICY`,
`frontend/UI/src/components/profile/ConnectCloudDialog.tsx:32-67`). This spec
deliberately does **not** do that. That policy's own comment frames it as
least-privilege *by action* over what the emulation catalogue calls, every
action in it is a write the emulations need, and account-wide IAM read is a
different kind of ask — one a security team should be able to review, grant
and revoke on its own terms. Folding it in would also silently widen the
grant for every existing tenant at their next re-connect.

Instead Scout gets its own connection. `SCOPED_POLICY` is untouched by this
work.

### Shape

A second, independent role ARN, stored alongside the first:

| | emulation role | **Scout audit role** |
|---|---|---|
| user field | `aws_role_arn` | `aws_audit_role_arn` |
| grants | write actions the emulations perform | read-only: `iam:GetAccountAuthorizationDetails` |
| verified by | STS AssumeRole (`AWSConnectorView`) | STS AssumeRole **plus a capability probe** |
| gates | every mutating endpoint (`HasAWSConnection`) | the Attack Graph scan (`HasScoutConnection`) |
| required for a scan | no | **yes** |

An org provisions this as its security-auditor role: a role trusting the same
MayaTrail principal, carrying one read action. The connect dialog leads with
that minimal inline policy, and offers the AWS managed `SecurityAudit` policy
as an alternative for orgs that standardise on it — without claiming in copy
what `SecurityAudit` contains, because the probe below is the real contract.

### Verification probes the permission, not just the trust

`AWSAuditConnectorView` assumes the role and then, with the returned
credentials, calls `iam:GetAccountAuthorizationDetails` with `MaxItems=1`
(and `Filter=["User"]` to keep it cheap). Only if that call succeeds is the
ARN stored. A role that is assumable but cannot read IAM is rejected at
connect time, with a message naming the missing action — the failure lands on
the person pasting the ARN, who can fix it, rather than on a scan result
someone reads as an all-clear three weeks later.

Requiring the audit connection removes most of the false-all-clear exposure
by construction: a user with no audit role never gets a scan at all, they get
a connect prompt. What it cannot remove is drift — the permission can be
revoked after connect time — so the run-time rule below still stands.

### Interactions between the two connections

- Disconnecting the **emulation** role (`DELETE /api/connectors/aws/verify/`)
  leaves `aws_audit_role_arn` alone. They are separate grants; dropping one
  because the other went away would be surprising, and Scout is read-only.
- Disconnecting the **audit** role is refused with 409 while the user has a
  `pending` or `running` scan *that was created recently enough to still be
  executing*, mirroring the in-flight-stack guard the emulation disconnect
  already uses (`connectors/views.py:25-33`). The age bound is not optional:
  Celery's hard `time_limit` kills the worker process, so a crashed scan
  never reaches a terminal status, and a status-only guard would refuse both
  this disconnect and every future scan permanently, with nothing in the UI
  able to clear it. The emulation guard has no equivalent problem because a
  stack can be moved out of an in-flight status by a refresh; a `ScoutScan`
  cannot. One helper, `attack_graph.models.active_scans`, defines it for both
  call sites.
- The audit endpoint does **not** touch `is_verified` or `is_demo`. The
  emulation verify sets `is_demo = False` as a side effect of proving account
  ownership for writes; connecting a read-only role proves nothing about
  writes and must not silently end a demo.

## Scan fidelity

`scout.aws.collect.gaad.collect()` falls back to a self-scoped enumeration
(`self_enum.synthesize_gaad()`) when the caller lacks account-wide IAM read.
A self-scoped GAAD holds one principal, so it yields approximately no edges,
so the pipeline returns zero chains. Rendered through a naive empty state,
that reads to the user as **"your account has no privilege-escalation
paths"** — a false all-clear from a security product.

The audit connection makes that the exception rather than the default, but it
does not make it impossible: the role's policy can be narrowed or detached
after it was verified. So the run-time rule holds regardless of what the
connect-time probe saw — **never render self-scoped as the clean empty
state**. The states are visually and textually distinct:

| condition | state |
|---|---|
| `mode == "account"`, zero chains | positive result — "no privilege-escalation paths found in this account" |
| `mode == "self"` | **warning** — "partial scan: Scout could only see the role it assumed" + a prompt to re-check the audit role's policy. Never the positive copy, even with zero chains. |
| any other `mode`, including none reported | **warning**, with the *generic* copy: the scan is not treated as complete, and no cause is named. See below. |
| `status == "failed"` | error state with `error_message` |

The classification is a whitelist — only `mode == "account"` earns a verdict —
so a mode a future Scout release invents lands on the cautious side without
the rule being edited. What must **not** happen is the reverse shortcut:
relabelling an absent or unrecognised mode as `"self"` to reuse the existing
copy. `"self"` is a diagnosis, and the UI turns it into advice ("your audit
role's policy no longer grants `iam:GetAccountAuthorizationDetails`"). Saying
that when Scout reported nothing at all asserts a cause the scan never
observed — the same failure as a false all-clear, one level up. So the
envelope carries the mode verbatim, or `"unknown"`, and the warning state
shows the diagnosis only for `"self"`.

The `mode == "account"` positive state also carries the SCP caveat from
Non-goals: chains are computed without organization policies applied.

## Architecture

A new isolated Django app, `apps/attack_graph`, following the same shape as
`emulations`/`infrastructure`: one model, one Celery task, three views. On
the frontend: one new Sidebar entry under "Security Content", one new route,
one Hub-style page, and one graph component structurally cloned from
`InfraGraphView.tsx`'s dagre+SVG approach.

```
User clicks "Run Scan" (Attack Graph page)
  -> POST /api/attack-graph/scan/                [ScoutScanTriggerView]
       -> 409 if this user already has a pending/running scan
       -> creates ScoutScan(status="pending")
       -> attack_graph.tasks.run_scout_scan.apply_async(queue="enterprise")
       -> stores task_id, returns 202 { scan_id }
  -> frontend polls GET /api/attack-graph/scan/<id>/         [ScoutScanDetailView]
  -> frontend lists GET /api/attack-graph/scan/list/         [ScoutScanListView, history]

Celery task (run_scout_scan), soft_time_limit=900, time_limit=960:
  0. status="running", started_at=now()
  1. creds = _assume_role_arn(user.aws_audit_role_arn,          # shared helper
            f"mayatrail-scout-{user.id}")
  2. session = boto3.Session(**creds)
  3. gaad, account_id, collection = scout.aws.collect.gaad.collect(session.client)
  4. report, graph = scout.pipeline.run(
         gaad=gaad, account_id=account_id,
         evaluator=EffectivePermissionEvaluator(...),
     )
  5. result = serialize_scan(report, collection, account_id)   # versioned envelope
  6. ScoutScan.objects.filter(id=scan_id).update(
         status="completed", result=result, completed_at=now(),
     )
     record_activity(Event.SCAN_COMPLETED, ..., actor=user)
```

Scout is imported **inside** the task function, not at module scope — see
[Dependency and packaging](#dependency-and-packaging).

On any exception in steps 1-5, the task catches it, sets `status="failed"`,
stores a human-readable `error_message`, and records `Event.SCAN_FAILED`
(mirrors how `deploy_emulation_stack` handles failures today).

## Backend components

### `ScoutScan` model (`apps/attack_graph/models.py`)

| field | type | notes |
|---|---|---|
| `id` | UUID/PK | `default=uuid.uuid4, editable=False`, as `EmulationRun` |
| `user` | FK to User, `CASCADE` | who triggered the scan. `CASCADE`, not `SET_NULL`: the Retention note below says these rows go with the user, and the task reads `scan.user` to resolve the audit role and to attribute the activity-trail entry — a null owner would be a scan that cannot run and an audit row nobody can see. |
| `status` | CharField, `TextChoices` | `pending` / `running` / `completed` / `failed` — **the same four values as `EmulationRun.Status`** (`apps/emulations/models.py:28-33`), not a near-miss synonym like `succeeded` |
| `task_id` | CharField, blank | Celery task id, as `Stack.task_id` — what you need when a scan hangs |
| `result` | JSONField, nullable | the versioned envelope below |
| `error_message` | TextField, blank | populated on failure |
| `created_at` | DateTimeField(auto_now_add) | |
| `started_at` | DateTimeField, nullable | set when the task begins, as `EmulationRun.started_at` |
| `completed_at` | DateTimeField, nullable | set when the task reaches a terminal status |

`Meta.ordering = ["-created_at"]`, `db_table = "scout_scans"`.

History is kept: every scan is its own row, listed newest-first (mirrors
`EmulationRunListView`). No latest-only overwrite.

**Retention.** `result` holds principal ARNs and the ranked paths between
them — a map of the tenant's weakest identities. It is stored unencrypted in
the application database, at the same sensitivity as the `Stack` outputs
already there, which is the accepted baseline rather than a new exposure.
`ScoutScan` rows are deleted with the user. History is otherwise unbounded in
v1 — a pruning rule is an open item below rather than an inline default,
because "delete the oldest" has to be specified carefully enough not to
delete a row someone is looking at.

### `result` envelope (the backend/frontend contract)

`report["chains"]` is Scout's internal shape and Scout is maintained
independently, so nothing in the frontend consumes it directly. The task
serializes into a versioned MayaTrail envelope, and `AttackChainGraph` reads
only this.

**Verified against `mayatrail-scout@0943023` (2026-09-21) — this replaces an
earlier, unverified guess at the shape below.** Scout does not use
`source`/`target` node objects or `steps[].from/to`; chains carry
`origin_identity_arn`/`terminal_target_arn` directly, and hops (not "steps")
carry `source_arn`/`target_arn`. There is no separate node-id space at all —
every identifier Scout emits, at every level, is an IAM ARN. That is simpler
than the spec feared, not harder: there is no id/ARN join to normalise.

```jsonc
{
  "schema_version": 1,
  "mode": "account" | "self",     // from collection["mode"] — drives the warning state
  "account_id": "123456789012",
  "scanned_at": "2026-09-21T10:04:00Z",
  "evaluator": "effective",       // records that SCPs were not applied
  "truncated": false,             // true when more than 25 chains were ranked
  "chains": [
    {
      "id": "chain-1",                // serializer-assigned: index+1, from report["chains"] order
      "rank": 1,                      // report["chains"] is already ranked descending by risk_score
      "score": 70,                    // chain["risk_score"], an int 0-100 in practice, not a float
      "source": { "arn": "arn:aws:iam::111122223333:user/ci-deploy", "label": "..." },
      "target": { "arn": "arn:aws:iam::111122223333:role/deploy-role", "label": "..." },
      "mitre_techniques": ["T1098.003"],   // chain-level list; Scout does not attach a technique per hop
      "steps": [
        {
          "from": "arn:aws:iam::111122223333:user/ci-deploy",
          "to": "arn:aws:iam::111122223333:role/deploy-role",
          "mechanism": "passrole_service", // Scout's own hop["mechanism"], e.g. "credential", "passrole_service"
          "action": "PassRole+lambda",     // Scout's own hop["action"]; free text, not an iam: action string
          "concrete_api_sequence": ["iam:PassRole(RoleArn=...)", "<lambda: launch compute executing as ...>"],
          "detail": "..."                  // one sentence for the detail panel, composed by the serializer
        }
      ]
    }
  ]
}
```

Field-by-field mapping from `report["chains"][n]` (Scout) to the envelope
(this backend), verified against the real output:

| envelope field | Scout source |
|---|---|
| `chains[].id` | assigned by the serializer (`chain-{index+1}`) — Scout's own `chain_id` (e.g. `"CHN-7540184B"`) is opaque and not guaranteed stable across scans, so it is not surfaced |
| `chains[].score` | `chain["risk_score"]` |
| `chains[].source.arn` | `chain["origin_identity_arn"]` |
| `chains[].target.arn` | `chain["terminal_target_arn"]` |
| `chains[].mitre_techniques` | `chain["mitre_techniques"]` (a list; MITRE technique IDs are per-chain, not per-hop) |
| `steps[]` | `chain["hops"]`, in `hop_number` order |
| `steps[].from` / `.to` | `hop["source_arn"]` / `hop["target_arn"]` |
| `steps[].mechanism` / `.action` | `hop["mechanism"]` / `hop["action"]` |

Two things the original guess got wrong in a way that changes what the UI can
show, not just field names:

- **There is no per-step `technique` or `condition` field.** The spec assumed
  the detail panel could show a technique per step; Scout only attaches
  `mitre_techniques` at the *chain* level. A per-hop "condition" field
  (Scout's evaluated condition detail) also does not exist on the hop shape
  observed here — `hop["conditional"]` exists as a field but was `null` on
  every hop in the fixture used, so its populated shape is still unconfirmed.
  Task 7's envelope must not invent a per-step technique; it renders
  `mitre_techniques` once, on the chain.
- **`source`/`target` carry no `type` or node-id.** Scout gives no node type
  (user/role/group/policy) or label anywhere in the chain — only ARNs. If
  `AttackChainGraph` wants a node type badge, Task 7 must derive it by parsing
  the ARN's resource segment (`:user/`, `:role/`, `:group/`) rather than
  reading it from Scout, since Scout does not provide one.

`schema_version` is asserted by the frontend, which renders an "update
required" notice rather than a broken graph if it ever sees a version
**newer** than it knows. Strictly newer: history is the reason scans are kept
as rows, so an equality check would put every stored scan behind that notice
the first time this number is bumped, deleting the comparison feature as a
side effect of a one-line backend change. A Scout upgrade that changes chain
shape therefore breaks one serializer function and its contract test, not the
UI.

`"evaluator"` names how the chains were computed. Verified: `pipeline.run()`
with `evaluator=None` (its default) constructs
`scout.eval.effective.EffectivePermissionEvaluator` internally — there is no
string name returned in the report itself, so the envelope's `"effective"`
literal is asserting something Scout does not state. The task still passes
`evaluator` explicitly rather than relying on the default, per the original
reasoning: an envelope that records which evaluator produced a security
finding must not be able to become false because a default changed upstream.

Nodes and steps are expressed in one identifier space with nothing to
reconcile: `hop["source_arn"]`/`hop["target_arn"]` and
`chain["origin_identity_arn"]`/`chain["terminal_target_arn"]` are all IAM
ARNs, verified to overlap exactly (every hop endpoint ARN in the sample
fixture also appears as a chain's origin or terminal ARN). The
id/ARN-mismatch risk this section originally worried about does not apply —
Scout never emits an opaque node id anywhere in the chain output. The
contract test still asserts consecutive hops join up (`hops[i].target_arn ==
hops[i+1].source_arn`), because that invariant is still worth defending even
though the identifier-space question itself is settled.

### Credential path

The scan assumes the **audit** role, not the emulation role.
`_assume_user_role(user)` (`backend/apps/emulations/tasks.py:173`) hardcodes
both `user.aws_role_arn` and the session name
`f"mayatrail-emulation-{user.id}"`, so it cannot serve this as written. It is
lifted into a parameterised helper both callers share, in a new
`apps/connectors/aws.py` — the credentials app, so the scan does not import
`emulations.tasks` and drag Pulumi into a read-only code path:

```python
def assume_role_arn(
    role_arn: str, session_name: str, duration_seconds: int = DEFAULT_SESSION_SECONDS,
) -> dict[str, str]:
    """STS AssumeRole -> {AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN}."""


def probe_account_authorization_details(creds: dict[str, str]) -> None:
    """Raise unless these credentials can read account-wide IAM."""
```

`duration_seconds` is a parameter, not a constant, because the two callers
need different answers. A task holds its credentials for its whole run, so
3600 (what `_assume_user_role` already asks for). A connect-time verify makes
one call and is done, and AWS rejects AssumeRole outright when
`DurationSeconds` exceeds the role's `MaxSessionDuration` — an org
provisioning a read-only auditor role being exactly the org that caps it. So
verification passes `VERIFY_SESSION_SECONDS = 900`, the AWS minimum, which is
what `AWSConnectorView` has always used for the same reason.

`_assume_user_role(user)` becomes a thin wrapper over the first, so no
existing caller changes, and the audit connector's connect-time probe uses the
second. The scan calls it with `user.aws_audit_role_arn` and
`f"mayatrail-scout-{user.id}"` — a distinct session name so the tenant's
CloudTrail separates read-only scan activity from emulation activity.

No region handling is needed: STS resolves globally and
`GetAccountAuthorizationDetails` is a global IAM call.

### GAAD collection

`scout.aws.collect.gaad.collect(session.client, self_only=False)`, taking a
`ClientFactory` that a plain `boto3.Session(...).client` bound method is
expected to satisfy directly. No Scout CLI profile files, no subprocess.

The audit role needs `iam:GetAccountAuthorizationDetails`, which the connect
probe already proved once (`sts:GetCallerIdentity` requires no permission at
all). If that grant has since been narrowed, `collect()` degrades to
self-scoped enumeration instead of raising; that is **not** treated as
success — see [Scan fidelity](#scan-fidelity). The `collection` dict's `mode`
is carried into the result envelope and drives the warning state.

### Evaluator

`EffectivePermissionEvaluator` — `scout.pipeline.run()`'s own default. No AWS
Organizations policy fetch in v1 (see Non-goals), which the result envelope
records as `"evaluator": "effective"` and the UI surfaces as the SCP caveat.

### Activity trail

`LogEntry.Event` is a closed enum (`apps/logs/models.py:32`), so three
members are added — `SCAN_STARTED = "scan.started"`,
`SCAN_COMPLETED = "scan.completed"`, `SCAN_FAILED = "scan.failed"` — and the
task writes them through `record_activity()` (`apps/logs/record.py:25`) with
`actor=user` and no `stack` (both FKs are nullable). Without the actor the
row is invisible to everyone, per that helper's own docstring.

## Dependency and packaging

### Distribution — decide before planning

`mayatrail-scout[aws]` must be pinned to a version or commit, and the plan
must state **where pip fetches it from**. `backend/Dockerfile:31` and
`backend/Dockerfile.worker:30` both run a bare
`pip install --no-cache-dir -r requirements.txt` with no credentials
available, and the CI job installs from `requirements-test.txt` on a runner
with no secrets. If `MayaTrail/scout` is a private repository, all three
break and one of these has to be chosen first:

- publish Scout to PyPI (or a private index, with a token plumbed into both
  Dockerfiles and CI);
- `git+https://...` with a deploy token, same plumbing;
- vendor the package into the repo.

This is a prerequisite, not an implementation detail.

**Decided 2026-09-21: option 2, `git+https://` pinned to a commit SHA.**
`MayaTrail/scout` is confirmed private with no git tags, so the pin is a raw
commit SHA (`0943023...feec` as of this writing), not a version number —
"upgrading Scout" means changing that SHA. A GitHub deploy token (or a
fine-grained PAT scoped to `MayaTrail/scout`, read-only) still needs plumbing
into `backend/Dockerfile:31`, `backend/Dockerfile.worker:30`, and the CI job's
install step before Task 1, Steps 6-7 can succeed outside a developer's own
authenticated shell — none of those three currently have any credential
available. That plumbing is not yet done; it is the remaining blocker in
Task 1.

### Interpreter version

The runtime is `python:3.12-slim` (`backend/Dockerfile:1`) and CI pins
`python-version: '3.12'`. Local `__pycache__` artifacts in this repo are
`cpython-314`, i.e. at least one development environment runs 3.14 — so
"works locally" does not evidence "works in the image."
**`mayatrail-scout[aws]` must be confirmed importable and functional on
3.12** before this ships. (The same skew is worth fixing repo-wide,
separately from this feature.)

Core Scout is stdlib-only; the `aws` extra adds `boto3`, already a direct
dependency of step1's backend.

### Import placement

`requirements-test.txt` is deliberately minimal (Django, decouple, PyYAML,
celery, feedparser, requests — no boto3, no pulumi) because
`config.settings.ci` swaps in sqlite and an empty URL config. A module-scope
`import scout` in `apps/attack_graph/tasks.py` would therefore break CI the
moment anything imports that module. Follow the established pattern: import
Scout inside the task function, as `apps/emulations/views.py:579` does with
`deploy_emulation_stack` (`# noqa: PLC0415`).

### New-app registration checklist

A new Django app in this repo is not registered in one place. All of these
are required, and omitting any of the last three fails silently:

- `LOCAL_APPS` in `config/settings/base.py:49`;
- the **separate, explicit** `INSTALLED_APPS` in `config/settings/ci.py:45`
  (a hand-maintained subset, not derived from base);
- the route in `config/urls.py`;
- the explicitly-named app list in the test command of
  `.github/workflows/backend-tests.yml` — a new suite that is not named there
  never runs;
- `python manage.py makemigrations users infrastructure emulations logs attack_graph`
  (CLAUDE.md: a bare `makemigrations` may silently miss apps), with the
  migration committed so the `makemigrations --check --dry-run` gate passes.

## API surface (`apps/attack_graph/urls.py`)

Mounted at `/api/attack-graph/` in `config/urls.py`.

| method | path | view | purpose |
|---|---|---|---|
| POST | `/api/attack-graph/scan/` | `ScoutScanTriggerView` | kick off a new scan, 202 + `scan_id`, or 409 |
| GET | `/api/attack-graph/scan/list/` | `ScoutScanListView` | history, newest-first |
| GET | `/api/attack-graph/scan/<id>/` | `ScoutScanDetailView` | status + result (for polling and for viewing a past scan) |

Permission class is a new **`HasScoutConnection`**
(`apps/attack_graph/permissions.py`), modelled on `HasAWSConnection`
(`apps/infrastructure/permissions.py:15`) but keyed on
`user.aws_audit_role_arn` rather than `is_verified`: reads open to any
authenticated user, POST gated on a connected audit role. `HasAWSConnection`
is deliberately **not** reused — it keys on `is_verified`, which only the
emulation role's verify flow sets, so an org that provisioned just the auditor
role would be refused its own scan. All queries are scoped to `request.user`'s
own scans.

### Connector additions (`apps/connectors/urls.py`)

| method | path | view | purpose |
|---|---|---|---|
| POST | `/api/connectors/aws/audit/` | `AWSAuditConnectorView` | verify + probe the audit role, store `aws_audit_role_arn` |
| DELETE | `/api/connectors/aws/audit/` | `AWSAuditConnectorView` | disconnect it; 409 while a scan is in flight |

Both are `IsAuthenticated`: connecting a read-only role is how a user *gets*
a connection, so it cannot require one. `aws_audit_role_arn` is added to
`User` and to `UserSerializer.Meta.fields` (`apps/users/serializers.py:89`,
beside `aws_role_arn`) so `/auth/me/` carries it and the frontend can gate on
it without a second request.

**Concurrency.** `ScoutScanTriggerView` returns `409 CONFLICT` with the active
`scanId` when the user already has a `pending` or `running` scan, mirroring
`EmulationDeployView`'s guard (`apps/emulations/views.py:526-563`). Without
it, ten clicks are ten concurrent GAAD collections on a two-slot worker.

## Frontend components

- **Sidebar** (`components/layout/Sidebar.tsx`): one new `NavItem` under the
  "Security Content" section, label **"Attack Graph"**, route
  `/attack-graph`. (User-facing label deliberately avoids the "Scout" engine
  name — see Naming below.)
- **Route** (`App.tsx`): `<Route path="attack-graph" element={<AttackGraphHub />} />`.
- **`AttackGraphHub.tsx`** (new, `components/attack-graph/`) — Hub-page header
  (eyebrow + title, same pattern as `EmulationsHub`), gated by a new
  `useScoutConnection()` hook beside `useAWSConnection` in `ConnectGate.tsx` —
  the existing one reads `user.isVerified` (`ConnectGate.tsx:12`), the
  emulation role's signal, so reusing it would gate this page on the wrong
  connection. The unconnected state is a `ConnectPrompt` pointing at the
  audit-role dialog, not at the emulation connector — which needs one new
  optional prop on `ConnectPrompt`, whose call to action is currently the
  hardcoded string "Connect AWS account" (`ConnectGate.tsx:47-53`). Telling a
  user who has already connected an account to connect one reads as a bug.
  Then a "Run Scan" button (disabled while a
  scan is pending/running, with the 409 surfaced as a pointer to the in-flight
  scan), a scan-history strip (status + timestamp per past `ScoutScan`, click
  to view), the result states from
  [Scan fidelity](#scan-fidelity), and the
  graph for the selected/latest scan. `ComingSoon` styling is used only for
  the never-scanned-yet state — never for a completed scan.
- **`AttackChainGraph.tsx`** (new) — structurally a clone of
  `InfraGraphView.tsx`: `dagre` layout, hand-rolled SVG nodes/edges,
  category-colored node cards (identity/role/resource, reusing the existing
  `net/compute/data/iam/other` palette where it maps — `iam` amber for
  identity nodes), arrow-marker edges highlighting on selection,
  click-to-open detail side panel (mirrors `DetailPanel`'s pattern, here
  showing the step's `technique`/`condition`/`detail` from the result
  envelope), legend, empty state. Consumes the envelope only, never Scout's
  raw output. **Lazy-loaded**, as `InfraGraphView` already is for exactly this
  reason: it pulls in dagre (`components/modals/ResourceMapModal.tsx:10`).
- **`chainGraph.ts`** (new) — the envelope to `{nodes, edges}` transform as a
  pure module, separate from the component, so it is testable without a DOM
  and so the layout code stays about layout.
- **Polling** — `hooks/useCachedResource.ts`, the hook `useEmulationRuns`
  already polls Active Runs with, rather than a bespoke
  `useEffect`+`setInterval`. It owns the interval, cancels in-flight requests
  on unmount, swallows a failed poll instead of raising an unhandled
  rejection, and never blanks the screen to re-fetch. Passing `pollMs:
  undefined` once a scan reaches a terminal status is what stops the polling;
  a completed scan never changes again and its `result` is the largest
  response on the page. It must render a distinct "waiting for a worker"
  state: the enterprise queue runs `--concurrency=2` alongside Pulumi deploys
  that take 20-27 minutes, so a queued scan can legitimately sit at `pending`
  for a long time, and "Running..." for half an hour with no explanation reads
  as a hang.

## Naming

User-facing label: **"Attack Graph"**. Internal code (Django app name, model
name, Python package) keeps the `scout`/`attack_graph` naming — only the
label a user sees changes. This matches the existing nav convention (plain
descriptive words: Emulations, Detections, Guardrails — not tool brand
names).

## Data flow diagram

```
[MayaTrail user] --click "Run Scan"--> [AttackGraphHub]
      |
      v
[POST /api/attack-graph/scan/] --409 if one already in flight
      |
      +--> [ScoutScan row: pending] --> [Celery: enterprise queue, concurrency 2]
      |                                                       |
      |                                              status=running, started_at
      |                                                       |
      |                                     _assume_role_arn(aws_audit_role_arn)
      |                                                       |
      |                                              boto3.Session(**creds)
      |                                                       |
      |                                              scout...gaad.collect(session.client)
      |                                                  -> mode: account | self
      |                                                       |
      |                                              scout.pipeline.run(evaluator=effective)
      |                                                       |
      |                                              serialize_scan() -> envelope v1
      |                                                       |
      |                                              ScoutScan: completed, result=envelope
      v                                                       |
[GET /api/attack-graph/scan/<id>/] <---------------------------
      |
      v
[chainGraph.ts: envelope -> nodes/edges] --> [AttackChainGraph renders]
      |
      +-- mode == "self" --> partial-scan warning + re-connect prompt
```

## Error handling

- **STS AssumeRole failure on the audit role** (deleted, or its trust policy
  changed since connect time) — task catches, sets `status=failed`,
  `error_message` from the botocore exception (same pattern `AWSConnectorView`
  already uses for surfacing STS errors), and the page offers re-connecting
  the audit role.
- **IAM read access denied** — Scout degrades to self-scoped enumeration, so
  the task succeeds, but the scan is reported as **partial**, never as clean.
  See [Scan fidelity](#scan-fidelity).
- **Empty result with `mode == "account"`** (a well-locked-down account) — not
  an error; positive empty state, carrying the SCP caveat.
- **Scan exceeds the time limit** — `soft_time_limit=900` lets the task catch
  `SoftTimeLimitExceeded` and write a real `error_message` ("scan timed out
  after 15 minutes") instead of leaving a row stuck at `running` forever.
- **Celery task never completes** (worker crash, or the hard `time_limit`
  killing the process) — a row is orphaned at `running`; `task_id` is stored
  so it can be inspected. No reaper in v1, so it keeps rendering as
  "Scanning" if selected. It does **not** keep blocking: both 409 guards read
  `active_scans()`, which stops counting it once it is older than the hard
  time limit. Without that, one crash would deny the user every future scan
  and the ability to disconnect the role, permanently.
- **The audit role is in a different account from the emulation role** —
  refused at connect time with a 422 naming both account ids, when an
  emulation role is connected. Allowed when none is, since an org may
  provision the auditor role first. Otherwise a scan succeeds, reports on an
  account the user was not looking at, and says so nowhere.

## Assumptions to verify (step 0 of implementation)

**Verified 2026-09-21, Task 1, against `mayatrail-scout` pinned to commit
`0943023 66538951c210e8204845976a67eb6feec` (installed via
`git+https://github.com/MayaTrail/scout.git@<sha>`, Python 3.12, offline
fixture `tests/fixtures/gaad_sample.json` from the Scout checkout — Scout
does not ship its test fixtures in the installed package, so this fixture was
copied out of the source checkout, not `pip`-installed).**

- `collect(client_factory, *, self_only=False, reuse_gaad=None,
  reuse_account_id="") -> tuple[dict, str, dict]` — confirmed, `self_only`
  is still a keyword-only parameter with the assumed default. (Return arity
  matches the guess: `(gaad, account_id, collection)`.)
- Whether a bound `boto3.Session(...).client` satisfies Scout's
  `ClientFactory` protocol was **not exercised** — the spike ran entirely
  against the offline GAAD fixture, with no AWS calls. Still unverified;
  confirm before Task 9 wires the real boto3 session in.
- `collection["mode"]` — not exercised directly (the fixture was fed straight
  to `pipeline.run()`), but `report["collection_mode"]` came back `"account"`
  on this fixture, consistent with the assumed `"account" | "self"` values.
- `pipeline.run(gaad=..., account_id=..., evaluator=None, ...) -> (report,
  graph)`. Confirmed: `report["chains"]` is already ranked descending by
  `risk_score` (verified: `[70, 63, 40]` on the 3-chain fixture). Confirmed:
  `evaluator=None` (the default) resolves internally to
  `scout.eval.effective.EffectivePermissionEvaluator` — but the report
  carries no field naming which evaluator ran; the envelope's `"effective"`
  string is the task's own claim, not something Scout states back.
- **The per-step fields differ substantially from the guess, in a way that
  changes what the UI can show, not just field names.** There is no `steps`
  key — it is `hops`. There is no per-hop `technique` or `condition`. Real
  chain keys: `chain_id, foothold_filtered, hops, impact_drivers,
  impact_score, likelihood_drivers, likelihood_score, mitre_techniques,
  origin_identity_arn, risk_drivers, risk_score, scp_blocked, target_filtered,
  terminal_impact, terminal_props, terminal_target_arn`. Real hop keys:
  `hop_number, mechanism, action, source_arn, target_arn,
  concrete_api_sequence, catalog_path_ids, conditional, granted_by,
  granted_by_overflow, bounded_by`. `mitre_techniques` is chain-level (a
  list), not attached per hop. See the envelope section's field-mapping table
  for the corrected mapping.
- **`source.id`/`target.id` and `steps[].from`/`steps[].to` identifier
  space — resolved, and simpler than feared.** There are no node ids
  anywhere in the chain output. `chain["origin_identity_arn"]`,
  `chain["terminal_target_arn"]`, `hop["source_arn"]`, and
  `hop["target_arn"]` are all IAM ARNs, and every hop endpoint ARN in the
  sample fixture also appears as some chain's origin or terminal ARN. No
  normalisation step is needed in the envelope; Task 7's `_node`/`_step` key
  everything directly on the ARN.

**New finding, not in the original list:** Scout's own package
(`pyproject.toml`) is unversioned in any meaningful sense — `version =
"0.0.1"` and the `MayaTrail/scout` repository carries no git tags. The pin in
`requirements.txt` (Task 1, Step 6) is therefore a commit SHA, not a semantic
version, and "upgrading Scout" means changing that SHA, not bumping a version
number.

First implementation task: vendor a chain fixture from
`scout/tests/fixtures/` into `apps/attack_graph/tests/fixtures/` and write a
contract test that runs `serialize_scan()` over it and asserts the envelope.
That test is what turns these assumptions into something CI defends, and
what catches a breaking Scout upgrade before a customer does.

## Testing

- **Backend contract test** (above) — the load-bearing one.
- **What CI can actually run.** `config/settings/ci.py` states it plainly:
  every test in the suite is a `SimpleTestCase`, the URLconf is empty, and
  neither DRF nor boto3 is installed (`requirements-test.txt` is six
  packages). There are no view tests anywhere in this repo, and none can be
  added without expanding that contract. So the logic that must not regress —
  `serialize_scan()` and the mode-to-state decision — lives in
  `apps/attack_graph/envelope.py`, importable with Django alone and tested
  with `SimpleTestCase`. `tasks.py`, which imports Scout and boto3, is left
  holding no decision worth testing.
- View behaviour (409 on a second scan, 403 without an audit connection, the
  connect-time probe) is **out of CI scope** in v1 and verified by hand
  against a real account. Expanding `requirements-test.txt` to cover DRF view
  tests is a separate decision, deliberately not smuggled in here.
- Add `apps.attack_graph` to the CI test command and to
  `config/settings/ci.py` — see the registration checklist.
- **Frontend** — the repo has **no test runner and zero `.test.tsx` files**
  (`frontend/UI/package.json` scripts are `dev`/`build`/`preview`/`lint`), so
  there is no existing pattern to follow. The plan must pick one explicitly:
  stand up Vitest + RTL and test `chainGraph.ts` (the transform is worth it,
  and is a pure function), or ship v1 with no frontend test and accept that
  the backend contract test is the only guard. Either is defensible; quietly
  assuming a test infrastructure that does not exist is not.
- No live-AWS test in CI, matching the repo's existing convention of skipping
  live tests by default.

## Open items for the implementation plan (not blocking this spec)

- ~~Exact polling hook to reuse from the emulations frontend flow.~~
  Settled: `useCachedResource`, above.
- Reaping orphaned scans. `active_scans()` stops a dead row from blocking the
  trigger and the disconnect, but nothing rewrites it to `failed`, so it
  still renders as "Scanning" if a user selects it from history. A periodic
  job that fails out non-terminal rows older than the hard time limit is the
  remaining piece.
- Whether a scan should fall back to the **emulation** role when no audit role
  is connected but that role holds Administrator. It would save some orgs a
  second role; it also reintroduces the silently-degraded scan this design
  exists to remove, so v1 requires the audit connection.
- Whether 25 chains needs a `result` max-size guard beyond the `truncated`
  flag (worth a sanity check against a real large-account scan once
  available).
- Whether the partial-scan re-connect prompt should also appear on the
  Profile/connector page, or only on the Attack Graph page.
- **Scan retention.** If history is pruned, the rule has to prune only
  terminal-status rows, never touch the newest N regardless of status (a
  `pending` row is one the user is watching), and state whether the deletion
  is recorded in the activity trail — silently dropping a scan a customer can
  still open is worse than an unbounded table at 25 chains per row.
- **The 15-minute timeout is a guess.** `soft_time_limit=900` was chosen
  without measuring `GetAccountAuthorizationDetails` plus chain ranking
  against a real large account. Re-check it against the first production-scale
  scan.

## Blocking decisions for the author (not the plan)

1. **Scout distribution + credentials** for `Dockerfile`, `Dockerfile.worker`
   and CI (see Dependency and packaging).
2. **`mayatrail-scout[aws]` on Python 3.12**, confirmed in the image.
3. **Frontend test runner**: stand up Vitest, or ship without.
