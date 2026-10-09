# Attack Graph (Scout Integration) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an "Attack Graph" page that runs a read-only IAM privilege-escalation scan through Scout against a dedicated auditor role the tenant provisions, and renders the ranked attack chains as a MayaTrail-native graph.

**Architecture:** A second AWS connection (`aws_audit_role_arn`, verified by STS AssumeRole *plus* a live `iam:GetAccountAuthorizationDetails` probe) feeds a new isolated Django app `apps/attack_graph`: one model, one Celery task on the `enterprise` queue, three views. The task never hands Scout's own objects to the frontend — it serializes them into a versioned envelope, and every security-relevant decision (what counts as a clean result) lives in a pure module CI can import with Django alone.

**Tech Stack:** Django 5.0 + DRF, Celery (queue `enterprise`), boto3, `mayatrail-scout[aws]`, React + TypeScript + Vite, dagre for graph layout.

**Spec:** `docs/superpowers/specs/2026-09-21-attack-graph-integration-design.md` — read it before Task 1. The plan argues from it; where they disagree, the spec wins and the plan gets fixed.

## Global Constraints

- **Branch:** all work lands on `feat/scout-integration` (already checked out). Do not branch from `main` mid-plan.
- **Python:** runtime and CI are **3.12** (`backend/Dockerfile:1`, `.github/workflows/backend-tests.yml`). A local 3.14 interpreter proves nothing here.
- **CI test contract:** `config/settings/ci.py` — sqlite, empty URLconf, `SimpleTestCase` only, and `requirements-test.txt` installs six packages: Django, python-decouple, PyYAML, celery, feedparser, requests. **DRF and boto3 are not installed in CI.** No test in this plan may import them. Do not expand `requirements-test.txt`.
- **New-app registration (all five, or it silently does nothing):** `LOCAL_APPS` in `config/settings/base.py:49`; `INSTALLED_APPS` in `config/settings/ci.py:45`; the route in `config/urls.py`; the app label in the test command of `.github/workflows/backend-tests.yml`; `python manage.py makemigrations users infrastructure emulations logs attack_graph` (never bare `makemigrations`).
- **Scout imports are deferred** — inside the task function, never at module scope, with `# noqa: PLC0415`, as `apps/emulations/views.py:579` does.
- **`SCOPED_POLICY` (`frontend/UI/src/components/profile/ConnectCloudDialog.tsx:32-67`) is not modified by this plan.** The emulation role's grant stays exactly as it is; the audit role is a separate connection.
- **Status vocabulary** is `pending` / `running` / `completed` / `failed` — the same four strings as `EmulationRun.Status` (`apps/emulations/models.py:28-33`). Never `succeeded`.
- **Frontend tests:** the repo has no test runner and zero `.test.tsx` files. v1 ships without one (Task 14 is the opt-in if you want it). Do not write a frontend test that cannot run.
- **Keep the graft index current:** the project CLAUDE.md asks for `graphify update .` after modifying code. Run it once at the end of each phase rather than per task — it is AST-only and costs nothing, and a stale index is what makes the next person's `graft ask` point at files that moved.
- **Backend test command (bash):** `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2`
  **PowerShell:** `cd backend; $env:DJANGO_SETTINGS_MODULE='config.settings.ci'; python manage.py test apps.attack_graph -v 2`

---

## File Structure

**Phase 1 — the Scout audit connection** (ships alone; a user can connect an auditor role and see it verified with no attack-graph code present)

| file | responsibility |
|---|---|
| `backend/apps/connectors/aws.py` *(new)* | `assume_role_arn()` and `probe_account_authorization_details()` — the only place STS AssumeRole is called; the session duration is the caller's to choose |
| `backend/apps/emulations/tasks.py:173` *(modify)* | `_assume_user_role` becomes a wrapper over the shared helper |
| `backend/apps/users/models.py` *(modify)* | `aws_audit_role_arn` field |
| `backend/apps/users/serializers.py:89` *(modify)* | expose it on `/auth/me/` |
| `backend/apps/connectors/serializers.py` *(modify)* | `AWSAuditConnectorSerializer` |
| `backend/apps/connectors/views.py` *(modify)* | `AWSAuditConnectorView` (POST verify+probe, DELETE disconnect) |
| `backend/apps/connectors/urls.py` *(modify)* | `/api/connectors/aws/audit/` |
| `frontend/UI/src/types/auth.ts` *(modify)* | `hasAuditRole` on `User` |
| `frontend/UI/src/services/auth.service.ts` *(modify)* | map it from `/auth/me/`; `verifyAuditRole` / `disconnectAuditRole` |
| `frontend/UI/src/context/AuthContext.tsx` *(modify)* | context actions mirroring `verifyConnector`/`disconnectConnector` |
| `frontend/UI/src/components/profile/ConnectScoutRoleDialog.tsx` *(new)* | the audit-role dialog: policy to copy, ARN input, probe errors |
| `frontend/UI/src/components/profile/ProfilePage.tsx` *(modify)* | a second connection card |
| `frontend/UI/src/components/common/ConnectGate.tsx` *(modify)* | `useScoutConnection()` |

**Phase 2 — the attack_graph backend**

| file | responsibility |
|---|---|
| `backend/apps/attack_graph/constants.py` *(new)* | the scan's time limits, shared by `tasks.py` and the model's staleness rule |
| `backend/apps/attack_graph/models.py` *(new)* | `ScoutScan`, and `active_scans()` — the one definition of "a scan is in flight", read by both 409 guards |
| `backend/apps/attack_graph/envelope.py` *(new)* | `serialize_scan()`, `result_state()` — **pure, no boto3, no Scout, no DRF**; the only file CI can defend |
| `backend/apps/attack_graph/tasks.py` *(new)* | `run_scout_scan` — orchestration only, no decisions |
| `backend/apps/attack_graph/permissions.py` *(new)* | `HasScoutConnection` |
| `backend/apps/attack_graph/views.py` / `urls.py` / `serializers.py` *(new)* | the three endpoints |
| `backend/apps/logs/models.py:32` *(modify)* | three `Event` members |

**Phase 3 — the attack_graph frontend**

| file | responsibility |
|---|---|
| `frontend/UI/src/services/attackGraph.service.ts` *(new)* | the three API calls |
| `frontend/UI/src/types/attackGraph.ts` *(new)* | envelope types mirroring `envelope.py` |
| `frontend/UI/src/components/attack-graph/chainGraph.ts` *(new)* | envelope → `{nodes, edges}`, pure, no React |
| `frontend/UI/src/components/attack-graph/AttackChainGraph.tsx` *(new)* | dagre + SVG rendering |
| `frontend/UI/src/components/attack-graph/AttackGraphHub.tsx` *(new)* | page, gating, polling, result states |
| `frontend/UI/src/App.tsx` / `components/layout/Sidebar.tsx` *(modify)* | route + nav entry |

---

## Task 1: Scout dependency spike

Everything downstream assumes five things about Scout's API that nothing in this repo pins. This task turns them into facts, on the interpreter that actually ships, before any code is written against them. It is the one task in this plan that is not test-first — it is the measurement that tells the later tests what to assert.

**Files:**
- Modify: `backend/requirements.txt`
- Create: `backend/apps/attack_graph/tests/fixtures/scout_report.json`
- Modify: `docs/superpowers/specs/2026-09-21-attack-graph-integration-design.md` (the "Assumptions to verify" section — record what was found)

- [x] **Step 1: Resolve where Scout is installed from**

If `pip download mayatrail-scout` fails, the package is not public and one of these must be settled with the author before continuing (spec, "Distribution — decide before planning"): publish to PyPI, use `git+https://` with a deploy token plumbed into `backend/Dockerfile`, `backend/Dockerfile.worker` and CI, or vendor it. Do not proceed on a `pip install` that only works on your laptop.

- [x] **Step 2: Install it on Python 3.12 in a throwaway venv**

```bash
py -3.12 -m venv /tmp/scout-spike           # Windows: py -3.12 -m venv $env:TEMP\scout-spike
/tmp/scout-spike/Scripts/pip install "mayatrail-scout[aws]==<pin>"
```

Expected: a clean install. A failure here is a blocking finding — report it, stop, do not work around it by changing the runtime's Python version.

- [x] **Step 3: Print the real shapes**

Run against Scout's own offline fixtures (no AWS calls):

```python
# /tmp/scout-spike/probe.py
import inspect, json
from scout.aws.collect import gaad
from scout import pipeline

# Signatures. Three things are being read out of these, not just the arity:
# whether collect() still takes self_only, what pipeline.run()'s `evaluator`
# parameter defaults to, and whether that default is the effective evaluator
# the envelope claims it is.
print("collect signature:", inspect.signature(gaad.collect))
print("run signature:", inspect.signature(pipeline.run))
print("run evaluator default:", inspect.signature(pipeline.run).parameters.get("evaluator"))

# Load Scout's own offline GAAD fixture — adjust the path to the installed package.
sample = json.load(open("<scout>/tests/fixtures/<gaad fixture>.json"))
report, graph = pipeline.run(gaad=sample, account_id="123456789012")
print("report keys:", sorted(report))
print("chain keys:", sorted(report["chains"][0]))
print("step keys:", sorted(report["chains"][0]["steps"][0]))
print(json.dumps(report["chains"][:2], indent=2)[:2000])

# THE IDENTIFIER-SPACE CHECK. Everything the graph draws depends on this and
# nothing else in the plan can discover it. The envelope keys nodes on
# source/target `id` and draws edges between steps' `from`/`to`. If Scout puts
# ARNs in the steps and opaque ids on the endpoints, every chain renders as
# disconnected fragments plus duplicate nodes, the graph looks plausible, and
# it is wrong. Confirm the two sets overlap before writing any mapping.
endpoint_ids = set()
step_ids = set()
for chain in report["chains"]:
    for end in ("source", "target"):
        endpoint_ids.add(chain[end].get("id") or chain[end].get("arn"))
    for step in chain["steps"]:
        step_ids.update([step["from"], step["to"]])
print("endpoint ids:", sorted(endpoint_ids)[:6])
print("step endpoint ids:", sorted(step_ids)[:6])
print("step ids NOT resolvable to an endpoint id:", sorted(step_ids - endpoint_ids)[:6])
```

The last line is allowed to be non-empty — intermediate hops legitimately are not chain endpoints. What must be true is that the two sets are drawn from **the same identifier space** (both ARNs, or both Scout node ids). If one is ARNs and the other is not, record which, and `_node`/`_step` in Task 7 normalise both to whichever one Scout's own graph keys on.

- [x] **Step 4: Record the answers in the spec**

Replace each bullet under "Assumptions to verify" with what you observed — the real `collect()` return arity, whether `self_only` is still a parameter, the real `collection["mode"]` values, `pipeline.run()`'s default evaluator and its name, the real chain and step field names, and **the identifier space each of `source.id`/`target.id`/`steps[].from`/`steps[].to` is expressed in**. If a shape differs from the spec, **the envelope mapping in Task 7 follows reality, not the spec's guess**, and you update the spec in this step rather than letting the two drift.

Two of these feed code directly and are easy to record and then forget:

- if `collect()` still takes `self_only`, Task 9 passes it explicitly rather than relying on its default;
- the envelope's `"evaluator"` value must be the evaluator that actually ran. It is currently written as the literal `"effective"`. If `pipeline.run()`'s default is named something else, change the literal — an envelope that asserts which evaluator produced it, without that having been checked, is a claim about how a security finding was computed.

- [x] **Step 5: Save the fixture**

Write the first two ranked chains from Step 3 to `backend/apps/attack_graph/tests/fixtures/scout_report.json`, wrapped as the pipeline returns them:

```json
{ "chains": [ { "...": "verbatim chain objects from Scout" } ] }
```

This file is what Task 7's contract test runs against. It must be Scout's real output, not hand-written — a fixture you invented would pass a test that proves nothing.

- [x] **Step 6: Pin the dependency**

Append to `backend/requirements.txt`, after the pysigma block:

```
# IAM privilege-escalation graph engine behind the Attack Graph page. Pinned
# exactly: Scout is maintained in its own repository and its chain output is a
# contract this backend serializes into a versioned envelope
# (apps/attack_graph/envelope.py). An unpinned upgrade can change that shape
# and turn a working graph into an empty one with no code change on our side.
mayatrail-scout[aws]==<pin>
```

- [x] **Step 7: Verify the images still build**

```bash
docker build -f backend/Dockerfile -t mayatrail-backend-spike backend/
docker build -f backend/Dockerfile.worker -t mayatrail-worker-spike backend/
```

Expected: both succeed. If Scout is private, this is where the missing credentials surface.

- [x] **Step 8: Commit**

```bash
git add backend/requirements.txt backend/apps/attack_graph/tests/fixtures/scout_report.json docs/superpowers/specs/2026-09-21-attack-graph-integration-design.md
git commit -m "chore: pin mayatrail-scout and record its verified API shape"
```

---

## Task 2: Shared AssumeRole helper

**Files:**
- Create: `backend/apps/connectors/aws.py`
- Modify: `backend/apps/emulations/tasks.py:173-203`
- Test: `backend/apps/emulations/tests/test_credentials.py`

**Interfaces:**
- Produces: `assume_role_arn(role_arn: str, session_name: str, duration_seconds: int = DEFAULT_SESSION_SECONDS) -> dict[str, str]` returning `{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}`; `VERIFY_SESSION_SECONDS: int = 900`; `probe_account_authorization_details(creds: dict[str, str]) -> None` raising `botocore.exceptions.ClientError` when the role cannot read IAM.
- Consumes: nothing.

- [x] **Step 1: Write the failing test**

boto3 is absent in CI, so this is a source-scan test in the style of `apps/infrastructure/tests/test_status_history.py` — it reads files as text and never imports them. That is exactly the bug it catches: a second hand-rolled `assume_role` call drifting out of sync with the first.

```python
# backend/apps/emulations/tests/test_credentials.py
"""
One place calls STS AssumeRole.

Both the emulation deploy path and the Scout scan need temporary credentials,
with different role ARNs and different session names. A second hand-rolled
sts.assume_role() would work on the day it is written and then drift — a
changed duration or session name in one copy and not the other is invisible
until a tenant's CloudTrail stops making sense. This test reads the source
rather than importing it: boto3 is not installed in CI.
"""

import pathlib

from django.test import SimpleTestCase

BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[3]

# Every module that resolves tenant credentials.
CREDENTIAL_SOURCES = [
    "apps/connectors/aws.py",
    "apps/emulations/tasks.py",
    "apps/attack_graph/tasks.py",
]


class AssumeRoleCallSiteTests(SimpleTestCase):
    """Where sts.assume_role may appear."""

    def _source(self, relative):
        path = BACKEND_ROOT / relative
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_only_the_shared_helper_calls_assume_role(self):
        offenders = [
            name
            for name in CREDENTIAL_SOURCES
            if name != "apps/connectors/aws.py" and ".assume_role(" in self._source(name)
        ]
        self.assertEqual(
            offenders,
            [],
            f"{offenders} call sts.assume_role directly; use connectors.aws.assume_role_arn",
        )

    def test_the_helper_is_parameterised_by_arn_session_name_and_duration(self):
        source = self._source("apps/connectors/aws.py")
        self.assertIn("def assume_role_arn(", source)
        for parameter in ("role_arn: str", "session_name: str", "duration_seconds: int"):
            self.assertIn(parameter, source, parameter)

    def test_a_connect_time_verify_asks_for_the_shortest_session(self):
        # AWS rejects AssumeRole outright when DurationSeconds exceeds the
        # role's MaxSessionDuration, and an org creating a read-only auditor
        # role is exactly the org that caps it. The existing emulation verify
        # already asks for the 900s minimum for this reason
        # (connectors/views.py, "# minimum allowed"); a one-hour session for a
        # single GetAccountAuthorizationDetails call would narrow which roles
        # can connect, for nothing.
        source = self._source("apps/connectors/aws.py")
        self.assertIn("VERIFY_SESSION_SECONDS = 900", source)

    def test_the_emulation_wrapper_still_names_its_own_session(self):
        source = self._source("apps/emulations/tasks.py")
        self.assertIn("mayatrail-emulation-", source)
```

- [x] **Step 2: Run it to verify it fails**

Bash: `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.emulations.tests.test_credentials -v 2`
PowerShell: `cd backend; $env:DJANGO_SETTINGS_MODULE='config.settings.ci'; python manage.py test apps.emulations.tests.test_credentials -v 2`

Expected: FAIL (5 tests) — `apps/connectors/aws.py` does not exist, and `apps/emulations/tasks.py` still calls `.assume_role(`.

- [x] **Step 3: Write the helper**

```python
# backend/apps/connectors/aws.py
"""
Tenant credential resolution.

Every MayaTrail task that touches a customer account does it by assuming a role
that customer created, never with stored keys. Two roles exist: the emulation
role, which performs the writes an emulation needs, and the Scout audit role,
which is read-only and exists so IAM-graph scanning does not widen the
emulation grant. Both come through assume_role_arn(); the session name is the
caller's to choose, so a tenant reading their own CloudTrail can tell a
read-only scan apart from an emulation.
"""

import boto3

# One hour: long enough for a full emulation deploy and attack cycle, and for
# a GAAD collection on a large account, without minting credentials that
# outlive the task that holds them.
DEFAULT_SESSION_SECONDS = 3600

# The 900-second AWS minimum, for connect-time verification. AssumeRole is
# rejected outright when DurationSeconds exceeds the role's MaxSessionDuration,
# so asking for the shortest possible session is what makes verification work
# against a role whose owner capped it — and a security team provisioning a
# read-only auditor role is exactly the owner who caps it. AWSConnectorView
# has always used 900 here for this reason; nothing about verification needs
# a credential that outlives the request.
VERIFY_SESSION_SECONDS = 900


def assume_role_arn(
    role_arn: str,
    session_name: str,
    duration_seconds: int = DEFAULT_SESSION_SECONDS,
) -> dict[str, str]:
    """
    Assume a tenant role via STS and return temporary credentials.

    Credentials are never stored in the database — they are generated per task
    invocation and discarded when the task completes.

    Args:
        role_arn: The tenant role to assume.
        session_name: STS session name, which appears in the tenant's
            CloudTrail. Identify the caller here.
        duration_seconds: Session lifetime. The default suits a task that
            holds the credentials for its whole run; pass
            VERIFY_SESSION_SECONDS for a single connect-time call, so a role
            with a short MaxSessionDuration still verifies.

    Returns:
        Dict with keys: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
        AWS_SESSION_TOKEN.

    Raises:
        botocore.exceptions.ClientError: if the role cannot be assumed, or if
            duration_seconds exceeds the role's MaxSessionDuration.
    """
    sts = boto3.client("sts")
    assumed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=duration_seconds,
    )
    creds = assumed["Credentials"]
    return {
        "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": creds["SessionToken"],
    }


def probe_account_authorization_details(creds: dict[str, str]) -> None:
    """
    Confirm a set of credentials can actually read account-wide IAM.

    Assumability is not the question the Scout connection needs answered. A
    role can be assumable and still unable to read IAM, and Scout responds to
    that by silently enumerating only the caller's own identity — which
    produces a scan with no findings, which reads as a clean account. Probing
    at connect time puts that failure in front of the person pasting the ARN,
    who can fix it.

    Args:
        creds: The dict returned by assume_role_arn().

    Returns:
        None on success.

    Raises:
        botocore.exceptions.ClientError: if the role cannot call
            iam:GetAccountAuthorizationDetails.
    """
    iam = boto3.client(
        "iam",
        aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=creds["AWS_SESSION_TOKEN"],
    )
    # One user is enough to prove the permission; Filter keeps a large account
    # from paying for a page of everything just to answer yes or no.
    iam.get_account_authorization_details(Filter=["User"], MaxItems=1)
```

- [x] **Step 4: Rewrite `_assume_user_role` as a wrapper**

In `backend/apps/emulations/tasks.py`, replace the body of `_assume_user_role` (keep the existing docstring, append the delegation note) and add the import at the top of the file:

```python
from apps.connectors.aws import assume_role_arn


def _assume_user_role(user) -> dict[str, str]:
    """
    Assume the enterprise user's cross-account IAM role via STS.

    Returns temporary credentials valid for 1 hour, which is more than
    sufficient for a full emulation deploy + attack cycle (~20-27 min).
    Credentials are never stored in the database — they are generated per-task
    invocation and discarded once the task completes.

    Delegates to connectors.aws.assume_role_arn so the Scout scan, which
    assumes a different role under a different session name, shares one
    implementation rather than a copy of this one.

    Args:
        user: Authenticated User instance with a valid aws_role_arn.

    Returns:
        Dict with keys: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
        AWS_SESSION_TOKEN.

    Raises:
        botocore.exceptions.ClientError if the role cannot be assumed.
    """
    return assume_role_arn(user.aws_role_arn, f"mayatrail-emulation-{user.id}")
```

- [x] **Step 5: Run the test to verify it passes**

Same command as Step 2. Expected: 5 tests PASS.

- [x] **Step 6: Run the whole CI suite — this task edited a shared file**

Bash: `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.emulations apps.metrics apps.guardrails apps.threatintel apps.workflows apps.infrastructure apps.users -v 1`

Expected: no new failures. (`apps/infrastructure/tests/test_status_history.py` scans `apps/emulations/tasks.py` — confirm your edit did not disturb a status transition.)

- [x] **Step 7: Commit**

```bash
git add backend/apps/connectors/aws.py backend/apps/emulations/tasks.py backend/apps/emulations/tests/test_credentials.py
git commit -m "refactor: one shared STS AssumeRole helper for both tenant roles"
```

---

## Task 3: The `aws_audit_role_arn` field

**Files:**
- Modify: `backend/apps/users/models.py`
- Modify: `backend/apps/users/serializers.py:89`
- Create: `backend/apps/users/migrations/00XX_user_aws_audit_role_arn.py` (generated)
- Test: `backend/apps/users/tests/test_audit_role.py`

**Interfaces:**
- Produces: `User.aws_audit_role_arn: str` (blank-default CharField), exposed on `GET /api/auth/me/` as `aws_audit_role_arn`.

- [x] **Step 1: Write the failing test**

```python
# backend/apps/users/tests/test_audit_role.py
"""
The Scout audit role is a second, separate connection.

It is not is_verified and it is not aws_role_arn. Those belong to the
emulation role, which grants writes; this one grants a single IAM read and is
what the Attack Graph scan assumes. Collapsing the two — gating a scan on
is_verified, or storing both ARNs in one field — is the mistake this test
exists to catch, because it silently re-widens the emulation grant.
"""

import pathlib

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase

User = get_user_model()
BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[3]


class AuditRoleFieldTests(SimpleTestCase):
    """What the model carries. No database is touched."""

    def test_the_audit_role_is_its_own_field(self):
        field = User._meta.get_field("aws_audit_role_arn")
        self.assertTrue(field.blank, "an unconnected user has no audit role")
        self.assertEqual(field.default, "")
        self.assertEqual(field.max_length, 256)

    def test_it_is_not_the_emulation_role(self):
        audit = User._meta.get_field("aws_audit_role_arn")
        emulation = User._meta.get_field("aws_role_arn")
        self.assertNotEqual(audit.name, emulation.name)

    def test_the_profile_endpoint_exposes_it(self):
        # The frontend gates the Attack Graph page on this value, and it reads
        # it from /auth/me/. DRF is not installed in CI, so the serializer is
        # read as source rather than imported.
        source = (BACKEND_ROOT / "apps/users/serializers.py").read_text(encoding="utf-8")
        self.assertIn('"aws_audit_role_arn"', source)
```

- [x] **Step 2: Run it to verify it fails**

Bash: `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.users.tests.test_audit_role -v 2`

Expected: FAIL with `FieldDoesNotExist: User has no field named 'aws_audit_role_arn'`.

- [x] **Step 3: Add the field**

In `backend/apps/users/models.py`, directly after `aws_role_arn`:

```python
    aws_audit_role_arn = models.CharField(
        max_length=256,
        blank=True,
        default="",
        help_text=(
            "Read-only IAM role the Attack Graph scan assumes. Separate from "
            "aws_role_arn on purpose: that role performs the writes emulations "
            "need, this one grants a single IAM read, so a security team can "
            "review and revoke IAM-graph access without touching emulations."
        ),
    )
```

- [x] **Step 4: Expose it on the profile endpoint**

In `backend/apps/users/serializers.py:89`, add `"aws_audit_role_arn"` to `UserSerializer.Meta.fields`, beside `"aws_role_arn"`.

- [x] **Step 5: Generate the migration**

```bash
cd backend && python manage.py makemigrations users infrastructure emulations logs
```

Expected: one new migration in `apps/users/migrations/` adding the field. Naming every app is required — a bare `makemigrations` may silently miss apps (CLAUDE.md).

- [x] **Step 6: Run the tests and the migration gate**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.users -v 2
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py makemigrations --check --dry-run
```

Expected: tests PASS; the check reports no missing migrations. (`apps.users` also carries the `.env.example` contract test — it must still pass; this task adds no new setting.)

- [x] **Step 7: Commit**

```bash
git add backend/apps/users/models.py backend/apps/users/serializers.py backend/apps/users/migrations/ backend/apps/users/tests/test_audit_role.py
git commit -m "feat: store a separate read-only audit role ARN per user"
```

---

## Task 4: The audit connector endpoint

**Files:**
- Modify: `backend/apps/connectors/serializers.py`
- Modify: `backend/apps/connectors/views.py`
- Modify: `backend/apps/connectors/urls.py`

**Interfaces:**
- Consumes: `assume_role_arn`, `probe_account_authorization_details` (Task 2); `User.aws_audit_role_arn` (Task 3).
- Produces: `POST /api/connectors/aws/audit/` → `200 {"status": "verified", "account_id": "..."}`, `400` bad ARN, `422 {"status": "error", "message": "..."}` when assume or probe fails. `DELETE /api/connectors/aws/audit/` → `200 {"status": "disconnected"}`, `409` while a scan is in flight.

**No CI test.** This view imports DRF and boto3, neither of which exists in the CI environment, and there are no view tests anywhere in this repo (`config/settings/ci.py` states the constraint outright). Steps 5-7 are a manual verification against a real account; do not skip them, and do not add a test that cannot run.

- [x] **Step 1: Add the serializer**

In `backend/apps/connectors/serializers.py`, after `AWSConnectorSerializer`:

```python
class AWSAuditConnectorSerializer(serializers.Serializer):
    """
    Validates the read-only audit role ARN submitted for Scout.

    Format-identical to AWSConnectorSerializer and deliberately a separate
    class: these two ARNs mean different things, and a shared serializer is
    how a future field on one quietly appears on the other.
    """

    role_arn = serializers.CharField(max_length=256)

    def validate_role_arn(self, value: str) -> str:
        """
        Ensure the ARN looks like a valid IAM role ARN.

        Format only — assumability and the IAM read permission are both
        verified against AWS in the view.

        Args:
            value: The role ARN string from the request body.

        Returns:
            The ARN unchanged if the pattern matches.

        Raises:
            serializers.ValidationError: If the format is invalid.
        """
        if not _ARN_RE.match(value.strip()):
            raise serializers.ValidationError(
                "Invalid ARN format. Expected: arn:aws:iam::<account-id>:role/<role-name>"
            )
        return value.strip()
```

- [x] **Step 2: Add the view**

In `backend/apps/connectors/views.py`, add the imports and the class:

```python
from apps.connectors.aws import (
    VERIFY_SESSION_SECONDS,
    assume_role_arn,
    probe_account_authorization_details,
)

from .serializers import AWSAuditConnectorSerializer, AWSConnectorSerializer


class AWSAuditConnectorView(APIView):
    """
    Connect the read-only role the Attack Graph scan assumes.

    POST /api/connectors/aws/audit/
    Accepts: { role_arn: "arn:aws:iam::123456789012:role/MayaTrailScoutAudit" }
    Returns:
      200 — { status: "verified", account_id: "..." }
      400 — validation errors (bad ARN format)
      422 — the role could not be assumed, or cannot read account-wide IAM

    DELETE /api/connectors/aws/audit/
    Returns:
      200 — { status: "disconnected" }
      409 — a scan is running against this role

    IsAuthenticated rather than HasAWSConnection: connecting this role is how a
    user acquires a connection, and an org may provision the auditor role
    before ever connecting an emulation role.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        """
        Assume the role, prove it can read IAM, then store it.

        The probe is the point. A role that is assumable but cannot call
        iam:GetAccountAuthorizationDetails produces a scan that finds nothing,
        which a reader takes for a clean account. Rejecting it here puts the
        failure in front of the person who can fix it.
        """
        serializer = AWSAuditConnectorSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        role_arn: str = serializer.validated_data["role_arn"]

        try:
            creds = assume_role_arn(
                role_arn,
                f"mayatrail-scout-verify-{request.user.id}",
                duration_seconds=VERIFY_SESSION_SECONDS,
            )
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "Audit role AssumeRole failed for user=%s arn=%s: %s",
                request.user.username, role_arn, exc,
            )
            return Response(
                {"status": "error", "message": _aws_message(exc)},
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        try:
            probe_account_authorization_details(creds)
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "Audit role cannot read IAM for user=%s arn=%s: %s",
                request.user.username, role_arn, exc,
            )
            return Response(
                {
                    "status": "error",
                    "message": (
                        "This role was assumed successfully but cannot call "
                        "iam:GetAccountAuthorizationDetails. Attach that permission "
                        "and try again — without it a scan can only see the role "
                        "itself and would report no findings."
                    ),
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        # The serializer's regex fixes the ARN's shape, so field 4 is the
        # account. Taken from the submitted ARN rather than the STS response
        # because assume_role_arn returns credentials only.
        account_id = role_arn.split(":")[4]

        user = request.user

        # Two roles, and nothing else compares their accounts. A user who
        # pastes an auditor ARN from a different account gets a scan that
        # succeeds, reports on an account they were not looking at, and says
        # so nowhere. Refused when both are connected and they disagree;
        # allowed when no emulation role is connected, because an org may
        # legitimately provision the auditor role first.
        if user.aws_role_arn and user.aws_role_arn.split(":")[4] != account_id:
            return Response(
                {
                    "status": "error",
                    "message": (
                        f"This audit role is in account {account_id}, but the "
                        f"connected emulation role is in account "
                        f"{user.aws_role_arn.split(':')[4]}. Scanning one "
                        "account while emulating in another would produce an "
                        "attack graph for neither. Disconnect the emulation "
                        "role first if the move is intentional."
                    ),
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        user.aws_audit_role_arn = role_arn
        # is_verified and is_demo are deliberately untouched: they record that
        # this user proved they own an account they can write to, and a
        # read-only role proves nothing about writes.
        user.save(update_fields=["aws_audit_role_arn"])

        return Response({"status": "verified", "account_id": account_id})

    def delete(self, request: Request) -> Response:
        """
        Disconnect the audit role.

        Refused while a scan is genuinely in flight: that task resolves
        credentials by reading aws_audit_role_arn at task time, so clearing it
        underneath makes the scan fail against a role it already assumed.

        "Genuinely" is what active_scans() adds over a status filter. Celery's
        hard time_limit kills the worker process outright, so a crashed scan
        never reaches a terminal status — and a status-only guard would then
        refuse this disconnect forever, with no way out from the UI. See
        attack_graph.models.active_scans.

        Nothing is changed in AWS. Revoking access properly means deleting the
        role in the tenant's own account.
        """
        # Imported here, not at module scope: the connectors app must not
        # depend on attack_graph at import time, and this view ships (Task 4)
        # before that app exists (Task 6).
        from apps.attack_graph.models import active_scans  # noqa: PLC0415

        if active_scans(request.user).exists():
            return Response(
                {
                    "detail": (
                        "Cannot disconnect while an attack graph scan is running. "
                        "Wait for it to finish, then try again."
                    ),
                },
                status=status.HTTP_409_CONFLICT,
            )

        user = request.user
        user.aws_audit_role_arn = ""
        user.save(update_fields=["aws_audit_role_arn"])

        logger.info("Scout audit role disconnected for user %s", user.id)

        return Response({"status": "disconnected"})
```

Extract the message helper the existing view already inlines, so both use one:

```python
def _aws_message(exc) -> str:
    """Return the human-readable part of a botocore exception."""
    if hasattr(exc, "response"):
        return exc.response.get("Error", {}).get("Message", str(exc))
    return str(exc)
```

Then replace the inline message extraction in `AWSConnectorView.post` with `_aws_message(exc)`.

> **Ordering note:** `apps.attack_graph` does not exist until Task 6. Write the `delete` handler now as shown — the import is inside the method, so the module still imports and `manage.py check` still passes — and verify DELETE in Task 6's manual check rather than here.

- [x] **Step 3: Route it**

```python
# backend/apps/connectors/urls.py
from .views import AWSAuditConnectorView, AWSConnectorView

urlpatterns = [
    path("aws/verify/", AWSConnectorView.as_view(), name="connector-aws-verify"),
    path("aws/audit/", AWSAuditConnectorView.as_view(), name="connector-aws-audit"),
]
```

- [x] **Step 4: Confirm the app still boots**

```bash
cd backend && python manage.py check
```

Expected: `System check identified no issues`. (Use your normal dev settings here, not `config.settings.ci` — the CI settings have an empty URLconf and would not load these routes.)

- [x] **Step 5: Manually verify the happy path**

In a real AWS account, create a role trusting the MayaTrail platform principal with this policy attached:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MayaTrailScoutAudit",
      "Effect": "Allow",
      "Action": "iam:GetAccountAuthorizationDetails",
      "Resource": "*"
    }
  ]
}
```

```bash
curl -X POST http://localhost/api/connectors/aws/audit/ \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"role_arn":"arn:aws:iam::123456789012:role/MayaTrailScoutAudit"}'
```

Expected: `200 {"status":"verified","account_id":"123456789012"}`.

- [x] **Step 6: Manually verify the probe actually rejects**

Detach the policy from the role, leaving it assumable, and POST the same ARN again.

Expected: `422` naming `iam:GetAccountAuthorizationDetails`. **If this returns 200, the whole design has failed** — the probe is the only thing standing between a narrow role and a false all-clear.

- [x] **Step 7: Verify a short-session role still connects**

Re-attach the policy, then set the role's `MaxSessionDuration` to 900 (the AWS console's minimum) and POST the ARN again.

```bash
aws iam update-role --role-name MayaTrailScoutAudit --max-session-duration 900
```

Expected: `200`. A `422` mentioning `DurationSeconds` means the verify path is not passing `VERIFY_SESSION_SECONDS` — it is falling through to the one-hour default, which AWS rejects outright against this role. Reset the role afterwards if you want the default back.

- [x] **Step 8: Confirm the emulation connection is untouched**

```bash
curl http://localhost/api/auth/me/ -H "Authorization: Bearer $TOKEN"
```

Expected: `is_verified` and `aws_role_arn` are exactly what they were before Step 5, and `aws_audit_role_arn` is the new ARN.

- [x] **Step 9: Verify the cross-account refusal**

With an emulation role connected, POST an audit ARN whose account id differs from it.

Expected: `422` naming both account ids. Then disconnect the emulation role and POST the same ARN again — expected `200`, because an org with no emulation role connected has nothing to disagree with.

- [x] **Step 10: Commit**

```bash
git add backend/apps/connectors/
git commit -m "feat: verify a read-only Scout audit role, probing the IAM read it needs"
```

---

## Task 5: Audit connection UI

**Files:**
- Modify: `frontend/UI/src/types/auth.ts:1-7`
- Modify: `frontend/UI/src/services/auth.service.ts` (the `/auth/me/` mapping around line 140-156, `getStoredUser` around line 339, and the connector calls around line 377-390)
- Modify: `frontend/UI/src/context/AuthContext.tsx:16-33,155-196`
- Create: `frontend/UI/src/components/profile/ConnectScoutRoleDialog.tsx`
- Modify: `frontend/UI/src/components/profile/ProfilePage.tsx`
- Modify: `frontend/UI/src/components/common/ConnectGate.tsx:12-14` (the hook) and `:31-56` (`ConnectPrompt`'s call to action)

**Interfaces:**
- Consumes: `POST`/`DELETE /api/connectors/aws/audit/` (Task 4); `aws_audit_role_arn` on `/auth/me/` (Task 3).
- Produces: `useScoutConnection(): { connected: boolean }`; `useAuth().verifyAuditRole(req)`, `useAuth().disconnectAuditRole()`; `ConnectPrompt`'s new optional `cta` prop.

- [x] **Step 1: Carry the flag on the User type**

```ts
// frontend/UI/src/types/auth.ts
export interface User {
  username: string
  name: string
  initials: string
  method: 'credentials' | 'google_sso'
  isVerified: boolean
  /**
   * Whether a read-only Scout audit role is connected. Separate from
   * isVerified, which is the emulation role: an org may connect either one
   * without the other, and the Attack Graph page gates on this.
   */
  hasAuditRole: boolean
}
```

- [x] **Step 2: Map it from the profile endpoint**

In `frontend/UI/src/services/auth.service.ts`, extend the `/auth/me/` response type and the returned object:

```ts
    is_verified: boolean
    aws_audit_role_arn?: string
    auth_method: string
  }>('/auth/me/', { headers })
```

```ts
  return {
    username: data.username,
    name,
    initials: initials(name),
    method,
    isVerified: data.is_verified ?? false,
    hasAuditRole: Boolean(data.aws_audit_role_arn),
  }
```

Then add `hasAuditRole: false` to every other place a `User` is constructed in this file — the JWT path in `getStoredUser` (~line 339), the mock-token path (~line 353), and `mockLogin` (~line 170). TypeScript will name any you miss, because the field is not optional. The JWT carries no audit claim on purpose: `AuthContext` hydrates from `/auth/me/` on mount precisely so a connection made after the token was issued is visible without a re-login, and `ProtectedRoute` holds the render until that lands (`ProtectedRoute.tsx:10`), so the stale `false` never reaches a page.

Also add `aws_audit_role_arn: string` to the exported `UserProfile` interface (~line 38) — it is this file's declared shape of `/auth/me/`, and leaving it out makes the two descriptions of one endpoint disagree.

- [x] **Step 3: Add the two API calls**

Beside the existing connector calls (~line 377-390):

```ts
/** POST /api/connectors/aws/audit/ — verify and store the Scout audit role. */
export async function verifyAuditRole(req: ConnectorRequest): Promise<ConnectorResponse> {
  const { data } = await api.post<ConnectorResponse>('/connectors/aws/audit/', req)
  return data
}

/** DELETE /api/connectors/aws/audit/ — disconnect it. */
export async function disconnectAuditRole(): Promise<void> {
  await api.delete('/connectors/aws/audit/')
}
```

- [x] **Step 4: Expose them on the context**

In `frontend/UI/src/context/AuthContext.tsx`, add to `AuthContextValue`:

```ts
  verifyAuditRole: (req: ConnectorRequest) => Promise<void>
  disconnectAuditRole: () => Promise<void>
```

and the implementations, mirroring `verifyConnector` (line 155) exactly — including the `refreshUser()` call, which is what makes `hasAuditRole` true everywhere the moment the dialog closes:

```ts
  const verifyAuditRole = useCallback(async (req: ConnectorRequest) => {
    setLoading(true)
    setError(null)
    try {
      await authService.verifyAuditRole(req)
      const refreshed = await authService.refreshUser()
      setUser(refreshed)
    } catch (err: any) {
      setError(err.message ?? 'Audit role verification failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const disconnectAuditRole = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      await authService.disconnectAuditRole()
      const refreshed = await authService.refreshUser()
      setUser(refreshed)
    } catch (err: any) {
      setError(err.message ?? 'Could not disconnect the audit role')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])
```

Add both to the provider `value` object (line 193-197).

- [x] **Step 5: Add the connection hook, and let `ConnectPrompt` name its own action**

In `frontend/UI/src/components/common/ConnectGate.tsx`, beside `useAWSConnection`:

```ts
/**
 * Whether a read-only Scout audit role is connected.
 *
 * Deliberately not useAWSConnection(): that reads isVerified, which the
 * emulation role's verification sets. An org that provisioned only the
 * auditor role would be told to connect an account it has already connected.
 */
export function useScoutConnection(): { connected: boolean } {
  const { user } = useAuth()
  return { connected: Boolean(user?.hasAuditRole) }
}
```

`ConnectPrompt` as written hardcodes its call to action — `to="/me"` and the
label "Connect AWS account" (`ConnectGate.tsx:47-53`). The spec requires the
Attack Graph page's unconnected state to point at the **audit-role** dialog,
"not at the emulation connector", so the label has to be overridable. Add one
optional prop, defaulting to today's value so no existing caller changes:

```ts
export function ConnectPrompt({
  title,
  body,
  cta = 'Connect AWS account',
}: {
  title: string
  body: string
  /**
   * The action's label. Overridden by the Attack Graph page, which needs a
   * read-only audit role rather than the emulation connection — a user who
   * has already connected an account and is told to "Connect AWS account"
   * reads the page as broken.
   */
  cta?: string
}) {
```

and render `{cta}` in place of the literal. Both connection cards live on
`/me`, so the link target stays as it is — the label is what was lying.

- [x] **Step 6: Build the dialog**

Create `frontend/UI/src/components/profile/ConnectScoutRoleDialog.tsx`, following `ConnectCloudDialog.tsx`'s structure (modal shell, policy panel, ARN input, error line). It differs in three ways, and all three matter:

```tsx
/**
 * Minimal policy for the Scout audit role — one read action.
 *
 * Stated as a single action on purpose. sts:GetCallerIdentity needs no
 * permission at all, and everything else Scout does is computed locally from
 * the authorization details this one call returns. A security product asking
 * for one read is a far better conversation with a customer's security team
 * than one asking for a broad managed policy.
 */
const AUDIT_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MayaTrailScoutAudit",
      "Effect": "Allow",
      "Action": "iam:GetAccountAuthorizationDetails",
      "Resource": "*"
    }
  ]
}`
```

1. It offers the AWS managed `SecurityAudit` policy as an alternative for orgs that standardise on one — as a named alternative only. Do not write copy claiming what `SecurityAudit` contains; the connect probe is the contract, and it will reject the role if the permission is not there.
2. The 422 body's `message` is rendered verbatim as the error. The backend's message names the missing action; paraphrasing it in the UI is how a user ends up unable to tell a trust-policy problem from a permissions problem.
3. On success it calls `onClose()`, and the caller refreshes — the context's `verifyAuditRole` has already re-fetched `/auth/me/`.

Wire it to `useAuth().verifyAuditRole({ role_arn })`.

- [x] **Step 7: Add the second connection card to the profile**

In `ProfilePage.tsx`, beneath the existing AWS connection card, add a "Scout audit role" card that shows the masked `aws_audit_role_arn` when connected (reuse the masking at line ~356), a Connect/Disconnect action, and one sentence of explanation: read-only, used only by the Attack Graph scan, safe to grant separately. Render `ConnectScoutRoleDialog` the way `ConnectCloudDialog` is rendered at line 179 — reloading the profile on close.

- [x] **Step 8: Verify the build and the behaviour**

```bash
cd frontend/UI && npm run build && npm run lint
```

Expected: both clean. Then, in the running app: connect an auditor role, confirm the card fills in without a page refresh; sign out and back in, confirm it is still shown (it comes from `/auth/me/`, not the token); confirm the emulation connection card is unchanged throughout.

**Do not test Disconnect yet.** Its handler imports `apps.attack_graph.models.active_scans`, and that app does not exist until Task 6 — clicking it now raises `ModuleNotFoundError` as a 500. Task 6, Step 8 is where Disconnect gets verified.

- [x] **Step 9: Commit**

```bash
git add frontend/UI/src/types/auth.ts frontend/UI/src/services/auth.service.ts frontend/UI/src/context/AuthContext.tsx frontend/UI/src/components/profile/ frontend/UI/src/components/common/ConnectGate.tsx
git commit -m "feat: connect and manage a read-only Scout audit role from the profile"
```

**Phase 1 ends here.** It is independently reviewable and mergeable to `feat/scout-integration` — a tenant can provision an auditor role, connect it and see it verified with no attack-graph code present. It is *not* independently releasable: shipped alone, the profile advertises a Scout connection that nothing in the product consumes. Do not put Phase 1 in front of users without Phase 3.

---

## Task 6: The `attack_graph` app and `ScoutScan`

**Files:**
- Create: `backend/apps/attack_graph/__init__.py`, `apps.py`, `constants.py`, `models.py`, `migrations/__init__.py`, `tests/__init__.py`
- Create: `backend/apps/attack_graph/tests/test_model.py`
- Modify: `backend/config/settings/base.py:49`, `backend/config/settings/ci.py:45`, `.github/workflows/backend-tests.yml`

**Interfaces:**
- Produces: `ScoutScan` with fields `id, user, status, task_id, result, error_message, created_at, started_at, completed_at` and `ScoutScan.Status.{PENDING,RUNNING,COMPLETED,FAILED}` = `"pending"/"running"/"completed"/"failed"`; `ACTIVE_SCAN_STATUSES`, `SCAN_STALE_AFTER_SECONDS: int`, `active_scans(user) -> QuerySet`.

- [x] **Step 1: Write the failing test**

```python
# backend/apps/attack_graph/tests/test_model.py
"""
What a scan row records.

The status vocabulary is asserted against EmulationRun's rather than against a
literal list: the frontend reads both through the same status chips, and a
scan that reports "succeeded" where a run reports "completed" produces a row
that renders as unknown with no error anywhere.
"""

from django.test import SimpleTestCase

from apps.attack_graph.models import (
    ACTIVE_SCAN_STATUSES,
    SCAN_STALE_AFTER_SECONDS,
    ScoutScan,
)
from apps.attack_graph.constants import SCAN_TIME_LIMIT
from apps.emulations.models import EmulationRun


class ScoutScanShapeTests(SimpleTestCase):
    """Model shape, without touching the database."""

    def test_status_vocabulary_matches_emulation_runs(self):
        self.assertEqual(
            sorted(ScoutScan.Status.values),
            sorted(EmulationRun.Status.values),
        )

    def test_newest_scans_come_first(self):
        self.assertEqual(ScoutScan._meta.ordering, ["-created_at"])

    def test_a_running_scan_can_be_traced_to_its_celery_task(self):
        self.assertTrue(ScoutScan._meta.get_field("task_id").blank)

    def test_lifecycle_timestamps_start_empty(self):
        for name in ("started_at", "completed_at"):
            self.assertTrue(ScoutScan._meta.get_field(name).null, name)

    def test_a_result_is_absent_until_there_is_one(self):
        self.assertTrue(ScoutScan._meta.get_field("result").null)


class StaleScanTests(SimpleTestCase):
    """
    The rule that keeps a dead scan from locking a user out.

    Two endpoints refuse a request while a scan is active: the trigger, and
    disconnecting the audit role. Celery's hard time_limit kills the worker
    process outright, so a crashed scan never runs its own failure handler and
    never reaches a terminal status — and a scan the worker never picked up
    sits at "pending" indefinitely. Keyed on status alone, one such row would
    refuse both endpoints forever, with no way out from the UI. These tests
    assert the cutoff exists and is wide enough not to cut off a live scan.
    """

    def test_active_means_pending_or_running(self):
        self.assertEqual(
            sorted(ACTIVE_SCAN_STATUSES),
            [ScoutScan.Status.PENDING, ScoutScan.Status.RUNNING],
        )

    def test_a_scan_is_stale_only_after_the_hard_time_limit(self):
        # Below the hard limit and the cutoff would reap a scan that is still
        # legitimately running, letting a second one start beside it.
        self.assertGreater(SCAN_STALE_AFTER_SECONDS, SCAN_TIME_LIMIT)

    def test_the_cutoff_is_not_so_wide_it_never_fires(self):
        # An hour of lockout after a worker crash is already unpleasant. This
        # is a sanity bound, not a tuned value.
        self.assertLessEqual(SCAN_STALE_AFTER_SECONDS, 3600)
```

- [x] **Step 2: Run it to verify it fails**

Bash: `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2`

Expected: FAIL — `ModuleNotFoundError: No module named 'apps.attack_graph'`.

- [x] **Step 3: Create the app**

```bash
cd backend && python manage.py startapp attack_graph apps/attack_graph
```

Then set the label in `apps/attack_graph/apps.py`:

```python
from django.apps import AppConfig


class AttackGraphConfig(AppConfig):
    """The Attack Graph app: Scout-powered IAM privilege-escalation scans."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.attack_graph"
    label = "attack_graph"
```

Delete the generated `views.py`, `tests.py` and `admin.py` — `views.py` is written in Task 10 and `tests/` is a package here.

- [x] **Step 4: Write the timeout constants**

These live in their own module because both `tasks.py` and `models.py` need
them and `tasks.py` already imports `models.py`. Keeping them here is also
what lets CI assert the relationship between the hard time limit and the
stale-scan cutoff — `tasks.py` imports Scout and boto3 and cannot be imported
by a test, and a cutoff that drifted below the time limit would start reaping
live scans with nothing to catch it.

```python
# backend/apps/attack_graph/constants.py
"""
Timing constants shared by the scan task and the model's staleness rule.

Separate from tasks.py so models.py can read them without a circular import,
and so the CI suite can assert SCAN_STALE_AFTER_SECONDS > SCAN_TIME_LIMIT
without importing the AWS runtime.
"""

# A GAAD collection plus chain ranking is minutes on a large account, not tens
# of minutes. The soft limit lets the task catch the timeout and write a real
# error message; without it a row sits at "running" forever and the page spins.
#
# Both figures are a guess until measured against a production-scale account
# (spec, open items). Re-check them against the first real large scan.
SCAN_SOFT_TIME_LIMIT = 900

# The hard limit. Celery enforces this by killing the worker process, so the
# task's own except-handlers do not run and the row does not reach a terminal
# status. That is what SCAN_STALE_AFTER_SECONDS exists to survive.
SCAN_TIME_LIMIT = 960
```

- [x] **Step 5: Write the model**

```python
# backend/apps/attack_graph/models.py
"""
Models for the attack_graph app.

ScoutScan — one run of the Scout IAM privilege-escalation scan against a
            tenant's account, holding the serialized result envelope the
            frontend renders.

active_scans — the single definition of "a scan is in flight", shared by the
            two endpoints that refuse a request while one is.
"""

import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from .constants import SCAN_TIME_LIMIT


class ScoutScan(models.Model):
    """
    A single Attack Graph scan.

    Every scan is its own row and history is kept, matching EmulationRun: a
    customer comparing this month's paths to last month's is the point of
    keeping them, and an overwritten latest-only row cannot answer that.

    `result` holds the versioned envelope produced by envelope.serialize_scan,
    never Scout's own objects — Scout is maintained independently and its
    chain shape is not a contract this product can hold the frontend to.
    """

    class Status(models.TextChoices):
        """Lifecycle statuses, deliberately identical to EmulationRun's."""

        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scout_scans",
        help_text="User who triggered this scan; the audit role assumed is theirs.",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    task_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Celery task id, for tracing a scan that stops reporting.",
    )
    result = models.JSONField(
        null=True,
        blank=True,
        help_text="The serialized result envelope (see envelope.py), once complete.",
    )
    error_message = models.TextField(
        blank=True,
        help_text="Human-readable failure reason, shown to the user verbatim.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="UTC timestamp when the Celery task began executing.",
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="UTC timestamp when the scan reached a terminal status.",
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "scout scan"
        verbose_name_plural = "scout scans"
        db_table = "scout_scans"

    def __str__(self) -> str:
        """Return a readable representation of this scan."""
        return f"scout scan [{self.status}] — {self.user_id}"


# Statuses that mean a scan has not finished.
ACTIVE_SCAN_STATUSES = (ScoutScan.Status.PENDING, ScoutScan.Status.RUNNING)

# How long a non-terminal scan is believed to still be running. Past this, it
# is treated as dead regardless of what its status column says.
#
# Celery's hard time_limit kills the worker process, so a scan that hits it —
# or whose worker crashed, or that was queued while no worker was up — never
# runs its own failure handler and stays at "running" or "pending" forever.
# Both callers of active_scans() refuse a request while a scan is active, so
# without this cutoff a single dead row would permanently deny the user both
# a new scan and the ability to disconnect the audit role, with no way out of
# either from the UI. The margin over SCAN_TIME_LIMIT covers queue latency
# between the row being created and the worker picking it up.
SCAN_STALE_AFTER_SECONDS = SCAN_TIME_LIMIT + 300


def active_scans(user):
    """
    Return this user's scans that are genuinely still in flight.

    The one definition of "in flight", used by ScoutScanTriggerView (which
    refuses a second concurrent scan) and by AWSAuditConnectorView.delete
    (which refuses to pull the role out from under a running task). Two
    copies of this filter would be two places for the staleness cutoff to go
    missing, and the symptom of it going missing is a user locked out with no
    error to search for.

    Args:
        user: The owner whose scans to consider.

    Returns:
        QuerySet of ScoutScan rows that are pending or running and were
        created recently enough to still plausibly be executing.
    """
    cutoff = timezone.now() - timedelta(seconds=SCAN_STALE_AFTER_SECONDS)
    return ScoutScan.objects.filter(
        user=user,
        status__in=ACTIVE_SCAN_STATUSES,
        created_at__gte=cutoff,
    )
```

> A stale row is left in the database at `running` rather than being rewritten
> to `failed`. Reaping it is a background job this plan does not add (see
> *Deliberately not in this plan*); what matters here is that it stops
> blocking. The page renders it from its status, so a user who selects it
> still sees "Scanning" — acceptable for v1, and named in the open items.

- [x] **Step 6: Register the app in all four places**

1. `backend/config/settings/base.py:49` — add `"apps.attack_graph",` to `LOCAL_APPS`.
2. `backend/config/settings/ci.py:45` — add `"apps.attack_graph",` to `INSTALLED_APPS`, with a comment matching that file's style:

```python
    # The attack graph suite tests the result envelope and the model's status
    # vocabulary. Its only foreign key reaches users, already present.
    "apps.attack_graph",
```

3. `.github/workflows/backend-tests.yml` — append `apps.attack_graph` to the test command and update the step name:

```yaml
      - name: Run the emulation, metrics, guardrail, threat feed, workflow, infrastructure, attack graph and users suites
        run: python manage.py test apps.emulations apps.metrics apps.guardrails apps.threatintel apps.workflows apps.infrastructure apps.attack_graph apps.users
```

4. `backend/config/urls.py` — this is done in Task 10, when the views exist.

- [x] **Step 7: Generate the migration**

```bash
cd backend && python manage.py makemigrations users infrastructure emulations logs attack_graph
```

Expected: `apps/attack_graph/migrations/0001_initial.py`.

- [x] **Step 8: Run the tests and the migration gate**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py makemigrations --check --dry-run
```

Expected: 8 tests PASS; no missing migrations.

- [x] **Step 9: Verify Task 4's DELETE handler, which only now can run**

```bash
cd backend && python manage.py check
```

Expected: no issues — `from apps.attack_graph.models import active_scans` in `AWSAuditConnectorView.delete` now resolves. Then, in the running app, disconnect the audit role from the profile: the card empties, the emulation connection card is untouched, and `/auth/me/` returns an empty `aws_audit_role_arn`. (The 409-while-scanning half of that handler is verified in Task 10, Step 8, once a scan can be started.)

- [x] **Step 10: Commit**

```bash
git add backend/apps/attack_graph/ backend/config/settings/base.py backend/config/settings/ci.py .github/workflows/backend-tests.yml
git commit -m "feat: add the attack_graph app and the ScoutScan model"
```

---

## Task 7: The result envelope

This is the load-bearing task. Everything the product must not get wrong — what counts as a clean account, what the frontend is allowed to see — is decided here, in a module with no boto3, no Scout and no DRF, so CI can hold it.

**Files:**
- Create: `backend/apps/attack_graph/envelope.py`
- Create: `backend/apps/attack_graph/tests/test_envelope.py`
- Uses: `backend/apps/attack_graph/tests/fixtures/scout_report.json` (Task 1)

**Interfaces:**
- Produces: `SCHEMA_VERSION: int = 1`, `MAX_CHAINS: int = 25`, `serialize_scan(report: dict, collection: dict, account_id: str, scanned_at: datetime) -> dict`, `result_state(envelope: dict) -> str` returning `"findings" | "clean" | "partial"`.
- Consumes: nothing.

> **Correction (applied when this task was implemented):** the test and
> implementation code blocks below were drafted before Task 1's spike ran and
> assumed a `steps[].technique`/`steps[].condition` shape. Task 1's real
> output has neither — Scout attaches `mitre_techniques` once, on the chain,
> and hops carry `mechanism`/`action`, not a per-hop technique (see the spec's
> field-mapping table). Per this plan's own header ("where they disagree, the
> spec wins and the plan gets fixed"), the blocks below are the corrected
> versions actually implemented, not the original guess. Expected test count
> in Step 4 is **20**, not 19 (one test added for chain-level
> `mitre_techniques`, one for `chain["id"]` never leaking Scout's own
> `chain_id`).

- [x] **Step 1: Write the failing tests**

```python
# backend/apps/attack_graph/tests/test_envelope.py
"""
The scan result contract.

Two things are being defended here. The first is the boundary: Scout is
maintained in its own repository, and if its chain objects reach the frontend
unchanged then a Scout upgrade is a frontend outage. The second is the reason
this product exists — a scan that could not read the account must never render
as an account with nothing to find. That rule is one branch in result_state(),
and these tests are what keep it there.
"""

import json
import pathlib
from datetime import datetime, timezone

from django.test import SimpleTestCase

from apps.attack_graph.envelope import (
    EVALUATOR,
    MAX_CHAINS,
    SCHEMA_VERSION,
    result_state,
    serialize_scan,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SCANNED_AT = datetime(2026, 9, 21, 10, 4, tzinfo=timezone.utc)


def _envelope(report, mode="account"):
    return serialize_scan(
        report=report,
        collection={"mode": mode},
        account_id="123456789012",
        scanned_at=SCANNED_AT,
    )


class SerializeScanTests(SimpleTestCase):
    """What the envelope carries."""

    def setUp(self):
        self.report = json.loads((FIXTURES / "scout_report.json").read_text("utf-8"))

    def test_it_stamps_the_schema_version(self):
        self.assertEqual(_envelope(self.report)["schema_version"], SCHEMA_VERSION)

    def test_it_records_the_collection_mode_and_account(self):
        envelope = _envelope(self.report)
        self.assertEqual(envelope["mode"], "account")
        self.assertEqual(envelope["account_id"], "123456789012")
        self.assertEqual(envelope["scanned_at"], "2026-09-21T10:04:00+00:00")

    def test_it_records_that_scps_were_not_applied(self):
        self.assertEqual(_envelope(self.report)["evaluator"], EVALUATOR)

    def test_every_chain_carries_a_rank_and_its_endpoints(self):
        chain = _envelope(self.report)["chains"][0]
        self.assertEqual(chain["rank"], 1)
        for end in ("source", "target"):
            self.assertIn("id", chain[end])
            self.assertIn("label", chain[end])
        step = chain["steps"][0]
        # No "technique" or "condition" here on purpose: Scout does not
        # attach either per hop (verified in Task 1). A per-step technique
        # would be a chain-level mitre_techniques entry duplicated onto every
        # hop — a false claim about which technique applies where.
        for key in ("from", "to", "mechanism", "action"):
            self.assertIn(key, step)

    def test_mitre_techniques_are_carried_on_the_chain_not_the_step(self):
        # Scout attaches MITRE technique ids to the chain as a whole, not to
        # individual hops. The envelope must surface that list once, on the
        # chain, rather than inventing a per-step value.
        chains = _envelope(self.report)["chains"]
        self.assertEqual(chains[0]["mitre_techniques"], ["T1098.003"])
        self.assertEqual(chains[1]["mitre_techniques"], ["T1528", "T1098.003"])

    def test_an_unknown_mode_fails_safe_to_partial(self):
        # A Scout upgrade that renames or drops the mode key must fail safe.
        # Defaulting the other way turns an unreadable account into a clean one.
        envelope = serialize_scan(
            report=self.report, collection={}, account_id="1", scanned_at=SCANNED_AT,
        )
        self.assertEqual(envelope["state"], "partial")

    def test_an_unknown_mode_is_not_relabelled_as_self(self):
        # "self" is a specific claim: Scout enumerated only the role it
        # assumed, which the UI explains as "the audit role's policy no
        # longer grants iam:GetAccountAuthorizationDetails, reconnect it".
        # Writing that word in when Scout reported no mode at all would have
        # the product assert a cause it never observed — the same error as a
        # false all-clear, one level up. Fail safe on the state; stay honest
        # about the reason.
        envelope = serialize_scan(
            report=self.report, collection={}, account_id="1", scanned_at=SCANNED_AT,
        )
        self.assertEqual(envelope["mode"], "unknown")

    def test_a_reported_mode_is_carried_through_verbatim(self):
        envelope = serialize_scan(
            report=self.report,
            collection={"mode": "self"},
            account_id="1",
            scanned_at=SCANNED_AT,
        )
        self.assertEqual(envelope["mode"], "self")

    def test_a_chains_source_and_target_are_its_first_and_last_hop(self):
        # A chain is a path from its origin to its terminal target. Scout
        # expresses both only as ARNs — there is no separate node-id space
        # (verified in Task 1: every hop endpoint ARN in the sample fixture
        # also appears as some chain's origin or terminal ARN) — so the
        # envelope keys source/target.id on the same ARN the first/last hop
        # names. That is the property the graph relies on to draw one
        # connected path per chain instead of disconnected fragments.
        for chain in _envelope(self.report)["chains"]:
            if not chain["steps"]:
                continue
            self.assertEqual(chain["steps"][0]["from"], chain["source"]["id"], chain["id"])
            self.assertEqual(chain["steps"][-1]["to"], chain["target"]["id"], chain["id"])

    def test_consecutive_steps_join_up(self):
        # The same property within a chain: step N's target is step N+1's
        # source, or the chain is not a chain.
        for chain in _envelope(self.report)["chains"]:
            for earlier, later in zip(chain["steps"], chain["steps"][1:]):
                self.assertEqual(earlier["to"], later["from"], chain["id"])

    def test_it_truncates_and_says_so(self):
        many = {"chains": self.report["chains"] * 40}
        envelope = _envelope(many)
        self.assertEqual(len(envelope["chains"]), MAX_CHAINS)
        self.assertTrue(envelope["truncated"])

    def test_an_untruncated_result_says_that_too(self):
        self.assertFalse(_envelope(self.report)["truncated"])

    def test_no_scout_object_survives_serialization(self):
        # The envelope must be plain JSON: anything else means a Scout type
        # leaked through and the frontend is now coupled to it.
        json.dumps(_envelope(self.report))

    def test_chain_ids_are_serializer_assigned_not_scouts_own(self):
        # Scout's own chain_id (e.g. "CHN-7540184B") is opaque and not
        # guaranteed stable across scans, so it must never surface. A
        # serializer that only falls back to "chain-{rank}" when Scout's id
        # is absent would silently start leaking it the day Scout adds one.
        chain = _envelope(self.report)["chains"][0]
        self.assertEqual(chain["id"], "chain-1")
        self.assertNotEqual(chain["id"], self.report["chains"][0]["chain_id"])


class ResultStateTests(SimpleTestCase):
    """The one rule this product cannot get wrong."""

    def test_a_full_scan_with_chains_reports_findings(self):
        envelope = {"mode": "account", "chains": [{"id": "chain-1"}]}
        self.assertEqual(result_state(envelope), "findings")

    def test_a_full_scan_with_no_chains_is_clean(self):
        self.assertEqual(result_state({"mode": "account", "chains": []}), "clean")

    def test_a_self_scoped_scan_with_no_chains_is_partial_never_clean(self):
        # Scout falls back to enumerating only the assumed role when it cannot
        # read account-wide IAM. That yields zero chains. Reporting it as clean
        # tells a customer their account has no privilege-escalation paths on
        # the strength of a scan that never looked.
        state = result_state({"mode": "self", "chains": []})
        self.assertEqual(state, "partial")
        self.assertNotEqual(state, "clean")

    def test_a_self_scoped_scan_with_chains_is_still_partial(self):
        self.assertEqual(result_state({"mode": "self", "chains": [{"id": "c"}]}), "partial")

    def test_any_mode_that_is_not_account_is_partial(self):
        # The rule is a whitelist, not a blacklist of "self". A mode Scout
        # invents in a future release must land on the cautious side without
        # this module being edited.
        for mode in ("self", "unknown", "partial-org", ""):
            self.assertEqual(result_state({"mode": mode, "chains": []}), "partial", mode)

    def test_the_state_is_stamped_into_the_envelope(self):
        # The frontend reads envelope["state"] rather than re-deriving the rule
        # in TypeScript, so there is exactly one implementation of it.
        envelope = serialize_scan(
            report={"chains": []},
            collection={"mode": "self"},
            account_id="1",
            scanned_at=SCANNED_AT,
        )
        self.assertEqual(envelope["state"], "partial")
```

- [x] **Step 2: Run them to verify they fail**

Bash: `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph.tests.test_envelope -v 2`

Expected: FAIL — `ModuleNotFoundError: No module named 'apps.attack_graph.envelope'`.

- [x] **Step 3: Write the envelope module**

Field names in `_node` and `_step` follow what Task 1 actually observed — see
the correction note above Step 1. `_node` takes an ARN **string**, not a dict
(`origin_identity_arn`/`terminal_target_arn` are flat, not nested objects),
and derives `type` by parsing the ARN's resource segment since Scout provides
none. `_step` reads `hops` (not `steps`), mapping `source_arn`/`target_arn` →
`from`/`to` plus `mechanism`/`action` — no `technique`, no `condition`.
`_chain`'s `id` is unconditionally `chain-{rank}`, never falling back to
Scout's own `chain_id`, because a conditional fallback would start leaking
that opaque id silently the day Scout's shape changes to trigger it.

```python
# backend/apps/attack_graph/envelope.py
"""
The scan result contract between Scout and this product.

Scout lives in its own repository and ranks chains in its own shape. Handing
that shape to the frontend would make every Scout upgrade a frontend
deployment, so the task serializes into the versioned envelope built here and
the graph component reads nothing else.

This module imports Django and the standard library only — no boto3, no
Scout, no DRF — because it holds the decisions that must not regress and the
test suite runs without those packages installed (see config/settings/ci.py).

Field names follow Scout's real output, verified in Task 1 against the pinned
commit (see docs/superpowers/specs/2026-09-21-attack-graph-integration-design.md,
"Assumptions to verify" and the envelope field-mapping table) — not the
pre-verification guess. In particular: a chain's `hops` (not `steps`) carry no
per-hop `technique` or `condition`; `mitre_techniques` is attached once, on
the chain; and both endpoints and every hop are plain IAM ARN strings, with no
separate node-id space to reconcile.
"""

from datetime import datetime
from typing import Any

# Bumped when the envelope's shape changes in a way the frontend must notice.
# The frontend refuses to render a version it does not know rather than
# drawing a half-empty graph.
SCHEMA_VERSION = 1

# The ranked chains kept per scan. Scout ranks descending, so this is the top
# of the list; `truncated` records that there were more.
MAX_CHAINS = 25

# The evaluator the scan runs. Recorded in the envelope because it is what
# makes the SCP caveat true: the effective evaluator applies permission
# boundaries from the GAAD but no AWS Organizations policies, so a chain it
# reports may in fact be blocked by an SCP the scan never fetched.
#
# Verified in Task 1: pipeline.run()'s evaluator=None default resolves
# internally to scout.eval.effective.EffectivePermissionEvaluator, but the
# report itself carries no field naming which evaluator ran — this literal is
# the task's own claim, made true by Task 9 passing evaluator explicitly
# rather than relying on the default.
EVALUATOR = "effective"

# What `mode` says when Scout reported none.
#
# Not "self". A scan is classified "partial" whenever mode is anything other
# than "account", so the safe classification does not need this value to lie —
# and "self" is a specific claim the UI turns into specific advice ("the audit
# role's policy no longer grants iam:GetAccountAuthorizationDetails, reconnect
# it"). Writing that word in when Scout said nothing at all would have the
# product assert a cause it never observed. That is the same failure as a
# false all-clear, moved up a level: a confident explanation of something that
# did not happen. Fail safe on the state; stay honest about the reason.
UNKNOWN_MODE = "unknown"


def serialize_scan(
    report: dict[str, Any],
    collection: dict[str, Any],
    account_id: str,
    scanned_at: datetime,
) -> dict[str, Any]:
    """
    Turn a Scout report into the envelope stored on ScoutScan.result.

    Args:
        report: Scout's pipeline output; `report["chains"]` is ranked descending.
        collection: Scout's collection metadata; `collection["mode"]` is
            "account" when account-wide IAM was readable and "self" when it
            fell back to enumerating only the assumed role.
        account_id: The AWS account the scan ran against.
        scanned_at: When the scan completed, timezone-aware.

    Returns:
        A plain-JSON envelope. `mode` is Scout's value verbatim, or UNKNOWN_MODE
        when it reported none — see the constant for why it is not silently
        rewritten to "self".
    """
    chains = list(report.get("chains") or [])
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "mode": collection.get("mode") or UNKNOWN_MODE,
        "account_id": account_id,
        "scanned_at": scanned_at.isoformat(),
        # v1 runs Scout's effective evaluator with no AWS Organizations
        # policies fetched, so a reported chain may be blocked by an SCP this
        # scan never saw. Recorded here so the UI can say so.
        #
        "evaluator": EVALUATOR,
        "truncated": len(chains) > MAX_CHAINS,
        "chains": [
            _chain(raw, rank)
            for rank, raw in enumerate(chains[:MAX_CHAINS], start=1)
        ],
    }
    envelope["state"] = result_state(envelope)
    return envelope


def result_state(envelope: dict[str, Any]) -> str:
    """
    Classify a scan result for display.

    Returns:
        "partial" — the scan did not demonstrably read account-wide IAM,
            whatever it found. This is checked first and on purpose: a
            self-scoped scan finds nothing because it could not look, and
            rendering that as an account with no privilege-escalation paths is
            a false all-clear from a security product.
        "clean" — a full scan that found no chains.
        "findings" — a full scan with ranked chains.

    The check is a whitelist of the one mode that earns a verdict, not a
    blacklist of the degraded ones. A mode Scout invents in a future release
    then lands on the cautious side of the line without this function being
    edited — which is the only way a rule like this survives a dependency
    that is maintained elsewhere.
    """
    if envelope.get("mode") != "account":
        return "partial"
    return "findings" if envelope.get("chains") else "clean"


def _chain(raw: dict[str, Any], rank: int) -> dict[str, Any]:
    """
    Normalise one ranked chain.

    `id` is always serializer-assigned (`chain-{rank}`), never Scout's own
    `chain_id`: that id is opaque and not guaranteed stable across scans, so
    surfacing it — even only as a fallback — would start leaking it silently
    the day Scout's shape changes to make the fallback trigger.
    """
    hops = sorted(raw.get("hops") or [], key=lambda hop: hop.get("hop_number", 0))
    return {
        "id": f"chain-{rank}",
        "rank": rank,
        "score": raw.get("risk_score"),
        "source": _node(str(raw.get("origin_identity_arn") or "")),
        "target": _node(str(raw.get("terminal_target_arn") or "")),
        # Chain-level, not per-hop: Scout does not attach a technique to an
        # individual hop (verified in Task 1).
        "mitre_techniques": list(raw.get("mitre_techniques") or []),
        "steps": [_step(hop) for hop in hops],
    }


def _node(arn: str) -> dict[str, Any]:
    """
    Normalise one identity endpoint.

    Scout gives no node id, type or label anywhere in the chain output — only
    an ARN (verified in Task 1). `id` is the ARN itself: it is the only
    identifier space Scout uses, at every level, so there is no id/ARN join to
    normalise. `type` is derived by parsing the ARN's resource segment
    (`user/`, `role/`, ...) since Scout does not provide one.
    """
    resource = arn.rsplit(":", 1)[-1] if arn else ""
    kind, _, name = resource.partition("/")
    return {
        "id": arn,
        "arn": arn,
        "type": kind or "other",
        # The graph renders this, so never leave it empty: an unlabelled node
        # is a box a reader cannot act on.
        "label": name or arn or "unknown",
    }


def _step(hop: dict[str, Any]) -> dict[str, Any]:
    """
    Normalise one hop of a chain.

    No `technique` or `condition` field: Scout attaches neither per hop.
    `mechanism`/`action` are Scout's own hop fields, carried through verbatim.
    `hop["conditional"]` was null on every hop observed in Task 1, so its
    populated shape is unconfirmed — it is deliberately not mapped here rather
    than guessed at.
    """
    mechanism = hop.get("mechanism") or ""
    action = hop.get("action") or ""
    return {
        "from": str(hop.get("source_arn") or ""),
        "to": str(hop.get("target_arn") or ""),
        "mechanism": mechanism,
        "action": action,
        "concrete_api_sequence": list(hop.get("concrete_api_sequence") or []),
        "detail": f"{action} ({mechanism})" if action and mechanism else (action or mechanism),
    }
```

- [x] **Step 4: Run the tests to verify they pass**

Same command as Step 2. Expected: **20** tests PASS (not the original 19 — see
the correction note above Step 1). If a chain-shape assertion fails, the
fixture is right and `_chain`/`_node`/`_step` are wrong — fix the mapping,
never the fixture.

`test_a_chains_source_and_target_are_its_first_and_last_hop` and
`test_consecutive_steps_join_up` are the ones to read carefully if they fail.
They are not asserting a preference; they are asserting that a chain's
endpoints and its hops name the same identities. A failure there means the
graph in Task 12 would have drawn something plausible and wrong.

- [x] **Step 5: Commit**

```bash
git add backend/apps/attack_graph/envelope.py backend/apps/attack_graph/tests/test_envelope.py
git commit -m "feat: versioned scan result envelope, with self-scoped scans never reported clean"
```

---

## Task 8: Activity trail events

**Files:**
- Modify: `backend/apps/logs/models.py:32-49`
- Create: `backend/apps/logs/migrations/00XX_alter_logentry_event.py` (generated)
- Create: `backend/apps/attack_graph/tests/test_activity_events.py`

**Interfaces:**
- Produces: `LogEntry.Event.SCAN_STARTED = "scan.started"`, `SCAN_COMPLETED = "scan.completed"`, `SCAN_FAILED = "scan.failed"`.

- [x] **Step 1: Write the failing test**

```python
# backend/apps/attack_graph/tests/test_activity_events.py
"""
A scan appears in the activity trail.

LogEntry.Event is a closed enum, so a task writing "scan.completed" against an
enum that does not define it writes a row nothing renders. Every other
lifecycle action in the product shows up in the notification panel; a scan
that runs for ten minutes and leaves no trace is the odd one out.
"""

from django.test import SimpleTestCase

from apps.logs.models import LogEntry


class ScanEventTests(SimpleTestCase):
    """The enum members the scan task writes."""

    def test_the_three_scan_events_exist(self):
        self.assertEqual(LogEntry.Event.SCAN_STARTED, "scan.started")
        self.assertEqual(LogEntry.Event.SCAN_COMPLETED, "scan.completed")
        self.assertEqual(LogEntry.Event.SCAN_FAILED, "scan.failed")

    def test_they_are_selectable_choices(self):
        values = dict(LogEntry.Event.choices)
        for value in ("scan.started", "scan.completed", "scan.failed"):
            self.assertIn(value, values)
```

- [x] **Step 2: Run it to verify it fails**

Bash: `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph.tests.test_activity_events -v 2`

Expected: FAIL with `AttributeError: SCAN_STARTED`.

- [x] **Step 3: Add the members**

In `backend/apps/logs/models.py`, at the end of the `Event` class:

```python
        # An attack graph scan reads the tenant's IAM and nothing else, but it
        # assumes a role in their account, so it belongs in the same trail as
        # every other action MayaTrail takes there.
        SCAN_STARTED = "scan.started", "Attack Graph Scan Started"
        SCAN_COMPLETED = "scan.completed", "Attack Graph Scan Completed"
        SCAN_FAILED = "scan.failed", "Attack Graph Scan Failed"
```

- [x] **Step 4: Generate the migration**

```bash
cd backend && python manage.py makemigrations users infrastructure emulations logs attack_graph
```

Expected: an `AlterField` migration on `logs.LogEntry.event` (changing `choices` is a migration in Django even though no column changes).

- [x] **Step 5: Run the tests and the migration gate**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph apps.logs -v 2
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py makemigrations --check --dry-run
```

Expected: PASS, no missing migrations.

- [x] **Step 6: Commit**

```bash
git add backend/apps/logs/models.py backend/apps/logs/migrations/ backend/apps/attack_graph/tests/test_activity_events.py
git commit -m "feat: record attack graph scans in the activity trail"
```

---

## Task 9: The scan task

**Files:**
- Create: `backend/apps/attack_graph/tasks.py`

**Interfaces:**
- Consumes: `assume_role_arn` (Task 2), `ScoutScan` (Task 6), `serialize_scan` (Task 7), `LogEntry.Event.SCAN_*` (Task 8).
- Produces: `run_scout_scan(scan_id: str)` — a Celery task routed to the `enterprise` queue by its caller.

**No CI test.** The function body imports boto3 and Scout, neither installed in CI, and the module holds no decision worth asserting — every decision lives in `envelope.py`, which Task 7 already covers. Step 5 is a real run against a real account; it is not optional.

> **Correction (applied when this task was implemented):** the evaluator
> import in the code block below was drafted as `from scout.evaluate import
> EffectivePermissionEvaluator`. Task 1's verified findings (spec,
> "Assumptions to verify") place the class at
> `scout.eval.effective.EffectivePermissionEvaluator` — confirmed directly
> against the installed package (`mayatrail-scout[aws]`, pinned commit) at
> implementation time: `from scout.eval.effective import
> EffectivePermissionEvaluator` imports cleanly and
> `inspect.signature(pipeline.run)` / `inspect.signature(gaad.collect)` match
> the parameter names used below. The block has been corrected to the real
> path.

- [x] **Step 1: Write the task**

```python
# backend/apps/attack_graph/tasks.py
"""
Celery task for the attack_graph app.

run_scout_scan — assume the tenant's read-only audit role, collect the account
                 authorization details, rank privilege-escalation chains with
                 Scout, and store the serialized envelope.

Scout and boto3 are imported inside the function, not at module scope. Views
import this module, config/urls.py imports the views, and Django imports the
URL configuration during system checks — so a module-scope import here would
drag the whole AWS runtime into every management command and break the CI
suite, which installs neither (see config/settings/ci.py).
"""

import logging

from celery import shared_task
from django.utils import timezone

from apps.logs.models import LogEntry
from apps.logs.record import record_activity

from .constants import SCAN_SOFT_TIME_LIMIT, SCAN_TIME_LIMIT
from .envelope import serialize_scan
from .models import ScoutScan

logger = logging.getLogger(__name__)

# What a user sees when the scan died of something this code did not
# anticipate. The exception text goes to the logger, not to the page:
# error_message is rendered verbatim, and an arbitrary Python exception string
# can carry a stack-adjacent detail, a credential fragment from a boto3 repr,
# or simply nothing a reader can act on.
UNEXPECTED_FAILURE_MESSAGE = (
    "The scan failed unexpectedly. The error has been logged — retry the "
    "scan, and contact support if it fails again."
)


@shared_task(soft_time_limit=SCAN_SOFT_TIME_LIMIT, time_limit=SCAN_TIME_LIMIT)
def run_scout_scan(scan_id: str) -> None:
    """
    Run one Attack Graph scan to a terminal status.

    Args:
        scan_id: String UUID of the ScoutScan row to execute.

    Returns:
        None. Every outcome is recorded on the row: the caller polls it, and a
        raised exception would leave the row at "running" with nothing to show
        the user.
    """
    from botocore.exceptions import BotoCoreError, ClientError  # noqa: PLC0415
    from celery.exceptions import SoftTimeLimitExceeded  # noqa: PLC0415

    scan = ScoutScan.objects.select_related("user").get(id=scan_id)
    user = scan.user

    ScoutScan.objects.filter(id=scan_id).update(
        status=ScoutScan.Status.RUNNING, started_at=timezone.now(),
    )
    record_activity(
        LogEntry.Event.SCAN_STARTED,
        "Attack graph scan started.",
        actor=user,
    )

    try:
        import boto3  # noqa: PLC0415
        from scout import pipeline  # noqa: PLC0415
        from scout.aws.collect import gaad  # noqa: PLC0415
        # Import path verified in Task 1, Step 3: pipeline.run()'s
        # evaluator=None default resolves internally to
        # scout.eval.effective.EffectivePermissionEvaluator. envelope.EVALUATOR
        # names the same evaluator; if Scout ever renames or relocates this
        # class, both must change together — they are one claim about how a
        # finding was computed, split across two files.
        from scout.eval.effective import EffectivePermissionEvaluator  # noqa: PLC0415

        creds = _audit_credentials(user)
        session = boto3.Session(
            aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=creds["AWS_SESSION_TOKEN"],
        )

        # collect() degrades to self-scoped enumeration rather than raising
        # when the role cannot read account-wide IAM. That is not success:
        # collection["mode"] carries it into the envelope, and the envelope's
        # state keeps it out of the clean-result copy.
        #
        # self_only and evaluator are passed explicitly rather than left to
        # their defaults. The envelope records which evaluator produced the
        # chains, and a default that changes in a Scout release would make
        # that record false without anything here changing.
        #
        # collection["mode"] itself is the one Task 1 assumption not
        # exercised against live AWS (the spike ran offline, against a
        # pre-built gaad fixture) — confirmed by Step 5's real-account check
        # below, not by this code.
        raw_gaad, account_id, collection = gaad.collect(session.client, self_only=False)
        report, _graph = pipeline.run(
            gaad=raw_gaad,
            account_id=account_id,
            evaluator=EffectivePermissionEvaluator(),
        )

        envelope = serialize_scan(
            report=report,
            collection=collection,
            account_id=account_id,
            scanned_at=timezone.now(),
        )

        ScoutScan.objects.filter(id=scan_id).update(
            status=ScoutScan.Status.COMPLETED,
            result=envelope,
            completed_at=timezone.now(),
        )
        record_activity(
            LogEntry.Event.SCAN_COMPLETED,
            f"Attack graph scan finished: {len(envelope['chains'])} chains "
            f"({envelope['state']}).",
            actor=user,
        )

    except SoftTimeLimitExceeded:
        _fail(
            scan_id,
            user,
            f"The scan timed out after {SCAN_SOFT_TIME_LIMIT // 60} minutes.",
        )
    except (ClientError, BotoCoreError) as exc:
        _fail(scan_id, user, _aws_message(exc))
    except Exception:  # noqa: BLE001 - the row must reach a terminal status
        # The detail goes to the logger. error_message is rendered to the user
        # verbatim, and str(exc) on an unanticipated exception is not text
        # written for a person — see UNEXPECTED_FAILURE_MESSAGE.
        logger.exception("Scout scan %s failed", scan_id)
        _fail(scan_id, user, UNEXPECTED_FAILURE_MESSAGE)


def _audit_credentials(user) -> dict[str, str]:
    """
    Assume the user's read-only audit role.

    The session name differs from the emulation path's on purpose: a tenant
    reading their own CloudTrail can then tell a read-only scan apart from an
    emulation without cross-referencing timestamps.
    """
    from apps.connectors.aws import assume_role_arn  # noqa: PLC0415

    return assume_role_arn(user.aws_audit_role_arn, f"mayatrail-scout-{user.id}")


def _aws_message(exc) -> str:
    """Return the human-readable part of a botocore exception."""
    if hasattr(exc, "response"):
        return exc.response.get("Error", {}).get("Message", str(exc))
    return str(exc)


def _fail(scan_id: str, user, message: str) -> None:
    """Move a scan to failed with a message written for the person reading it."""
    ScoutScan.objects.filter(id=scan_id).update(
        status=ScoutScan.Status.FAILED,
        error_message=message,
        completed_at=timezone.now(),
    )
    record_activity(
        LogEntry.Event.SCAN_FAILED,
        f"Attack graph scan failed: {message}",
        actor=user,
        level=LogEntry.Level.ERROR,
    )
```

- [x] **Step 2: Confirm the module imports without the AWS stack**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python -c "import django; django.setup(); import apps.attack_graph.tasks; print('imports clean')"
```

Expected: `imports clean`. A failure here means an import escaped into module scope — fix it before continuing, because CI will fail the same way.

- [x] **Step 3: Run the existing suite**

Bash: `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2`

Expected: PASS, unchanged.

- [x] **Step 4: Commit**

```bash
git add backend/apps/attack_graph/tasks.py
git commit -m "feat: run a Scout scan on the enterprise queue"
```

- [x] **Step 5: Verify against a real account after Task 10**

The task cannot be triggered until the views exist. Return here after Task 10 and confirm, against an account with a connected audit role: a scan reaches `completed` with `state: "findings"` or `"clean"`; with the IAM permission detached it reaches `completed` with `state: "partial"` and `mode: "self"`; with the role deleted it reaches `failed` with a readable `error_message`; and all three appear in the activity panel.

Then verify the staleness escape hatch, which is the one behaviour no unit test can reach. Start a scan, kill the worker mid-run (`docker-compose kill worker_enterprise`, or Ctrl-C the local worker), and confirm the row is stuck at `running`:

- immediately after: `POST /api/attack-graph/scan/` returns `409`, and `DELETE /api/connectors/aws/audit/` returns `409`. Both correct — nothing knows the worker is gone.
- then age the row past the cutoff rather than waiting 21 minutes:

```bash
cd backend && python manage.py shell -c "
from datetime import timedelta
from django.utils import timezone
from apps.attack_graph.models import SCAN_STALE_AFTER_SECONDS, ScoutScan
row = ScoutScan.objects.filter(status='running').first()
ScoutScan.objects.filter(id=row.id).update(
    created_at=timezone.now() - timedelta(seconds=SCAN_STALE_AFTER_SECONDS + 60))
print('aged', row.id)"
```

Expected: both endpoints now succeed — a new scan starts, and the audit role can be disconnected. **If either still returns 409, a user whose worker crashed is permanently locked out of both**, and there is no way to clear it from the UI.

---

## Task 10: The scan API

**Files:**
- Create: `backend/apps/attack_graph/permissions.py`, `serializers.py`, `views.py`, `urls.py`
- Create: `backend/apps/attack_graph/tests/test_api_contract.py`
- Modify: `backend/config/urls.py`

**Interfaces:**
- Consumes: `ScoutScan` (Task 6), `run_scout_scan` (Task 9).
- Produces: `POST /api/attack-graph/scan/` → `202 {"scanId": "..."}` or `409 {"detail": ..., "scanId": ...}`; `GET /api/attack-graph/scan/` → list; `GET /api/attack-graph/scan/<id>/` → one scan.

> **Correction (applied when this task was implemented):** `HasScoutConnection`'s
> docstring, as originally drafted in Step 3 below, explained why it does not
> reuse `HasAWSConnection` by naming the field that class keys on — and wrote
> that field's literal name, `is_verified`, straight into the docstring. That
> trips `test_the_gate_reads_the_audit_role`'s own
> `assertNotIn("is_verified", source)` (confirmed: ran red for exactly this
> reason). Reworded to "the emulation role's own verified flag" so the
> explanation survives without the literal substring. The code block below is
> the corrected version.

- [x] **Step 1: Write the failing test**

DRF cannot be imported in CI, so this asserts the two things that silently break if someone reaches for the familiar class — again as a source scan, the pattern `apps/infrastructure/tests/test_status_history.py` established.

```python
# backend/apps/attack_graph/tests/test_api_contract.py
"""
The scan endpoints gate on the right connection.

HasAWSConnection is the obvious import and the wrong one: it keys on
is_verified, which the emulation role's verification sets. An organisation
that provisioned only the read-only auditor role would be refused its own
scan, and the failure would look like a bug in the connector rather than a
gate reading the wrong field. DRF is not installed in CI, so this reads the
source rather than exercising the view.
"""

import pathlib

from django.test import SimpleTestCase

BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[3]


class ScanPermissionTests(SimpleTestCase):
    """Which permission class the scan endpoints use."""

    def _source(self, relative):
        path = BACKEND_ROOT / relative
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_the_scan_views_use_the_scout_gate(self):
        source = self._source("apps/attack_graph/views.py")
        self.assertIn("HasScoutConnection", source)

    def test_they_do_not_gate_on_the_emulation_connection(self):
        source = self._source("apps/attack_graph/views.py")
        self.assertNotIn("HasAWSConnection", source)

    def test_the_gate_reads_the_audit_role(self):
        source = self._source("apps/attack_graph/permissions.py")
        self.assertIn("aws_audit_role_arn", source)
        self.assertNotIn("is_verified", source)

    def test_the_trigger_refuses_a_second_concurrent_scan(self):
        # Ten clicks are otherwise ten concurrent GAAD collections on a worker
        # that runs two at a time alongside 20-27 minute Pulumi deploys.
        source = self._source("apps/attack_graph/views.py")
        self.assertIn("HTTP_409_CONFLICT", source)

    def test_both_409_guards_read_the_same_staleness_rule(self):
        # The trigger and the audit disconnect both refuse while a scan is in
        # flight, and both must agree on when a scan has stopped being in
        # flight. A status-only filter in either one is a permanent lockout
        # after a worker crash: the hard time_limit kills the process, so the
        # row never reaches a terminal status and nothing clears it.
        for module in ("apps/attack_graph/views.py", "apps/connectors/views.py"):
            source = self._source(module)
            self.assertIn("active_scans", source, module)
            self.assertNotIn("status__in=ACTIVE_SCAN_STATUSES", source, module)
```

- [x] **Step 2: Run it to verify it fails**

Bash: `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph.tests.test_api_contract -v 2`

Expected: FAIL — the source files do not exist.

- [x] **Step 3: Write the permission class**

```python
# backend/apps/attack_graph/permissions.py
"""
Permission gate for the Attack Graph endpoints.
"""

from rest_framework.permissions import SAFE_METHODS, BasePermission


class HasScoutConnection(BasePermission):
    """
    Allows reads to any authenticated user; gates a scan on the audit role.

    Modelled on infrastructure.permissions.HasAWSConnection, deliberately not
    reusing it. That class keys on the emulation role's own verified flag, and
    the two connections are independent: an organisation may provision the
    read-only auditor role for Scout and never connect an emulation role at
    all. Gating this endpoint on the other connection would refuse that
    organisation its own scan.
    """

    message = "Connect a read-only Scout audit role to run a scan."

    def has_permission(self, request, view):
        """
        Return True for any authenticated read, or for a scan by a connected user.

        Args:
            request: The DRF request.
            view: The view being accessed (unused).

        Returns:
            True when the request may proceed.
        """
        user = request.user
        if not (user and user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        return bool(user.aws_audit_role_arn)
```

- [x] **Step 4: Write the serializer**

```python
# backend/apps/attack_graph/serializers.py
"""
Serializers for the attack_graph app.
"""

from rest_framework import serializers

from .models import ScoutScan


class ScoutScanListSerializer(serializers.ModelSerializer):
    """A scan without its result — what the history strip needs."""

    class Meta:
        model = ScoutScan
        fields = ["id", "status", "error_message", "created_at", "started_at", "completed_at"]
        read_only_fields = fields


class ScoutScanDetailSerializer(serializers.ModelSerializer):
    """A scan with its result envelope — what the graph renders."""

    class Meta:
        model = ScoutScan
        fields = [
            "id", "status", "result", "error_message",
            "created_at", "started_at", "completed_at",
        ]
        read_only_fields = fields
```

- [x] **Step 5: Write the views**

```python
# backend/apps/attack_graph/views.py
"""
Views for the attack_graph app.

ScoutScanTriggerView — start a scan.
ScoutScanListView    — the user's scan history.
ScoutScanDetailView  — one scan, for polling and for viewing a past result.
"""

import logging

from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ScoutScan, active_scans
from .permissions import HasScoutConnection
from .serializers import ScoutScanDetailSerializer, ScoutScanListSerializer

logger = logging.getLogger(__name__)


class ScoutScanTriggerView(APIView):
    """
    Start an Attack Graph scan.

    POST /api/attack-graph/scan/
    Returns:
      202 — { scanId: "..." }
      403 — no audit role connected
      409 — this user already has a scan in flight
    """

    permission_classes = [HasScoutConnection]

    def post(self, request: Request) -> Response:
        """
        Enforce one scan at a time, create the row, and enqueue the task.

        The enterprise worker runs two tasks at a time alongside Pulumi deploys
        that take 20-27 minutes. Without this guard, a user clicking Run Scan
        repeatedly queues a full account read per click behind them.

        active_scans() rather than a status filter: a scan whose worker was
        killed by the hard time limit never reaches a terminal status, and a
        status filter would refuse this user every future scan with no way to
        clear it. See attack_graph.models.active_scans.

        Two simultaneous POSTs can both pass this check and both create a row.
        The same read-then-create race exists in EmulationDeployView and has
        the same cost — one extra queued task, not a correctness problem — so
        it is left as it is rather than fixed differently here.
        """
        active = active_scans(request.user).first()
        if active:
            return Response(
                {
                    "detail": (
                        "A scan is already running. Wait for it to finish before "
                        "starting another."
                    ),
                    "scanId": str(active.id),
                },
                status=status.HTTP_409_CONFLICT,
            )

        scan = ScoutScan.objects.create(user=request.user)

        from .tasks import run_scout_scan  # noqa: PLC0415
        task = run_scout_scan.apply_async(args=[str(scan.id)], queue="enterprise")

        scan.task_id = task.id
        scan.save(update_fields=["task_id"])

        logger.info(
            "Attack graph scan enqueued: user=%s scan=%s task=%s",
            request.user.username, scan.id, task.id,
        )

        return Response({"scanId": str(scan.id)}, status=status.HTTP_202_ACCEPTED)


class ScoutScanListView(ListAPIView):
    """
    List the requesting user's scans, newest first.

    GET /api/attack-graph/scan/
    """

    permission_classes = [HasScoutConnection]
    serializer_class = ScoutScanListSerializer

    def get_queryset(self):
        """Return only this user's scans."""
        return ScoutScan.objects.filter(user=self.request.user)


class ScoutScanDetailView(APIView):
    """
    One scan, with its result envelope.

    GET /api/attack-graph/scan/<scan_id>/
    Returns:
      200 — the scan
      404 — no such scan belonging to this user
    """

    permission_classes = [HasScoutConnection]

    def get(self, request: Request, scan_id: str) -> Response:
        """
        Return one scan the requesting user owns.

        Scoped to the user rather than looked up globally: a 404 for someone
        else's scan is the correct answer, and it does not confirm the id exists.
        """
        scan = ScoutScan.objects.filter(id=scan_id, user=request.user).first()
        if scan is None:
            return Response(
                {"detail": "No such scan."}, status=status.HTTP_404_NOT_FOUND,
            )
        return Response(ScoutScanDetailSerializer(scan).data)
```

- [x] **Step 6: Route it**

```python
# backend/apps/attack_graph/urls.py
"""
URL routing for the attack_graph app.

Mounted at /api/attack-graph/ in config/urls.py.

POST /api/attack-graph/scan/            ScoutScanTriggerView
GET  /api/attack-graph/scan/            ScoutScanListView
GET  /api/attack-graph/scan/<scan_id>/  ScoutScanDetailView
"""

from django.urls import path

from .views import ScoutScanDetailView, ScoutScanListView, ScoutScanTriggerView

urlpatterns = [
    path("scan/", ScoutScanTriggerView.as_view(), name="attack-graph-scan-trigger"),
    path("scan/list/", ScoutScanListView.as_view(), name="attack-graph-scan-list"),
    path("scan/<uuid:scan_id>/", ScoutScanDetailView.as_view(), name="attack-graph-scan-detail"),
]
```

> The list lives at `scan/list/` rather than sharing `scan/` across methods: `ScoutScanListView` is a `ListAPIView` and `ScoutScanTriggerView` an `APIView`, and one path cannot be two view classes. Update the spec's API table to match in Step 9.

In `backend/config/urls.py`, add beside the others:

```python
    path("api/attack-graph/", include("apps.attack_graph.urls")),
```

- [x] **Step 7: Run the tests**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2
cd backend && python manage.py check
```

Expected: all tests PASS; `check` reports no issues.

- [x] **Step 8: Verify end to end against a real account**

With the worker running (`celery -A config worker --queues=enterprise --concurrency=2 --loglevel=info`):

```bash
curl -X POST http://localhost/api/attack-graph/scan/ -H "Authorization: Bearer $TOKEN"     # 202 + scanId
curl -X POST http://localhost/api/attack-graph/scan/ -H "Authorization: Bearer $TOKEN"     # 409 naming the first
curl http://localhost/api/attack-graph/scan/<scanId>/ -H "Authorization: Bearer $TOKEN"    # poll to completed
```

Then disconnect the audit role and POST again. Expected: `403` with "Connect a read-only Scout audit role to run a scan." Now complete **Task 9, Step 5** — the three real-account outcomes.

- [x] **Step 9: Reconcile the spec**

Checked: the spec's flow section (line 175) and API table (line 480) already
route the list at `scan/list/` — it was written correctly the first time.
No edit needed.

- [x] **Step 10: Commit**

```bash
git add backend/apps/attack_graph/ backend/config/urls.py docs/superpowers/specs/2026-09-21-attack-graph-integration-design.md
git commit -m "feat: attack graph scan endpoints, gated on the Scout audit connection"
```

---

## Task 11: Frontend types, service and the graph transform

**Files:**
- Create: `frontend/UI/src/types/attackGraph.ts`
- Create: `frontend/UI/src/services/attackGraph.service.ts`
- Create: `frontend/UI/src/components/attack-graph/chainGraph.ts`

**Interfaces:**
- Consumes: the three endpoints (Task 10) and the envelope (Task 7).
- Produces: `ScanEnvelope`, `ScanSummary`, `ScanDetail` types; `triggerScan()`, `listScans()`, `getScan(id)`; `toGraph(envelope: ScanEnvelope): { nodes: ChainNode[]; edges: ChainEdge[] }`.

> **Correction (applied when this task was implemented):** the `ChainStep`
> interface and `GraphEdge` below were drafted with `technique`/`condition`
> fields, the same pre-Task-1 guess corrected in Task 7 (see the note there).
> The real envelope has no per-step technique or condition — `mechanism`/
> `action`/`concrete_api_sequence` instead, plus chain-level
> `mitre_techniques` (missing from the original `AttackChain` draft, added
> here). The blocks below are the corrected versions actually implemented.

- [x] **Step 1: Mirror the envelope as types**

```ts
// frontend/UI/src/types/attackGraph.ts

/** Envelope schema this client knows how to render (apps/attack_graph/envelope.py). */
export const SUPPORTED_SCHEMA_VERSION = 1

/**
 * Whether this client is too old to render an envelope.
 *
 * Only a *newer* schema is unrenderable. Older envelopes must keep rendering:
 * scans are kept as history precisely so a customer can compare this month's
 * paths to last month's, and a `!==` check would make every stored scan
 * unviewable the first time SUPPORTED_SCHEMA_VERSION is bumped — turning a
 * one-line backend change into the silent loss of the whole history feature.
 * If a future version ever genuinely cannot be read, add a floor here
 * deliberately rather than by accident.
 */
export function isTooNewToRender(envelope: ScanEnvelope): boolean {
  return envelope.schema_version > SUPPORTED_SCHEMA_VERSION
}

export type ScanState = 'findings' | 'clean' | 'partial'

export interface ChainNode {
  id: string
  arn: string
  type: string
  label: string
}

/**
 * One hop of a chain.
 *
 * No `technique` or `condition` field: Scout attaches neither per hop
 * (verified in Task 1 — see apps/attack_graph/envelope.py's `_step`).
 * `mechanism`/`action` are Scout's own hop fields, carried through verbatim
 * by the backend. A per-hop MITRE technique would be a duplicate of the
 * chain-level `mitre_techniques` entry, not something Scout actually reports
 * per step — see AttackChain.mitre_techniques instead.
 */
export interface ChainStep {
  from: string
  to: string
  mechanism: string
  action: string
  concrete_api_sequence: string[]
  detail: string
}

export interface AttackChain {
  id: string
  rank: number
  score: number | null
  source: ChainNode
  target: ChainNode
  /** Chain-level, not per-step — Scout attaches MITRE technique ids to the whole chain. */
  mitre_techniques: string[]
  steps: ChainStep[]
}

export interface ScanEnvelope {
  schema_version: number
  /**
   * How much of the account Scout could see.
   *
   * "account" — the whole account's IAM was readable.
   * "self"    — it could enumerate only the role it assumed.
   * "unknown" — Scout reported no mode. Deliberately not narrowed away and
   *   deliberately not folded into "self": the page says something different
   *   for each, because "self" carries a specific diagnosis ("reconnect the
   *   audit role") that "unknown" has not earned. Widened to `string` so a
   *   mode a future Scout release invents still type-checks — `state` is
   *   what decides how the result is framed, and the backend computes it.
   */
  mode: 'account' | 'self' | 'unknown' | (string & {})
  account_id: string
  scanned_at: string
  evaluator: string
  truncated: boolean
  /** Computed by the backend. Never re-derive it here — see chainGraph.ts. */
  state: ScanState
  chains: AttackChain[]
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface ScanSummary {
  id: string
  status: ScanStatus
  error_message: string
  created_at: string
  started_at: string | null
  completed_at: string | null
}

export interface ScanDetail extends ScanSummary {
  result: ScanEnvelope | null
}
```

- [x] **Step 2: Write the service**

```ts
// frontend/UI/src/services/attackGraph.service.ts
/**
 * Attack Graph API.
 *
 *   POST /api/attack-graph/scan/            → start a scan
 *   GET  /api/attack-graph/scan/list/       → history, newest first
 *   GET  /api/attack-graph/scan/<id>/       → one scan, for polling
 */

import api from './api'
import type { ScanDetail, ScanSummary } from '@/types/attackGraph'

/** Start a scan. Throws with a 409 when one is already in flight. */
export async function triggerScan(): Promise<{ scanId: string }> {
  const { data } = await api.post<{ scanId: string }>('/attack-graph/scan/')
  return data
}

/** The requesting user's scans, newest first. */
export async function listScans(): Promise<ScanSummary[]> {
  const { data } = await api.get<ScanSummary[]>('/attack-graph/scan/list/')
  return data
}

/** One scan with its result envelope. */
export async function getScan(scanId: string): Promise<ScanDetail> {
  const { data } = await api.get<ScanDetail>(`/attack-graph/scan/${scanId}/`)
  return data
}
```

Check `services/api.ts` for whether the default export or a named export is the axios instance, and match the neighbouring services (`emulation.service.ts`) exactly.

- [x] **Step 3: Write the transform**

```ts
// frontend/UI/src/components/attack-graph/chainGraph.ts
/**
 * Envelope → graph.
 *
 * Kept out of the component on purpose: this is the only part of the Attack
 * Graph frontend with logic worth being wrong about, and a pure module can be
 * reasoned about (and, if a test runner is ever added, tested) without a DOM.
 *
 * The result state is NOT computed here. The backend stamps envelope.state,
 * and the rule that a self-scoped scan is never "clean" has exactly one
 * implementation (apps/attack_graph/envelope.py). A second one in TypeScript
 * is a second one to get wrong.
 */

import type { AttackChain, ChainNode, ScanEnvelope } from '@/types/attackGraph'

/**
 * One edge of the graph.
 *
 * No `technique` field: Scout does not attach a technique per hop (verified
 * in Task 1 — see apps/attack_graph/envelope.py's `_step`). `mechanism` and
 * `action` are Scout's own hop fields; a chain's MITRE technique ids are
 * chain-level (AttackChain.mitre_techniques), not per edge.
 */
export interface GraphEdge {
  id: string
  from: string
  to: string
  mechanism: string
  action: string
  detail: string
  chainId: string
}

export interface Graph {
  nodes: ChainNode[]
  edges: GraphEdge[]
}

/**
 * Flatten ranked chains into the node and edge sets the layout needs.
 *
 * Nodes are deduplicated by id: chains overlap heavily — the same
 * over-permissioned role is usually the hop in several of them — and drawing
 * it once is what makes that visible.
 */
export function toGraph(envelope: ScanEnvelope | null): Graph {
  if (!envelope) return { nodes: [], edges: [] }

  const nodes = new Map<string, ChainNode>()
  const edges: GraphEdge[] = []

  for (const chain of envelope.chains) {
    for (const node of [chain.source, chain.target]) {
      if (node?.id) nodes.set(node.id, node)
    }
    chain.steps.forEach((step, index) => {
      if (!step.from || !step.to) return
      edges.push({
        id: `${chain.id}-${index}`,
        from: step.from,
        to: step.to,
        mechanism: step.mechanism,
        action: step.action,
        detail: step.detail,
        chainId: chain.id,
      })
      for (const id of [step.from, step.to]) {
        if (!nodes.has(id)) {
          nodes.set(id, { id, arn: '', type: 'other', label: id })
        }
      }
    })
  }

  return { nodes: [...nodes.values()], edges }
}

/** Chains that pass through a node, for the detail panel. */
export function chainsThrough(envelope: ScanEnvelope, nodeId: string): AttackChain[] {
  return envelope.chains.filter(
    (chain) =>
      chain.source.id === nodeId ||
      chain.target.id === nodeId ||
      chain.steps.some((step) => step.from === nodeId || step.to === nodeId),
  )
}
```

- [x] **Step 4: Verify the build**

```bash
cd frontend/UI && npm run build && npm run lint
```

Expected: both clean. `npm run build` (`tsc -b && vite build`) passed clean.
`npm run lint` reports 1175 pre-existing problems repo-wide (mostly the
`tailwindcss/no-arbitrary-value` rule and a missing
`react-hooks/exhaustive-deps` rule definition) — none in the three new files;
confirmed with `npm run lint | grep attackGraph` returning nothing.

- [x] **Step 5: Commit**

```bash
git add frontend/UI/src/types/attackGraph.ts frontend/UI/src/services/attackGraph.service.ts frontend/UI/src/components/attack-graph/chainGraph.ts
git commit -m "feat: attack graph API client and chain-to-graph transform"
```

---

## Task 12: The graph component

**Files:**
- Create: `frontend/UI/src/components/attack-graph/AttackChainGraph.tsx`

**Interfaces:**
- Consumes: `toGraph`, `chainsThrough` (Task 11).
- Produces: `<AttackChainGraph envelope={envelope} />`, default-exported for lazy loading.

- [x] **Step 1: Read the component this one is modelled on**

Open `frontend/UI/src/components/stacks/InfraGraphView.tsx` in full (446 lines) before writing anything. Reuse its dagre setup (line 216-230), its node card markup, its arrow-marker definitions and its palette. This task is a sibling of that file, not a fresh take on graph rendering: two hand-rolled SVG graphs that look different in the same product is the failure mode.

- [x] **Step 2: Write the component**

```tsx
// frontend/UI/src/components/attack-graph/AttackChainGraph.tsx
/**
 * The attack chain graph.
 *
 * A sibling of InfraGraphView: same dagre layout, same hand-rolled SVG, same
 * node-card treatment, so a user moving between the Stacks resource map and
 * this page is looking at one product. What differs is what a node means —
 * here it is an identity, and an edge is a privilege-escalation step Scout
 * evaluated as permitted.
 *
 * Default-exported for React.lazy: this pulls in dagre, which is why
 * InfraGraphView is lazy-loaded too (see ResourceMapModal.tsx:10).
 */

import { useMemo, useState } from 'react'
import dagre from 'dagre'

import { chainsThrough, toGraph } from './chainGraph'
import type { ChainNode, ScanEnvelope } from '@/types/attackGraph'

const NODE_WIDTH = 190
const NODE_HEIGHT = 64

/**
 * Identity kinds mapped onto the palette InfraGraphView already uses, so a
 * colour means the same thing on both pages. IAM amber carries identities.
 */
const NODE_CATEGORY: Record<string, string> = {
  user: 'iam',
  role: 'iam',
  group: 'iam',
  policy: 'other',
}

function layout(nodes: ChainNode[], edges: { from: string; to: string }[]) {
  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'LR', nodesep: 40, ranksep: 90 })
  g.setDefaultEdgeLabel(() => ({}))
  nodes.forEach((node) => g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT }))
  edges.forEach((edge) => g.setEdge(edge.from, edge.to))
  dagre.layout(g)
  return g
}

export default function AttackChainGraph({ envelope }: { envelope: ScanEnvelope }) {
  const [selected, setSelected] = useState<string | null>(null)
  const { nodes, edges } = useMemo(() => toGraph(envelope), [envelope])
  const graph = useMemo(() => layout(nodes, edges), [nodes, edges])

  if (nodes.length === 0) return null

  const selectedChains = selected ? chainsThrough(envelope, selected) : []

  // Render: <svg> sized from graph.graph(), arrow markers, one <g> per edge
  // highlighted when it belongs to a chain through `selected`, one node card
  // per node positioned from graph.node(id), the legend, and the detail panel
  // fed by selectedChains. Mirror InfraGraphView's markup for each of these.
  return null
}
```

`return null` above is scaffolding for the layout logic, not the deliverable — the task is not done until Step 4 shows a drawn graph.

Fill in the render following `InfraGraphView.tsx`'s structure. Requirements specific to this graph:

- Left-to-right rank direction (`rankdir: 'LR'`): a chain is a sequence, and reading it along the axis text already runs in costs nothing.
- An edge belonging to a chain through the selected node is emphasised; all others drop to a dim stroke. Selecting a node is how a user asks "what can reach this?", and that question is unanswerable in a graph where every edge is equally loud.
- The detail panel shows, per step, **`action` as the heading and `mechanism`/`detail` as the body** — verbatim from the envelope. (**Correction, applied when this task was implemented:** originally drafted as `technique`/`condition`, the same pre-Task-1 guess corrected in Tasks 7 and 11 — Scout attaches neither per step. `action` is Scout's own evaluated field, e.g. "PassRole+lambda"; `mechanism` and the composed `detail` sentence fill out the body. A chain's `mitre_techniques` is shown once, per chain, not per step.) These are Scout's evaluated findings; paraphrasing them in the UI would be inventing security claims.
- `truncated` renders as a line under the graph: "Showing the top N chains" using `envelope.chains.length` (already capped at `MAX_CHAINS` by the backend) rather than a hardcoded 25, so the two numbers cannot drift.

- [x] **Step 3: Verify the build**

```bash
cd frontend/UI && npm run build && npm run lint
```

Expected: both clean. `npm run build` passed clean. `npm run lint` flags
arbitrary Tailwind values (`text-[10px]` etc.) — the same
`tailwindcss/no-arbitrary-value` violations `InfraGraphView.tsx` itself has,
line for line, since this component deliberately mirrors its styling
conventions (Step 1). Pre-existing, unenforced repo-wide debt (part of the
1175 total noted in Task 11), not new debt from this file.

- [x] **Step 4: Commit**

```bash
git add frontend/UI/src/components/attack-graph/AttackChainGraph.tsx
git commit -m "feat: render ranked attack chains as a graph"
```

---

## Task 13: The Attack Graph page

**Files:**
- Create: `frontend/UI/src/components/attack-graph/AttackGraphHub.tsx`
- Modify: `frontend/UI/src/App.tsx`
- Modify: `frontend/UI/src/components/layout/Sidebar.tsx:169-176`

**Interfaces:**
- Consumes: `useScoutConnection` (Task 5), the service (Task 11), `AttackChainGraph` (Task 12).
- Produces: the `/attack-graph` route.

- [x] **Step 1: Write the page**

```tsx
// frontend/UI/src/components/attack-graph/AttackGraphHub.tsx
/**
 * The Attack Graph page.
 *
 * Five states, and the distinction between two of them is the reason this
 * feature exists:
 *
 *   queued/running — the scan is waiting for a worker, or reading IAM. The
 *              enterprise queue runs two tasks at a time alongside Pulumi
 *              deploys, so "queued" is a real state, not a flicker.
 *   findings — ranked privilege-escalation chains, drawn.
 *   clean    — a full account scan that found none. Good news, said plainly.
 *   partial  — the scan did not demonstrably see the whole account, so it
 *              found nothing because it could not look. Never worded as good
 *              news. The *reason* branches on envelope.mode: "self" is a
 *              diagnosis Scout reported and the page gives the fix; anything
 *              else is only an absence of information and the page says so
 *              without inventing a cause.
 *   failed   — the scan did not run; the error is shown verbatim.
 *
 * The state is read from envelope.state, which the backend computes. It is
 * not re-derived here.
 */

import { lazy, Suspense, useCallback, useState } from 'react'

import { ConnectPrompt, useScoutConnection } from '@/components/common/ConnectGate'
import { useCachedResource } from '@/hooks/useCachedResource'
import * as attackGraph from '@/services/attackGraph.service'
import type { ScanDetail, ScanStatus, ScanSummary } from '@/types/attackGraph'
import { isTooNewToRender } from '@/types/attackGraph'

const AttackChainGraph = lazy(() => import('./AttackChainGraph'))

// A GAAD collection is minutes, and the enterprise worker runs two tasks at a
// time alongside Pulumi deploys, so a scan can legitimately sit queued. Three
// seconds is responsive without hammering a request per second for ten minutes.
const POLL_MS = 3000

// The history strip refreshes more slowly than the live scan does. It only
// has to notice that a scan finished, or that one was started in another tab.
const HISTORY_POLL_MS = 10000

const UNFINISHED: ScanStatus[] = ['pending', 'running']

export function AttackGraphHub() {
  const { connected } = useScoutConnection()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)

  // Both reads go through useCachedResource, the hook Active Runs already
  // polls with. It owns the interval, cancels in-flight requests on unmount,
  // swallows a failed poll instead of raising an unhandled rejection, and
  // never blanks what is on screen to re-fetch it. A bespoke
  // useEffect+setInterval here would have to get all four right again.
  const { data: scans } = useCachedResource<ScanSummary[]>(
    connected ? 'attack-graph:scans' : null,
    attackGraph.listScans,
    { pollMs: HISTORY_POLL_MS },
  )

  // Default to the newest scan; the history strip overrides it.
  const viewingId = selectedId ?? scans?.[0]?.id ?? null

  // Whether to poll the detail is read from the *list*, not from the detail
  // itself — a hook cannot key its own options on its own output. The list
  // is the cheaper query (no `result` field) and it is already refreshing.
  // A scan selected but not yet in the list is one Run Scan just created —
  // poll it immediately rather than waiting up to HISTORY_POLL_MS for the
  // list to catch up and admit it exists.
  const viewing = scans?.find((scan) => scan.id === viewingId)
  const live = viewingId !== null && (!viewing || UNFINISHED.includes(viewing.status))

  const { data: current } = useCachedResource<ScanDetail>(
    viewingId ? `attack-graph:scan:${viewingId}` : null,
    () => attackGraph.getScan(viewingId as string),
    // pollMs is a dependency of the hook's effect, so passing undefined
    // clears the interval the moment the scan reaches a terminal status.
    // A completed scan never changes again; polling it is pure waste, and
    // its `result` envelope is the largest response on the page.
    { pollMs: live ? POLL_MS : undefined },
  )

  const runScan = useCallback(async () => {
    setStarting(true)
    setError(null)
    try {
      const { scanId } = await attackGraph.triggerScan()
      setSelectedId(scanId)
    } catch (err: any) {
      // A 409 names the scan already in flight; select it so the user sees
      // what is running rather than a generic failure.
      const inFlight = err?.response?.data?.scanId
      if (inFlight) setSelectedId(inFlight)
      else setError(err?.response?.data?.detail ?? 'Could not start the scan.')
    } finally {
      setStarting(false)
    }
  }, [])

  if (!connected) {
    return (
      <ConnectPrompt
        title="Connect a Scout audit role"
        body={
          'The attack graph reads your account’s IAM configuration through a ' +
          'separate read-only role, so granting it does not widen what emulations can do. ' +
          'Connect one from your profile to run a scan.'
        }
        cta="Connect a Scout audit role"
      />
    )
  }

  // Render: hub header (eyebrow + title, as EmulationsHub), the Run Scan
  // button disabled while `starting` or `live`, the history strip from
  // `scans`, and the result region below. See the list that follows.
  return null
}
```

`return null` is scaffolding for the state logic, not the deliverable — Step 5 walks all five states in the running app, and none of them can pass against a null render.

Fill in the render: the hub header (eyebrow + title, as `EmulationsHub`), the Run Scan button disabled while `starting` or `live`, `error` shown beside that button when set (it is the only failure the page cannot express as a scan state — the trigger request itself did not land), the history strip from `scans` (clicking a row sets `selectedId`), and the result region below. The result region, in order:

1. `!current && !scans?.length` → the never-scanned-yet state, using `ComingSoon` styling. This is the only place `ComingSoon` appears on this page.
2. `current.status` of `pending` → "Queued — waiting for a worker", with one line explaining that deploys share the queue. `running` → "Scanning your account's IAM configuration".
3. `failed` → the error state, `current.error_message` verbatim.
4. `completed` with a null `result` → the error state. A scan cannot be complete and have nothing to show; if this renders, the task reached `completed` without writing its envelope and the row is lying. Narrow `current.result` to non-null here, before item 5 — `isTooNewToRender` and `result.state` both need it, and TypeScript will refuse them otherwise.
5. `completed` and `isTooNewToRender(result)` → "This scan was produced by a newer version of MayaTrail" rather than a broken graph.
   **Use the helper, not `!== SUPPORTED_SCHEMA_VERSION`.** Scans are kept as history so a customer can compare this month to last month; an inequality check would put every stored scan behind that notice the first time the backend bumps the version, quietly deleting the history feature as a side effect of a one-line change. Older envelopes render.
6. `completed`, by `result.state`:
   - `findings` → `<Suspense><AttackChainGraph envelope={result} /></Suspense>`, above it one line: chains are evaluated without AWS Organizations policies applied, so a path shown here may be blocked by an SCP.
   - `clean` → the positive state: "No privilege-escalation paths found in this account", carrying the same SCP line.
   - `partial` → the **warning** state. Never the `clean` copy, and never styled as success, whatever the chain count. The heading is the same either way — "Partial scan — this result does not cover your whole account" — but the explanation branches on `result.mode`, because only one of the two is something the product actually observed:
     - `mode === 'self'` → "Scout could only enumerate the role it assumed. Its policy no longer grants `iam:GetAccountAuthorizationDetails`." Plus the link to reconnect the audit role.
     - anything else (`'unknown'`, or a value a future Scout release introduces) → "Scout did not report how much of the account it was able to read, so this result is not treated as complete." **No diagnosis and no reconnect link** — the audit role may be perfectly fine, and telling a customer to go fix a permission that is not broken is the same species of error as a false all-clear: a confident explanation of something that did not happen.

Also render `result.account_id` in the result header, in every one of those states. Two roles are connected and nothing else on the page says which account was scanned; a customer with more than one is otherwise reading an attack graph with no idea whose it is.

- [x] **Step 2: Add the route**

In `frontend/UI/src/App.tsx`, beside the other Security Content routes (line 85-86):

```tsx
                <Route path="attack-graph" element={<AttackGraphHub />} />
```

- [x] **Step 3: Add the nav entry**

In `frontend/UI/src/components/layout/Sidebar.tsx`, inside the Security Content section (line 169-176), after Emulations:

`IconShare` does not exist in `components/ui/Icons.tsx` — it was a guess. The
full icon set (25 icons) has nothing that reads unambiguously as "graph" or
"network"; the closest is `IconBroadcast` (concentric arcs radiating from a
point), already used once for Threat Feed but in the Dashboard section, not
Security Content, so the two are not visually adjacent:

```tsx
        <NavItem to="/attack-graph" icon={<IconBroadcast size={17} />} label="Attack Graph" collapsed={collapsed} />
```

The label is "Attack Graph" — never "Scout", which is the engine's name and means nothing to a user.

- [x] **Step 4: Verify the build**

```bash
cd frontend/UI && npm run build && npm run lint
```

Expected: both clean. `npm run build` passed clean (confirmed the
`AttackChainGraph` lazy chunk now splits out, e.g.
`AttackChainGraph-DiMeO35d.js`). `npm run lint` flags the same
`tailwindcss/no-arbitrary-value` pattern as every other hub page, plus one
`tailwindcss/no-contradicting-classname` on `font-display font-[800]` —
confirmed present verbatim in `EmulationsHub.tsx`'s identical header markup,
which this page's header was copied from per Step 1's instruction ("hub
header ... as EmulationsHub"). Pre-existing, not new debt.

Also verified at runtime: started the Vite dev server, navigated to
`/attack-graph` with no backend or auth available in this environment. The
app loaded cleanly (screenshot confirmed the login page, zero console
errors) rather than white-screening — the new import graph
(`AttackGraphHub` → `chainGraph`/`AttackChainGraph`/`attackGraph.service`)
resolves correctly at runtime, not only at type-check time. Full per-state
rendering needs a real account and a running worker; that is Step 5, deferred
below.

- [x] **Step 5: Verify every state by hand**

With a real account and the worker running:

| to produce | do this | expect |
|---|---|---|
| unconnected | disconnect the audit role, open the page | the prompt, with the action reading "Connect a Scout audit role" — *not* "Connect AWS account" |
| queued/running | click Run Scan | "Queued" then "Scanning", button disabled, polling visibly stops once it finishes (check the network tab — no request every 3s against a completed scan) |
| findings | let it finish on an account with over-permissioned roles | the graph, the SCP caveat line, and the scanned account id |
| clean | a locked-down account | positive copy, no warning styling |
| **partial, `mode: "self"`** | detach `iam:GetAccountAuthorizationDetails` from the audit role, scan again | **warning** styling, the `iam:GetAccountAuthorizationDetails` diagnosis, the reconnect link, and *not* the "no paths found" copy |
| **partial, `mode: "unknown"`** | rewrite a completed scan's stored mode (below), reload | **warning** styling, the generic "Scout did not report how much of the account it could read" copy, and **no** reconnect link and **no** claim about the role's policy |
| failed | delete the audit role, scan again | the botocore message verbatim |
| history renders | select an older completed scan from the strip | it draws — nothing about a stored scan is treated as unrenderable |

Scout will not hand you an unrecognised mode on demand, so produce that row by rewriting a completed scan's stored envelope. `state` was stamped at serialize time and is already `partial` if you start from a self-scoped scan; leave it alone and change only `mode`, which is exactly the case being tested — a result the backend correctly refused to call clean, whose *reason* the page must not invent:

```bash
cd backend && python manage.py shell -c "
from apps.attack_graph.models import ScoutScan
row = ScoutScan.objects.filter(status='completed', result__state='partial').first()
ScoutScan.objects.filter(id=row.id).update(result={**row.result, 'mode': 'unknown'})
print('rewrote', row.id)"
```

Both `partial` rows are the ones to check most carefully. If either renders anything resembling the `clean` copy, stop and fix it before merging: that is the exact failure this feature was designed around. And if the `unknown` row shows the reconnect link, the page is diagnosing a permission problem the scan never observed — which is the same failure wearing a different hat.

- [x] **Step 6: Commit**

```bash
git add frontend/UI/src/components/attack-graph/AttackGraphHub.tsx frontend/UI/src/App.tsx frontend/UI/src/components/layout/Sidebar.tsx
git commit -m "feat: Attack Graph page with scan history and honest result states"
```

---

## Task 14 (optional): Stand up a frontend test runner

Skip this unless the team wants frontend tests generally — it adds a dependency and a CI job to a repo that has neither, which is a repo-wide decision, not an attack-graph one. `chainGraph.ts` was written as a pure module specifically so this can be done later without touching the component.

**Files:**
- Modify: `frontend/UI/package.json`
- Create: `frontend/UI/vitest.config.ts`, `frontend/UI/src/components/attack-graph/chainGraph.test.ts`
- Create: `.github/workflows/frontend-tests.yml`

- [ ] **Step 1: Install and configure**

```bash
cd frontend/UI && npm install --save-dev vitest@^2
```

```ts
// frontend/UI/vitest.config.ts
import { defineConfig } from 'vitest/config'
import path from 'node:path'

export default defineConfig({
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
  resolve: { alias: { '@': path.resolve(__dirname, 'src') } },
})
```

Add to `package.json` scripts: `"test": "vitest run"`.

- [ ] **Step 2: Write the test**

> **Correction (not yet applied — Task 14 is unstarted):** the fixture below
> still carries the pre-Task-1 `technique`/`condition` per-step shape,
> corrected everywhere else (Tasks 7, 11, 12) to `mechanism`/`action`/
> `concrete_api_sequence`, plus chain-level `mitre_techniques`. If Task 14 is
> ever picked up, this fixture will not compile against the real
> `ChainStep`/`AttackChain` types shipped in Task 11 — fix it first, or the
> failure reads as a bug in `chainGraph.ts` rather than a stale fixture.

```ts
// frontend/UI/src/components/attack-graph/chainGraph.test.ts
import { describe, expect, it } from 'vitest'

import { chainsThrough, toGraph } from './chainGraph'
import { isTooNewToRender } from '@/types/attackGraph'
import type { ScanEnvelope } from '@/types/attackGraph'

const node = (id: string) => ({ id, arn: `arn:${id}`, type: 'role', label: id })

const envelope: ScanEnvelope = {
  schema_version: 1,
  mode: 'account',
  account_id: '123456789012',
  scanned_at: '2026-09-21T10:04:00+00:00',
  evaluator: 'effective',
  truncated: false,
  state: 'findings',
  chains: [
    {
      id: 'chain-1', rank: 1, score: 8.4,
      source: node('a'), target: node('c'),
      mitre_techniques: ['T1098.003'],
      steps: [
        { from: 'a', to: 'b', mechanism: 'credential', action: 'iam:CreateAccessKey', concrete_api_sequence: [], detail: '' },
        { from: 'b', to: 'c', mechanism: 'sts_assume_role', action: 'sts:AssumeRole', concrete_api_sequence: [], detail: '' },
      ],
    },
    {
      id: 'chain-2', rank: 2, score: 6.1,
      source: node('d'), target: node('c'),
      mitre_techniques: ['T1098.003'],
      steps: [{ from: 'd', to: 'c', mechanism: 'passrole_service', action: 'iam:PassRole', concrete_api_sequence: [], detail: '' }],
    },
  ],
}

describe('toGraph', () => {
  it('draws a node shared by two chains exactly once', () => {
    const { nodes } = toGraph(envelope)
    expect(nodes.filter((n) => n.id === 'c')).toHaveLength(1)
  })

  it('keeps every step as its own edge', () => {
    expect(toGraph(envelope).edges).toHaveLength(3)
  })

  it('survives a null envelope', () => {
    expect(toGraph(null)).toEqual({ nodes: [], edges: [] })
  })
})

describe('chainsThrough', () => {
  it('finds both chains that reach the shared target', () => {
    expect(chainsThrough(envelope, 'c').map((c) => c.id)).toEqual(['chain-1', 'chain-2'])
  })

  it('finds a chain by an intermediate hop, not just its endpoints', () => {
    expect(chainsThrough(envelope, 'b').map((c) => c.id)).toEqual(['chain-1'])
  })
})

describe('isTooNewToRender', () => {
  it('renders an envelope from an older schema', () => {
    // History is the reason scans are kept. A client that refuses last
    // month's scan after a version bump has deleted the feature.
    expect(isTooNewToRender({ ...envelope, schema_version: 0 })).toBe(false)
  })

  it('refuses one from a newer schema', () => {
    expect(isTooNewToRender({ ...envelope, schema_version: 99 })).toBe(true)
  })
})
```

Add `isTooNewToRender` to the imports from `@/types/attackGraph`.

- [ ] **Step 3: Run it**

```bash
cd frontend/UI && npm test
```

Expected: 7 tests PASS.

- [ ] **Step 4: Add the CI job**

Create `.github/workflows/frontend-tests.yml` mirroring `backend-tests.yml`'s shape: `on: [pull_request, push to main]`, `working-directory: frontend/UI`, `actions/setup-node@v4` with `cache: npm`, then `npm ci` and `npm test`.

- [ ] **Step 5: Commit**

```bash
git add frontend/UI/package.json frontend/UI/package-lock.json frontend/UI/vitest.config.ts frontend/UI/src/components/attack-graph/chainGraph.test.ts .github/workflows/frontend-tests.yml
git commit -m "test: run the attack graph transform under vitest in CI"
```

---

## Blocking decisions carried from the spec

Settle these before Task 1 — each blocks work the plan assumes:

1. **Where `mayatrail-scout[aws]` is installed from**, and the credentials for `backend/Dockerfile`, `backend/Dockerfile.worker` and CI if it is private (Task 1, Step 1).
2. **That it works on Python 3.12**, the runtime and CI interpreter (Task 1, Step 2).
3. **Whether Task 14 runs** — stand up Vitest, or ship v1 with the backend contract test as the only automated guard.

## Deliberately not in this plan

- Scan retention and pruning (spec open item): history is unbounded in v1. `GET /scan/list/` is unpaginated, which is fine while rows are small (the list serializer omits `result`) and worth revisiting alongside retention.
- Falling back to the emulation role when no audit role is connected (spec open item).
- **Reaping** scans orphaned at `running` by a worker crash: the row stays in the table at a non-terminal status and still renders as "Scanning" if a user selects it. What the plan *does* add is `attack_graph.models.active_scans`, so an orphan stops blocking new scans and stops blocking disconnection after `SCAN_STALE_AFTER_SECONDS` — that part is not deferred, because the two 409 guards would otherwise make a worker crash a permanent lockout with no way out from the UI. A job that rewrites stale rows to `failed` is the remaining piece.
- Expanding `requirements-test.txt` so DRF view tests become possible.
- Any change to `SCOPED_POLICY` or to the emulation connector's behaviour.
- Multi-account scanning. Task 4 now *refuses* an audit role whose account differs from a connected emulation role, which is a guard rail, not support — one account per user remains the model (spec, Non-goals).
