# Attack Graph — Entity Records, Icons, and Path Query — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store the `scout.graph.Graph` the scan task currently discards, and expose it as per-entity records, entity search, and an on-demand path query — drawn through the chain view's existing layout primitives, with real AWS icons in the entity panel, the query pickers and the graph's own node cards.

**Architecture:** One nullable `JSONField` on `ScoutScan` holds `graph.to_dict()`. Three new read endpoints sit on top of it, split across two modules by what CI can import: `graph_search.py` is stdlib-only (search, entity lookup, the `ChainNode` mapping, hop assembly) and fully CI-tested; `graph_query.py` defers its Scout imports and runs the BFS. The frontend gains an entity panel and a query panel that reuse the chain view's layout/node/edge primitives via one behaviour-preserving extraction.

**Tech Stack:** Django 5.0 + DRF, `mayatrail-scout[aws]`, React + TypeScript + Vite, dagre, axios.

**Spec:** `docs/superpowers/specs/2026-09-22-attack-graph-entity-graph-and-query-design.md` — read it before Task 1. The plan argues from it; where they disagree, the spec wins and the plan gets fixed — **except for the nine deviations enumerated in Self-review notes at the bottom of this file.** Those are decided, they are what this plan implements, and the spec is the document that needs amending. Do not "fix" the plan back toward the spec on any of the seven without raising it first.
**Reviews:** the spec's, at `docs/superpowers/reviews/2026-09-22-attack-graph-entity-graph-and-query-review.md`; this plan's, at `docs/superpowers/reviews/2026-09-22-attack-graph-entity-graph-and-query-plan-review.md`. Both are closed — every finding is applied here.

## Global Constraints

- **Branch:** all work lands on `feat/scout-integration` (already checked out). Do not branch from `main` mid-plan.
- **Python:** runtime and CI are **3.12** (`backend/Dockerfile:1`, `.github/workflows/backend-tests.yml`).
- **CI test contract:** `config/settings/ci.py` — sqlite, empty URLconf, `SimpleTestCase` only. `requirements-test.txt` installs exactly six packages: Django, python-decouple, PyYAML, celery, feedparser, requests. **DRF, boto3 and Scout are not installed in CI.** No test in this plan may import them at module scope. **Do not expand `requirements-test.txt`.**
- **`apps.attack_graph` is already registered** — in `LOCAL_APPS`, in `ci.py`'s `INSTALLED_APPS`, in `config/urls.py`, and in the workflow's test label. The five-point new-app registration from the 2026-09-21 plan does **not** apply here; do not redo it.
- **Migrations:** `makemigrations --check --dry-run` is a CI step. A model change without a committed migration **fails the build**. Generate with the apps named explicitly: `python manage.py makemigrations users infrastructure emulations logs attack_graph` — never bare `makemigrations`.
- **Scout imports are deferred** — inside the function, never at module scope, with `# noqa: PLC0415`, as `apps/attack_graph/tasks.py:54` does.
- **The envelope contract does not change.** `SCHEMA_VERSION` stays at 1, `serialize_scan()` is not touched, and no stored scan becomes unrenderable.
- **The graph is never in the scan detail or list response — and never in the query that builds it.** The frontend polls `/scan/<id>/` every 3s while a scan runs (`AttackGraphHub.tsx`'s `POLL_MS`); a multi-MB field there is paid for on every poll. Keeping it out of `Meta.fields` is **not sufficient**: `ScoutScanDetailView.get` (`views.py:118`) and `ScoutScanListView.get_queryset` (`views.py:97`) are both bare `SELECT *`, there is no DRF pagination configured, and `ScoutScanListSerializer.get_state` already forces `obj.result` per row. Without `.defer("graph")` the blob is fetched from Postgres and deserialized by psycopg on every poll and for every row of the history strip, and the serializer test passes the whole time. Task 1 adds both the `.defer()` and the test that checks the **queryset**, not the serializer. `active_scans()` (`models.py:128`) is left alone on purpose: it is bounded to `pending`/`running` rows, whose `graph` is always `NULL`.
- **Frontend query params go through axios `params`**, never hand-built query strings — node ids contain `:`, `/` and sometimes `*`, and axios urlencodes `params` for you. This is the repo convention (`detectionExport.service.ts:43`, `coverageHistory.service.ts:33`).
- **Frontend tests:** the repo has no test runner and zero `.test.tsx` files. Do not add one. Frontend verification is the dev-preview approach used earlier in this feature.
- **Keep the graft index current:** run `graphify update .` once at the end of each phase. AST-only, no API cost.
- **Backend test command (bash):** `cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2`
  **PowerShell:** `cd backend; $env:DJANGO_SETTINGS_MODULE='config.settings.ci'; python manage.py test apps.attack_graph -v 2`
- **Naming, copied verbatim from the spec** — use these exact values, they appear across several tasks:
  - `MAX_NODE_RESULTS = 50`, `MAX_QUERY_PATHS = 25`, `MAX_QUERY_DEPTH = 10`, `MAX_VISITED = 50_000`
  - `QUERY_EDGE_TYPE_NAMES = ["PRIVESC_TO", "CAN_ASSUME", "CAN_ACCESS_RESOURCE"]`
  - Search debounce: **200ms**
  - LRU: `maxsize=4`, keyed on `scan_id` alone — **two** of them, one per module. `graph_search` caches the parsed dict (so a hit skips the SELECT *and* psycopg's jsonb parse, which is what the autocomplete pays); `graph_query` caches the rehydrated `Graph` (what the traversal needs). A worker holds up to four of each.
- **Tailwind tokens** (`frontend/UI/tailwind.config.ts`) — this repo has no `status-*` or `surface-raised` scale. Use only what exists: surfaces are `surface-deep|base|card|elevated`, text is `content-primary|secondary|dim|muted`, and the semantic colours are `danger`, `warning`, `safe` and `accent-blue`, each as a bare class (`text-warning`, `bg-danger`) since `DEFAULT` is defined.

---

## File Structure

**Phase 1 — storage and the pure search module** (ships alone: the graph is captured and searchable; no UI depends on it yet)

| file | responsibility |
|---|---|
| `backend/apps/attack_graph/models.py` *(modify)* | `graph` JSONField |
| `backend/apps/attack_graph/migrations/0002_scoutscan_graph.py` *(new)* | the migration CI's `--check` step demands |
| `backend/apps/attack_graph/views.py` *(modify, Task 1)* | `.defer("graph")` on the two polled querysets — the serializer alone does not keep the blob out |
| `backend/apps/attack_graph/tasks.py:140` *(modify)* | `_graph` → `graph`, and store `graph.to_dict()` |
| `backend/apps/attack_graph/graph_search.py` *(new)* | **pure, stdlib only** — `search_nodes`, `get_entity`, `chain_node`, `chain_nodes_for_steps`, `hop_dict`, `node_ids`, `payload_bytes`. The file CI can defend. |
| `backend/apps/attack_graph/tests/test_graph_search.py` *(new)* | CI tests for all of the above, including the conditional-certainty regression |
| `backend/apps/attack_graph/tests/test_model.py` *(modify)* | `graph` defaults to `None`; absent from both serializers **and** deferred in both querysets |

**Phase 2 — the path query and the endpoints**

| file | responsibility |
|---|---|
| `backend/apps/attack_graph/graph_query.py` *(new)* | Scout-dependent — `query_paths`, `_hop_from_edge`, `graph_for_scan` (the LRU), `reachable`. Deferred imports. |
| `backend/apps/attack_graph/views.py` *(modify)* | three views + one shared scan-with-graph resolver |
| `backend/apps/attack_graph/urls.py` *(modify)* | three routes |
| `backend/apps/attack_graph/tests/test_graph_query.py` *(new)* | `skipUnless(HAS_SCOUT)` — real traversal against a real `Graph` |
| `backend/apps/attack_graph/tests/test_api_contract.py` *(modify)* | source-reading contract tests for the new endpoints |

**Phase 3 — the frontend**

| file | responsibility |
|---|---|
| `frontend/UI/src/components/attack-graph/chainGraph.ts` *(modify)* | extract `stepsToGraph`; `toGraph` becomes its caller |
| `frontend/UI/src/types/attackGraph.ts` *(modify)* | `ChainNode.node_type?`/`name?`; `GraphEntity`, `QueryPath`, `PathQueryResult` |
| `frontend/UI/src/services/attackGraph.service.ts` *(modify)* | `searchGraphNodes`, `getGraphEntity`, `findPaths` |
| `frontend/UI/src/components/attack-graph/nodeIcons.tsx` *(new)* | `NODE_TYPE_ICON` lookup + the letter-badge fallback |
| `frontend/UI/src/components/attack-graph/AttackChainGraph.tsx` *(modify)* | `DetailPanel` → `EntityPanel`; mount `QueryPanel` |
| `frontend/UI/src/components/attack-graph/QueryPanel.tsx` *(new)* | two pickers, "Find paths", the four result states |
| `frontend/UI/src/assets/aws-icons/` *(new)* | the icon SVGs — **external download, needs explicit permission** (Task 11, isolated so nothing else blocks on it) |

---

## Task 0: Measure the graph payload (the spec's migration gate)

**Files:**
- Modify: `docs/superpowers/plans/2026-09-22-attack-graph-entity-graph-and-query.md` (record the numbers in this task's block)

The spec makes "measure before the migration lands" a gate on Blocking Decision 2. Two measurements: one synthetic (always runnable, establishes the order of magnitude) and one real (only if you can reach the audit-role AWS account).

- [x] **Step 1: Run the synthetic measurement**

Needs the dev venv, which has Scout (`backend/venv-dev`). Run from `backend/`:

```bash
python - <<'PY'
import json
from scout.graph.schema import Graph, Node, Edge, NodeType, EdgeType

TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
         "Principal": {"Service": "lambda.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}

for identities, resources in ((70, 300), (500, 3000)):
    g = Graph()
    for i in range(identities):
        g.add_node(Node(id=f"arn:aws:iam::123456789012:role/role-{i}",
                        type=NodeType.IAM_ROLE, name=f"role-{i}",
                        account_id="123456789012",
                        properties={"trust_policy": TRUST, "tags": {"team": "x"}}))
    for i in range(resources):
        g.add_node(Node(id=f"arn:aws:s3:::bucket-{i}", type=NodeType.RESOURCE,
                        name=f"bucket-{i}", account_id="123456789012",
                        properties={"resource_type": "s3"}))
    for i in range(identities - 1):
        g.add_edge(Edge(f"arn:aws:iam::123456789012:role/role-{i}",
                        f"arn:aws:iam::123456789012:role/role-{i+1}",
                        EdgeType.PRIVESC_TO, "PassRole+lambda",
                        properties={"category": "passrole", "service": "lambda",
                                    "granted_by": [{"action": "iam:PassRole",
                                                    "policy_arn": "arn:aws:iam::aws:policy/X",
                                                    "sid": "s", "statement_index": 0}]}))
    size = len(json.dumps(g.to_dict()))
    print(f"{identities} identities / {resources} resources: {size:,} bytes "
          f"({size / 1024 / 1024:.2f} MB)")
PY
```

- [x] **Step 2: Record both numbers in this task block**

```
MEASURED (synthetic, 2026-09-22, backend/venv-dev):
  70 identities  /  300 resources =    89,004 bytes (0.08 MB)
  500 identities / 3000 resources =   770,023 bytes (0.73 MB)
MEASURED (real account): not run — no audit-role account reachable this session.
```

**Caveat on the synthetic number, which matters more than the number.** The
script wires `identities - 1` edges — a single chain, one `granted_by` entry
each. A real account is dense: many PRIVESC_TO edges per identity, `granted_by`
arrays of several statements, and a `CAN_ACCESS_RESOURCE` edge per
identity/resource pair that resolves. Edges, not nodes, are where a real graph
grows, and this synthetic barely has any. Treat 0.73 MB as a floor, not an
estimate — an order-of-magnitude check that says "not 50 MB", not a prediction.

Take the real measurement at Task 2 Step 5, which runs a scan anyway:

```python
from apps.attack_graph.models import ScoutScan
from apps.attack_graph.graph_search import payload_bytes
s = ScoutScan.objects.exclude(graph=None).order_by("-created_at").first()
print(payload_bytes(s.graph) / 1024 / 1024, "MB",
      len(s.graph["nodes"]), "nodes", len(s.graph["edges"]), "edges")
```

Record it here when taken. If it lands above 4 MB, the rungs in Step 3 still
apply — a migration is cheap to redo at Task 2 and expensive once rows exist.

- [x] **Step 3: Apply the gate**

**Applied: passes on the synthetic at 0.73 MB. `JSONField` on `ScoutScan` is confirmed and Task 1 lands as written.** Re-check against the real number when Task 2 Step 5 produces it; the rungs below stay live until then.

If the real-account measurement (or, absent one, the 500/3000 synthetic) is **at or below 4MB**, proceed: `JSONField` on `ScoutScan` is confirmed, and Task 1 lands as written.

If it is **above 4MB**, do not stop — take the first rung below and record which one you took in this task block. Both are the same amount of work as the plain field; neither changes any later task except the two lines that read `scan.graph`.

1. **Own table (take this one unless something rules it out).** Put the blob on `ScoutScanGraph(scan=OneToOneField(ScoutScan, related_name="graph_row", on_delete=CASCADE), data=JSONField())` instead of a column on `ScoutScan`. The "never in the detail or list response" invariant then holds *by construction* rather than by a `.defer()` a future queryset can forget, and Task 1's Step 5 becomes unnecessary (keep its test anyway — it costs nothing and documents the reason). Every later `scan.graph` read becomes one narrow `ScoutScanGraph.objects.filter(scan_id=scan_id).values_list("data", flat=True).first()` in `_ScanGraphView._resolve`, and Task 2 writes `ScoutScanGraph.objects.update_or_create(scan_id=scan_id, defaults={"data": graph.to_dict()})`.
2. **Compress.** `data = models.BinaryField()` holding `gzip.compress(json.dumps(graph.to_dict()).encode())`, decompressed in `graph_for_scan`. Scout graphs are highly repetitive JSON — expect 8-12×. Take this only if rung 1 alone is not enough, because it makes the column unreadable from `psql` and from the Django admin.

Raise it with the author only if **both** rungs still leave the payload unworkable — that is a genuine reopening of the spec's Blocking Decision 2, and it is not a decision to make inside this plan.

- [x] **Step 4: Commit**

```bash
git add docs/superpowers/plans/2026-09-22-attack-graph-entity-graph-and-query.md
git commit -m "docs: record measured graph payload size for the storage gate"
```

---

## Task 1: `ScoutScan.graph` field, migration, and the "never fetched by a polled query" invariant

**Files:**
- Modify: `backend/apps/attack_graph/models.py:60-65` (after the `result` field)
- Create: `backend/apps/attack_graph/migrations/0002_scoutscan_graph.py`
- Modify: `backend/apps/attack_graph/views.py:97` and `:118` (`.defer("graph")`)
- Modify: `backend/apps/attack_graph/tests/test_model.py`

**Interfaces:**
- Produces: `ScoutScan.graph` — `JSONField(null=True, blank=True)`. Every later task reads `scan.graph` and must treat `None` as a normal, permanent state.

- [x] **Step 1: Write the failing tests**

Append to `backend/apps/attack_graph/tests/test_model.py`:

```python
class GraphFieldTests(SimpleTestCase):
    """
    ScoutScan.graph holds Scout's own Graph.to_dict(), and never reaches the
    polled endpoints.

    Nullable is the permanent state for every scan stored before this field
    existed — nothing backfills them, so `None` is normal rather than a bug.
    """

    def test_graph_is_nullable_and_defaults_to_none(self):
        field = ScoutScan._meta.get_field("graph")
        self.assertTrue(field.null)
        self.assertTrue(field.blank)
        self.assertIsNone(ScoutScan().graph)

    def test_the_detail_serializer_never_returns_the_graph(self):
        # Necessary, not sufficient — see the queryset test below. This one is
        # what stops a later fields = "__all__".
        self.assertNotIn("graph", ScoutScanDetailSerializer.Meta.fields)

    def test_the_list_serializer_never_returns_the_graph(self):
        self.assertNotIn("graph", ScoutScanListSerializer.Meta.fields)
```

The serializer is only half the invariant, and it is the half that is already
safe. Add the half that is not — these read the **source of the views**, so
they run in CI where DRF is absent:

```python
    def test_the_polled_querysets_defer_the_graph(self):
        # Keeping `graph` out of Meta.fields stops DRF rendering it. It does
        # NOT stop Django fetching it: ScoutScanDetailView.get and
        # ScoutScanListView.get_queryset are bare filter() calls, i.e.
        # SELECT *, so without .defer() the blob is read out of Postgres and
        # deserialized by psycopg on every 3s poll and for every row of the
        # history strip — with the serializer tests above passing throughout.
        # There is no DRF pagination configured, so the list is every scan the
        # user has ever run.
        source = (
            pathlib.Path(__file__).resolve().parents[1] / "views.py"
        ).read_text(encoding="utf-8")
        # Two call sites, counted rather than merely present: a later view
        # that queries ScoutScan without deferring is exactly the regression,
        # and `assertIn` would not notice it. Keep the literal out of the
        # comments in views.py or this count stops meaning what it says.
        self.assertEqual(source.count('.defer("graph")'), 2)
```

(The matching "the graph endpoints read the column narrowly" check belongs with
the views that do it — it is in Task 5.)

The serializer import must be guarded — DRF is absent in CI. Add at the top of the file, alongside the existing imports:

```python
import unittest

try:
    from apps.attack_graph.serializers import (
        ScoutScanDetailSerializer,
        ScoutScanListSerializer,
    )
    HAS_DRF = True
except ImportError:  # DRF is not installed under config.settings.ci
    HAS_DRF = False
```

and decorate the two serializer tests with `@unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")`.

Because those two are skipped in CI, add the source-reading equivalent that is **not** skipped, in the same class:

```python
    def test_the_serializer_fields_lists_do_not_mention_graph(self):
        # The skipUnless tests above do not run in CI. This one does: it reads
        # the file, so the invariant is defended where DRF is absent.
        #
        # Scoped to the two `fields = [...]` lists rather than the whole file:
        # Task 10 adds documentation, and a grep for the bare word over the
        # whole source would fail on an explanatory comment that happens to
        # quote it.
        source = (
            pathlib.Path(__file__).resolve().parents[1] / "serializers.py"
        ).read_text(encoding="utf-8")
        for block in re.findall(r"fields = \[[^\]]*\]", source):
            self.assertNotIn("graph", block)
```

Add `import pathlib` and `import re` if the file does not already have them.

- [x] **Step 2: Run the tests to verify they fail**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph.tests.test_model -v 2
```

Expected: FAIL — `FieldDoesNotExist: ScoutScan has no field named 'graph'`.

- [x] **Step 3: Add the field**

In `backend/apps/attack_graph/models.py`, directly after the `result` field:

```python
    graph = models.JSONField(
        null=True,
        blank=True,
        help_text=(
            "Scout's own Graph.to_dict() for this scan — every node and edge, "
            "not just the chain endpoints the envelope keeps. Null for every "
            "scan stored before this field existed: that is a normal, "
            "permanent state, not a backfill that is pending. Never returned "
            "by the detail or list serializer; the page polls those."
        ),
    )
```

- [x] **Step 4: Generate the migration**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py makemigrations users infrastructure emulations logs attack_graph
```

Expected: creates `apps/attack_graph/migrations/0002_scoutscan_graph.py` and nothing else. If it proposes changes to another app, stop — that is an unrelated drift and belongs in its own commit.

- [x] **Step 5: Keep the new column out of the two polled querysets**

Adding the field is what makes this necessary, so it lands in the same commit. In `backend/apps/attack_graph/views.py`:

```python
    def get_queryset(self):
        """Return only this user's scans."""
        # Deferring the graph column: this list is unpaginated — every scan
        # the user has ever run — and get_state already forces `result` per
        # row. Without it, one history-strip load pulls every stored graph out
        # of Postgres. Keeping `graph` out of Meta.fields stops DRF
        # *rendering* it; only this stops Django *fetching* it.
        return ScoutScan.objects.filter(user=self.request.user).defer("graph")
```

```python
        # Deferring the graph column: AttackGraphHub polls this every 3s
        # while a scan runs. The graph is served by the /graph/ endpoints,
        # which fetch it deliberately and narrowly; nothing on this path
        # needs it.
        scan = (
            ScoutScan.objects.filter(id=scan_id, user=request.user)
            .defer("graph")
            .first()
        )
```

Write the comments as above, without the literal `.defer("graph")` in them — the test below counts occurrences of that string in the file, and a comment quoting it makes the count say 4 when there are two call sites.

`active_scans()` (`models.py:110`) is deliberately left alone: it filters to `pending`/`running` rows, whose `graph` is always `NULL`.

- [x] **Step 6: Verify migrations and models agree, the way CI does**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py makemigrations --check --dry-run
```

Expected: exit 0, "No changes detected".

- [x] **Step 7: Run the tests to verify they pass**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2
```

Expected: PASS, with 2 skips (the DRF-gated serializer tests).

- [x] **Step 8: Commit**

```bash
git add backend/apps/attack_graph/models.py backend/apps/attack_graph/migrations/0002_scoutscan_graph.py backend/apps/attack_graph/views.py backend/apps/attack_graph/tests/test_model.py
git commit -m "feat(attack-graph): store Scout's full graph on the scan row"
```

---

## Task 2: Store `graph.to_dict()` from the scan task

**Files:**
- Modify: `backend/apps/attack_graph/tasks.py:140` (the `pipeline.run` call) and `:163-167` (the completion update)
- Modify: `backend/apps/attack_graph/tests/test_api_contract.py`

**Interfaces:**
- Consumes: `ScoutScan.graph` from Task 1.
- Produces: a completed scan row whose `graph` is `{"nodes": [...], "edges": [...]}`.

- [ ] **Step 1: Write the failing test**

`tasks.py` imports Scout and boto3, so CI cannot import it. Follow the source-reading pattern the file already uses. Append to `backend/apps/attack_graph/tests/test_api_contract.py`:

```python
class ScanTaskStoresTheGraphTests(SimpleTestCase):
    """
    The task keeps Scout's graph instead of discarding it.

    pipeline.run() has always returned (report, graph) and the task bound the
    second value to `_graph` — the underscore that says "intentionally
    unused". Reading the source rather than running the task: tasks.py imports
    boto3 and Scout, neither of which is installed under config.settings.ci.
    """

    def _tasks_source(self):
        path = BACKEND_ROOT / "apps/attack_graph/tasks.py"
        return path.read_text(encoding="utf-8")

    def test_the_graph_return_value_is_no_longer_discarded(self):
        source = self._tasks_source()
        self.assertNotIn("report, _graph = pipeline.run", source)
        self.assertIn("report, graph = pipeline.run", source)

    def test_the_completion_update_writes_the_graph(self):
        source = self._tasks_source()
        self.assertIn("graph=graph.to_dict()", source)
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph.tests.test_api_contract -v 2
```

Expected: FAIL on both — the source still says `report, _graph`.

- [ ] **Step 3: Make the change**

In `backend/apps/attack_graph/tasks.py`, change the unpack:

```python
        report, graph = pipeline.run(
```

and add the field to the completion update, which currently reads
`status=..., result=envelope, completed_at=...`:

```python
        ScoutScan.objects.filter(id=scan_id).update(
            status=ScoutScan.Status.COMPLETED,
            result=envelope,
            # Scout's own loss-free serializer (scout/graph/schema.py) — no
            # reshaping. This is every node and edge, not the chain endpoints
            # the envelope keeps, and it is what the /graph/ endpoints read.
            # Deliberately not in the detail serializer: the page polls that.
            graph=graph.to_dict(),
            completed_at=timezone.now(),
        )
```

Also update the comment above `pipeline.run` that currently explains the underscore, if one is present, so it does not describe behaviour that no longer exists.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2
```

Expected: PASS.

- [ ] **Step 5: Prove the write actually succeeds**

The test above reads source. It passes whether or not the `.update()` throws, and
nothing between here and Task 5 runs a scan — so without this step the first
real scan after the migration is the implicit integration test, and its failure
mode is *every scan failing at the last line*.

The risk is concrete: `result=envelope` has always been safe because
`envelope.py` assembles primitives by hand, while `graph.to_dict()` is the first
time raw Scout `properties` reach a `JSONField`, and Django's default encoder
raises `TypeError` on a `datetime`. It *should* be fine —
`scout/aws/collect/standalone.py:32,70,77` `.isoformat()`s every date at
collection time, and `scout/graph/store.py:132` `json.dumps` node properties
with no `default=str`, so Scout's own sqlite backend already depends on them
being JSON-native — but "should" is what this step replaces.

Run a real scan against the audit account (the UI's Run Scan, or
`run_scout_scan.apply(args=[scan_id])` in a shell), then:

```bash
cd backend && ./venv-dev/Scripts/python.exe manage.py shell -c "
from apps.attack_graph.models import ScoutScan
s = ScoutScan.objects.exclude(graph=None).order_by('-created_at').first()
print(s.status, len(s.graph['nodes']), len(s.graph['edges']))
"
```

Expected: `completed`, with non-zero node and edge counts. If it raises
`TypeError: Object of type datetime is not JSON serializable` on the write
instead, add `encoder=DjangoJSONEncoder` (`django.core.serializers.json`) to the
field in Task 1 and regenerate the migration — and note that `from_dict` will
then see ISO strings where Scout wrote datetimes, which is what Scout's own
sqlite round-trip already produces.

If no AWS account is reachable, say so here rather than silently skipping, and
carry it as the one unverified assumption into Task 5's browser check.

- [ ] **Step 6: Commit**

```bash
git add backend/apps/attack_graph/tasks.py backend/apps/attack_graph/tests/test_api_contract.py
git commit -m "feat(attack-graph): persist the scan's full graph instead of discarding it"
```

---

## Task 3: `graph_search.py` — the pure module

**Files:**
- Create: `backend/apps/attack_graph/graph_search.py`
- Create: `backend/apps/attack_graph/tests/test_graph_search.py`

**Interfaces:**
- Consumes: nothing. Stdlib only — this is deliberately the file CI can defend.
- Produces, used by Tasks 4 and 5:
  - `MAX_NODE_RESULTS: int = 50`
  - `chain_node(node: dict) -> dict` → `{"id", "arn", "type", "label", "node_type", "name"}`
  - `search_nodes(graph_dict: dict, q: str, limit: int = MAX_NODE_RESULTS) -> list[dict]` → list of `chain_node` dicts
  - `get_entity(graph_dict: dict, node_id: str) -> dict | None` → `{"id", "type", "name", "account_id", "properties"}`
  - `node_ids(graph_dict: dict) -> set[str]`
  - `chain_nodes_for_steps(graph_dict: dict, steps: list[dict]) -> list[dict]`
  - `hop_dict(edge, hop_number: int, mechanism: str, concrete_api_sequence: list[str]) -> dict`
  - `payload_bytes(graph_dict: dict) -> int` — the storage measurement, here rather than in `graph_query.py` because it is stdlib (Task 0 inlines the same expression only because this module does not exist yet)
  - `graph_dict_for_scan(scan_id: str, load) -> dict | None`, `clear_graph_dict_cache()` — the LRU in front of the DB read, so a cache hit skips the SELECT and the jsonb parse, not just the rehydrate

- [ ] **Step 1: Write the failing tests**

Create `backend/apps/attack_graph/tests/test_graph_search.py`:

```python
"""
The stored graph's search, entity lookup and hop assembly.

Pure by design, and that is the point: config/settings/ci.py installs six
packages and Scout is not one of them. Everything a user can get wrong about
this feature — a search that returns a different list twice, a query result
whose nodes render as grey "other" boxes, a conditional hop that reports
itself as deterministic — is decided here, where CI can hold it.

The conditional-certainty test is the load-bearing one. The defect it guards
against (see the 2026-09-22 spec review) was exactly a hop losing its
`conditional` data on the way to _step and every query hop then rendering as
deterministic, contradicting the ranked-chains view about the same edge. A
skipUnless-gated test would reproduce the original silence, so hop_dict takes
a duck-typed edge and this runs with a four-line fake.
"""

import json

from django.test import SimpleTestCase

from apps.attack_graph.envelope import _step
from apps.attack_graph.graph_search import (
    _DICT_CACHE,
    MAX_NODE_RESULTS,
    chain_node,
    chain_nodes_for_steps,
    clear_graph_dict_cache,
    get_entity,
    graph_dict_for_scan,
    hop_dict,
    node_ids,
    payload_bytes,
    search_nodes,
)

ALICE = "arn:aws:iam::123456789012:user/alice"
DEPLOY = "arn:aws:iam::123456789012:role/deploy"
BUCKET = "arn:aws:s3:::alice-backups"
LAMBDA = "lambda.amazonaws.com"

GRAPH = {
    "nodes": [
        {"id": BUCKET, "type": "RESOURCE", "name": "alice-backups",
         "account_id": "123456789012", "properties": {"resource_type": "s3"}},
        {"id": LAMBDA, "type": "SERVICE", "name": "lambda.amazonaws.com",
         "account_id": "", "properties": {}},
        {"id": ALICE, "type": "IAM_USER", "name": "alice",
         "account_id": "123456789012", "properties": {"tags": {"team": "eng"}}},
        {"id": DEPLOY, "type": "IAM_ROLE", "name": "deploy",
         "account_id": "123456789012",
         "properties": {"trust_policy": {"Version": "2012-10-17"}}},
    ],
    "edges": [],
}


class _FakeEdge:
    """Anything with these four attributes is an edge as far as hop_dict cares."""

    def __init__(self, source, target, method, properties):
        self.source = source
        self.target = target
        self.method = method
        self.properties = properties


class ChainNodeTests(SimpleTestCase):
    def test_an_iam_user_maps_to_the_type_the_frontend_colours_on(self):
        # NODE_CATEGORY in AttackChainGraph.tsx keys on "user"/"role"/"group",
        # the lowercase vocabulary envelope._node() produces from an ARN. Scout
        # says IAM_USER. If this mapping is wrong the node renders grey.
        self.assertEqual(chain_node(GRAPH["nodes"][2])["type"], "user")

    def test_an_iam_role_maps_to_role(self):
        self.assertEqual(chain_node(GRAPH["nodes"][3])["type"], "role")

    def test_a_service_node_keeps_scouts_type_for_the_icon_lookup(self):
        node = chain_node(GRAPH["nodes"][1])
        self.assertEqual(node["node_type"], "SERVICE")
        self.assertEqual(node["type"], "service")

    def test_the_label_is_the_name_not_the_raw_id(self):
        self.assertEqual(chain_node(GRAPH["nodes"][0])["label"], "alice-backups")

    def test_a_nameless_node_falls_back_to_its_id(self):
        node = chain_node({"id": "*", "type": "PUBLIC", "name": "",
                           "account_id": "", "properties": {}})
        self.assertEqual(node["label"], "*")


class SearchNodesTests(SimpleTestCase):
    def test_it_matches_on_id_and_on_name(self):
        found = {n["id"] for n in search_nodes(GRAPH, "alice")}
        self.assertEqual(found, {ALICE, BUCKET})

    def test_it_is_case_insensitive(self):
        self.assertEqual(len(search_nodes(GRAPH, "ALICE")), 2)

    def test_identities_sort_before_everything_else(self):
        # A picker whose first row is an S3 bucket buries the identity the user
        # is almost always looking for.
        self.assertEqual(search_nodes(GRAPH, "alice")[0]["id"], ALICE)

    def test_the_order_is_the_same_twice(self):
        self.assertEqual(search_nodes(GRAPH, ""), search_nodes(GRAPH, ""))

    def test_a_short_query_returns_the_head_of_the_list_not_an_error(self):
        # An autocomplete opened on focus sends q="". Returning nothing there
        # reads as "this account has no entities".
        self.assertEqual(len(search_nodes(GRAPH, "")), 4)

    def test_it_caps_results(self):
        big = {"nodes": [
            {"id": f"arn:aws:iam::123456789012:role/r{i}", "type": "IAM_ROLE",
             "name": f"r{i}", "account_id": "1", "properties": {}}
            for i in range(200)
        ], "edges": []}
        self.assertEqual(len(search_nodes(big, "r")), MAX_NODE_RESULTS)

    def test_it_survives_a_scan_whose_graph_has_no_nodes_key(self):
        self.assertEqual(search_nodes({}, "alice"), [])


class GetEntityTests(SimpleTestCase):
    def test_it_returns_the_full_record(self):
        entity = get_entity(GRAPH, DEPLOY)
        self.assertEqual(entity["type"], "IAM_ROLE")
        self.assertEqual(entity["name"], "deploy")
        self.assertEqual(entity["account_id"], "123456789012")
        self.assertIn("trust_policy", entity["properties"])

    def test_an_unknown_id_is_none_not_an_exception(self):
        self.assertIsNone(get_entity(GRAPH, "arn:aws:iam::1:role/nope"))

    def test_node_ids_is_the_validation_set_for_a_query(self):
        self.assertEqual(node_ids(GRAPH), {ALICE, DEPLOY, BUCKET, LAMBDA})


class ChainNodesForStepsTests(SimpleTestCase):
    def test_every_id_a_step_references_gets_a_node(self):
        # Without this the frontend's toGraph synthesizes
        # {type: 'other', label: id} for each one and the whole path renders
        # grey, labelled with raw ARNs.
        steps = [{"from": ALICE, "to": DEPLOY}, {"from": DEPLOY, "to": BUCKET}]
        self.assertEqual({n["id"] for n in chain_nodes_for_steps(GRAPH, steps)},
                         {ALICE, DEPLOY, BUCKET})

    def test_an_id_absent_from_the_graph_still_gets_a_usable_node(self):
        steps = [{"from": ALICE, "to": "arn:aws:iam::1:role/ghost"}]
        nodes = {n["id"]: n for n in chain_nodes_for_steps(GRAPH, steps)}
        self.assertEqual(nodes["arn:aws:iam::1:role/ghost"]["label"],
                         "arn:aws:iam::1:role/ghost")


class HopDictTests(SimpleTestCase):
    def test_a_conditional_edge_stays_conditional_through_step(self):
        # THE regression test. render_path dropped `conditional`, so every
        # query hop rendered "deterministic" while the ranked-chains view
        # showed the same edge as conditional.
        edge = _FakeEdge(ALICE, DEPLOY, "PassRole+lambda",
                         {"conditional": {"gating": [{"klass": "deny_may_apply"}]}})
        step = _step(hop_dict(edge, 1, "passrole_service", ["iam:PassRole"]))
        self.assertEqual(step["certainty"], "conditional")
        self.assertEqual(step["conditional_reason"],
                         "a conditional Deny may block this")

    def test_the_edge_method_survives_as_the_step_action(self):
        # render_path dropped this too; without it `detail` degrades from
        # "PassRole+lambda (passrole_service)" to the bare mechanism.
        edge = _FakeEdge(ALICE, DEPLOY, "PassRole+lambda", {})
        step = _step(hop_dict(edge, 1, "passrole_service", []))
        self.assertEqual(step["action"], "PassRole+lambda")
        self.assertEqual(step["detail"], "PassRole+lambda (passrole_service)")

    def test_an_ungated_edge_is_deterministic(self):
        edge = _FakeEdge(ALICE, DEPLOY, "sts:AssumeRole", {})
        self.assertEqual(_step(hop_dict(edge, 1, "assume_role", []))["certainty"],
                         "deterministic")

    def test_the_hop_has_full_parity_with_scouts_own_hop(self):
        # These five keys do NOT reach the response — _step drops them. The
        # parity is what makes hop_dict swappable for Hop.to_dict() and what
        # makes carrying provenance a later one-line change to _step rather
        # than a re-plumbing. Asserted at this level, not at the endpoint,
        # because the endpoint genuinely does not carry them.
        edge = _FakeEdge(ALICE, DEPLOY, "sts:AssumeRole",
                         {"granted_by": [{"action": "sts:AssumeRole"}],
                          "granted_by_overflow": 3,
                          "bounded_by": {"boundary": "arn:aws:iam::1:policy/b"}})
        hop = hop_dict(edge, 2, "assume_role", [])
        self.assertEqual(hop["hop_number"], 2)
        self.assertEqual(hop["granted_by_overflow"], 3)
        self.assertEqual(hop["bounded_by"]["boundary"], "arn:aws:iam::1:policy/b")
        self.assertNotIn("granted_by", _step(hop))


class PayloadBytesTests(SimpleTestCase):
    def test_it_measures_the_serialized_size(self):
        self.assertEqual(payload_bytes(GRAPH), len(json.dumps(GRAPH)))


class GraphDictCacheTests(SimpleTestCase):
    def setUp(self):
        clear_graph_dict_cache()

    def test_a_hit_does_not_call_the_loader(self):
        # The loader is the DB read plus the jsonb parse. This is the whole
        # point of the cache: /graph/nodes/ is an autocomplete, and without it
        # every debounced keystroke pays both.
        calls = []

        def load():
            calls.append(1)
            return GRAPH

        graph_dict_for_scan("scan-1", load)
        graph_dict_for_scan("scan-1", load)
        self.assertEqual(len(calls), 1)

    def test_it_evicts_beyond_its_size(self):
        for i in range(6):
            graph_dict_for_scan(f"scan-{i}", lambda: GRAPH)
        self.assertEqual(len(_DICT_CACHE), 4)

    def test_an_absent_graph_is_not_cached(self):
        # A running scan's graph is None and stops being None without anything
        # here being told. Caching that would pin "no graph" for this worker
        # until eviction.
        calls = []

        def load():
            calls.append(1)
            return None

        graph_dict_for_scan("scan-x", load)
        graph_dict_for_scan("scan-x", load)
        self.assertEqual(len(calls), 2)
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph.tests.test_graph_search -v 2
```

Expected: FAIL at import — `ModuleNotFoundError: No module named 'apps.attack_graph.graph_search'`.

- [ ] **Step 3: Write the module**

Create `backend/apps/attack_graph/graph_search.py`:

```python
"""
Reading the stored graph — search, entity lookup, and hop assembly.

Pure on purpose. config/settings/ci.py installs six packages and Scout is not
one of them, so a module that imports scout.chains.builder is a module CI
cannot load and therefore cannot defend. Everything here works on the plain
dict Graph.to_dict() produced; graph_query.py holds the half that needs a real
scout.graph.Graph and defers its imports.

Not rehydrating is part of the performance answer, not all of it.
Graph.from_dict() walks every node and edge and rebuilds two adjacency
indexes; /graph/nodes/ is an autocomplete, so doing that per keystroke would
rebuild a multi-MB graph on every character typed. Scout reached the same
conclusion for its own viewer — see scout/graph/neighborhood.py, which
traverses the serialized dict rather than the object.

The other two terms are easy to miss because they are not in this file:

- the SELECT of a multi-MB jsonb column, and psycopg deserializing it into a
  Python dict, happen per request whether or not anything rehydrates. That is
  what graph_dict_for_scan() below caches, and why the cache lives here rather
  than only in graph_query.
- search_nodes uses heapq.nsmallest, not sort. The short-query branch does not
  filter at all, and an autocomplete opened on focus sends q="" — a full sort
  there is a sort of every node in the account to return fifty of them.
"""

import heapq
import json
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

# A hard cap, not a page size: this feeds a picker, not a browse view. An
# unbounded q="" on a large account is otherwise the whole node list.
MAX_NODE_RESULTS = 50

# Matches graph_query._GRAPH_CACHE_SIZE, and the two caches are deliberately
# separate: this one holds the parsed dict (what search and entity lookup
# read), that one holds the rehydrated Graph (what the traversal needs). A
# worker running against four scans therefore holds up to four of each —
# budget for both, not one.
_DICT_CACHE_SIZE = 4
_DICT_CACHE: "OrderedDict[str, dict[str, Any]]" = OrderedDict()

# Scout's NodeType -> the lowercase vocabulary envelope._node() produces by
# parsing an ARN, which is what the frontend's NODE_CATEGORY colours on
# (AttackChainGraph.tsx). Remapping NODE_CATEGORY to Scout's names instead
# would touch the chain view for no gain, and ARN parsing cannot produce these
# at all for SERVICE ("lambda.amazonaws.com") or PUBLIC ("*") — they have no
# ARN to parse. Scout's raw NodeType travels alongside as `node_type`, because
# that is the key the icon lookup needs.
_ARN_KIND_BY_NODE_TYPE = {
    "IAM_USER": "user",
    "IAM_ROLE": "role",
    "IAM_GROUP": "group",
    "AWS_ACCOUNT": "account",
    "SERVICE": "service",
    "FEDERATED": "federated",
    "PUBLIC": "public",
    "EXTERNAL_ACCOUNT": "external",
    "RESOURCE": "resource",
    "UNKNOWN": "other",
}

# Identities sort first in a picker. A search for "alice" whose first row is an
# S3 bucket buries the identity the user is almost always after.
_SORT_RANK = {"IAM_USER": 0, "IAM_ROLE": 0, "IAM_GROUP": 0}
_DEFAULT_RANK = 1


def chain_node(node: dict[str, Any]) -> dict[str, Any]:
    """
    One graph node in the frontend's existing ChainNode shape.

    `type` stays in the ARN-parsed vocabulary so the chain view's colouring
    works unchanged; `node_type` and `name` are new optional fields carrying
    what only the real graph knows. Never returns an empty label — an
    unlabelled box is one a reader cannot act on, the same rule
    envelope._node() follows.
    """
    node_id = node.get("id") or ""
    node_type = node.get("type") or "UNKNOWN"
    name = node.get("name") or ""
    return {
        "id": node_id,
        "arn": node_id,
        "type": _ARN_KIND_BY_NODE_TYPE.get(node_type, "other"),
        "label": name or node_id or "unknown",
        "node_type": node_type,
        "name": name,
    }


def _sort_key(node: dict[str, Any]) -> tuple[int, str, str]:
    """Identities first, then by name, then by id — so the same query twice
    returns the same list. Dict insertion order is not a stable contract when
    the graph is rebuilt by a later scan."""
    return (
        _SORT_RANK.get(node.get("type") or "", _DEFAULT_RANK),
        (node.get("name") or "").lower(),
        node.get("id") or "",
    )


def search_nodes(
    graph_dict: dict[str, Any], q: str, limit: int = MAX_NODE_RESULTS,
) -> list[dict[str, Any]]:
    """
    Nodes whose id or name contains `q`, capped and deterministically ordered.

    A `q` under two characters is not an error: it returns the head of the same
    ordering. An autocomplete opened on focus sends an empty q, and answering
    that with nothing reads as "this account has no entities" rather than
    "start typing".
    """
    needle = (q or "").strip().lower()
    nodes = graph_dict.get("nodes") or []
    if len(needle) < 2:
        matched = nodes
    else:
        matched = [
            n for n in nodes
            if needle in (n.get("id") or "").lower()
            or needle in (n.get("name") or "").lower()
        ]
    # nsmallest, not sort: the short-query branch does not filter at all, so an
    # autocomplete opened on focus (q="") would otherwise fully sort every node
    # in the account to return 50 of them. nsmallest is O(n log limit) and
    # returns the same head of the same total order.
    return [chain_node(n) for n in heapq.nsmallest(limit, matched, key=_sort_key)]


def get_entity(graph_dict: dict[str, Any], node_id: str) -> dict[str, Any] | None:
    """One entity's full record, or None when the graph has no such node."""
    for node in graph_dict.get("nodes") or []:
        if node.get("id") == node_id:
            return {
                "id": node.get("id") or "",
                "type": node.get("type") or "UNKNOWN",
                "name": node.get("name") or "",
                "account_id": node.get("account_id") or "",
                "properties": dict(node.get("properties") or {}),
            }
    return None


def node_ids(graph_dict: dict[str, Any]) -> set[str]:
    """Every node id, for validating a query's src/dst before traversing."""
    return {n.get("id") or "" for n in graph_dict.get("nodes") or []}


def chain_nodes_for_steps(
    graph_dict: dict[str, Any], steps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    A ChainNode for every id the given steps reference.

    Without this the frontend's toGraph synthesizes {type: 'other', label: id}
    for any id it sees only inside a step (chainGraph.ts) — which, for a query
    result, is every id. The whole path then renders grey and labelled with raw
    ARNs. An id the graph does not carry still gets a node rather than being
    dropped: a missing endpoint is a hole in the picture, which is worse than
    an unstyled box.
    """
    by_id = {n.get("id"): n for n in graph_dict.get("nodes") or []}
    wanted: list[str] = []
    for step in steps:
        for key in ("from", "to"):
            node_id = step.get(key)
            if node_id and node_id not in wanted:
                wanted.append(node_id)
    return [
        chain_node(by_id.get(node_id) or {"id": node_id, "type": "UNKNOWN"})
        for node_id in wanted
    ]


def hop_dict(
    edge: Any, hop_number: int, mechanism: str, concrete_api_sequence: list[str],
) -> dict[str, Any]:
    """
    One hop, in the shape envelope._step consumes.

    Takes the edge duck-typed (.source / .target / .method / .properties) and
    the already-computed mechanism and API sequence, because deciding those two
    needs Scout and the rest does not — that split is what lets the certainty
    regression test run in CI.

    Field-for-field identical to the Hop scout/chains/builder.py builds at
    :1174. Carrying `action` and `conditional` is the entire point: Scout's
    render_path() emits neither, so a hop routed through it reaches _step with
    no method and no gating and renders "deterministic" even when the
    ranked-chains view shows the same edge as conditional.

    Note that only six of these keys survive: envelope._step emits exactly
    from / to / mechanism / action / concrete_api_sequence / detail /
    certainty / conditional_reason, so hop_number, catalog_path_ids,
    granted_by, granted_by_overflow and bounded_by are dropped one call later
    and never cross the wire. They are kept because full Hop parity is what
    makes this swappable for Scout's own Hop.to_dict(), and because a `_step`
    that carries provenance is the obvious next change — not because anything
    reads them today.

    Read-only on `edge.properties`, and it has to stay that way: unlike
    Node.to_dict(), Edge.to_dict() hands out the live dict by reference
    (scout/graph/schema.py:78), so mutating it here would edit the cached
    Graph that every later query on this scan reuses.
    """
    properties = getattr(edge, "properties", None) or {}
    return {
        "hop_number": hop_number,
        "mechanism": mechanism,
        "action": getattr(edge, "method", "") or "",
        "source_arn": getattr(edge, "source", "") or "",
        "target_arn": getattr(edge, "target", "") or "",
        "concrete_api_sequence": list(concrete_api_sequence or []),
        "catalog_path_ids": list(properties.get("path_ids") or []),
        "conditional": properties.get("conditional"),
        "granted_by": properties.get("granted_by") or [],
        "granted_by_overflow": properties.get("granted_by_overflow", 0),
        "bounded_by": properties.get("bounded_by"),
    }


def graph_dict_for_scan(scan_id: str, load: Callable[[], dict[str, Any] | None]):
    """
    This scan's stored graph dict, reusing the last few.

    `load` is called only on a miss, so a cache hit skips the SELECT as well
    as the parse. Both matter, and the parse is the one that is easy to miss:
    the column is jsonb, so psycopg deserializes the whole blob into a Python
    dict on every fetch — comparable to Graph.from_dict(), and paid by
    /graph/nodes/, which is an autocomplete. Caching only the rehydrated Graph
    (graph_query.graph_for_scan) would leave the search path paying full price
    per keystroke while appearing to be "the cheap one".

    Keyed on scan_id alone: a completed scan is immutable — nothing writes
    `graph` after the task sets it — so there is nothing to invalidate.

    A miss that loads None is NOT cached: that is the "scan has no graph yet"
    state, which for a running scan stops being true without anything here
    hearing about it.
    """
    cached = _DICT_CACHE.get(scan_id)
    if cached is not None:
        _DICT_CACHE.move_to_end(scan_id)
        return cached
    loaded = load()
    if loaded:
        _DICT_CACHE[scan_id] = loaded
        while len(_DICT_CACHE) > _DICT_CACHE_SIZE:
            _DICT_CACHE.popitem(last=False)
    return loaded


def clear_graph_dict_cache() -> None:
    """Drop every cached dict. For tests; nothing in the request path calls it."""
    _DICT_CACHE.clear()


def payload_bytes(graph_dict: dict[str, Any]) -> int:
    """
    Serialized size of a stored graph — the storage measurement from Task 0.

    Here rather than in graph_query.py because it needs no Scout, and the
    split in this app is "stdlib goes in the file CI can import". Scout has
    its own (scout/viz.py:66) against an 8MB ceiling; this one exists so the
    number can be taken from a stored row without importing Scout at all.
    """
    return len(json.dumps(graph_dict))
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2
```

Expected: PASS, all of `test_graph_search` running (no skips in that module).

- [ ] **Step 5: Commit**

```bash
git add backend/apps/attack_graph/graph_search.py backend/apps/attack_graph/tests/test_graph_search.py
git commit -m "feat(attack-graph): pure graph search, entity lookup and hop assembly"
```

- [ ] **Step 6: Refresh the graft index (end of Phase 1)**

```bash
graphify update .
```

---

## Task 4: `graph_query.py` — the Scout-dependent path query

**Files:**
- Create: `backend/apps/attack_graph/graph_query.py`
- Create: `backend/apps/attack_graph/tests/test_graph_query.py`

**Interfaces:**
- Consumes from Task 3: `hop_dict`, `chain_nodes_for_steps`, `node_ids`.
- Produces, used by Task 5:
  - `MAX_QUERY_PATHS = 25`, `MAX_QUERY_DEPTH = 10`, `MAX_VISITED = 50_000`
  - `QUERY_EDGE_TYPE_NAMES: list[str]`
  - `query_paths(graph_dict: dict, scan_id: str, src: str, dst: str) -> dict` → the `/graph/path/` response body
  - `reachable(graph_dict: dict, scan_id: str, origin: str) -> dict` (exposed, not wired to UI)

- [ ] **Step 1: Write the failing tests**

Create `backend/apps/attack_graph/tests/test_graph_query.py`:

```python
"""
The path query, against a real scout.graph.Graph.

Gated: Scout is not installed under config.settings.ci, so this module runs
locally (backend/venv-dev) and skips in CI — the same arrangement
apps/emulations/tests/test_access_contract.py:103 uses for DRF. What CI *can*
hold about this feature lives in test_graph_search.py, deliberately, including
the certainty regression; nothing load-bearing is only here.
"""

import unittest

from django.test import SimpleTestCase

try:
    from scout.graph.schema import Edge, EdgeType, Graph, Node, NodeType
    HAS_SCOUT = True
except ImportError:  # Scout is not installed under config.settings.ci
    HAS_SCOUT = False

from apps.attack_graph import graph_query

ALICE = "arn:aws:iam::123456789012:user/alice"
DEPLOY = "arn:aws:iam::123456789012:role/deploy"
ADMIN = "arn:aws:iam::123456789012:role/admin"
BUCKET = "arn:aws:s3:::secrets"
FUNC = "arn:aws:lambda:ap-south-1:123456789012:function:billing"
ISLAND = "arn:aws:iam::123456789012:role/island"


def _graph_dict():
    """
    alice -> deploy -> admin -> {(s3) secrets, (lambda) billing}, plus an
    unreachable role.

    The lambda leg is not decoration: its node carries category "compute"
    (what ingest/resources.py:240 writes for a lambda) while its edge carries
    no category at all (what attack_surface/build.py:124 emits). That is the
    exact shape where reading the category off the edge instead of the node
    silently downgrades the hop to "resource_access".
    """
    g = Graph()
    g.add_node(Node(id=ALICE, type=NodeType.IAM_USER, name="alice",
                    account_id="123456789012"))
    g.add_node(Node(id=DEPLOY, type=NodeType.IAM_ROLE, name="deploy",
                    account_id="123456789012"))
    g.add_node(Node(id=ADMIN, type=NodeType.IAM_ROLE, name="admin",
                    account_id="123456789012"))
    g.add_node(Node(id=ISLAND, type=NodeType.IAM_ROLE, name="island",
                    account_id="123456789012"))
    g.add_node(Node(id=BUCKET, type=NodeType.RESOURCE, name="secrets",
                    account_id="123456789012",
                    properties={"resource_type": "s3", "category": "data"}))
    g.add_node(Node(id=FUNC, type=NodeType.RESOURCE, name="billing",
                    account_id="123456789012",
                    properties={"resource_type": "lambda",
                                "category": "compute"}))
    g.add_edge(Edge(ALICE, DEPLOY, EdgeType.CAN_ASSUME, "sts:AssumeRole"))
    g.add_edge(Edge(DEPLOY, ADMIN, EdgeType.PRIVESC_TO, "PassRole+lambda",
                    properties={"category": "passrole", "service": "lambda",
                                "conditional": {"gating": [
                                    {"klass": "deny_may_apply"}]}}))
    g.add_edge(Edge(ADMIN, BUCKET, EdgeType.CAN_ACCESS_RESOURCE,
                    "s3:GetObject", properties={"category": "data"}))
    # No `category` on the edge — the attack-surface shape.
    g.add_edge(Edge(ADMIN, FUNC, EdgeType.CAN_ACCESS_RESOURCE,
                    "lambda:UpdateFunctionCode",
                    properties={"kind": "public_policy", "via": "resource_policy"}))
    return g.to_dict()


def _two_path_graph_dict():
    """alice reaches admin two ways: directly, and via deploy."""
    g = Graph.from_dict(_graph_dict())
    g.add_edge(Edge(ALICE, ADMIN, EdgeType.CAN_ASSUME, "sts:AssumeRole"))
    return g.to_dict()


@unittest.skipUnless(HAS_SCOUT, "scout is not installed under config.settings.ci")
class QueryPathsTests(SimpleTestCase):
    def setUp(self):
        graph_query.clear_graph_cache()
        self.graph = _graph_dict()

    def test_it_finds_an_identity_to_identity_path(self):
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ADMIN)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["hop_count"], 2)

    def test_it_finds_a_path_that_ends_at_a_resource(self):
        # The default edge-type list is [PRIVESC_TO, CAN_ASSUME], under which
        # this returns nothing and the UI says "no path found" — a false
        # statement, since the traversal never looked at a resource edge.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["steps"][-1]["to"], BUCKET)

    def test_a_resource_hop_gets_scouts_resource_mechanism(self):
        # _mechanism_for has no branch for CAN_ACCESS_RESOURCE and would label
        # it "direct_iam"; _resource_reach_chains uses these instead.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET)
        self.assertEqual(result["paths"][0]["steps"][-1]["mechanism"],
                         "resource_access")

    def test_the_resource_category_is_read_off_the_node_not_the_edge(self):
        # The lambda edge carries no `category` (the attack_surface/build.py
        # shape) while its node says "compute". Reading the edge alone yields
        # the "data" default and labels this "resource_access", while the
        # ranked-chains view — which reads the node, builder.py:581-583 —
        # labels the same edge "resource_control". One grant rendering two
        # ways is the defect this asserts against; note that an assertion
        # built on a "data" fixture cannot detect it, because "data" is also
        # the fallback.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, FUNC)
        self.assertEqual(result["paths"][0]["steps"][-1]["mechanism"],
                         "resource_control")

    def test_a_conditional_hop_survives_the_real_traversal(self):
        # The CI-side version of this is in test_graph_search.py. This one
        # proves the wiring, end to end, with a real Scout edge.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ADMIN)
        hop = result["paths"][0]["steps"][1]
        self.assertEqual(hop["certainty"], "conditional")
        self.assertEqual(hop["action"], "PassRole+lambda")

    def test_no_path_is_an_empty_list_with_the_flags_clear(self):
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ISLAND)
        self.assertEqual(result["paths"], [])
        self.assertFalse(result["truncated"])
        self.assertFalse(result["search_capped"])

    def test_the_response_names_what_was_traversed(self):
        # "No path found" is only true of the edge types actually followed, so
        # the UI has to be able to say which.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ISLAND)
        self.assertEqual(result["edge_types"], graph_query.QUERY_EDGE_TYPE_NAMES)
        self.assertEqual(result["max_depth"], graph_query.MAX_QUERY_DEPTH)

    def test_nodes_cover_every_id_the_steps_reference(self):
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET)
        referenced = set()
        for path in result["paths"]:
            for step in path["steps"]:
                referenced |= {step["from"], step["to"]}
        self.assertTrue(referenced <= {n["id"] for n in result["nodes"]})

    def test_the_nodes_carry_real_types_not_the_grey_fallback(self):
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET)
        by_id = {n["id"]: n for n in result["nodes"]}
        self.assertEqual(by_id[ALICE]["type"], "user")
        self.assertEqual(by_id[ALICE]["node_type"], "IAM_USER")

    def test_search_capped_is_reported_when_the_budget_ends_the_search(self):
        # A bailed-out BFS that looks like "nothing is reachable" is the worst
        # available wrong answer — scout/chains/builder.py:1043 says so about
        # its own reachable_from, and this endpoint must not reintroduce it.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ISLAND,
                                         max_visited=1)
        self.assertTrue(result["search_capped"])

    def test_search_capped_is_false_when_a_bounded_search_simply_finished(self):
        # The inverse, and the one that matters in practice: this graph is
        # exhausted long before the budget, so claiming otherwise would put a
        # permanent "there may be paths we did not find" banner on an answer
        # that is complete. An over-eager capping signal is a quieter bug than
        # a missing one and lasts longer.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, ISLAND)
        self.assertFalse(result["search_capped"])

    def test_search_capped_is_reported_even_when_paths_were_found(self):
        # Finding some paths says nothing about whether the walk completed —
        # the budget runs out one dequeue after the bucket is reached, with
        # the lambda still queued. The old "infer it from a second walk"
        # approach could not report this case at all: it only asked the
        # question when fewer paths than the cap came back.
        result = graph_query.query_paths(self.graph, "scan-1", ALICE, BUCKET,
                                         max_visited=4)
        self.assertEqual(len(result["paths"]), 1)
        self.assertTrue(result["search_capped"])

    def test_truncated_is_reported_when_more_paths_exist_than_are_returned(self):
        # Two real paths, one asked for — not max_paths=0, which would assert
        # truncation against an empty list and a UI string ("showing the 0
        # shortest") that has no meaning.
        result = graph_query.query_paths(_two_path_graph_dict(), "scan-2",
                                         ALICE, ADMIN, max_paths=1)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["paths"]), 1)
        # BFS order, so the one kept is the shortest — which is what the
        # panel's "showing the N shortest" claims.
        self.assertEqual(result["paths"][0]["hop_count"], 1)

    def test_the_cache_returns_the_same_graph_object_for_one_scan(self):
        first = graph_query.graph_for_scan("scan-1", self.graph)
        second = graph_query.graph_for_scan("scan-1", self.graph)
        self.assertIs(first, second)

    def test_the_cache_evicts_beyond_its_size(self):
        first = graph_query.graph_for_scan("scan-1", self.graph)
        for i in range(2, 7):
            graph_query.graph_for_scan(f"scan-{i}", self.graph)
        self.assertIsNot(graph_query.graph_for_scan("scan-1", self.graph), first)


@unittest.skipUnless(HAS_SCOUT, "scout is not installed under config.settings.ci")
class IterPathsParityTests(SimpleTestCase):
    """
    _iter_paths_capped is a copy of Scout's iter_paths. Hold it to the original.

    Copying was the deliberate choice (see the module docstring): the capping
    signal depends on iter_paths' own pruning, so re-deriving it from a
    separate walk means maintaining a second model of rules that live
    upstream. The cost of copying is drift, and this is what catches it — a
    Scout release that changes the traversal fails here, by name, rather than
    on a user's query.
    """

    def setUp(self):
        self.graph = Graph.from_dict(_two_path_graph_dict())
        self.edge_types = [EdgeType(n) for n in graph_query.QUERY_EDGE_TYPE_NAMES]

    def _find_paths(self, **kwargs):
        from scout.chains.builder import find_paths  # noqa: PLC0415
        return find_paths(self.graph, ALICE, ADMIN, edge_types=self.edge_types,
                          **kwargs)

    def test_it_yields_exactly_what_find_paths_yields(self):
        mine, _ = graph_query._iter_paths_capped(
            self.graph, ALICE, ADMIN, max_depth=10, edge_types=self.edge_types,
            max_paths=50, max_visited=50_000)
        theirs = self._find_paths(max_depth=10, max_paths=50, max_visited=50_000)
        self.assertEqual([[e.key() for e in p] for p in mine],
                         [[e.key() for e in p] for p in theirs])

    def test_it_prunes_at_max_depth_the_same_way(self):
        # The divergence that matters most: without the depth prune the copy
        # visits states the original never does, and every extra visit pushes
        # the capping signal toward a false positive.
        mine, _ = graph_query._iter_paths_capped(
            self.graph, ALICE, ADMIN, max_depth=1, edge_types=self.edge_types,
            max_paths=50, max_visited=50_000)
        theirs = self._find_paths(max_depth=1, max_paths=50, max_visited=50_000)
        self.assertEqual(len(mine), len(theirs))
        self.assertEqual(len(mine), 1)

    def test_it_stops_at_max_paths_the_same_way(self):
        mine, _ = graph_query._iter_paths_capped(
            self.graph, ALICE, ADMIN, max_depth=10, edge_types=self.edge_types,
            max_paths=1, max_visited=50_000)
        self.assertEqual(len(mine), 1)


@unittest.skipUnless(HAS_SCOUT, "scout is not installed under config.settings.ci")
class ScoutHelperContractTests(SimpleTestCase):
    """
    The three private helpers this module borrows from Scout.

    Underscore-private in scout/chains/builder.py, so a Scout upgrade can
    rename them. Failing here names the cause; failing at runtime happens on a
    user's query.
    """

    def test_the_helpers_are_importable(self):
        from scout.chains.builder import (  # noqa: PLC0415
            _concrete_api, _concrete_resource_reach, _mechanism_for,
        )
        self.assertTrue(callable(_mechanism_for))
        self.assertTrue(callable(_concrete_api))
        self.assertTrue(callable(_concrete_resource_reach))

    def test_concrete_resource_reach_tolerates_a_missing_node(self):
        # _hop_from_edge passes graph.get(edge.target) straight through, which
        # is None for an edge whose target was never added as a node.
        from scout.chains.builder import _concrete_resource_reach  # noqa: PLC0415
        from apps.attack_graph.tests.test_graph_search import _FakeEdge  # noqa: PLC0415
        self.assertIsInstance(
            _concrete_resource_reach(_FakeEdge(ALICE, BUCKET, "s3:GetObject", {}), None),
            list,
        )
```

- [ ] **Step 2: Run the tests to verify they fail**

With the dev venv (which has Scout) so they do not merely skip:

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci ./venv-dev/Scripts/python.exe manage.py test apps.attack_graph.tests.test_graph_query -v 2
```

Expected: FAIL at import — `cannot import name 'graph_query'`.

- [ ] **Step 3: Write the module**

Create `backend/apps/attack_graph/graph_query.py`:

```python
"""
The on-demand path query over a stored scan graph.

Scout-dependent, and therefore deliberately thin: everything that can be
decided without Scout lives in graph_search.py, which CI can import and test.
Every Scout import here is inside a function (# noqa: PLC0415), matching
tasks.py — views.py imports this module, config/urls.py imports the views, and
Django imports the URL configuration during system checks, so a module-scope
import would drag Scout into every management command and break the CI suite.

Three decisions worth knowing before changing anything here:

1. Scout's render_path() is NOT used. It emits only hop_number / mechanism /
   source_arn / target_arn / concrete_api_sequence, while envelope._step reads
   `action` and `conditional` — so a hop routed through it renders
   "deterministic" for every edge, including ones the ranked-chains view shows
   as conditional. Hops are built from the edges instead, the way
   scout/chains/builder.py:1174 does.
2. The traversed edge types are explicit. Scout's default is
   [PRIVESC_TO, CAN_ASSUME], under which any resource destination returns "no
   path found" — for every bucket, in every account — because the traversal
   never looks at a resource edge. That is a confident false statement, which
   is worse than an error.
3. Truncation is reported, and the traversal is vendored to report it.
   find_paths()/iter_paths() cap silently; a bailed-out BFS that reads as
   "nothing is reachable" is, in Scout's own words about reachable_from, "the
   worst available wrong answer here". _iter_paths_capped below is a
   line-for-line copy of iter_paths (scout/chains/builder.py:970-988) that
   additionally reports whether it exited with a non-empty queue — exactly
   what reachable_from already does for itself at :1043-1047. Copying is the
   cheap option here: inferring the same signal from a second, separate walk
   means writing a second model of iter_paths' pruning, and any divergence in
   that model (a missing depth bound, a missing dst short-circuit) shows up as
   a confident wrong answer rather than an error. IterPathsParityTests holds
   the copy to the original.
"""

import logging
from collections import OrderedDict, deque
from typing import Any

from .envelope import _step
from .graph_search import chain_nodes_for_steps, hop_dict

logger = logging.getLogger(__name__)

# Named rather than EdgeType members so this module has no import-time Scout
# dependency; resolved to real members inside the functions that traverse.
# CAN_PASS_ROLE, MEMBER_OF, DEPENDS_ON and TRIGGERS are excluded on purpose —
# see the spec's edge-type table. In short: a raw CAN_PASS_ROLE edge is added
# whenever iam:PassRole is allowed (scout/privesc/rules.py:399) while the
# PRIVESC_TO edge is added only when a launch variant is actually satisfiable
# (:431), so traversing the raw edge reports paths nobody can walk.
QUERY_EDGE_TYPE_NAMES = ["PRIVESC_TO", "CAN_ASSUME", "CAN_ACCESS_RESOURCE"]

# Matches envelope.MAX_CHAINS. iter_paths yields in BFS order, so these are
# genuinely the shortest paths and "showing the 25 shortest" is accurate.
MAX_QUERY_PATHS = 25

# Scout's own default. Carried in the response so the "within N hops" copy
# cannot drift from the value actually used.
MAX_QUERY_DEPTH = 10

# Scout's own default. The real rail — bounded by nodes visited, so a dense hub
# cannot explode regardless of how many paths are wanted.
MAX_VISITED = 50_000

# Rebuilding a multi-MB graph per request is the cost this avoids; four keeps a
# user running several queries against one scan cheap while bounding resident
# memory per worker process. Keyed on scan_id alone: a completed scan is
# immutable — nothing writes `graph` after the task sets it — so there is no
# invalidation to do and no update timestamp on ScoutScan to key on.
_GRAPH_CACHE_SIZE = 4
_graph_cache: "OrderedDict[str, Any]" = OrderedDict()


def clear_graph_cache() -> None:
    """Drop every cached graph. For tests; nothing in the request path calls it."""
    _graph_cache.clear()


def graph_for_scan(scan_id: str, graph_dict: dict[str, Any]):
    """Rehydrate this scan's graph, reusing the last few."""
    from scout.graph.schema import Graph  # noqa: PLC0415

    cached = _graph_cache.get(scan_id)
    if cached is not None:
        _graph_cache.move_to_end(scan_id)
        return cached
    graph = Graph.from_dict(graph_dict)
    _graph_cache[scan_id] = graph
    while len(_graph_cache) > _GRAPH_CACHE_SIZE:
        _graph_cache.popitem(last=False)
    return graph


def _hop_from_edge(graph, edge, hop_number: int) -> dict[str, Any]:
    """
    One hop, with the mechanism and API sequence Scout would give it.

    Dispatches on edge type because Scout renders a resource hop differently
    from an identity hop, and this query can now produce both: _mechanism_for
    has no branch for CAN_ACCESS_RESOURCE and would label it "direct_iam",
    while _concrete_api has no branch for it at all. The resource arm mirrors
    _resource_reach_chains (scout/chains/builder.py:586-597).
    """
    from scout.chains.builder import (  # noqa: PLC0415
        _concrete_api, _concrete_resource_reach, _mechanism_for,
    )
    from scout.graph.schema import EdgeType  # noqa: PLC0415

    if edge.type is EdgeType.CAN_ACCESS_RESOURCE:
        # graph.get() is None for an edge whose target was never added as a
        # node. _concrete_resource_reach guards for that itself
        # (builder.py:500), and ScoutHelperContractTests holds it to that.
        node = graph.get(edge.target)
        # The NODE's category first, the edge's only as a fallback — the same
        # precedence _resource_reach_chains uses (builder.py:581-583). This is
        # not interchangeable: ingest/resources.py sets `category` on both, but
        # attack_surface/build.py:124 adds CAN_ACCESS_RESOURCE edges carrying
        # none, and ingest/resources.py:20-32 categorises lambda/sns/ecr as
        # "compute" on the node. Reading the edge alone would label a publicly
        # exposed Lambda "resource_access" here while the ranked-chains view
        # labels the same edge "resource_control" — one grant, two
        # contradictory renderings, which is the defect class this whole
        # module's hop assembly exists to avoid.
        category = (
            (node.properties.get("category") if node is not None else None)
            or edge.properties.get("category")
            or "data"
        )
        mechanism = "resource_access" if category == "data" else "resource_control"
        api = _concrete_resource_reach(edge, node)
    else:
        mechanism = _mechanism_for(edge)
        api = _concrete_api(edge)
    return hop_dict(edge, hop_number, mechanism, api)


def _iter_paths_capped(
    graph, src: str, dst: str, *, max_depth: int, edge_types,
    max_paths: int, max_visited: int,
) -> tuple[list, bool]:
    """
    All simple paths src->dst in BFS order, plus whether the budget ran out.

    A verbatim copy of scout.chains.builder.iter_paths (:970-988) with one
    addition: the loop's exit condition is inspected afterwards, so a caller
    can tell "that is all of them" apart from "we stopped looking". This is
    what reachable_from already does for itself (`visit_capped = bool(queue)`,
    :1043-1047) and what iter_paths, returning a bare generator, cannot.

    Copied rather than wrapped because the signal depends on iter_paths' own
    pruning: it does not expand `dst`, and it stops descending at max_depth.
    A separate walk that reconstructs those rules is a second model of the
    first, and every divergence between them surfaces as a confident wrong
    answer — "we stopped looking" on a search that finished. IterPathsParity-
    Tests asserts this yields exactly what find_paths does.

    Returns (paths, search_capped). Note `produced` counts what the generator
    yielded, so a caller wanting N+1 to detect truncation gets an honest
    search_capped for that larger budget too.
    """
    queue = deque([(src, [], {src})])
    produced = visited_count = 0
    out: list = []
    while queue and produced < max_paths and visited_count < max_visited:
        node_id, path, seen = queue.popleft()
        visited_count += 1
        if node_id == dst and path:
            produced += 1
            out.append(path)
            continue
        if len(path) >= max_depth:
            continue
        for edge_type in edge_types:
            for edge in graph.out_edges(node_id, edge_type):
                if edge.target in seen:
                    continue
                queue.append((edge.target, path + [edge], seen | {edge.target}))
    # A non-empty queue means the loop exited on a budget, not on exhaustion.
    # `produced >= max_paths` is the caller's own cap and is reported as
    # `truncated` instead, so only the visit ceiling counts as capped here.
    return out, bool(queue) and visited_count >= max_visited


def query_paths(
    graph_dict: dict[str, Any],
    scan_id: str,
    src: str,
    dst: str,
    *,
    max_depth: int = MAX_QUERY_DEPTH,
    max_paths: int = MAX_QUERY_PATHS,
    max_visited: int = MAX_VISITED,
) -> dict[str, Any]:
    """
    Paths from src to dst, as steps the frontend already knows how to render.

    _iter_paths_capped rather than Scout's find_paths, for two reasons that
    both come down to a capped search being indistinguishable from a complete
    one: taking one more path than wanted tells us whether the cap or the
    graph ended the list, and the vendored loop tells us whether the visit
    budget ended the walk. The two states say different things to a user and
    only one of them is safe to phrase as "no path found".
    """
    from scout.graph.schema import EdgeType  # noqa: PLC0415

    graph = graph_for_scan(scan_id, graph_dict)
    edge_types = [EdgeType(name) for name in QUERY_EDGE_TYPE_NAMES]

    # max_paths + 1: consuming one extra distinguishes "these are all of them"
    # from "there are more". max_visited is passed through unchanged — it is
    # the budget whose exhaustion makes the answer incomplete.
    produced, search_capped = _iter_paths_capped(
        graph, src, dst, max_depth=max_depth, edge_types=edge_types,
        max_paths=max_paths + 1, max_visited=max_visited,
    )
    truncated = len(produced) > max_paths
    produced = produced[:max_paths]

    paths = []
    all_steps: list[dict[str, Any]] = []
    for edges in produced:
        steps = [_step(_hop_from_edge(graph, e, i))
                 for i, e in enumerate(edges, start=1)]
        all_steps.extend(steps)
        paths.append({"hop_count": len(steps), "steps": steps})

    return {
        "src": src,
        "dst": dst,
        "max_depth": max_depth,
        "edge_types": list(QUERY_EDGE_TYPE_NAMES),
        # Not optional: without real types the frontend's toGraph synthesizes
        # a grey "other" node for every id in the path. See
        # graph_search.chain_nodes_for_steps.
        "nodes": chain_nodes_for_steps(graph_dict, all_steps),
        "paths": paths,
        "truncated": truncated,
        "search_capped": search_capped,
    }


def reachable(graph_dict: dict[str, Any], scan_id: str, origin: str) -> dict[str, Any]:
    """
    Everything `origin` can reach — identities, then their resources.

    Not wired to any UI in this iteration. Exposed so the "what can this
    identity reach" view is additive rather than a rewrite, and so its
    visit_capped flag is carried for the same reason search_capped exists
    above.
    """
    from scout.chains.builder import reachable_from  # noqa: PLC0415
    from scout.graph.schema import EdgeType  # noqa: PLC0415

    graph = graph_for_scan(scan_id, graph_dict)
    return reachable_from(
        graph, origin,
        edge_types=[EdgeType(name) for name in QUERY_EDGE_TYPE_NAMES],
        max_visited=MAX_VISITED,
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci ./venv-dev/Scripts/python.exe manage.py test apps.attack_graph.tests.test_graph_query -v 2
```

Expected: PASS.

- [ ] **Step 5: Confirm the suite still passes with Scout absent**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2
```

Expected: PASS, with `test_graph_query`'s tests skipped and `test_graph_search`'s all running. If anything in `test_graph_query` **errors** rather than skips, a Scout import escaped to module scope — fix that before committing.

- [ ] **Step 6: Commit**

```bash
git add backend/apps/attack_graph/graph_query.py backend/apps/attack_graph/tests/test_graph_query.py
git commit -m "feat(attack-graph): on-demand path query with explicit edge types and truncation reporting"
```

---

## Task 5: The three endpoints

**Files:**
- Modify: `backend/apps/attack_graph/views.py` (append after `ScoutScanDetailView`)
- Modify: `backend/apps/attack_graph/urls.py`
- Modify: `backend/apps/attack_graph/tests/test_api_contract.py`

**Interfaces:**
- Consumes: `graph_search.search_nodes/get_entity/node_ids/graph_dict_for_scan`, `graph_query.query_paths`.
- Produces, used by Task 7's service layer:
  - `GET /api/attack-graph/scan/<uuid:scan_id>/graph/nodes/?q=` → `{"nodes": [ChainNode]}`
  - `GET /api/attack-graph/scan/<uuid:scan_id>/graph/entity/?id=` → `{"id","type","name","account_id","properties"}`
  - `GET /api/attack-graph/scan/<uuid:scan_id>/graph/path/?src=&dst=` → the `query_paths` body
  - All three 404 with a `code` of `GRAPH_UNAVAILABLE`, `GRAPH_PENDING` or `GRAPH_FAILED`, or a plain "No such scan." — four situations, four messages, because "run a new scan" is wrong advice for three of them.

- [ ] **Step 1: Write the failing tests**

DRF is absent in CI, so these read the source — the pattern `test_api_contract.py` already uses and explains. Append to it:

```python
class GraphEndpointContractTests(SimpleTestCase):
    """
    What the three graph endpoints must and must not do.

    Source-reading, like the rest of this file: DRF is not installed under
    config.settings.ci, so the views cannot be exercised. These hold the
    decisions that are expensive to get wrong and cheap to check textually.
    """

    def _source(self, relative):
        path = BACKEND_ROOT / relative
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def _class_body(self, source, name):
        """
        One class's source, from its `class X` line to the next top-level one.

        Needed because a substring search over a whole file cannot tell "the
        new views do this" from "some view in this file already did this" —
        which is how an assertion about a new class ends up passing off an old
        one and never failing again.
        """
        start = source.index(f"class {name}")
        rest = source[start + 1:]
        end = rest.find("\nclass ")
        return rest if end == -1 else rest[:end]

    GRAPH_VIEWS = (
        "_ScanGraphView",
        "ScoutScanGraphNodesView",
        "ScoutScanGraphEntityView",
        "ScoutScanGraphPathView",
    )

    def test_node_ids_travel_as_query_parameters_not_path_segments(self):
        # arn:aws:iam::1:role/foo contains a slash, which Django's default str
        # converter excludes, and a PUBLIC node's id is literally "*". A path
        # segment cannot carry either.
        urls = self._source("apps/attack_graph/urls.py")
        self.assertIn("graph/entity/", urls)
        self.assertNotIn("graph/entity/<", urls)
        self.assertNotIn("<str:arn>", urls)
        self.assertNotIn("<path:arn>", urls)

    def test_all_three_routes_are_registered(self):
        urls = self._source("apps/attack_graph/urls.py")
        for route in ("graph/nodes/", "graph/entity/", "graph/path/"):
            self.assertIn(route, urls)

    def test_the_graph_views_use_the_scout_gate(self):
        # Asserted positively, on the base class. The earlier draft of this
        # test asserted `assertNotIn("HasAWSConnection", views)` — an
        # identifier that exists nowhere in this repo, so it could not fail
        # and checked nothing.
        views = self._source("apps/attack_graph/views.py")
        for name in self.GRAPH_VIEWS[1:]:
            self.assertIn(f"class {name}", views)
        self.assertIn(
            "permission_classes = [HasScoutConnection]",
            self._class_body(views, "_ScanGraphView"),
        )
        for name in self.GRAPH_VIEWS[1:]:
            self.assertIn("(_ScanGraphView)", self._class_body(views, name))

    def test_they_scope_the_lookup_to_the_requesting_user(self):
        # Someone else's scan is a 404, which is the correct answer and does
        # not confirm the id exists.
        #
        # Scoped to _ScanGraphView's own body, not the whole file: a plain
        # `assertIn("user=request.user", views)` passes off ScoutScanDetail-
        # View, which has contained that string since before this feature
        # existed — so it would keep passing if all three new views did a
        # global ScoutScan.objects.filter(id=scan_id). A cross-user access
        # check that cannot detect its own absence is worse than none, because
        # it reads like coverage.
        views = self._source("apps/attack_graph/views.py")
        body = self._class_body(views, "_ScanGraphView")
        self.assertEqual(body.count("user=request.user"), 2)   # row + graph loader
        # And nothing else in the three subclasses queries the model at all:
        # one resolver is the point.
        for name in self.GRAPH_VIEWS[1:]:
            self.assertNotIn("ScoutScan.objects", self._class_body(views, name))

    def test_the_four_reasons_a_graph_is_missing_are_told_apart(self):
        # "Run a new scan to get it" is wrong advice for a scan that is
        # running right now, and for one that failed. All four are 404s; only
        # one of them is the pre-feature scan.
        views = self._source("apps/attack_graph/views.py")
        body = self._class_body(views, "_ScanGraphView")
        for code in ("GRAPH_UNAVAILABLE", "GRAPH_PENDING", "GRAPH_FAILED"):
            self.assertIn(code, body)
        self.assertIn("No such scan.", body)

    def test_the_graph_column_is_read_narrowly_and_through_the_cache(self):
        # The counterpart to test_model's deferral test, which owns the "the
        # polled paths must not fetch it" half — not repeated here, because
        # two copies of one string count in two files is two numbers to keep
        # in step. This half: the one path that *does* fetch it pulls the
        # column alone, through the LRU, so a cache hit skips the SELECT and
        # the jsonb parse rather than only the rehydrate.
        body = self._class_body(
            self._source("apps/attack_graph/views.py"), "_ScanGraphView",
        )
        self.assertIn('values_list("graph", flat=True)', body)
        self.assertIn("graph_search.graph_dict_for_scan", body)

    def test_a_query_to_the_same_entity_is_rejected(self):
        # iter_paths never yields a zero-length path, so without this the
        # answer is an empty result rendered as "no escalation path found from
        # alice to alice" — which reads like a finding.
        body = self._class_body(
            self._source("apps/attack_graph/views.py"), "ScoutScanGraphPathView",
        )
        self.assertIn("src == dst", body)

    def test_render_path_is_never_used(self):
        # It drops `action` and `conditional`; every query hop would then
        # render deterministic. See graph_query's module docstring.
        self.assertNotIn("render_path", self._source("apps/attack_graph/graph_query.py"))
        self.assertNotIn("render_path", self._source("apps/attack_graph/views.py"))

    def test_resolve_arn_tokens_is_never_used(self):
        # Its warnings are Scout CLI copy ("--foothold/--target ... matched
        # zero nodes") and its matching is unbounded. The pickers submit exact
        # ids; an unknown one is a 400.
        self.assertNotIn("resolve_arn_tokens",
                         self._source("apps/attack_graph/graph_query.py"))
        self.assertNotIn("resolve_arn_tokens", self._source("apps/attack_graph/views.py"))

    def test_scout_is_not_imported_at_module_scope_in_the_query_module(self):
        # views.py imports graph_query, config/urls.py imports the views, and
        # Django imports the URLconf during system checks. A module-scope Scout
        # import breaks every management command and the CI suite.
        source = self._source("apps/attack_graph/graph_query.py")
        head = source.split("def ", 1)[0]
        self.assertNotIn("from scout", head)
        self.assertNotIn("import scout", head)
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph.tests.test_api_contract -v 2
```

Expected: FAIL — the routes and view classes do not exist yet.

- [ ] **Step 3: Write the views**

Append to `backend/apps/attack_graph/views.py`, and add `from . import graph_query, graph_search` to its imports:

```python
# Why a scan has no graph, in the user's terms. All four are 404s — the
# resource genuinely is not there — but they are four different situations and
# only one of them is fixed by running a new scan. Collapsing them into one
# string would tell someone watching a scan that is running right now to go run
# a scan.
GRAPH_UNAVAILABLE = (
    "This scan has no stored graph. Scans run before this feature shipped do "
    "not have one — run a new scan to get it."
)
GRAPH_PENDING = "This scan is still running. Its graph is stored when it finishes."
GRAPH_FAILED = "This scan failed, so no graph was stored."


class _ScanGraphView(APIView):
    """
    Shared resolution for the three graph endpoints.

    One place that answers "does this user own a scan with a usable graph",
    because three copies of an ownership check is three places for one of them
    to drift into a global lookup.
    """

    permission_classes = [HasScoutConnection]

    def _resolve(self, request: Request, scan_id: str):
        """
        Returns (graph_dict, None) or (None, error Response).

        Scoped to the requesting user, matching ScoutScanDetailView: a 404 for
        someone else's scan is the correct answer and does not confirm the id
        exists. The ownership filter is inside this method and nowhere else,
        so there is one place to read to know the three endpoints are scoped.

        The graph itself comes through graph_search's LRU, so a hit skips both
        the SELECT of a multi-MB jsonb column and psycopg's parse of it. The
        status row is still read every time — it is three small columns, and
        it is what decides which of the four 404s to send.
        """
        scan = (
            ScoutScan.objects
            .filter(id=scan_id, user=request.user)
            .only("id", "status", "error_message")
            .first()
        )
        if scan is None:
            return None, Response(
                {"detail": "No such scan."}, status=status.HTTP_404_NOT_FOUND,
            )

        graph = graph_search.graph_dict_for_scan(
            str(scan_id),
            lambda: (
                ScoutScan.objects
                .filter(id=scan_id, user=request.user)
                .values_list("graph", flat=True)
                .first()
            ),
        )
        if not graph:
            if scan.status in (ScoutScan.Status.PENDING, ScoutScan.Status.RUNNING):
                detail, code = GRAPH_PENDING, "GRAPH_PENDING"
            elif scan.status == ScoutScan.Status.FAILED:
                detail = scan.error_message or GRAPH_FAILED
                code = "GRAPH_FAILED"
            else:
                detail, code = GRAPH_UNAVAILABLE, "GRAPH_UNAVAILABLE"
            return None, Response(
                {"detail": detail, "code": code},
                status=status.HTTP_404_NOT_FOUND,
            )
        return graph, None


class ScoutScanGraphNodesView(_ScanGraphView):
    """
    Search this scan's graph nodes.

    GET /api/attack-graph/scan/<scan_id>/graph/nodes/?q=<term>
    Returns:
      200 — { nodes: [...] }, at most graph_search.MAX_NODE_RESULTS
      404 — no such scan, or the scan has no stored graph
    """

    def get(self, request: Request, scan_id: str) -> Response:
        """Return matching nodes. No rehydrate — see graph_search's docstring."""
        graph, error = self._resolve(request, scan_id)
        if error is not None:
            return error
        return Response(
            {"nodes": graph_search.search_nodes(graph, request.query_params.get("q", ""))},
        )


class ScoutScanGraphEntityView(_ScanGraphView):
    """
    One entity's full record.

    GET /api/attack-graph/scan/<scan_id>/graph/entity/?id=<node id>
    Returns:
      200 — the entity
      400 — `id` missing, or not a node in this graph
      404 — no such scan, or the scan has no stored graph

    `id` is a query parameter, not a path segment: node ids contain "/" (which
    Django's default str converter excludes) and are not always ARNs at all —
    a SERVICE node is "lambda.amazonaws.com" and PUBLIC is "*".
    """

    def get(self, request: Request, scan_id: str) -> Response:
        """Return one node's record."""
        graph, error = self._resolve(request, scan_id)
        if error is not None:
            return error
        node_id = request.query_params.get("id", "")
        if not node_id:
            return Response(
                {"detail": "An 'id' query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        entity = graph_search.get_entity(graph, node_id)
        if entity is None:
            return Response(
                {"detail": f"No entity '{node_id}' in this scan's graph."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(entity)


class ScoutScanGraphPathView(_ScanGraphView):
    """
    Paths between two entities in this scan's graph.

    GET /api/attack-graph/scan/<scan_id>/graph/path/?src=<id>&dst=<id>
    Returns:
      200 — { src, dst, max_depth, edge_types, nodes, paths, truncated, search_capped }
      400 — src or dst missing, or not a node in this graph
      404 — no such scan, or the scan has no stored graph

    Exact node ids, not fuzzy tokens: both pickers are backed by
    /graph/nodes/, so the client already has an exact id. Scout's
    resolve_arn_tokens is deliberately not used — its warnings are CLI copy and
    its suffix match is unbounded.
    """

    def get(self, request: Request, scan_id: str) -> Response:
        """Run the query and return its result, truncation flags included."""
        graph, error = self._resolve(request, scan_id)
        if error is not None:
            return error

        src = request.query_params.get("src", "")
        dst = request.query_params.get("dst", "")
        if not src or not dst:
            return Response(
                {"detail": "Both 'src' and 'dst' query parameters are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        known = graph_search.node_ids(graph)
        unknown = [i for i in (src, dst) if i not in known]
        if unknown:
            return Response(
                {"detail": f"Not an entity in this scan's graph: {', '.join(unknown)}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # iter_paths' `if node_id == dst and path` never yields a zero-length
        # path, so this would otherwise come back as an ordinary empty result
        # and the panel would say "no escalation path found from alice to
        # alice within 10 hops" — which is true, useless, and reads like a
        # finding. The pickers do not stop a user choosing the same entity
        # twice, so it is stopped here.
        if src == dst:
            return Response(
                {"detail": "Pick two different entities — a path needs somewhere to go."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(graph_query.query_paths(graph, str(scan_id), src, dst))
```

- [ ] **Step 4: Wire the routes**

In `backend/apps/attack_graph/urls.py`, extend the import and the list, and add the three lines to the module docstring's route table. While editing that docstring, fix the line already in it: it claims `GET /api/attack-graph/scan/` is `ScoutScanListView`, but the list route is `scan/list/` — `GET scan/` matches nothing.

```python
from .views import (
    ScoutScanDetailView,
    ScoutScanGraphEntityView,
    ScoutScanGraphNodesView,
    ScoutScanGraphPathView,
    ScoutScanListView,
    ScoutScanTriggerView,
)

urlpatterns = [
    path("scan/", ScoutScanTriggerView.as_view(), name="attack-graph-scan-trigger"),
    path("scan/list/", ScoutScanListView.as_view(), name="attack-graph-scan-list"),
    path("scan/<uuid:scan_id>/", ScoutScanDetailView.as_view(), name="attack-graph-scan-detail"),
    # Node ids ride as query parameters, never path segments: they contain "/"
    # and are not always ARNs (a SERVICE node is "lambda.amazonaws.com",
    # PUBLIC is "*").
    path("scan/<uuid:scan_id>/graph/nodes/", ScoutScanGraphNodesView.as_view(),
         name="attack-graph-graph-nodes"),
    path("scan/<uuid:scan_id>/graph/entity/", ScoutScanGraphEntityView.as_view(),
         name="attack-graph-graph-entity"),
    path("scan/<uuid:scan_id>/graph/path/", ScoutScanGraphPathView.as_view(),
         name="attack-graph-graph-path"),
]
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd backend && DJANGO_SETTINGS_MODULE=config.settings.ci python manage.py test apps.attack_graph -v 2
```

Expected: PASS.

- [ ] **Step 6: Verify the URLconf actually loads under the real settings**

CI uses an empty URLconf, so it never resolves these. Check by hand:

```bash
cd backend && ./venv-dev/Scripts/python.exe manage.py check
```

Expected: "System check identified no issues".

- [ ] **Step 7: Commit**

```bash
git add backend/apps/attack_graph/views.py backend/apps/attack_graph/urls.py backend/apps/attack_graph/tests/test_api_contract.py
git commit -m "feat(attack-graph): graph node search, entity lookup and path query endpoints"
```

- [ ] **Step 8: Refresh the graft index (end of Phase 2)**

```bash
graphify update .
```

---

## Task 6: Extract `stepsToGraph` — behaviour-preserving, on its own

**Files:**
- Modify: `frontend/UI/src/components/attack-graph/chainGraph.ts:47-78`

**Interfaces:**
- Produces, used by Task 9: `stepsToGraph(steps: ChainStep[], pathId: string, known: ChainNode[], seed: ChainNode[] = []): Graph`

This goes first and alone. It touches the file every later frontend task also touches, and its only check is "the chain view renders exactly as before" — which stops being checkable the moment new rendering lands in the same commit.

**Two things the obvious extraction gets wrong.** Read these before writing it; both are silent, and neither is obvious from a screenshot.

1. **`known` and "nodes to include" are not the same list.** The chain caller needs `chain.source`/`chain.target` *in the output even when there are no steps* — a zero-hop chain is a real result (commit `b556c22`) and it draws as its two endpoints. The query caller has the opposite need: it passes the whole response's `nodes` array as the typing source for *each* path, and a path must not be laid out with the other paths' nodes in it. So the parameter splits in two: `known` is a **lookup** consulted when a step references an id, `seed` is what goes in **regardless**.
2. **The per-chain merge must not be unconditional.** The current `toGraph` accumulates into one map across all chains, and its synthesized fallback is guarded by `if (!nodes.has(id))` — so a node that chain 1 already contributed as a real typed endpoint cannot be downgraded by chain 2, which only touches it mid-path. Extracting a per-chain sub-graph and merging it with a bare `nodes.set(...)` loses that guard: chain 2's sub-map synthesizes its own grey `{type: 'other', label: <raw arn>}` for that node and overwrites the real one. The fix is to hoist every chain's endpoints into a single `known` lookup passed to every call, so no sub-graph ever synthesizes a node another chain knows the type of.

- [ ] **Step 1: Read the current behaviour so you can compare against it**

Start the dev server and open the Attack Graph page on a completed scan with findings:

```bash
cd frontend/UI && npm run dev
```

Screenshot the graph. This is the before.

- [ ] **Step 2: Extract the function**

Replace `toGraph`'s body in `frontend/UI/src/components/attack-graph/chainGraph.ts`:

```typescript
/**
 * Flatten one path's steps into the node and edge sets the layout needs.
 *
 * `known` is a *lookup*, not a seed list: an id a step references is rendered
 * with the real node when one is known, and synthesized as an untyped box
 * otherwise. That fallback is correct for a stray id and would be wrong for
 * every node in a query result — which is why the path endpoint returns
 * `nodes` at all, and why the query caller passes the whole response's node
 * array here for each path without those nodes leaking into paths that do not
 * reference them.
 *
 * `seed` is what goes in regardless of the steps. Only the ranked-chain
 * caller uses it, for one reason: a zero-hop chain has no steps and still has
 * to draw — its two endpoints are the entire result.
 */
export function stepsToGraph(
  steps: ChainStep[],
  pathId: string,
  known: ChainNode[],
  seed: ChainNode[] = [],
): Graph {
  const lookup = new Map<string, ChainNode>()
  for (const node of known) {
    if (node?.id) lookup.set(node.id, node)
  }

  const nodes = new Map<string, ChainNode>()
  const edges: GraphEdge[] = []

  const include = (id: string) => {
    if (!id || nodes.has(id)) return
    nodes.set(id, lookup.get(id) ?? { id, arn: '', type: 'other', label: id })
  }

  for (const node of seed) {
    if (node?.id) include(node.id)
  }

  steps.forEach((step, index) => {
    if (!step.from || !step.to) return
    edges.push({
      id: `${pathId}-${index}`,
      from: step.from,
      to: step.to,
      mechanism: step.mechanism,
      action: step.action,
      detail: step.detail,
      chainId: pathId,
      certainty: step.certainty,
    })
    include(step.from)
    include(step.to)
  })

  return { nodes: [...nodes.values()], edges }
}

/**
 * Flatten ranked chains into the node and edge sets the layout needs.
 *
 * Nodes are deduplicated by id: chains overlap heavily — the same
 * over-permissioned role is usually the hop in several of them — and drawing
 * it once is what makes that visible.
 *
 * Every chain's endpoints are hoisted into one `known` lookup before any
 * chain is walked, and the merge below is guarded. Both matter: a role that
 * is chain 1's target and chain 2's middle hop must keep chain 1's real type.
 * Building each chain's sub-graph against only its own endpoints, then
 * merging with a bare set(), replaces that role with a grey ARN-labelled box
 * — a regression this function did not have before it was extracted.
 */
export function toGraph(envelope: ScanEnvelope | null): Graph {
  if (!envelope) return { nodes: [], edges: [] }

  const known = envelope.chains.flatMap((chain) => [chain.source, chain.target])
  const nodes = new Map<string, ChainNode>()
  const edges: GraphEdge[] = []

  for (const chain of envelope.chains) {
    const sub = stepsToGraph(chain.steps, chain.id, known,
                             [chain.source, chain.target])
    for (const node of sub.nodes) {
      if (!nodes.has(node.id)) nodes.set(node.id, node)
    }
    edges.push(...sub.edges)
  }

  return { nodes: [...nodes.values()], edges }
}
```

- [ ] **Step 3: Verify the chain view is unchanged**

Reload the page. Compare against the Step 1 screenshot: same nodes, same colours, same edge labels, same layout. Check the browser console for errors.

Look specifically for the regression the extraction invites: **a node that is grey and labelled with a raw ARN where it was previously amber and labelled with a name.** Pick a scan whose chains overlap (most do) and check a role that appears as one chain's endpoint and another's middle hop. A screenshot diff of the whole canvas will not make this obvious — dagre may also have shifted things — so check that one node by name.

If a node count differs at all between the two screenshots, stop: the seed/lookup split is the likely cause, and a zero-hop chain disappearing is the shape to check first.

- [ ] **Step 4: Verify the build is clean**

```bash
cd frontend/UI && npm run build
```

Expected: no TypeScript errors.

- [ ] **Step 5: Commit**

```bash
git add frontend/UI/src/components/attack-graph/chainGraph.ts
git commit -m "refactor(attack-graph): extract stepsToGraph from toGraph"
```

---

## Task 7: Frontend types and service functions

**Files:**
- Modify: `frontend/UI/src/types/attackGraph.ts`
- Modify: `frontend/UI/src/services/attackGraph.service.ts`

**Interfaces:**
- Consumes: the three endpoints from Task 5.
- Produces, used by Tasks 8 and 9:
  - `ChainNode` gains `node_type?: string` and `name?: string`
  - `GraphEntity`, `QueryPath`, `PathQueryResult`
  - `searchGraphNodes(scanId, q): Promise<ChainNode[]>`
  - `getGraphEntity(scanId, id): Promise<GraphEntity>`
  - `findPaths(scanId, src, dst): Promise<PathQueryResult>`

- [ ] **Step 1: Extend the types**

In `frontend/UI/src/types/attackGraph.ts`, replace the `ChainNode` interface:

```typescript
export interface ChainNode {
  id: string
  arn: string
  /**
   * The ARN-parsed kind ("user" / "role" / "group" / ...). This is what
   * NODE_CATEGORY colours on, so it stays in that vocabulary even now that the
   * real graph could give Scout's own NodeType instead.
   */
  type: string
  label: string
  /**
   * Scout's own NodeType ("IAM_USER", "SERVICE", "RESOURCE", ...), when the
   * node came from the stored graph. Optional: envelope._node() derives nodes
   * by parsing an ARN and cannot produce this, so every stored scan lacks it.
   * The icon lookup keys on it and falls back to the letter badge when absent.
   */
  node_type?: string
  /** The entity's real name, when the node came from the stored graph. */
  name?: string
}
```

and append:

```typescript
/** One entity's full record from the stored graph (GET .../graph/entity/). */
export interface GraphEntity {
  id: string
  /** Scout's NodeType — "IAM_USER", "RESOURCE", "SERVICE", ... */
  type: string
  name: string
  account_id: string
  /** Everything Scout recorded. Rendered raw in a disclosure; may include a
   *  role's full trust policy document and its tags. */
  properties: Record<string, unknown>
}

/** One path from a query. No id, rank, score or narrative: a query result has
 *  none of those, and the panel must not imply it does. */
export interface QueryPath {
  hop_count: number
  /** Identical shape to a ranked chain's steps — same renderer, no new cases. */
  steps: ChainStep[]
}

export interface PathQueryResult {
  src: string
  dst: string
  /** Echoed by the backend so the "within N hops" copy cannot drift. */
  max_depth: number
  /** Which edge types were followed. "No path found" is only true of these,
   *  so the panel names them. */
  edge_types: string[]
  /** A real ChainNode for every id the steps reference. Not optional: without
   *  it stepsToGraph synthesizes an untyped grey box for every node. */
  nodes: ChainNode[]
  paths: QueryPath[]
  /** More paths existed than were returned. The shown ones are the shortest —
   *  the backend consumes them in BFS order. */
  truncated: boolean
  /** The search budget ran out before the graph was explored. The only state
   *  where "no path found" would be an unsafe thing to say. */
  search_capped: boolean
}
```

- [ ] **Step 2: Add the service functions**

Append to `frontend/UI/src/services/attackGraph.service.ts`, and extend its import:

```typescript
import type {
  ChainNode, GraphEntity, PathQueryResult, ScanDetail, ScanSummary,
} from '@/types/attackGraph'
```

```typescript
/**
 * Search one scan's graph nodes. Backs both query pickers.
 *
 * Node ids go through axios `params`, never a hand-built query string: they
 * contain ":", "/" and sometimes "*", and `params` urlencodes them. Debounce
 * the caller at 200ms — this is an autocomplete, and the endpoint's cost
 * should track searches rather than keystrokes.
 */
export async function searchGraphNodes(scanId: string, q: string): Promise<ChainNode[]> {
  const { data } = await api.get<{ nodes: ChainNode[] }>(
    `/attack-graph/scan/${scanId}/graph/nodes/`,
    { params: { q } },
  )
  return data.nodes
}

/** One entity's full record. 404s for a scan stored before graphs were kept. */
export async function getGraphEntity(scanId: string, id: string): Promise<GraphEntity> {
  const { data } = await api.get<GraphEntity>(
    `/attack-graph/scan/${scanId}/graph/entity/`,
    { params: { id } },
  )
  return data
}

/** Paths between two entities. Both ids must be exact — the pickers supply them. */
export async function findPaths(
  scanId: string, src: string, dst: string,
): Promise<PathQueryResult> {
  const { data } = await api.get<PathQueryResult>(
    `/attack-graph/scan/${scanId}/graph/path/`,
    { params: { src, dst } },
  )
  return data
}
```

Also extend the module docstring's route list with the three new paths.

- [ ] **Step 3: Verify the build**

```bash
cd frontend/UI && npm run build
```

Expected: no TypeScript errors. `ChainNode`'s two new fields are optional, so nothing that constructs one breaks.

- [ ] **Step 4: Commit**

```bash
git add frontend/UI/src/types/attackGraph.ts frontend/UI/src/services/attackGraph.service.ts
git commit -m "feat(attack-graph): types and client for the graph entity and path endpoints"
```

---

## Task 8: `nodeIcons.tsx` and the `EntityPanel`

**Files:**
- Create: `frontend/UI/src/components/attack-graph/nodeIcons.tsx`
- Modify: `frontend/UI/src/components/attack-graph/AttackChainGraph.tsx:173-286` (`DetailPanel`) and `:287+` (its call site)

**Interfaces:**
- Consumes: `getGraphEntity` (Task 7), `ChainNode.node_type`.
- Produces, used by Task 9: `<NodeIcon nodeType={...} label={...} />`.

This task ships the panel with the **letter-badge fallback only**. Task 11 swaps in real SVGs behind the same component, so a pending download permission blocks nothing.

- [ ] **Step 1: Write the icon component**

Create `frontend/UI/src/components/attack-graph/nodeIcons.tsx`:

```tsx
/**
 * The per-entity glyph.
 *
 * Keyed on Scout's NodeType, which only a node from the stored graph carries —
 * every scan stored before that field existed has none, and so does every node
 * the envelope derived by parsing an ARN. Both fall through to the letter
 * badge, which is also what an uncurated NodeType gets. There is no broken-image
 * state by construction: NODE_TYPE_ICON is a lookup, and a miss is a badge.
 *
 * NODE_TYPE_ICON is empty until the AWS Architecture Icons are added. Until
 * then every entity renders as a badge, exactly as it did before this feature.
 */

/** Scout NodeType -> imported SVG url. Populated when the icons land. */
export const NODE_TYPE_ICON: Record<string, string> = {}

function initials(label: string): string {
  const trimmed = (label || '?').trim()
  return trimmed.slice(0, 3).toUpperCase()
}

export function NodeIcon({
  nodeType, label, size = 20,
}: { nodeType?: string; label: string; size?: number }) {
  const src = nodeType ? NODE_TYPE_ICON[nodeType] : undefined

  if (src) {
    return (
      <img
        src={src}
        alt=""
        width={size}
        height={size}
        // Decorative: the entity's name is rendered next to it as text, so a
        // screen reader announcing the icon would just repeat it.
        aria-hidden="true"
        className="shrink-0"
      />
    )
  }

  return (
    <span
      aria-hidden="true"
      className="shrink-0 inline-flex items-center justify-center rounded bg-surface-elevated text-content-secondary font-mono"
      style={{ width: size, height: size, fontSize: size * 0.38 }}
    >
      {initials(label)}
    </span>
  )
}
```

- [ ] **Step 2: Evolve `DetailPanel` into `EntityPanel`**

In `AttackChainGraph.tsx`, rename `DetailPanel` to `EntityPanel`, add `scanId` and `node` to its props, and add the fetch. Its existing props and body are kept; this adds a header and a properties section above what is already there.

```tsx
function EntityPanel({
  scanId, node, nodeId, chains, onClose, onFindPaths,
}: {
  scanId: string
  node: ChainNode | undefined
  nodeId: string
  chains: AttackChain[]
  onClose: () => void
  onFindPaths: (id: string) => void
}) {
  const [entity, setEntity] = useState<GraphEntity | null>(null)
  const [rawOpen, setRawOpen] = useState(false)

  // A 404 here is the normal, permanent state for any scan stored before the
  // graph was kept — nothing backfills those. Falling back to the ARN-parsed
  // header is the whole handling; there is no error to show a user who did
  // nothing wrong.
  useEffect(() => {
    let cancelled = false
    setEntity(null)
    setRawOpen(false)
    getGraphEntity(scanId, nodeId)
      .then((data) => { if (!cancelled) setEntity(data) })
      .catch(() => { if (!cancelled) setEntity(null) })
    return () => { cancelled = true }
  }, [scanId, nodeId])

  // ... the existing copyArn helper stays exactly as it is ...

  return (
    <div className="w-[320px] shrink-0 bg-surface-card border border-border rounded-card p-4 animate-slideUp shadow-ring overflow-y-auto" style={{ maxHeight: '74vh' }}>
      <div className="flex items-start gap-2 mb-3">
        <NodeIcon nodeType={entity?.type ?? node?.node_type} label={node?.label ?? nodeId} size={24} />
        <div className="min-w-0 flex-1">
          <div className="font-display text-[0.9rem] font-bold text-content-primary leading-tight truncate"
               title={entity?.name || node?.label || nodeId}>
            {entity?.name || node?.label || nodeId}
          </div>
          <div className="text-[0.7rem] text-content-secondary truncate">
            {entity ? `${entity.type}${entity.account_id ? ` · ${entity.account_id}` : ''}` : (node?.type ?? 'entity')}
          </div>
        </div>
        {/* the existing close button stays here */}
      </div>

      <button
        type="button"
        onClick={() => onFindPaths(nodeId)}
        className="w-full mb-3 px-3 py-1.5 text-[0.75rem] rounded border border-border text-content-primary hover:bg-surface-elevated"
      >
        Find paths from here
      </button>

      {entity && Object.keys(entity.properties).length > 0 && (
        <div className="mb-3">
          <button
            type="button"
            onClick={() => setRawOpen((open) => !open)}
            className="text-[0.7rem] text-content-secondary hover:text-content-primary"
            aria-expanded={rawOpen}
          >
            {rawOpen ? 'Hide' : 'Show'} raw properties
          </button>
          {rawOpen && (
            <pre className="mt-2 text-[0.65rem] leading-tight text-content-secondary bg-surface-elevated rounded p-2 overflow-x-auto">
              {JSON.stringify(entity.properties, null, 2)}
            </pre>
          )}
        </div>
      )}

      {/* ... the existing "N chains through this identity" section, unchanged ... */}
    </div>
  )
}
```

Add the imports: `useEffect` from react, `NodeIcon` from `./nodeIcons`, `getGraphEntity` from `@/services/attackGraph.service`, and `GraphEntity` from `@/types/attackGraph`.

- [ ] **Step 3: Thread `scanId` down from the hub**

The panel fetches per scan, and nothing below `ResultRegion` currently knows
which scan it is rendering. Three edits, in `AttackGraphHub.tsx`:

```tsx
// :274 — ResultRegion already holds `current`, a ScanDetail, which has .id
  return <CompletedResult result={result} scanId={current.id} />

// :277
function CompletedResult({ result, scanId }: { result: ScanEnvelope; scanId: string }) {

// :300
          <AttackChainGraph envelope={result} scanId={scanId} />
```

Then in `AttackChainGraph.tsx`, change the component signature to
`{ envelope, scanId }: { envelope: ScanEnvelope; scanId: string }`, pass the
selected node's `ChainNode` (it is already in the computed layout — look it up
by `nodeId` rather than re-deriving it), and thread `onFindPaths` as a
`useState` setter for now. Task 9 gives that setter a panel to open.

- [ ] **Step 4: Verify in the browser**

```bash
cd frontend/UI && npm run dev
```

On a scan run **after** Task 2 landed: clicking a node shows the real name, Scout's NodeType and the account id, with a working raw-properties disclosure. On a scan run **before** it: the panel still renders, falling back to the ARN-parsed label, with no console error and no properties section.

- [ ] **Step 5: Verify the build**

```bash
cd frontend/UI && npm run build
```

- [ ] **Step 6: Commit**

```bash
git add frontend/UI/src/components/attack-graph/nodeIcons.tsx frontend/UI/src/components/attack-graph/AttackChainGraph.tsx frontend/UI/src/components/attack-graph/AttackGraphHub.tsx
git commit -m "feat(attack-graph): entity panel backed by the stored graph"
```

---

## Task 9: `QueryPanel`

**Files:**
- Create: `frontend/UI/src/components/attack-graph/QueryPanel.tsx`
- Modify: `frontend/UI/src/components/attack-graph/AttackChainGraph.tsx` (mount it)

**Interfaces:**
- Consumes: `searchGraphNodes`, `findPaths`, `stepsToGraph`, `NodeIcon`, `PathQueryResult`.

- [ ] **Step 1: Write the panel**

Create `frontend/UI/src/components/attack-graph/QueryPanel.tsx`:

```tsx
/**
 * Ask the stored graph for the paths between two entities.
 *
 * Not the ranked-chains list: that is the top 25 Scout pre-scored at depth 5,
 * and this searches the whole graph to depth 10 for one specific pair. A path
 * found here that is not in the list is the point, not a discrepancy — hence
 * the depth note below.
 *
 * Four result states, and the distinctions matter more than the happy path:
 *
 *   paths found   — drawn through the same layout the chain view uses.
 *   none found    — named with the edge types actually traversed, because
 *                   "no path" is only true of those.
 *   search capped — the budget ran out. "No path found" would be unsafe to
 *                   say, so it is not said.
 *   truncated     — more paths exist; the shown ones are the shortest.
 *
 * One combination this view produces that the chain view almost never did: a
 * resource_access/resource_control hop carrying certainty: 'conditional'. The
 * spec flagged it as worth confirming the step renderer survives. It does, and
 * by construction rather than by luck — `mechanism` is read in exactly two
 * places (AttackChainGraph.tsx:246 and :445), both as the fallback half of
 * `step.action || step.mechanism`. Nothing in this frontend branches on its
 * value, so certainty and mechanism cannot interact. Keep it that way: a
 * `switch (step.mechanism)` is what would make this a real case to handle.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import * as attackGraph from '@/services/attackGraph.service'
import type { ChainNode, PathQueryResult } from '@/types/attackGraph'

import { stepsToGraph } from './chainGraph'
import { NodeIcon } from './nodeIcons'

// The endpoint's cost should track searches, not keystrokes. 200ms is the
// contract the backend's no-rehydrate search path was sized against.
const SEARCH_DEBOUNCE_MS = 200

function EntityPicker({
  scanId, label, value, onChange,
}: {
  scanId: string
  label: string
  value: ChainNode | null
  onChange: (node: ChainNode | null) => void
}) {
  const [term, setTerm] = useState('')
  const [options, setOptions] = useState<ChainNode[]>([])
  const [open, setOpen] = useState(false)
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => {
    if (!open) return
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => {
      attackGraph.searchGraphNodes(scanId, term)
        .then(setOptions)
        .catch(() => setOptions([]))
    }, SEARCH_DEBOUNCE_MS)
    return () => window.clearTimeout(timer.current)
  }, [scanId, term, open])

  return (
    <div className="relative">
      <label className="block text-[0.7rem] text-content-secondary mb-1">{label}</label>
      <input
        type="text"
        value={value ? value.label : term}
        onChange={(e) => { onChange(null); setTerm(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
        placeholder="Search identities and resources"
        className="w-full px-2 py-1.5 text-[0.75rem] rounded border border-border bg-surface-elevated text-content-primary"
      />
      {open && options.length > 0 && !value && (
        <ul className="absolute z-10 mt-1 w-full max-h-56 overflow-y-auto rounded border border-border bg-surface-card shadow-ring">
          {options.map((node) => (
            <li key={node.id}>
              <button
                type="button"
                onClick={() => { onChange(node); setOpen(false) }}
                className="w-full flex items-center gap-2 px-2 py-1.5 text-left text-[0.72rem] hover:bg-surface-elevated"
              >
                <NodeIcon nodeType={node.node_type} label={node.label} size={16} />
                <span className="truncate" title={node.id}>{node.label}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function QueryPanel({
  scanId, initialSource, onClose,
}: { scanId: string; initialSource: ChainNode | null; onClose: () => void }) {
  const [src, setSrc] = useState<ChainNode | null>(initialSource)
  const [dst, setDst] = useState<ChainNode | null>(null)
  const [result, setResult] = useState<PathQueryResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => { setSrc(initialSource); setResult(null) }, [initialSource])

  const run = useCallback(async () => {
    if (!src || !dst) return
    setBusy(true)
    setError('')
    setResult(null)
    try {
      setResult(await attackGraph.findPaths(scanId, src.id, dst.id))
    } catch (err: unknown) {
      // The backend's message names the id it could not find, or says the scan
      // has no stored graph — both are worth showing verbatim.
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail
      setError(detail || 'The path query failed. Try again.')
    } finally {
      setBusy(false)
    }
  }, [scanId, src, dst])

  // Each path gets its own node/edge set so one long path does not distort
  // another's layout. `result.nodes` is passed as the type LOOKUP, not as a
  // seed — stepsToGraph only emits the ids this path's steps reference, so
  // path 1's layout does not contain path 3's nodes. (No `seed` argument:
  // that exists for zero-hop ranked chains, and a query never returns one.)
  // Without the lookup every node here would be a grey ARN-labelled box.
  const graphs = useMemo(
    () => (result?.paths ?? []).map((path, i) =>
      stepsToGraph(path.steps, `q${i}`, result?.nodes ?? [])),
    [result],
  )

  const edgeTypes = (result?.edge_types ?? []).join(' / ')
  const longPath = (result?.paths ?? []).some((p) => p.hop_count > 5)

  return (
    <div className="w-[360px] shrink-0 bg-surface-card border border-border rounded-card p-4 animate-slideUp shadow-ring overflow-y-auto" style={{ maxHeight: '74vh' }}>
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="font-display text-[0.9rem] font-bold text-content-primary">
          Find paths
        </div>
        <button type="button" onClick={onClose}
                className="text-content-secondary hover:text-content-primary text-[0.8rem]">
          Close
        </button>
      </div>

      <div className="space-y-2 mb-3">
        <EntityPicker scanId={scanId} label="From" value={src} onChange={setSrc} />
        <EntityPicker scanId={scanId} label="To" value={dst} onChange={setDst} />
      </div>

      <button
        type="button"
        onClick={run}
        disabled={!src || !dst || busy}
        className="w-full mb-3 px-3 py-1.5 text-[0.75rem] rounded border border-border text-content-primary hover:bg-surface-elevated disabled:opacity-40"
      >
        {busy ? 'Searching…' : 'Find paths'}
      </button>

      {error && <div className="text-[0.72rem] text-danger mb-3">{error}</div>}

      {result && result.search_capped && (
        <div className="text-[0.72rem] text-warning mb-3">
          Search budget reached before the graph was fully explored — there may
          be paths this query did not find.
        </div>
      )}

      {result && !result.search_capped && result.paths.length === 0 && (
        <div className="text-[0.72rem] text-content-secondary mb-3">
          No escalation path found from {src?.label} to {dst?.label} within{' '}
          {result.max_depth} hops, following {edgeTypes} edges.
        </div>
      )}

      {result && result.truncated && (
        <div className="text-[0.72rem] text-content-secondary mb-2">
          Showing the {result.paths.length} shortest paths; more exist.
        </div>
      )}

      {longPath && (
        <div className="text-[0.72rem] text-content-secondary mb-2">
          The ranked chain list only covers paths up to 5 hops, so a longer path
          here is differently scoped — not missing from the list by mistake.
        </div>
      )}

      {graphs.map((graph, i) => (
        <div key={i} className="mb-3">
          <div className="text-[0.7rem] text-content-secondary mb-1">
            Path {i + 1} — {result?.paths[i].hop_count} hops
          </div>
          <ol className="space-y-1">
            {result?.paths[i].steps.map((step, s) => (
              <li key={s} className="text-[0.7rem] text-content-primary">
                <span className="text-content-secondary">{s + 1}.</span>{' '}
                {step.detail}
                {step.certainty === 'conditional' && (
                  <span className="text-warning"> — {step.conditional_reason}</span>
                )}
              </li>
            ))}
          </ol>
          {/* graph.nodes / graph.edges feed the same computeLayout + SvgNode the
              chain view uses; wire them in Step 2 once the drawing surface is
              lifted out of AttackChainGraph. */}
        </div>
      ))}
    </div>
  )
}
```

- [ ] **Step 2: Draw the path with the shared primitives**

`computeLayout` and `SvgNode` are module-private to `AttackChainGraph.tsx`.
Export both (`export function computeLayout`, `export function SvgNode`) and
import them in `QueryPanel`, replacing the placeholder comment with the same
`<svg>` element `AttackChainGraph` renders, fed by `graph.nodes`/`graph.edges`.
Do not copy the SVG markup — move it into an exported
`GraphCanvas({ graph }: { graph: Graph })` in `AttackChainGraph.tsx` and call
that from both places.

- [ ] **Step 3: Give resources and services a colour**

`NODE_CATEGORY` (`AttackChainGraph.tsx:47`) maps exactly four keys — `user`,
`role`, `group`, `policy` — so `categorize()` returns `'other'` for everything
`graph_search._ARN_KIND_BY_NODE_TYPE` emits. Left alone, every S3 bucket and
Lambda function in a query result draws grey and labelled "Other", on the one
feature whose point is showing resources.

Extend the three lookups together — they are parallel and a key missing from
any one of them is a silent fallback:

```tsx
type Category = 'iam' | 'resource' | 'service' | 'other'

const NODE_CATEGORY: Record<string, Category> = {
  user: 'iam',
  role: 'iam',
  group: 'iam',
  policy: 'other',
  // From the stored graph (graph_search._ARN_KIND_BY_NODE_TYPE). The
  // ARN-parsing envelope._node() never produces these, so ranked chains are
  // unaffected and this changes nothing that renders today.
  resource: 'resource',
  service: 'service',
}

const CAT_COLOR: Record<Category, string> = {
  iam: '#ffbc33',
  resource: '#4ea8de',   // accent-blue's family — the loot, not the identity
  service: '#8a8f98',
  other: '#8a8f98',
}

const CAT_LABEL: Record<Category, string> = {
  iam: 'IAM Identity',
  resource: 'Resource',
  service: 'AWS Service',
  other: 'Other',
}
```

`account`, `federated`, `public` and `external` stay unmapped on purpose:
they are principals a v1 query cannot reach as a destination, and inventing a
colour for a node nobody will see is how a palette stops meaning anything.

- [ ] **Step 4: Mount the panel**

In `AttackChainGraph`, hold `queryOpen: boolean` and `querySource: ChainNode | null`.
`EntityPanel`'s `onFindPaths` sets both. Render `QueryPanel` beside `EntityPanel`
when open. Add a "Find paths" button to the graph toolbar so the panel is
reachable without selecting a node first.

- [ ] **Step 5: Verify in the browser**

```bash
cd frontend/UI && npm run dev
```

Check every state against a scan run after Task 2:
1. two identities with a known chain between them → paths drawn, identities amber (not grey), conditional hops showing their reason;
2. an identity and an S3 bucket it can reach → a path ending at the resource, drawn blue and labelled "Resource" (this is the one the default edge-type list would have failed, and the one Step 3's palette is for);
3. two unrelated identities → the no-path message, naming the three edge types;
4. the same entity in both pickers → the 400's "pick two different entities", not an empty result rendered as "no escalation path found from alice to alice";
5. a scan from before Task 2 → "run a new scan to get it", not a blank panel;
6. a scan that is **still running**, reached by opening the query panel on it → "this scan is still running", *not* the run-a-new-scan copy. If the hub does not mount the panel for a running scan, hit the endpoint directly (`/api/attack-graph/scan/<id>/graph/nodes/`) and check the JSON — the four 404 reasons are a backend contract whether or not the UI can reach all of them today.

- [ ] **Step 6: Verify the build**

```bash
cd frontend/UI && npm run build
```

- [ ] **Step 7: Commit**

```bash
git add frontend/UI/src/components/attack-graph/QueryPanel.tsx frontend/UI/src/components/attack-graph/AttackChainGraph.tsx
git commit -m "feat(attack-graph): on-demand path query panel"
```

---

## Task 10: Documentation

**Files:**
- Modify: `docs/` — the Scout integration README referenced by commit `4e36ddf`

- [ ] **Step 1: Document the three endpoints and the null-graph state**

Add a section covering:

- the new `ScoutScan.graph` field, and that it is null for pre-existing scans permanently;
- **the `.defer("graph")` invariant** — why the two polled querysets must never fetch the column, and that the serializer's `Meta.fields` is not what enforces it. This is the item most likely to be undone by someone who does not know it is load-bearing;
- the three endpoint paths with their query parameters, and the four 404 codes (`GRAPH_UNAVAILABLE` / `GRAPH_PENDING` / `GRAPH_FAILED` / no-such-scan) a client can branch on;
- the measured payload size from Task 0, and which storage rung was taken;
- the traversed edge types, the depth (10, vs the ranked list's 5), and what `truncated` and `search_capped` each mean — these are in the response so the UI can be honest about them, and a client author needs to know which is which;
- the fact that `graph_search.py` is CI-tested while `graph_query.py` is not, with the reason.

- [ ] **Step 2: Commit**

```bash
git add docs/
git commit -m "docs: attack graph entity records and path query"
```

- [ ] **Step 3: Refresh the graft index (end of Phase 3)**

```bash
graphify update .
```

---

## Task 11: AWS Architecture Icons (isolated — needs download permission)

**Files:**
- Create: `frontend/UI/src/assets/aws-icons/*.svg`
- Modify: `frontend/UI/src/components/attack-graph/nodeIcons.tsx` (populate `NODE_TYPE_ICON`)
- Modify: `frontend/UI/src/components/attack-graph/AttackChainGraph.tsx` (`SvgNode` — the graph's own node cards, which `NodeIcon` does not reach)

Nothing else depends on this. Every task above ships with the letter badge, which is `NODE_TYPE_ICON`'s miss path — so a pending or refused permission costs the feature its icons and nothing else.

- [ ] **Step 1: Ask for permission before downloading**

State to the user, before fetching anything: the source URL, the archive filename, its size, and the exact list of icons to be extracted. Do not download first and ask after.

- [ ] **Step 2: Decide the subset**

Cover the `NodeType` values that actually appear: `IAM_USER`, `IAM_ROLE`, `IAM_GROUP`, `AWS_ACCOUNT`, `SERVICE`, `FEDERATED`, `PUBLIC`, `EXTERNAL_ACCOUNT`, plus the `properties.resource_type` values a real scan produces for `RESOURCE` (EC2, Lambda, S3, KMS, SSM, ECS, SageMaker, CloudFormation at minimum — confirm against a real scan's graph rather than guessing). Do not vendor icons for services this product never sees.

- [ ] **Step 3: Populate the lookup**

```tsx
import iamRole from '@/assets/aws-icons/iam-role.svg'
import iamUser from '@/assets/aws-icons/iam-user.svg'
// ... one import per icon

export const NODE_TYPE_ICON: Record<string, string> = {
  IAM_USER: iamUser,
  IAM_ROLE: iamRole,
  // ...
}
```

Vite resolves an imported `.svg` to a url, which is what `NodeIcon`'s `<img src>` already expects — no change to that component is needed.

- [ ] **Step 4: Put the icon on the graph's node cards too**

`NodeIcon` covers the entity panel and the query pickers. It does **not** cover
the nodes in the graph, which are drawn by `SvgNode`
(`AttackChainGraph.tsx:123`) and currently render `node.type.slice(0, 3)` in a
rounded rect. An `<img>` cannot go inside an `<svg>`, so this is a separate
edit rather than a reuse — which is exactly why it is easy to ship the icons
and still have the graph look untouched.

In `SvgNode`, replace the badge rect + text with the icon when one exists,
keeping the badge as the miss path:

```tsx
const iconHref = node.node_type ? NODE_TYPE_ICON[node.node_type] : undefined

// ...
<rect x={x + 11} y={y + 19} width={26} height={26} rx={7} fill={color} fillOpacity={0.14} />
{iconHref ? (
  <image href={iconHref} x={x + 15} y={y + 23} width={18} height={18} />
) : (
  <text x={x + 24} y={y + 36} textAnchor="middle" fill={color} fontSize={9}
        fontFamily="Geist Mono, monospace" fontWeight={700}>
    {node.type.slice(0, 3).toUpperCase()}
  </text>
)}
```

`node_type` is only present on nodes that came from the stored graph, so
ranked-chain nodes keep their letter badge and nothing that renders today
changes. Use `href`, not `xlink:href` — React 16+ supports the former and the
latter is deprecated.

- [ ] **Step 5: Verify**

```bash
cd frontend/UI && npm run build && npm run dev
```

Every entity with a mapped type shows its icon — in the entity panel, in both
query pickers, **and** on the node cards in the graph. Anything unmapped still
shows the letter badge. Confirm no broken-image glyph appears anywhere, and
check the SVG case specifically: a bad `href` inside `<svg>` fails silently
(empty space) rather than showing a broken-image marker, so compare against a
node you know is mapped.

- [ ] **Step 6: Commit**

```bash
git add frontend/UI/src/assets/aws-icons frontend/UI/src/components/attack-graph/nodeIcons.tsx
git commit -m "feat(attack-graph): AWS Architecture Icons per entity type"
```

---

## Self-review notes

**Spec coverage.** Every spec section maps to a task: `ScoutScan.graph` + measurement gate (and its two fallback rungs) → Tasks 0–1; the serializer **and queryset** invariants → Task 1; `tasks.py`, plus proving the write actually succeeds → Task 2; the module split, `search_nodes`/`get_entity`/`hop_dict`, the dict LRU → Task 3; edge types, hop construction, the vendored traversal and its truncation flags, the Graph LRU, `reachable` → Task 4; the three endpoints, query-param ids, exact-id validation, the four 404 reasons → Task 5; `stepsToGraph` → Task 6; types and client → Task 7; `EntityPanel`, raw-properties disclosure, icon fallback → Task 8; `QueryPanel`, its result states, the resource palette and the depth-5-vs-10 note → Task 9; icons, in the panel and on the node cards → Task 11.

**Deviations from the spec, all deliberate, all to be amended into it:**
1. `hop_dict` returns a plain dict rather than constructing Scout's `Hop` and calling `.to_dict()`. Same fields, one fewer Scout import, and it is what lets the certainty regression test run in CI instead of behind a `skipUnless` — which would have reproduced the original defect's silence.
2. The spec's Testing section assumed the endpoints could be exercised. They cannot: DRF is absent in CI. They are covered by source-reading contract tests in `test_api_contract.py`'s established style.
3. **The spec's "detail endpoint does not grow" invariant is a queryset invariant, not a serializer one.** The spec review (item #7) asked for the serializer to be written down and tested; that is necessary and it is the half that was already safe. `.defer("graph")` on `ScoutScanDetailView` and `ScoutScanListView` is the half that actually keeps the blob out of a poll, and the test belongs there.
4. **Four 404 reasons, not two.** The spec distinguishes "no such scan" from "this scan predates the graph field". A running scan and a failed scan are also graphless, and "run a new scan to get it" is wrong advice for both. `GRAPH_PENDING` and `GRAPH_FAILED` are new response codes.
5. **`src == dst` is a 400.** The spec's error handling enumerates null-graph, zero-match and no-path-found. `iter_paths` never yields a zero-length path, so without this the answer is a well-formed empty result the panel renders as "no escalation path found from alice to alice" — a true statement that reads like a finding.
6. **Resource and service nodes get their own colour** (Task 9, Step 3). The spec left `NODE_CATEGORY` alone, correctly, on the argument that remapping it to Scout's vocabulary buys nothing. But it maps only four identity kinds, so without three added keys every resource in a query result draws grey and labelled "Other" — on the feature whose point is showing resources.
7. **Two LRUs, not one.** The spec's caching posture covers the rehydrated `Graph`. The autocomplete never builds one, and still pays a multi-MB SELECT plus a jsonb parse per debounced keystroke; `graph_search.graph_dict_for_scan` is what makes the search path actually cheap rather than only appearing to be.
8. **The resource hop's category comes off the node, not the edge — the spec's code block is wrong here.** The spec specifies `category = edge.properties.get("category", "data")` and comments that "a resource hop's mechanism comes from the edge's category". The function it cites as the thing being mirrored does the opposite: `_resource_reach_chains` reads `node.properties.get("category")` first and falls back to the edge (`builder.py:581-583`). Following the spec produces `resource_access` for a publicly exposed Lambda that the ranked-chains view calls `resource_control`. This is the one deviation where the spec is not merely silent or out of date but states something its own reference contradicts, so amend it rather than reconciling toward it.
9. **`payload_bytes` is this app's own, not `scout.viz.payload_bytes`.** The spec names Scout's. Task 0 runs before any of this app's modules exist, so it inlines `len(json.dumps(...))`, and `graph_search.payload_bytes` is the stdlib version kept for taking the number off a stored row later — importing Scout to measure a dict that is already a dict buys nothing and puts a Scout import in the pure module.

**One thing this plan adds that the spec does not specify:** `_iter_paths_capped`. `iter_paths` reports no budget exhaustion at all, so `search_capped` has to be established some other way, and there are only two: copy the traversal so it can report on itself, or infer the answer from a second walk.

The plan originally inferred it, and that was wrong. The inference needs a second model of `iter_paths`' pruning — it does not expand `dst`, and it stops descending at `max_depth` — and a model missing either one visits states the real search never reaches, over-counts, and reports "we stopped looking" about a search that finished. That is the same class of confident wrong answer the edge-type decision exists to avoid, just pointed at the opposite state, and it lands on the endpoint's most common answer. It also costs a second full traversal on every under-cap query.

So the traversal is vendored instead, which is what `reachable_from` already does for itself (`visit_capped = bool(queue)`, `builder.py:1043-1047`). The cost of a copy is drift, and `IterPathsParityTests` is what pays it: a Scout release that changes the traversal fails there, by name, instead of on a user's query. The better fix is still upstream — have `iter_paths` yield its own cap signal — and this is the shape to propose when it is.

**Four things the plan got wrong and now doesn't:**
1. *The blob would have been fetched on every 3s poll and every history load.* Keeping `graph` out of `Meta.fields` stops DRF rendering it, not Django fetching it, and both polled querysets were bare `SELECT *` with no pagination. Task 1 now adds `.defer("graph")` to both and tests the **queryset**, which is the half that was unguarded.
2. *The resource mechanism was read off the edge, not the node* — diverging from `builder.py:581-583` for exactly the edges `attack_surface/build.py:124` writes, and rendering one grant two ways. Fixed, with a fixture (a `compute` node, a category-less edge) that can actually detect it; the old fixture asserted the same value the default produces.
3. *Three contract tests could not fail* — the ownership test passed off a string `ScoutScanDetailView` has contained since before this feature, and `assertNotIn("HasAWSConnection", …)` named an identifier that exists nowhere in the repo. Now scoped per class.
4. *The extraction in Task 6 was not behaviour-preserving.* A per-chain sub-graph merged with a bare `set()` lets one chain's synthesized grey node overwrite another chain's real typed one. `known` is now hoisted across all chains and the merge is guarded — and `known` and `seed` are separate parameters, because the query caller needs a type lookup while the chain caller needs zero-hop endpoints drawn regardless.
