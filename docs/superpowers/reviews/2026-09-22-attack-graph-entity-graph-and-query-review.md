# Review — Attack Graph: Full Entity Graph, Icons, and Path Query

Reviewing: `docs/superpowers/specs/2026-09-22-attack-graph-entity-graph-and-query-design.md`
Date: 2026-09-22
Verdict: **sound premise, three blocking gaps before an implementation plan.**

The core insight is right and cheaply verified: `pipeline.run()` does return a
fully-typed graph the task throws away, `Graph.to_dict()`/`from_dict()` is
loss-free by contract (`scout/graph/schema.py:193-224`), and Scout's
path-finding is real and tested. Nothing below disputes that.

What follows are gaps where the spec asserts something the code contradicts, or
leaves a decision undefined that changes what gets built.

---

## Blocking

### 1. `render_path` drops `action` and `conditional` — every query hop will render as "deterministic"

The spec says `render_path`'s output is "normalised through the same
step-mapping logic `_step` already applies to chain hops (including
`certainty`/`conditional_reason` if the underlying edge carries `conditional`
data … absent means `deterministic`, same default `_step` already uses)."

That is not what happens. `render_path` (`scout/chains/builder.py:1007-1020`)
emits exactly five keys per hop:

```python
{"hop_number", "mechanism", "source_arn", "target_arn", "concrete_api_sequence"}
```

`_step` (`backend/apps/attack_graph/envelope.py:210`) reads `hop["action"]` and
`hop["conditional"]`. Neither key exists in `render_path`'s output, so:

- `action` is always `""` → `detail` degrades to the bare mechanism, where the
  ranked-chain view shows `"{action} ({mechanism})"`.
- `conditional` is always `None` → `_conditional_summary` returns
  `"deterministic"` for **every hop of every query result**.

This is not a missing field, it is a wrong answer. The same edge, in the
ranked-chains view, renders as `conditional` with a reason; in the query view it
renders as `deterministic`. The product tells the user two contradictory things
about one grant. The spec's justification — "absent means deterministic, same
default `_step` already uses" — inverts the meaning of that default: it exists
for edges Scout genuinely never gated, not for a field the renderer discarded.

**Fix, and it is cheaper than what the spec proposes.** Don't use `render_path`.
Build Scout's own `Hop` objects straight off the edge list, exactly the way
`build_chains` already does (`scout/chains/builder.py:1174-1186`):

```python
Hop(hop_number=i, mechanism=_mechanism_for(e), action=e.method,
    source_arn=e.source, target_arn=e.target,
    concrete_api_sequence=_concrete_api(e),
    conditional=e.properties.get("conditional"),
    granted_by=e.properties.get("granted_by", []), ...)
```

then `_step(hop.to_dict())`. That is full parity with chain hops — `action`,
`conditional`, `granted_by`, `bounded_by` — for the same amount of code, and it
makes the spec's "zero new cases on the frontend" claim actually true instead of
aspirationally true. `render_path` goes unused.

### 2. `find_paths` never traverses resource edges, but the pickers offer every node

`iter_paths`' default is `edge_types = [EdgeType.PRIVESC_TO, EdgeType.CAN_ASSUME]`
(`scout/chains/builder.py:980`). `CAN_ACCESS_RESOURCE`, `CAN_PASS_ROLE`,
`MEMBER_OF`, `DEPENDS_ON` and `TRIGGERS` are not traversed.

Goal #1 of this spec is to expose "every AWS identity, service and resource
node," `/graph/nodes/?q=` searches all of them, and `QueryPanel` lets the user
pick any of them as a destination. So: the user picks an S3 bucket, and the
endpoint returns "No path found from X to Y within depth 10" — **always**, for
every bucket, in every account. That message is a false statement. The traversal
never looked at a single resource edge.

The spec picks neither available resolution. It needs to choose one:

- pass an explicit `edge_types` list including `CAN_ACCESS_RESOURCE` (and decide
  about `CAN_PASS_ROLE`/`MEMBER_OF` — they change what "a path" means), **or**
- constrain the destination picker to the node types the default traversal can
  actually reach, and say so in the UI.

Either is fine. Silence is not, because the failure mode is a confident wrong
answer rather than a visible error.

### 3. A capped BFS is indistinguishable from "no more paths" — Scout's own author already flagged this

`find_paths` carries `max_paths=50` and `max_visited=50_000`
(`scout/chains/builder.py:999`) and returns a bare list. It has no truncation
signal.

Compare `reachable_from` in the same file (`scout/chains/builder.py:1043-1047`),
which returns `visit_capped` with this comment:

> a bailed-out BFS is indistinguishable from "nothing else is reachable" — the
> worst available wrong answer here.

The spec's Error handling section enumerates null-graph, zero-match, and
no-path-found. It does not enumerate "we stopped looking." This product already
carries `truncated` in the envelope for exactly this reason
(`backend/apps/attack_graph/envelope.py:101`), and the whole feature's design
posture is "an explicit state, never a blank panel indistinguishable from X."
The query endpoint needs the same: call `iter_paths` directly, count, and report
when the budget — not the graph — ended the search.

---

## Non-blocking, but fix before the plan is written

### 4. `/graph/entity/<arn>/` is not a routable URL

Node ids are not URL-path-safe. `arn:aws:iam::123456789012:role/foo` contains a
`/`, which Django's default `str` converter excludes. And not every node id is
an ARN at all — `SERVICE` nodes are `lambda.amazonaws.com`, and `PUBLIC` is
literally `*` (`scout/graph/schema.py:17-28`).

Use a query parameter (`/graph/entity/?id=<urlencoded>`), not a path segment.
Same for `/graph/path/`, which the spec already gets right with `?src=&dst=`.

### 5. `resolve_arn_tokens` is the wrong tool here, and its warnings are CLI strings

The spec says its warnings are surfaced "verbatim rather than translating."
Verbatim is (`scout/chains/builder.py:1063`):

```
--foothold/--target 'alice' matched zero nodes
```

That puts Scout's CLI flag names in the product's web UI. "Not re-worded into a
guess about what went wrong" is a good instinct pointed at the wrong artifact —
the warning's *classification* is what shouldn't be guessed at; its *wording* is
CLI copy.

Three further problems with using it at all:

- `matches = [k for k in graph.nodes if k == token or k.endswith(token)]` — an
  empty token matches every node, and a short token (`"e"`) matches most of them.
- It returns a **flat** `(resolved, warnings)` with no token→match attribution.
  With a two-field src/dst form, "token matched 3 nodes" has no defined
  resolution — which of the 3 is the source? The spec says an ambiguous match
  "renders an explicit state" without saying what that state offers the user.
- If both pickers are autocomplete-backed by `/graph/nodes/` as designed, the
  client already submits an exact node id. Fuzzy suffix resolution solves a
  problem the UI design removed. Validate the id exists and 400/404 if not.

### 6. The storage decision defers a measurement that can be taken today

Blocking decision #2 says revisit JSONField "only if a real scan's graph size,
measured against a production-scale account, turns out to be a genuine problem."
Three things make that deferral cheaper to close than to carry:

- `scout.viz.payload_bytes()` (`scout/viz.py:66`) is a ready-made measurement,
  and `SIZE_LIMIT_BYTES = 8 * 1024 * 1024` is Scout's own ceiling.
- Every role node carries its **full trust policy document** in `properties`
  (`scout/ingest/gaad.py:199`), plus tags.
- `SqliteGraph` moves `granted_by` into a separate table specifically because it
  is a size problem (`scout/graph/store.py:45-49`), and `granted_by` rides on
  edge properties that `to_dict()` serializes whole.

The 67-identity account that produced this feature's timing numbers is the same
account that can produce this number. Make "measure `payload_bytes` on a real
scan" a gate on the migration landing, not a future revisit — a JSONField is
easy to add and expensive to move off once rows exist.

### 7. State the "detail endpoint does not grow" invariant explicitly

`ScoutScanDetailSerializer` lists its fields explicitly
(`backend/apps/attack_graph/serializers.py:29-38`), so adding `graph` to the
model won't leak it into the poll response. That is luck, not design — a later
`fields = "__all__"`, or a well-meant "add graph to the detail response," would
start shipping the entire graph on **every poll of a running scan**, which the
frontend does on an interval. Write it down as an invariant with a test, next to
the existing `ScoutScanListSerializer` comment that already reasons about
`result` being "the largest field on the row."

### 8. "The same step/edge components, zero new cases" understates the frontend work

`AttackChainGraph` takes `{ envelope: ScanEnvelope }`
(`frontend/UI/src/components/attack-graph/AttackChainGraph.tsx:287`) and
`toGraph()` iterates `envelope.chains`
(`frontend/UI/src/components/attack-graph/chainGraph.ts:47`). `DetailPanel`
takes `chains: AttackChain[]`.

A query result has no `chain_id`, `rank`, `score`, `terminal_impact`,
`narrative`, `detection`, `remediation`, or `alternate_mechanisms` — every field
the `AttackChain` type declares non-optional
(`frontend/UI/src/types/attackGraph.ts`). So one of two things has to happen,
and the spec should name which:

- refactor the components to accept a chain list (or a step list) rather than an
  envelope, **or**
- have the backend synthesize an `AttackChain`-shaped object with null/empty
  scoring fields.

Then say what the shared UI renders where those fields are absent — the panel
currently leads with "N chains through this identity" and a risk score.

### 9. Latency and rehydration are unaddressed, and `/graph/nodes/` is the worst case

All three endpoints do `Graph.from_dict(scan.graph)` synchronously in the Django
request thread. `/graph/nodes/?q=` is autocomplete — that is a **full graph
rehydrate per keystroke**, on a JSONField read of a multi-MB blob.

Scout already solved the shape of this: `scout/graph/neighborhood.py` does
bounded traversal over the **serialized dict**, never rehydrating, and its
header comment records that "real account graphs are dense enough that a capped
node set can still carry a huge edge count." For search specifically you don't
need a `Graph` object at all — scan the `nodes` list in the stored dict.

The spec needs: a caching posture (per-request? per-scan LRU? none, with a
stated p95?), a client debounce contract, and the result cap the Open Items
section already anticipates. Right now the 50-result cap is listed as an open
item while the per-keystroke rehydrate behind it isn't mentioned at all.

---

## Framing

**Goal #1 overclaims.** "The full entity graph — every AWS identity, service and
resource node Scout modelled" describes a viewer. Nothing in this design renders
a graph; the Non-goals section explicitly forbids one. What ships is entity
lookup, entity search, and a linear path query — all of which are worth
shipping. Retitle it to what it is ("per-entity records from Scout's graph,
stored and queryable") so a reader approving this spec approves the right thing.

## Smaller notes

- **Raw-properties disclosure leaks policy documents.** `EntityPanel`'s
  "collapsible raw properties JSON" will render `trust_policy` documents and
  resource tags verbatim. Probably fine for an authenticated account owner
  viewing their own scan, but it is a deliberate decision the spec should record
  rather than arrive at by default.
- **Depth 5 vs depth 10.** `build_chains` defaults to `max_depth=5`
  (`scout/chains/builder.py:1079`) while the query uses 10. A path the query
  finds at depth 8 will not appear in the ranked list, which is the *point* —
  but the UI should say so, or a user will read the ranked list as incomplete
  rather than differently scoped.
- **Migration naming.** Per `CLAUDE.md`, `makemigrations` must name apps
  explicitly (`makemigrations attack_graph`). Worth one line in the plan given
  there is already an uncommitted `users` migration in the tree.
- **Testing gaps.** The Testing section covers `graph_query.py` but not the
  endpoints. Add: a cross-user access test on all three (someone else's scan id
  returns 404, matching `ScoutScanDetailView`'s posture), and a test for the
  `scan.graph is None` → 404 branch, which is the permanent state of every scan
  stored before this ships.

## What to keep exactly as it is

- Nullable `graph` with no backfill, and the reasoning for why that is a normal
  permanent state rather than migration debt.
- `404` rather than `200` + empty body for a scan with no graph.
- Keeping the ranked-chains list as the landing view and the full graph as a
  drill-down. The Non-goals section's argument against a force-directed dump is
  the strongest paragraph in the spec, and `neighborhood.py`'s own comment about
  dagre choking on dense account graphs is independent evidence for it.
- Exposing `reachable_from` in the query module without wiring it to the UI.
