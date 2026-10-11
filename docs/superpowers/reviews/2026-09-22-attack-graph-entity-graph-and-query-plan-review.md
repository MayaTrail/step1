# Review — Implementation Plan: Attack Graph Entity Records, Icons, and Path Query

Reviewing: `docs/superpowers/plans/2026-09-22-attack-graph-entity-graph-and-query.md`
(The existing `...-entity-graph-and-query-review.md` reviews the **spec**; this one
reviews the **plan** written from it.)
Date: 2026-09-22
Verdict: **executable, and it answers all nine spec-review items. Three blocking
defects, two correctness bugs in the frontend refactor, and a set of tests that
cannot fail.**

> **Status: every finding below is applied to the plan** (same date). The plan's
> "Self-review notes" carries the four it got wrong and the nine deviations
> from the spec that now need amending into the spec. This document is kept as
> the record of what was found and why, not as an open list.

The plan is unusually well argued — the module split (`graph_search.py` pure /
`graph_query.py` deferred) is the right answer to the six-package CI contract,
the `render_path` avoidance is correctly implemented, and the edge-type and
truncation decisions land where the spec review asked. Everything below is a
place where the plan asserts something the installed source or the repo
contradicts, or defends an invariant with a check that cannot detect its
violation.

---

## Blocking

### 1. `graph` will be SELECTed on every 3-second poll and every history load — the plan's own Global Constraint, falsified one layer below the test that guards it

The plan states: *"The graph is never in the scan detail or list response … a
multi-MB field there is paid for on every poll. Task 1 adds the test that
enforces this."* The test it adds checks `ScoutScanDetailSerializer.Meta.fields`
and the serializer source. Both pass. The cost lands in the **queryset**, which
nothing in the plan touches:

```python
# views.py:118 — ScoutScanDetailView.get, polled every 3s by AttackGraphHub
scan = ScoutScan.objects.filter(id=scan_id, user=request.user).first()
```

No `.only()`, no `.defer()` — that is `SELECT *`, so after Task 1 every poll
pulls the full graph out of Postgres and psycopg deserializes the jsonb into a
Python dict before DRF discards it. The serializer test passes the whole time.

The list endpoint is worse:

```python
# views.py:97 — ScoutScanListView.get_queryset
return ScoutScan.objects.filter(user=self.request.user)
```

Also `SELECT *`, with **no DRF pagination configured** (`grep PAGE_SIZE
config/settings/*.py` → nothing), and `ScoutScanListSerializer.get_state` at
`serializers.py:26` already forces `obj.result` per row. So one history-strip
load becomes *N* rows × (envelope + full graph). The existing comment on that
serializer — "the largest field on the row" — stops being true the moment this
migration lands, and the thing that replaces it is an order of magnitude bigger.

`active_scans()` (`models.py:128`) is also `SELECT *`, but it is bounded to
`pending`/`running` rows whose `graph` is `NULL`, so that one is cheap. The two
above are not.

**Two ways to fix it, and they are not equivalent:**

- **Floor:** add `.defer("graph")` to both querysets, plus a source-reading test
  in `test_api_contract.py` asserting both contain it. Cheap, but it is a
  convention a future queryset can forget — exactly the failure mode the spec
  review's item #7 was written about, moved down a layer.
- **Structural, and it closes Task 0's open end too (see #6):** put the blob on
  its own table — `ScoutScanGraph(scan=OneToOneField(ScoutScan), data=JSONField)`.
  Then "never in the detail or list response" is true by construction, no
  queryset can regress it, and `graph_for_scan` reads one narrow row by
  `scan_id`. Same migration cost. Not mandated here — one table may be worth
  keeping for other reasons — but it should be a decision, not a default.

Whichever is chosen, the invariant test in Task 1 needs to move from
`Meta.fields` to the queryset, because the `Meta.fields` version is the one that
already passes.

### 2. `_visit_ceiling_reached` does not model the search it claims to be checking

This is the one thing the plan's self-review flags as invented beyond the spec,
and it is defended on a premise the code breaks: *"bounded by the same ceiling
it is testing, so it cannot itself run longer than the search it is checking."*

Compare it to `iter_paths` (`scout/chains/builder.py:970-988`), verified in the
installed package:

```python
while queue and produced < max_paths and visited_count < max_visited:
    node_id, path, seen = queue.popleft()
    visited_count += 1
    if node_id == dst and path:
        produced += 1; yield path; continue       # dst is never expanded
    if len(path) >= max_depth:
        continue                                   # depth prune
    for t in types:
        for e in graph.out_edges(node_id, t): ...
```

The plan's replica has **neither guard**. It carries no path length, so it never
prunes at `max_depth`; and it has no `dst`, so it expands straight through the
destination. Both make it enqueue and dequeue path-states that `iter_paths`
never touches — and since both walks enumerate *simple paths* (a fresh
`seen | {target}` per branch), not nodes, the state count grows with branching
and depth. The replica's visit count is therefore a strict over-estimate of the
real search's, biased in exactly one direction: toward reporting
`search_capped: true` when the actual traversal completed. Wherever the depth
bound is doing real work — which is the case this whole ceiling exists for — the
two walks disagree.

The consequence is the failure mode the spec review demanded be removed, merely
inverted: instead of a false "nothing is reachable", a false "we stopped
looking", on the endpoint's most common answer. Plus a second full traversal on
every under-cap query.

**Fix, and it is the pattern Scout already uses.** `reachable_from`
(`builder.py:1043-1047`) reports `visit_capped = bool(queue)` — from inside its
own loop. Do the same: vendor `iter_paths`' ~15 lines into `graph_query.py` as a
generator that records whether it exited with a non-empty queue, and yield that
alongside the paths. It is fewer lines than the replica, it is exact rather than
inferred, it works when paths *were* found (the current version can only report
capping when `len(produced) < max_paths`), and it costs one traversal instead of
two. Keep `ScoutHelperContractTests` and add one asserting the vendored
generator yields the same paths as `find_paths` on the fixture graph, so a Scout
upgrade that changes the traversal is caught by name.

### 3. `_hop_from_edge` reads `category` off the edge; Scout reads it off the node

```python
# the plan's graph_query._hop_from_edge
category = edge.properties.get("category", "data")
mechanism = "resource_access" if category == "data" else "resource_control"
```

The code it claims to mirror (`_resource_reach_chains`, `builder.py:560-583`)
resolves the category from the **target node**, with the edge only as a fallback:

```python
node = graph.get(e.target)
cat = ((node.properties.get("category") if node is not None else None)
       or mp.get("category") or "data")
```

The two diverge in one specific shape: **the target node carries `category` and
the edge does not.** `ingest/resources.py` sets it on both the node (`:240`,
`:401`) and the edge (`:326`, `:346`, `:410`), so edges from there agree either
way. Two other creation sites set it on the edge at all:

- `attack_surface/build.py:124` — `properties={"kind":…, "via":…, "confidence":…}`
- `ingest/dns.py:149` — `properties={"via": "identity_policy", "dangling": True, …}`

The attack-surface site is the live case. A Lambda function that
`ingest/resources.py` already ingested carries `category: "compute"` on its node
(`RESOURCE_ACCESS`, `ingest/resources.py:20-32`, categorises `lambda`, `sns` and
`ecr` as `"compute"`); when `attack_surface/build.py` then adds a
`CAN_ACCESS_RESOURCE` edge to it with no `category`, the plan's code falls back
to `"data"` and labels the hop `resource_access`, while the ranked-chains view
reads the node and labels the same edge `resource_control`. One grant, two
contradictory renderings: precisely the defect class the spec review's blocking
item #1 existed to eliminate. (`ingest/dns.py:149` points at S3-implied ARNs,
where `"data"` happens to be right — it is a second category-less site, not a
second divergence.)

Fix is one line — mirror `builder.py:583`:

```python
node = graph.get(edge.target)
category = ((node.properties.get("category") if node is not None else None)
            or edge.properties.get("category") or "data")
```

**And the test that should have caught this is vacuous.**
`test_a_resource_hop_gets_scouts_resource_mechanism` builds the edge with
`properties={"category": "data"}` and asserts `resource_access` — which is also
what the `"data"` *default* produces, so the assertion holds whether the lookup
reads the edge, the node, or nothing at all. Rewrite it with a `compute` node and
a category-less edge; that version fails today and passes after the fix.

---

## Correctness bugs in the frontend tasks

### 4. Task 6's extraction is not behaviour-preserving — real nodes get overwritten by grey ones

Current `toGraph` (`chainGraph.ts:47-78`) accumulates into **one** map across all
chains, and the synthesized fallback is guarded:

```typescript
if (!nodes.has(id)) nodes.set(id, { id, arn: '', type: 'other', label: id })
```

So once role X is in the map as a real typed `chain.source`, a later chain that
touches X only as a step cannot downgrade it.

The plan's version builds a **per-chain** sub-map and merges unconditionally:

```typescript
const sub = stepsToGraph(chain.steps, chain.id, [chain.source, chain.target])
for (const node of sub.nodes) nodes.set(node.id, node)    // unguarded
```

Inside chain 2's sub-map, X is absent from `known`, so it is synthesized as
`{type: 'other', label: <raw arn>}` — and that grey node then overwrites chain
1's real one. The symptom is a node that is a typed endpoint of one chain and an
intermediate hop of another rendering grey and ARN-labelled, which is exactly
the regression class the task's one verification step (screenshot comparison) is
least likely to be read carefully for.

Either guard the merge (`if (!nodes.has(node.id)) …`) or, better, hoist the
seed — `const known = envelope.chains.flatMap(c => [c.source, c.target])` once,
passed to every call. The second is strictly closer to the current semantics.

### 5. `QueryPanel` gives every path the whole result's node set

```typescript
(result?.paths ?? []).map((path, i) => stepsToGraph(path.steps, `q${i}`, result?.nodes ?? []))
```

with the comment *"Each path gets its own node/edge set so one long path does
not distort another's layout."* It does not. `stepsToGraph` seeds **every**
`known` node into its map unconditionally, so each per-path `Graph` carries all
nodes from all paths — path 1's dagre layout includes disconnected nodes that
belong to path 3, and `computeLayout` (`AttackChainGraph.tsx:93`) will rank and
space them.

Note the seeding is load-bearing elsewhere and must not simply be removed: a
zero-hop chain has no steps, and `toGraph` still has to emit its source and
target (the behaviour commit `b556c22` shipped). So the two callers genuinely
need different things. Either filter in `QueryPanel`
(`result.nodes.filter(n => idsIn(path).has(n.id))`) or split the parameter —
`known` as a typing lookup consulted when synthesizing, plus an explicit
`seed` list that `toGraph` passes and `QueryPanel` leaves empty.

---

## Tests that cannot fail

Three of the Task 5 contract tests assert strings that are already in the file,
so they pass today and would keep passing if the code they describe were never
written.

- **`test_they_scope_the_lookup_to_the_requesting_user`** — `assertIn("user=request.user", views)`.
  `ScoutScanDetailView.get` (`views.py:118`) already contains that substring.
  If all three new views did a global `ScoutScan.objects.filter(id=scan_id)`,
  this test still passes. That is a **cross-user data-access property defended
  by a check that cannot detect its absence** — and the spec review explicitly
  asked for a cross-user test. Assert per class instead (slice the source from
  each `class ScoutScanGraph…View` to the next `class`, and require the scoping
  inside each), or accept that this one needs a real request and put it in a
  `skipUnless(HAS_DRF)` module alongside the source-reading floor.
- **`test_the_graph_views_use_the_scout_gate`** — `assertNotIn("HasAWSConnection", views)`.
  That identifier does not exist anywhere in the repo; the permission class is
  `HasScoutConnection`. The assertion is unfalsifiable. What the test name
  claims — that the three new views carry a permission class at all — is not
  checked, and `_ScanGraphView` setting `permission_classes` is worth asserting
  positively.
- **`test_a_scan_with_no_stored_graph_is_distinguishable_from_a_missing_scan`** —
  `assertIn("GRAPH_UNAVAILABLE", views)` proves the constant exists, not that
  the two 404 branches differ. Assert the two distinct `detail` strings.

---

## Non-blocking

### 6. Task 0's gate has no fallback branch, so a tripped gate stops an agentic worker dead

Step 3 says: above 4MB, *"stop and raise it with the author before Task 1 — the
spec reopens the storage decision at that point."* Nothing says what the
reopened decision resolves to, and the plan is addressed to a subagent executing
task-by-task. A worker that measures 6MB has no defined next action.

Name the branch. The separate-table option from finding #1 is the natural one —
it is the same change, it makes the poll cost structural rather than
conventional, and it is what you would want anyway at that size. A second rung
(gzip into a `BinaryField`, with `graph_for_scan` decompressing) is worth one
line so the worker does not have to invent it.

Also: `payload_bytes()` is defined at the bottom of `graph_query.py` and called
by nothing — Task 0's script inlines `len(json.dumps(...))` instead. It is pure
stdlib in the Scout-dependent module, which is backwards from the plan's own
split. Either have Task 0 import it or drop it.

### 7. The `/graph/nodes/` latency story closes the cheaper half of the cost

The plan's answer to the spec review's per-keystroke concern is "don't
rehydrate" plus a 200ms debounce, and `graph_search.py`'s docstring makes that
the headline. But `Graph.from_dict` was never the dominant term. Per keystroke,
after debounce, the endpoint still pays:

1. a `SELECT` of the multi-MB jsonb column (finding #1's `.only("id","graph")`
   does narrow this one correctly — credit where due), then
2. psycopg deserializing that blob into a Python dict — comparable to
   `from_dict`, and *not* cached, then
3. `matched.sort(key=_sort_key)` over the **entire** node list, because
   `search_nodes` sorts after filtering and a `q` under two characters skips the
   filter entirely. An autocomplete opened on focus sends `q=""`, so the first
   request of every session sorts every node in the account.

The `_graph_cache` LRU only holds the rehydrated `Graph`, and it takes
`graph_dict` as a *parameter* — so it caches the one step this path does not
use. Options, cheapest first: cache the parsed dict (or a prepared search index)
under the same `scan_id` key and have both modules read through it; and use
`heapq.nsmallest(limit, matched, key=_sort_key)` instead of a full sort.

Worth stating a p95 target for `/graph/path/` too. With `max_visited=50_000`,
every queued state holding a `path` list and a `seen` set copy, running
synchronously in the Django request thread, the worst case is not small and the
plan never bounds it.

### 8. `GRAPH_UNAVAILABLE` tells a running scan the wrong story

`_resolve` returns it for any falsy `scan.graph`, with the copy *"Scans run
before this feature shipped do not have one — run a new scan to get it."* That
is also the state of a scan that is **currently running**, and of one that
**failed** — and for both, "run a new scan" is wrong advice. Branch on
`scan.status`: `pending`/`running` → "this scan is still running",
`failed` → the existing `error_message`, `completed` with no graph → the current
message. Today this is reachable only by a direct API call — the UI mounts
`EntityPanel` under `CompletedResult`, so a running or failed scan never renders
it — but the plan is otherwise scrupulous about naming states rather than
collapsing them, and this is the one place it collapses three.

### 8b. Nothing in the plan proves the `graph` write actually succeeds

Task 2's test is `assertIn("graph=graph.to_dict()", source)` — source-reading, so
it passes whether or not the `.update()` throws. `result=envelope` has always
been safe because `envelope.py` assembles primitives by hand; `graph.to_dict()`
is the first time raw Scout `properties` reach a `JSONField`, and Django's
default encoder raises `TypeError` on a `datetime`. Nothing between Task 2 and
Task 5 runs a scan, so the first real scan after the migration is the implicit
integration test.

I checked, and it looks safe: `aws/collect/standalone.py:32,70,77` `.isoformat()`s
every date at collection time, and `graph/store.py:132` `json.dumps` node
properties with no `default=str`, so Scout's sqlite backend already depends on
them being JSON-native. Still worth one explicit step in Task 2 — run a scan
against the audit account, then assert the row's `graph` came back with nodes —
rather than leaving the guarantee to a `grep`.

### 9. `hop_dict`'s provenance fields never reach the response

`hop_dict` carries `granted_by`, `granted_by_overflow`, `bounded_by`,
`catalog_path_ids` and `hop_number`, and
`test_provenance_rides_along_for_a_later_view` asserts them. But `query_paths`
returns `_step(_hop_from_edge(...))`, and `_step` (`envelope.py:210-228`) emits
exactly eight keys — none of those five among them. The fields are dropped one
line later and never cross the wire. That is fine as forward-compat, but the
test name asserts a property the pipeline does not have; say "kept for a future
`_step` that carries them" in the docstring, or drop them until something reads
them.

### 10. Icons never reach the graph nodes, which is what the Goal line promises

The plan's Goal says the graph is *"rendered with real AWS icons through the
chain view's existing layout primitives."* Task 11 populates `NODE_TYPE_ICON`,
consumed by `NodeIcon` — an `<img>` element, used in `EntityPanel`'s header and
the picker dropdown rows. `SvgNode` (`AttackChainGraph.tsx:123-160`), which
draws the nodes in the graph, is never modified; it keeps rendering
`node.type.slice(0, 3).toUpperCase()` as a text badge, and an `<img>` cannot go
inside an `<svg>` anyway (it needs `<image href>`). Either add that to Task 11
or narrow the Goal line to "icons in the entity panel and pickers."

### 11. Resource and service nodes will render grey, including in Task 9's Step 4 check

`NODE_CATEGORY` (`AttackChainGraph.tsx:47`) maps exactly four keys:
`user`, `role`, `group`, `policy`. The plan's `_ARN_KIND_BY_NODE_TYPE` emits
`resource`, `service`, `account`, `federated`, `public`, `external`, `other` —
none of which are in that map, so `categorize()` returns `'other'` and every
resource and service node draws grey, labelled "Other", with a "RES" badge.

That is a defensible v1 (the plan's mapping comment argues correctly against
remapping `NODE_CATEGORY` wholesale), but Task 9's verification step says to
confirm *"a path ending at the resource … nodes coloured (not grey)"* — which
cannot pass as specified. Either extend `NODE_CATEGORY`/`CAT_COLOR`/`CAT_LABEL`
with a resource category (this is the feature whose entire point is showing
resources) or fix the verification text.

### 12. Smaller things

- **`src === dst`.** The pickers permit it; `iter_paths`' `if node_id == dst and path` means a zero-length path is never yielded, so the user gets "no escalation path found from alice to alice within 10 hops." Reject it in the view with a specific 400, or say something better in the panel.
- **`test_truncated_is_reported_…` passes `max_paths=0`.** That makes `paths` empty *and* `truncated` true — a state the UI has no copy for ("Showing the 0 shortest paths; more exist"). Test with `max_paths=1` against a graph carrying two paths instead; it exercises the real branch.
- **`Edge.to_dict()` returns `self.properties` by reference** (`scout/graph/schema.py:78`), unlike `Node.to_dict()` which copies. Nothing in the plan mutates hop properties, so this is currently safe — worth a note in `graph_query.py` so it stays that way.
- **`test_the_serializer_source_does_not_mention_graph`** greps for `'"graph"'` in `serializers.py`. Task 10 adds documentation; a future explanatory comment containing the quoted word fails this test with a confusing message. Low cost, non-zero.
- **`urls.py`'s module docstring is already wrong** — it lists `GET /api/attack-graph/scan/` as `ScoutScanListView`, but the list route is `scan/list/`. Task 5 edits that docstring; fix the existing line while there.
- **Route ordering** is fine as written: `scan/<uuid:scan_id>/` anchors to end-of-path, so the three `graph/…` routes below it resolve correctly regardless of order. Worth not worrying about.

---

## What to keep exactly as it is

- The `graph_search.py` / `graph_query.py` split, and the reasoning that the
  certainty regression test must run in CI rather than behind `skipUnless`. That
  is the single best decision in the plan — it puts the spec review's blocking
  item #1 under a test that actually runs.
- Not using `render_path`, and the module docstring explaining why. Verified
  against `builder.py:1007-1020`: it does emit exactly five keys and `_step` does
  read `action` and `conditional`.
- Explicit `QUERY_EDGE_TYPE_NAMES` including `CAN_ACCESS_RESOURCE`, echoed in
  the response so the "no path found" copy can name what was traversed.
  `EdgeType("PRIVESC_TO")` works — the enum's values equal its names
  (`scout/graph/schema.py:30-38`) — so the deferred-import-by-name trick is safe.
- Task 6 going first and alone, for the reason given.
- Task 11 isolated behind the letter-badge fallback, so a refused download
  permission costs the feature nothing but icons.
- The `?id=` / `?src=&dst=` query-parameter decision and the refusal to use
  `resolve_arn_tokens`, both with tests.
- The depth-5-vs-10 note in `QueryPanel`. It is the kind of thing that gets cut
  and then generates a support ticket.
