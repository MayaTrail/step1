# Attack Graph — Entity Records, Icons, and Path Query — Design Spec

Date: 2026-09-22
Branch: `feat/scout-integration`
Status: Revised after review — ready for planning
Review: [2026-09-22 review](../reviews/2026-09-22-attack-graph-entity-graph-and-query-review.md)
(what changed and why is in Revision notes at the bottom)

## Goal

Extend the Attack Graph feature with three things Scout's own graph already
computes but the current integration discards:

1. **Per-entity records from Scout's graph, stored and queryable.** Every AWS
   identity, service and resource node Scout modelled — not just the ARNs that
   happen to be a chain endpoint — with a real type, name and properties per
   entity, reachable by lookup and by search. This is not a graph *viewer*:
   nothing here renders the whole graph, and the Non-goals below say why.
2. **A path query.** "Find the paths between these two entities" run on-demand
   against the whole graph, not limited to the top-25 pre-ranked chains the
   envelope already carries.
3. **Real icons.** Official AWS Architecture Icons per entity type, replacing
   the current three-letter text badge.

## Why

`pipeline.run()` already returns `(report, graph)`
([tasks.py:140](../../../backend/apps/attack_graph/tasks.py)) and the task
discards `graph` entirely. That object is a fully-typed `scout.graph.Graph`
— every `IAM_USER`/`IAM_ROLE`/`SERVICE`/`RESOURCE`/`AWS_ACCOUNT` node Scout
saw, with real `name`/`properties`, not the ARN-string-parsing
[`envelope.py`'s `_node()`](../../../backend/apps/attack_graph/envelope.py)
does today. Scout's own CLI already has working, tested path-finding
(`scout path`, `scout reachable` — `scout/chains/builder.py`'s
`iter_paths`/`find_paths`/`reachable_from`) built for exactly this question,
and a full graph viewer (`scout/viz.py` + `viz_assets/template.html`) that
already ships real AWS service icons. None of this requires new algorithms —
it requires capturing data Scout already produces and exposing it through the
product's own UI instead of Scout's.

## Non-goals

- AWS Organizations SCP/RCP fetching. Separate, already-flagged future item
  (Organizations API access needs a different permission model than the
  per-account audit role this feature uses) — not part of this spec.
- Replacing the ranked-chains list as the landing view. Entity records and the
  path query stay a drill-down, never the default view — a raw force-directed
  dump of every node an account has is the anti-pattern this product has
  deliberately avoided so far. Scout's own
  [`graph/neighborhood.py`](../../../backend/venv-dev/Lib/site-packages/scout/graph/neighborhood.py)
  header records the mechanical version of the same finding: real account
  graphs are dense enough that a capped node set still carries an edge count
  that hangs a synchronous dagre layout.
- Cytoscape.js or any new graph-rendering dependency. Query results render
  through the existing dagre+SVG primitives
  (`AttackChainGraph.tsx`/`chainGraph.ts`), not a second rendering stack — see
  Frontend components for exactly which primitives are shared and which are not.
- Editing or annotating the graph.
- Backfilling historical scans. See Error handling.

## Architecture

```
Scan completes (existing flow, unchanged up to this point)
  tasks.py: report, graph = pipeline.run(...)
      -> envelope = serialize_scan(report, ...)          [unchanged]
      -> ScoutScan.result = envelope                       [unchanged]
      -> ScoutScan.graph  = graph.to_dict()                [NEW]

Three new read endpoints, scoped to one scan and its owner:
  GET .../graph/nodes/?q=<term>          search — reads the stored dict, no rehydrate
  GET .../graph/entity/?id=<node id>     one entity's full record, no rehydrate
  GET .../graph/path/?src=&dst=          rehydrates, runs iter_paths

Frontend:
  EntityPanel   (evolves the current DetailPanel's node header)
      -> fetches /graph/entity/?id= for icon + curated properties
  QueryPanel    (new)
      -> autocomplete via /graph/nodes/, "Find paths" via /graph/path/
      -> renders each path through the SAME layout/node/edge primitives a
         ranked chain uses (computeLayout / SvgNode / the edge path renderer),
         with its own header — a query result has no rank, score or narrative
         and must not borrow a UI that implies it does
      -> "Find paths from here" shortcut on a selected node pre-fills it
```

## Backend components

### `ScoutScan.graph` field (`apps/attack_graph/models.py`)

A new `JSONField(null=True, blank=True)`, sibling to `result`. Nullable
because every scan stored before this feature ships has no graph — that is
a normal, permanent state (see Error handling), not a migration to backfill.
Same retention posture as `result`: unencrypted at the same sensitivity as
the rest of the row, deleted with the user, no separate pruning rule.

**Gate on the migration landing: measure first.** The storage decision below
was taken without a number, and one is available today rather than later:

- `scout.viz.payload_bytes()`
  ([viz.py:66](../../../backend/venv-dev/Lib/site-packages/scout/viz.py)) is a
  ready-made measurement, and Scout's own static-viewer ceiling is
  `SIZE_LIMIT_BYTES = 8 * 1024 * 1024`.
- Every role node carries its **full trust policy document** plus tags in
  `properties`
  ([ingest/gaad.py:199](../../../backend/venv-dev/Lib/site-packages/scout/ingest/gaad.py)).
- `SqliteGraph` moves `granted_by` into a separate table specifically because
  it is a size problem
  ([graph/store.py:45-49](../../../backend/venv-dev/Lib/site-packages/scout/graph/store.py)),
  and `granted_by` rides on edge properties that `to_dict()` serializes whole.

Before the migration is written, run one scan against the same 67-identity
account this feature's timing numbers came from and record
`len(json.dumps(graph.to_dict()))` in the implementation plan. A JSONField is
cheap to add and expensive to move off once rows exist; if that number is
already within an order of magnitude of 8MB on a small account, the storage
decision gets reopened before anything is built, not after.

### `ScoutScanDetailSerializer` must not grow the graph field — invariant

`ScoutScanDetailSerializer` lists its fields explicitly
([serializers.py:29-38](../../../backend/apps/attack_graph/serializers.py)), so
adding `graph` to the model does not leak it into the detail response. That is
currently luck rather than design. **The graph is never included in the scan
detail or list response**: the frontend polls the detail endpoint on an
interval while a scan runs, and a multi-MB field there would be paid for on
every poll. A test asserts `graph` is absent from
`ScoutScanDetailSerializer(scan).data`, so a later `fields = "__all__"` fails
CI rather than shipping.

### `tasks.py`

After `pipeline.run()` returns `(report, graph)`, store `graph.to_dict()` on
the scan row alongside the envelope. `Graph.to_dict()`/`Graph.from_dict()` are
Scout's own loss-free JSON serializer
([graph/schema.py:193-224](../../../backend/venv-dev/Lib/site-packages/scout/graph/schema.py))
— built for exactly this, no reshaping needed. `graph` was previously bound to
`_graph` (the underscore signalling "intentionally unused"); this spec removes
the underscore and adds the one line that stores it.

### Query modules — split by what CI can import

`config/settings/ci.py` installs six packages: Django, python-decouple, PyYAML,
celery, feedparser, requests. **Scout, DRF and boto3 are not among them**, every
test is a `SimpleTestCase`, and `requirements-test.txt` is not to be expanded.
A single `graph_query.py` importing `scout.chains.builder` would be a module CI
cannot load, and therefore cannot defend. The app already solves this exact
problem twice — `envelope.py` is pure, and `tasks.py` defers its Scout imports
with `# noqa: PLC0415` — so this feature splits the same way:

| module | imports | CI |
|---|---|---|
| `apps/attack_graph/graph_search.py` *(new)* | stdlib only | **fully tested** |
| `apps/attack_graph/graph_query.py` *(new)* | Scout, deferred inside functions | `skipUnless(HAS_SCOUT)` locally |

`graph_search.py` holds search, entity lookup, the `ChainNode` mapping, and —
importantly — `hop_dict()`, which assembles a hop from any object exposing
`.source`/`.target`/`.method`/`.properties`. `graph_query.py` computes the
mechanism and API sequence with Scout's helpers and calls `hop_dict()` for the
rest. That split is what puts the one test this spec calls load-bearing (a
conditional hop keeps `certainty == "conditional"`) on the CI side, exercised
with a four-line fake edge, instead of behind a `skipUnless` that silently never
runs — which is the same class of silence as the defect it guards against.

A related simplification: `hop_dict()` returns a **plain dict** with `Hop`'s
field names rather than constructing Scout's `Hop` dataclass and calling
`.to_dict()`. `_step` consumes a dict either way, the field parity that
motivated the change is identical, and it removes one more Scout import from the
path that needs testing.

The rest of this section describes `graph_query.py`'s three concerns:

#### Search and entity lookup read the stored dict directly — no rehydrate

`Graph.from_dict()` walks every node and edge and rebuilds adjacency indexes.
`/graph/nodes/?q=` is autocomplete: rehydrating there is a full graph rebuild
**per keystroke**, on a JSONField read of a multi-MB blob. Neither search nor
entity lookup needs a `Graph` object — both are a scan of `scan.graph["nodes"]`,
which is a plain list of dicts. Scout reached the same conclusion for its own
viewer: `graph/neighborhood.py` does bounded traversal over the *serialized
dict* precisely to avoid this, and the module docstring says so.

- `search_nodes(graph_dict, q, limit=50)` — case-insensitive substring match on
  `id` and `name`. Results ordered identity types first (`IAM_USER`, `IAM_ROLE`,
  `IAM_GROUP`), then everything else, then by `name` — deterministic, so the
  same query produces the same list twice. A `q` shorter than 2 characters is
  not an error: it returns the first `limit` nodes in that same ordering, which
  is what an autocomplete opened on focus should show. `limit` is a hard cap at
  50, not a page size — this is a picker, not a browse view.
- `get_entity(graph_dict, node_id)` — exact-id lookup, returning
  `{id, type, name, account_id, properties}` or `None`.

The frontend debounces `/graph/nodes/` at 200ms. That is a contract, not a
suggestion: it is what keeps the endpoint's cost proportional to searches
rather than keystrokes.

#### Path query rehydrates, once, behind a small cache

`find_paths` needs real adjacency, so `/graph/path/` does call
`Graph.from_dict(scan.graph)`. A process-local LRU keyed by
**`scan_id` alone** with `maxsize=4` keeps a user running several queries
against one scan from paying the rebuild each time, and bounds the resident
cost at four graphs per worker process. `scan_id` is a sufficient key because a
completed scan is immutable: nothing writes `graph` after the task sets it, and
`ScoutScan` has no update timestamp to key on (`created_at`/`started_at`/
`completed_at` only) — so there is no invalidation problem to solve and no
field to add. If the measured graph size makes even one resident graph per
process unacceptable, the fallback is `maxsize=1` — not a different
architecture.

#### Edge types traversed — an explicit list, not the default

`iter_paths`' default is `edge_types = [PRIVESC_TO, CAN_ASSUME]`
([chains/builder.py:980](../../../backend/venv-dev/Lib/site-packages/scout/chains/builder.py)).
Left at the default, a user who picks an S3 bucket as the destination — which
Goal 1 explicitly makes possible, since `/graph/nodes/` searches resource nodes
— gets "No path found" for **every** bucket in **every** account, because the
traversal never looks at a resource edge. That is a confident false statement,
which is worse than an error.

The query passes an explicit list:

```python
QUERY_EDGE_TYPES = [EdgeType.PRIVESC_TO, EdgeType.CAN_ASSUME,
                    EdgeType.CAN_ACCESS_RESOURCE]
```

Rationale per excluded type, so this is a decision and not an oversight:

| type | traversed | why |
|---|---|---|
| `PRIVESC_TO` | yes | the escalation edge — the whole point |
| `CAN_ASSUME` | yes | trust-allowed role assumption |
| `CAN_ACCESS_RESOURCE` | yes | the only way a path can *end* at a resource. Naturally terminal under this set: resources have no outbound edge of any traversed type, so including it cannot invent a bogus transit hop |
| `CAN_PASS_ROLE` | no | PassRole alone is not escalation. Scout's rules already fold `PassRole + <service that launches with it>` into a `PRIVESC_TO` edge (`privesc/rules.py:400,431`); traversing the raw edge would report paths that cannot actually be walked |
| `MEMBER_OF` | no | group membership is flattened into the identity's effective permissions upstream; a `user → group` hop is not a step an attacker takes |
| `DEPENDS_ON` / `TRIGGERS` | no | resource→resource control/event edges. Real, but they answer a different question ("what does this resource reach") and pull the query away from "what can this identity do" without a UI that distinguishes them |

Excluding a type is a scoping choice the UI states rather than hides: the
QueryPanel result header names what was traversed, so "no path" reads as "no
escalation path" and not "no relationship of any kind."

#### Hops are built from the edges, not from `render_path`

**`render_path` is not used.** It emits only
`hop_number`/`mechanism`/`source_arn`/`target_arn`/`concrete_api_sequence`
([chains/builder.py:1007-1020](../../../backend/venv-dev/Lib/site-packages/scout/chains/builder.py)),
while [`envelope.py`'s `_step`](../../../backend/apps/attack_graph/envelope.py)
reads `hop["action"]` and `hop["conditional"]`. Feeding `render_path` output
through `_step` would give `action == ""` and — worse —
`certainty == "deterministic"` for *every* hop of *every* query result,
including hops the ranked-chains view renders as `conditional` with a reason.
The same edge would carry two contradictory certainty claims in one product.
`_step`'s deterministic default exists for edges Scout genuinely never gated,
not for a field a renderer discarded.

Instead `graph_query.py` builds Scout's own `Hop` objects straight off the edge
list, the same way `build_chains` does
([chains/builder.py:1174-1186](../../../backend/venv-dev/Lib/site-packages/scout/chains/builder.py)),
and hands `hop.to_dict()` to `_step`. That is full parity with chain hops —
`action`, `conditional`, `granted_by`, `bounded_by` — for the same amount of
code, and it is what makes "the frontend needs zero new step cases" true rather
than aspirational.

One dispatch, because Scout renders a resource hop differently from an identity
hop and this query can now produce both:

```python
def _hop_from_edge(graph, edge, hop_number):
    if edge.type is EdgeType.CAN_ACCESS_RESOURCE:
        # Mirrors _resource_reach_chains (builder.py:586-597): a resource hop's
        # mechanism comes from the edge's category, and its API sequence from
        # _concrete_resource_reach — _mechanism_for would label it "direct_iam"
        # and _concrete_api has no branch for it.
        # graph.get() may return None for an edge whose target was never added
        # as a node. _concrete_resource_reach is None-safe by its own guard
        # (builder.py:500 — `if node is not None else ""`), so no check is
        # needed here; that guard is asserted by a unit test so a Scout upgrade
        # that removes it fails CI rather than raising on a user's query.
        node = graph.get(edge.target)
        category = edge.properties.get("category", "data")
        mechanism = "resource_access" if category == "data" else "resource_control"
        api = _concrete_resource_reach(edge, node)
    else:
        mechanism = _mechanism_for(edge)
        api = _concrete_api(edge)
    return Hop(
        hop_number=hop_number, mechanism=mechanism, action=edge.method,
        source_arn=edge.source, target_arn=edge.target,
        concrete_api_sequence=api,
        catalog_path_ids=list(edge.properties.get("path_ids", [])),
        conditional=edge.properties.get("conditional"),
        granted_by=edge.properties.get("granted_by", []),
        granted_by_overflow=edge.properties.get("granted_by_overflow", 0),
        bounded_by=edge.properties.get("bounded_by"),
    )
```

`_mechanism_for`, `_concrete_api` and `_concrete_resource_reach` are imported
from `scout.chains.builder`. They are underscore-private to that module, which
is a real coupling risk: a test asserts all three are importable and return the
expected shape, so a Scout upgrade that renames them fails CI with a clear
cause rather than at runtime on a user's query.

#### Truncation is reported, never silent

`find_paths` caps at `max_paths=50` and `max_visited=50_000`
([chains/builder.py:999](../../../backend/venv-dev/Lib/site-packages/scout/chains/builder.py))
and returns a bare list with no signal that the budget, rather than the graph,
ended the search. Scout's own `reachable_from` returns `visit_capped` for
exactly this reason, with the comment:

> a bailed-out BFS is indistinguishable from "nothing else is reachable" — the
> worst available wrong answer here.

This product already carries `truncated` in the envelope on the same principle
([envelope.py:101](../../../backend/apps/attack_graph/envelope.py)). The query
endpoint therefore calls `iter_paths` (the generator) directly with an explicit
budget rather than `find_paths`, consumes at most `MAX_QUERY_PATHS = 25`, and
reports two distinct booleans:

- `truncated` — more paths existed than were returned (the generator had not
  finished when the cap was hit).
- `search_capped` — `max_visited` was exhausted, so the answer is incomplete in
  a way the caller cannot bound. Only this one makes "no path found" unsafe to
  state, and the UI says so differently.

`max_depth` stays at Scout's default of 10, and the response carries it so the
"no path found within depth N" copy cannot drift from the value actually used.

#### `resolve_arn_tokens` is not used

The first draft routed `src`/`dst` through `resolve_arn_tokens` and promised to
surface its warnings "verbatim." Verbatim is
`"--foothold/--target 'alice' matched zero nodes"`
([chains/builder.py:1063](../../../backend/venv-dev/Lib/site-packages/scout/chains/builder.py))
— Scout's CLI flag names, in the product's web UI. Beyond the copy, it is the
wrong tool for this UI:

- its match is `k == token or k.endswith(token)`, so an empty token matches
  every node and a one-character token matches most of them;
- it returns a **flat** `(resolved, warnings)` with no token→match attribution,
  so a two-field src/dst form has no defined answer to "this token matched
  three nodes — which one is the source?";
- both pickers are autocomplete-backed by `/graph/nodes/`, so the client
  already submits an exact node id. Fuzzy suffix resolution solves a problem
  the UI design removed.

`/graph/path/` therefore takes **exact node ids** and validates them against
`scan.graph["nodes"]`, returning `400` with a message naming the unknown id.
The "did you mean" affordance lives in the picker, where it belongs.

`reachable_from` is still wrapped and exposed from this module — for a later
"what can this identity reach" view, not wired into the UI in this iteration,
so that follow-up is additive rather than a rewrite. Its `visit_capped` flag is
carried through for the same reason `search_capped` exists above.

### API surface additions (`apps/attack_graph/urls.py`, `views.py`)

Node ids are **not URL-path-safe**: `arn:aws:iam::123456789012:role/foo`
contains a `/`, which Django's default `str` converter excludes, and not every
node id is an ARN — `SERVICE` nodes are `lambda.amazonaws.com` and `PUBLIC` is
literally `*`
([graph/schema.py:17-28](../../../backend/venv-dev/Lib/site-packages/scout/graph/schema.py)).
Every node id travels as a urlencoded query parameter, never a path segment.

| method | path | purpose |
|---|---|---|
| GET | `/api/attack-graph/scan/<scan_id>/graph/nodes/?q=<term>` | search stored graph nodes by id/name substring, capped at 50 — powers both pickers |
| GET | `/api/attack-graph/scan/<scan_id>/graph/entity/?id=<node id>` | one entity's full record: type, name, account_id, properties |
| GET | `/api/attack-graph/scan/<scan_id>/graph/path/?src=<node id>&dst=<node id>` | up to 25 paths as `_step`-shaped hops, plus `truncated`/`search_capped`/`max_depth`/`edge_types` |

All three scoped to `request.user`'s own scan, reusing the ownership check
`ScoutScanDetailView` already applies — a scan belonging to someone else is a
`404`, which is the correct answer and does not confirm the id exists.

`/graph/path/` response shape:

```json
{
  "src": "<node id>", "dst": "<node id>",
  "max_depth": 10,
  "edge_types": ["PRIVESC_TO", "CAN_ASSUME", "CAN_ACCESS_RESOURCE"],
  "nodes": [ /* ChainNode for every id the steps reference */ ],
  "paths": [{ "hop_count": 3, "steps": [ /* ChainStep, identical shape to a chain's */ ] }],
  "truncated": false,
  "search_capped": false
}
```

`steps` are `_step`'s output, so they are `ChainStep` on the frontend with no
new type and no new rendering cases. There is deliberately no `chain_id`,
`rank`, `score`, `narrative` or `terminal_impact`: a query result has none of
those, and synthesizing them would be inventing a risk assessment nobody made.

**`nodes` is not optional, and it is why the query result looks like the chain
view instead of a row of grey boxes.** `toGraph` today seeds real `ChainNode`s
from `chain.source`/`chain.target` and only synthesizes
`{ type: 'other', label: id }` for an id that appears solely inside a step
([chainGraph.ts:68-72](../../../frontend/UI/src/components/attack-graph/chainGraph.ts)).
A path response carrying only steps would hit that synthesized branch for
*every* node, so `categorize()` would drop the whole path into the `other`
category — grey, labelled with a raw ARN
([AttackChainGraph.tsx:47-66](../../../frontend/UI/src/components/attack-graph/AttackChainGraph.tsx)).
The graph already holds a real `type` and `name` per node, which is the entire
premise of Goal 1, so the response carries them:

```python
def _chain_node(node_dict) -> dict:
    """A graph node in the frontend's existing ChainNode shape.

    `type` stays in envelope._node()'s lowercase vocabulary ("user"/"role"/
    "group"/...) because that is what NODE_CATEGORY keys on; remapping
    NODE_CATEGORY to Scout's NodeType names would touch the chain view for no
    gain. `node_type` carries Scout's raw NodeType alongside it — that is the
    key NODE_TYPE_ICON needs, and the one thing ARN parsing cannot supply
    (SERVICE and PUBLIC nodes have no ARN to parse).
    """
```

`ChainNode` therefore gains two **optional** fields, `node_type?: string` and
`name?: string`. Optional, not required: `envelope._node()` does not set them,
so every stored scan keeps type-checking and the chain view keeps rendering
exactly as it does today. The icon lookup falls back to the letter badge when
`node_type` is absent, which is the same fallback an uncurated `NodeType`
already gets.

## Frontend components

### Icons

A curated subset of the official AWS Architecture Icons, mapped from
Scout's `NodeType` plus the resource-type strings its `properties` carry
(EC2, Lambda, S3, KMS, ...). Committed as static SVG assets under
`frontend/UI/src/assets/aws-icons/`, with a `NODE_TYPE_ICON: Record<string,
string>` lookup. **Sourcing the actual icon files is an external download** —
per this session's operating rules that requires explicit permission at the
point of doing it (filename/source/size stated first), not assumed here. The
exact subset and AWS's current package URL are an open item below, resolved at
implementation time rather than guessed at in this spec.

### `EntityPanel` (evolves the current `DetailPanel`)

On node click, additionally fetches `/graph/entity/?id=`. Renders the type
icon, name, account id, a curated set of properties (the fields worth a
security reader's attention per type — not decided per-type here, left to the
implementation plan), and a collapsible "raw properties" JSON disclosure for
anything not curated. Falls back to today's ARN-parsed badge when the fetch
404s (older scan, no stored graph) — never a broken panel.

**The raw-properties disclosure renders trust policy documents and resource
tags verbatim** (`ingest/gaad.py:199`). That is accepted deliberately: the
viewer is the authenticated owner of the account being scanned, looking at
their own scan, and a redacted policy document is worse than useless to a
security reader. Recorded here so it is a decision rather than a default.

### `QueryPanel` (new)

Two autocomplete entity pickers, each backed by `/graph/nodes/?q=` with a 200ms
debounce, and a "Find paths" action calling `/graph/path/`. A "Find paths from
here" action on the selected node in `EntityPanel` opens `QueryPanel` with that
node pre-filled as the source.

**What is shared with the chain view, precisely.** `AttackChainGraph` today
takes `{ envelope: ScanEnvelope }` and `toGraph()` iterates `envelope.chains`
([chainGraph.ts:47](../../../frontend/UI/src/components/attack-graph/chainGraph.ts)),
while `DetailPanel` takes `chains: AttackChain[]`. A query result has none of
`AttackChain`'s non-optional fields, so "reuse the same components" is split
rather than asserted:

- **Shared, by extraction.** The per-chain loop body in `toGraph` already is
  "turn a `ChainStep[]` into nodes and edges." It is extracted to
  `stepsToGraph(steps: ChainStep[], pathId: string, known: ChainNode[]): Graph`,
  and `toGraph` becomes its caller over `envelope.chains` (passing
  `[chain.source, chain.target]` as `known`). `QueryPanel` passes the
  response's `nodes` array, which is what keeps query-result nodes typed,
  coloured and labelled rather than falling into the synthesized-`other`
  branch. `computeLayout`, `SvgNode` and the edge path renderer are then used
  unchanged by both views. This is the only refactor of existing code the
  feature requires, and it is behaviour-preserving.
- **Not shared.** `DetailPanel`'s header ("N chains through this identity", risk
  score, narrative, MITRE ids) stays chain-only. `QueryPanel` gets its own
  header stating what the query was, how many paths were found, the depth
  searched, and which edge types were traversed. Borrowing the chain header
  would imply a ranking and a risk assessment that were never computed.

Result states are explicit, never a blank panel (see Error handling).

## Error handling

- `scan.graph` is `None` (a scan stored before this feature, or a scan whose
  task predates the `tasks.py` change) — every one of the three new endpoints
  returns `404` with a message distinguishing "the graph is not available for
  this scan" from "no such scan," and `EntityPanel`/`QueryPanel` render that
  distinctly from a real empty result. Re-running the scan produces a new row
  that has one; nothing backfills old rows.
- An unknown `src`/`dst`/`id` — `400`, naming the id that was not found. Not a
  `404`: the scan and its graph exist, the id does not.
- **No path found** — "No escalation path found from X to Y within 10 hops,
  following PRIVESC_TO / CAN_ASSUME / CAN_ACCESS_RESOURCE edges." The traversed
  set is named because it is what makes the statement true; "no path" unqualified
  would be a claim the query did not test.
- **`search_capped` is true** — "Search budget reached before the graph was
  fully explored; there may be paths this query did not find." Rendered
  *instead of* the no-path-found copy, never alongside it, and never silently
  swallowed. This is the one case where the honest answer is "we don't know."
- **`truncated` is true** — "Showing the 25 shortest paths; more exist."
  `iter_paths` yields in BFS order, so the shown set is genuinely the shortest
  ones and that sentence is accurate.
- A `NodeType`/resource type with no curated icon — a generic fallback glyph
  (today's letter-badge treatment), never a broken image.

### Depth 5 vs depth 10

`build_chains` ranks at `max_depth=5`
([chains/builder.py:1079](../../../backend/venv-dev/Lib/site-packages/scout/chains/builder.py));
the query searches to 10. A path found at depth 8 therefore will not appear in
the ranked-chains list. That is the point of having a query at all, but it
reads as an inconsistency unless said out loud: when a query returns a path
longer than 5 hops, the result carries a one-line note that the ranked list
only covers paths up to 5 hops — so the user reads the list as differently
scoped, not as incomplete.

## Testing

**Backend — what runs in CI.** Everything below that touches only
`graph_search.py`, `envelope.py`, the model and the serializers runs in CI as a
`SimpleTestCase`. Everything that needs a real `scout.graph.Graph` is gated
behind `skipUnless(HAS_SCOUT, ...)` (the pattern at
`apps/emulations/tests/test_access_contract.py:103`) and runs locally only; the
endpoints are covered CI-side by source-reading contract tests in
`test_api_contract.py`'s existing style, since DRF is absent. `MIGRATION`:
`makemigrations --check --dry-run` is a CI step, so the migration must be
committed with the model change.

Unit tests against a small fixture graph (built inline, mirroring the existing
`test_envelope.py` pattern, not a new fixture file unless the existing one
proves reusable):

- a path found; a path not found; a path ending at a `RESOURCE` node via
  `CAN_ACCESS_RESOURCE` (the case the default edge-type list silently fails);
- **a conditional hop keeps `certainty == "conditional"` and its reason through
  the query path** — the regression test for the `render_path` defect this
  revision removes, and the one test that must not be dropped;
- `truncated` and `search_capped` each set, by shrinking the budgets against a
  fixture that exceeds them;
- an unknown `src` id → `400`;
- `search_nodes` ordering is deterministic, honours the 50 cap, and a `q` under
  2 characters returns the head of the list rather than an error;
- a round-trip through `to_dict()`/`from_dict()`;
- the three private Scout imports (`_mechanism_for`, `_concrete_api`,
  `_concrete_resource_reach`) are importable and return the expected shape,
  and `_concrete_resource_reach(edge, None)` does not raise — the None-guard
  `_hop_from_edge` relies on;
- `nodes` covers every id referenced by every returned step, and each carries a
  `type` that `NODE_CATEGORY` recognises — the regression test for query
  results rendering as uncategorised grey boxes.

Endpoint tests:

- all three return `404` for another user's scan id;
- all three return `404` when `scan.graph is None`, with the distinguishing
  message;
- `graph` is absent from `ScoutScanDetailSerializer(scan).data` and from the
  list serializer — the invariant above;
- `ScoutScan.graph` defaults to `None` and `serialize_scan()` remains
  indifferent to its presence (the envelope contract does not change, and
  `schema_version` is not bumped).

Migration is created with the app named explicitly —
`python manage.py makemigrations attack_graph` — per the repo's `makemigrations`
gotcha.

**Frontend.** No test runner exists in this repo (unchanged from the original
integration spec's finding) — verified visually via the same throwaway
dev-preview approach used earlier in this feature's development, against a mock
graph/query response. The `toGraph` → `stepsToGraph` extraction is
behaviour-preserving and is checked by confirming the existing chain view
renders identically before and after.

## Open items for the implementation plan (not blocking this spec)

- **Exact AWS Architecture Icons subset and source.** Resolve at implementation
  time: AWS's own Architecture Icons download vs. a maintained, license-clean
  npm package, if one exists that covers Scout's node/resource types without
  pulling in icons for services never seen here.
- **Which entity properties are "curated" per type** for the entity panel (vs.
  relegated to the raw-properties disclosure) — a per-type decision better made
  against real scan data than guessed at in this spec.
- **The measured graph size** (see the migration gate above). The number itself
  is an open item; taking it before the migration lands is not.
- **Whether `MAX_QUERY_PATHS = 25` and the 50-result search cap are right**
  against a large account. Both are chosen to match numbers already in this
  codebase (`MAX_CHAINS = 25`) rather than tuned; confirm once a large-account
  scan is available.

## Blocking decisions for the author

1. **Icon sourcing** — official AWS Architecture Icons, confirmed with the user
   this session (over reusing Scout's bundled PNGs or staying with colored
   badges). The concrete download source/version is still open (see Open items)
   and needs explicit download permission when reached.
2. **Storage** — `ScoutScan.graph` as a Postgres `JSONField`, confirmed with the
   user this session, not S3. Now conditional on the measurement gate above:
   confirmed as the default, reopened before implementation if the measured
   graph on a small real account is already near Scout's own 8MB ceiling.

## Revision notes (2026-09-22)

Changed after [review](../reviews/2026-09-22-attack-graph-entity-graph-and-query-review.md):

1. **`render_path` dropped.** It discards `action` and `conditional`, which
   would have rendered every query hop as `deterministic` — contradicting the
   ranked-chains view about the same edge. Hops are now built from the edges via
   Scout's own `Hop`, matching `build_chains`.
2. **Explicit `edge_types`.** The default `[PRIVESC_TO, CAN_ASSUME]` never
   traverses a resource edge, so every resource destination would have returned
   a false "no path found." `CAN_ACCESS_RESOURCE` added; the other four types
   are excluded with a stated reason each.
3. **Truncation reported.** `iter_paths` with an explicit budget and two
   distinct flags (`truncated`, `search_capped`) replaces `find_paths`' silent
   bare list.
4. **Node ids moved to query parameters.** `/graph/entity/<arn>/` was not
   routable — node ids contain `/` and are not always ARNs.
5. **`resolve_arn_tokens` dropped.** Its warnings are CLI copy, its matching is
   unbounded, and autocomplete already yields exact ids. Exact ids + `400`.
6. **Measurement gate on the storage decision**, using `scout.viz.payload_bytes`.
7. **Serializer invariant written down** with a test, so the graph can never
   join the polled detail response.
8. **Frontend sharing specified precisely** — `stepsToGraph` extraction, shared
   layout/node/edge primitives, separate headers — replacing "zero new cases."
   The path response carries `nodes` so query results are typed and coloured
   like chain nodes instead of falling into `toGraph`'s synthesized `other`
   branch. One caveat the "zero new step cases" claim does not cover: a
   `resource_access`/`resource_control` hop can now arrive with
   `certainty: 'conditional'` through the query, a combination the chain view
   only produced via `_resource_reach_chains` — worth confirming during
   implementation that the step renderer does not branch on mechanism in a way
   that assumes an identity hop.
9. **No-rehydrate search path** plus a bounded LRU for the path query, replacing
   a per-keystroke `Graph.from_dict()`.
10. **Goal 1 retitled** from "the full entity graph" to what actually ships:
    per-entity records, stored and queryable. Nothing here renders a graph.
