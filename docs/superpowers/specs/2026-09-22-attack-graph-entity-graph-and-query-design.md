# Attack Graph — Full Entity Graph, Icons, and Path Query — Design Spec

Date: 2026-09-22
Branch: `feat/scout-integration`
Status: Approved for planning

## Goal

Extend the Attack Graph feature with three things Scout's own graph already
computes but the current integration discards:

1. **The full entity graph.** Every AWS identity, service and resource node
   Scout modelled — not just the ARNs that happen to be a chain endpoint —
   with a real type, name and properties per entity.
2. **A path query.** "Find the chains between these two entities" run
   on-demand against the whole graph, not limited to the top-25 pre-ranked
   chains the envelope already carries.
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
`find_paths`/`render_path`/`reachable_from`/`resolve_arn_tokens`) built for
exactly this question, and a full graph viewer (`scout/viz.py` +
`viz_assets/template.html`) that already ships real AWS service icons. None
of this requires new algorithms — it requires capturing data Scout already
produces and exposing it through the product's own UI instead of Scout's.

## Non-goals

- AWS Organizations SCP/RCP fetching. Separate, already-flagged future item
  (Organizations API access needs a different permission model than the
  per-account audit role this feature uses) — not part of this spec.
- Replacing the ranked-chains list as the landing view. The full graph stays
  a drill-down (entity panel + on-demand query), never the default view —
  a raw force-directed dump of every node an account has is the anti-pattern
  this product has deliberately avoided so far.
- Cytoscape.js or any new graph-rendering dependency. Query results render
  through the existing dagre+SVG chain components
  (`AttackChainGraph.tsx`/`chainGraph.ts`), not a second rendering stack.
- Editing or annotating the graph.

## Architecture

```
Scan completes (existing flow, unchanged up to this point)
  tasks.py: report, graph = pipeline.run(...)
      -> envelope = serialize_scan(report, ...)          [unchanged]
      -> ScoutScan.result = envelope                       [unchanged]
      -> ScoutScan.graph  = graph.to_dict()                [NEW]

Three new read endpoints, scoped to one scan and its owner:
  GET /api/attack-graph/scan/<id>/graph/nodes/?q=<term>    search/autocomplete
  GET /api/attack-graph/scan/<id>/graph/entity/<arn>/      one entity's full record
  GET /api/attack-graph/scan/<id>/graph/path/?src=&dst=    find_paths + render_path

Frontend:
  EntityPanel   (evolves the current DetailPanel's node header)
      -> fetches /graph/entity/<arn>/ for icon + curated properties
  QueryPanel    (new)
      -> autocomplete via /graph/nodes/, "Find path" via /graph/path/
      -> renders the result through the SAME step/edge components a
         ranked chain already uses — no second visual language
      -> "Find path to..." shortcut on a selected node pre-fills it
```

## Backend components

### `ScoutScan.graph` field (`apps/attack_graph/models.py`)

A new `JSONField(null=True, blank=True)`, sibling to `result`. Nullable
because every scan stored before this feature ships has no graph — that is
a normal, permanent state (see Error handling), not a migration to backfill.
Same retention posture as `result`: unencrypted at the same sensitivity as
the rest of the row, deleted with the user, no separate pruning rule.

### `tasks.py`

After `pipeline.run()` returns `(report, graph)`, store
`graph.to_dict()` on the scan row alongside the envelope.
`Graph.to_dict()`/`Graph.from_dict()` are Scout's own loss-free JSON
serializer (`scout/graph/schema.py`) — built for exactly this, no reshaping
needed. `graph` was previously bound to `_graph` (the underscore signalling
"intentionally unused"); this spec removes the underscore and adds the one
line that stores it.

### Query module (`apps/attack_graph/graph_query.py`, new)

A thin wrapper, not a reimplementation. Rehydrates
`scout.graph.Graph.from_dict(scan.graph)` and calls straight through to:

- `resolve_arn_tokens(graph, [token])` — fuzzy ARN-suffix matching, so a
  user can type `alice` instead of the full ARN. Returns `(matches,
  warnings)`; a token matching zero nodes, or a source token matching a
  non-origin-capable type, produces a warning this module surfaces
  verbatim rather than translating.
- `find_paths(graph, src, dst, max_depth=10)` + `render_path(graph, path)`
  for the path query — the hop shape `render_path` returns
  (`hop_number`/`mechanism`/`source_arn`/`target_arn`/`concrete_api_sequence`)
  is normalised through the same step-mapping logic
  [`envelope.py`'s `_step`](../../../backend/apps/attack_graph/envelope.py)
  already applies to chain hops (including `certainty`/`conditional_reason`
  if the underlying edge carries `conditional` data — Scout's rule-built
  `PRIVESC_TO` edges may not always carry it; absent means `deterministic`,
  same default `_step` already uses), so the frontend's existing step
  rendering needs zero new cases.
- `reachable_from(graph, origin_arn)` — exposed for a later "what can this
  identity reach" view; not wired into the UI in this iteration, but the
  endpoint module supports it so that follow-up is additive, not a rewrite.

### API surface additions (`apps/attack_graph/urls.py`, `views.py`)

| method | path | purpose |
|---|---|---|
| GET | `/api/attack-graph/scan/<id>/graph/nodes/?q=<term>` | search stored graph nodes by id/name substring — powers both query pickers |
| GET | `/api/attack-graph/scan/<id>/graph/entity/<arn>/` | one entity's full record: type, name, account_id, properties |
| GET | `/api/attack-graph/scan/<id>/graph/path/?src=<token>&dst=<token>` | `find_paths`/`render_path` via `graph_query.py`, `resolve_arn_tokens` warnings included in the response |

All three scoped to `request.user`'s own scan, reusing the ownership check
`ScoutScanDetailView` already applies. `404` (not `200` with an empty body)
when `scan.graph` is `None` — see Error handling.

## Frontend components

### Icons

A curated subset of the official AWS Architecture Icons, mapped from
Scout's `NodeType` plus the resource-type strings its `properties` carry
(EC2, Lambda, S3, KMS, ...). Committed as static SVG assets under
`frontend/UI/src/assets/aws-icons/`, with a `NODE_TYPE_ICON: Record<string,
string>` lookup. **Sourcing the actual icon files is an external download**
— per this session's operating rules that requires explicit permission at
the point of doing it (filename/source/size stated first), not assumed here.
The exact subset and AWS's current package URL are an open item below,
resolved at implementation time rather than guessed at in this spec.

### `EntityPanel` (evolves the current `DetailPanel`)

On node click, additionally fetches `/graph/entity/<arn>/`. Renders the
type icon, name, account id, a curated set of properties (the fields worth
a security reader's attention per type — not decided per-type here, left to
the implementation plan), and a collapsible "raw properties" JSON
disclosure for anything not curated. Falls back to today's ARN-parsed badge
when the fetch 404s (older scan, no stored graph) — never a broken panel.

### `QueryPanel` (new)

Two autocomplete entity pickers, each backed by `/graph/nodes/?q=`, and a
"Find path" action calling `/graph/path/`. The result renders through the
same step-list and edge-highlight components a ranked chain already uses —
this is the point of normalising `render_path`'s output through `_step`'s
shape on the backend. Zero/ambiguous match and no-path-found both render an
explicit state (see Error handling), never a blank panel. A "Find path
to..." action on the existing `DetailPanel`/`EntityPanel` opens `QueryPanel`
with the selected node pre-filled as the source.

## Error handling

- `scan.graph` is `None` (a scan stored before this feature, or a scan whose
  task predates the `tasks.py` change) — every one of the three new
  endpoints returns `404` with a message distinguishing "not available for
  this scan" from "not found," and `EntityPanel`/`QueryPanel` render that
  distinctly from a real empty result.
- No path found within `max_depth` — an explicit "No path found from X to Y
  within depth 10" state, matching Scout's own CLI wording, not a blank
  panel indistinguishable from a slow request.
- A query token matches zero nodes, or matches a node type that can never be
  a chain origin — `resolve_arn_tokens`'s own warning is shown verbatim,
  not swallowed or re-worded into a guess about what went wrong.
- A `NodeType`/resource type with no curated icon — a generic fallback
  glyph (today's letter-badge treatment), never a broken image.

## Testing

- **Backend.** `graph_query.py` unit tests against a small fixture graph
  (built inline, mirroring the existing `test_envelope.py` pattern, not a
  new fixture file unless the existing one proves reusable): a path found,
  a path not found, an ambiguous/zero-match token, a round-trip through
  `to_dict()`/`from_dict()`. A migration test confirming `ScoutScan.graph`
  defaults to `None` and `serialize_scan()` remains indifferent to its
  presence (the envelope contract does not change).
- **Frontend.** No test runner exists in this repo (unchanged from the
  original integration spec's finding) — verified visually via the same
  throwaway dev-preview approach used earlier in this feature's
  development, against a mock graph/query response.

## Open items for the implementation plan (not blocking this spec)

- **Exact AWS Architecture Icons subset and source.** Resolve at
  implementation time: AWS's own Architecture Icons download vs. a
  maintained, license-clean npm package, if one exists that covers Scout's
  node/resource types without pulling in icons for services never seen
  here.
- **Which entity properties are "curated" per type** for the entity panel
  (vs. relegated to the raw-properties disclosure) — a per-type decision
  better made against real scan data than guessed at in this spec.
- **`/graph/nodes/` result bounding.** Scout's own static-HTML viewer caps
  out at 8MB total payload; a live search endpoint sidesteps that ceiling
  structurally, but an unbounded `q=""` (match-everything) response on a
  large account still needs a sane limit — a fixed cap (e.g. 50 results) is
  the likely answer, confirmed against a real large-account scan once one
  is available.
- **No backfill for historical scans.** A scan stored before this ships
  simply never gets a graph; re-running it produces a new row that does.
  This spec does not propose re-running old scans to backfill `graph`.

## Blocking decisions for the author

1. **Icon sourcing** — official AWS Architecture Icons, confirmed with the
   user this session (over reusing Scout's bundled PNGs or staying with
   colored badges). The concrete download source/version is still open
   (see Open items) and needs explicit download permission when reached.
2. **Storage** — `ScoutScan.graph` as a Postgres `JSONField`, confirmed with
   the user this session, not S3. Revisit only if a real scan's graph size,
   measured against a production-scale account, turns out to be a genuine
   problem — not before.
