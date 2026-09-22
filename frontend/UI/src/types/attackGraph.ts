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

/**
 * One hop of a chain.
 *
 * No `technique` field: Scout attaches none per hop (verified in Task 1 —
 * see apps/attack_graph/envelope.py's `_step`). `mechanism`/`action` are
 * Scout's own hop fields, carried through verbatim by the backend. A per-hop
 * MITRE technique would be a duplicate of the chain-level `mitre_techniques`
 * entry, not something Scout actually reports per step — see
 * AttackChain.mitre_techniques instead.
 *
 * `certainty`/`conditional_reason` are derived by the backend from Scout's
 * `hop.conditional` gating (see `_conditional_summary` in envelope.py) —
 * never re-derived here. No "blocked" state: Scout's evaluator does not
 * evaluate SCPs or permission boundaries, so a hop is only ever
 * "deterministic" or "conditional".
 */
export interface ChainStep {
  from: string
  to: string
  mechanism: string
  action: string
  concrete_api_sequence: string[]
  detail: string
  certainty: 'deterministic' | 'conditional'
  conditional_reason: string
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
  /**
   * What this chain ends in (e.g. "FULL_ACCOUNT_COMPROMISE"), or null if
   * Scout reported none. When `steps` is empty this is the only thing that
   * explains the chain: a zero-step chain means the identity already holds
   * this impact directly, not that nothing was found.
   */
  terminal_impact: string | null
  /**
   * Other mechanisms Scout found reaching the same source→target pair,
   * merged away into this chain's representative entry (chains/builder.py's
   * _collapse_by_mechanism). Empty when this is the only route found —
   * never omitted, so the frontend can render "N alt routes" off `.length`
   * without a presence check.
   */
  alternate_mechanisms: string[]
  /** Plain-English "how this chain works", from Scout's reasoning engine
   * (deterministic template by default, no LLM). Empty when no analysis was
   * run for this scan (e.g. an older stored scan). */
  narrative: string
  /** One detection idea for this chain, or empty if none was matched. */
  detection: string
  /** One remediation idea for this chain, or empty if none was matched. */
  remediation: string
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
  /**
   * Regions resource collection covered (User.aws_audit_regions at scan
   * time). Empty or absent means the scan was IAM-only — no EC2/Lambda/S3/
   * etc. were collected, so it can only report identities that already hold
   * an impact directly, never a path through an actual resource. Optional:
   * scans stored before this field existed have no "regions" key at all, not
   * an empty array — treat both the same way (@/components/attack-graph/
   * AttackGraphHub.tsx's regionsLine does), never `result.regions.length`
   * directly.
   */
  regions?: string[]
  truncated: boolean
  /** Computed by the backend. Never re-derive it here — see chainGraph.ts. */
  state: ScanState
  chains: AttackChain[]
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface ScanSummary {
  id: string
  status: ScanStatus
  /**
   * The completed scan's top-level classification (see ScanState), without
   * paying for its full result envelope — the history strip needs this to
   * say "5 findings" or "Partial" next to a past scan. Null for a scan that
   * hasn't completed, or one that completed with no result recorded.
   */
  state: ScanState | null
  error_message: string
  created_at: string
  started_at: string | null
  completed_at: string | null
}

export interface ScanDetail extends ScanSummary {
  result: ScanEnvelope | null
}

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
