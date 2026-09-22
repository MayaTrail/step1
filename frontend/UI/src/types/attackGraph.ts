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
  /**
   * What this chain ends in (e.g. "FULL_ACCOUNT_COMPROMISE"), or null if
   * Scout reported none. When `steps` is empty this is the only thing that
   * explains the chain: a zero-step chain means the identity already holds
   * this impact directly, not that nothing was found.
   */
  terminal_impact: string | null
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
