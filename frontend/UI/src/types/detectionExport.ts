/**
 * Types for the detection export endpoints (/api/emulations/.../export/).
 *
 * A bundle carries three disjoint lists, and keeping them apart is the point:
 * what compiled, what this SIEM cannot express, and what the catalogue does not
 * have. Collapsing them would let an engineer deploy a file believing it covers
 * rules it silently omitted.
 */

/** A SIEM dialect this deployment may be able to compile to. */
export interface DetectionTarget {
  /** Stable key used in query strings, e.g. "splunk". */
  name: string
  /** Human label, e.g. "OpenSearch / Wazuh Indexer (Lucene)". */
  label: string
  /** Output formats this backend supports. */
  formats: string[]
  /** False when the backend package is not installed on this server. */
  installed: boolean
  /** The pip package that would make it available. */
  install: string
}

/** One compiled query. */
export interface ExportedQuery {
  /** The technique grouping key that was requested, e.g. "t1070". */
  ruleId: string
  /** The Sigma document's own UUID. One file can hold several. */
  sigmaId: string
  title: string
  query: string
}

/** A rule this target cannot express, and why. */
export interface SkippedQuery {
  ruleId: string
  sigmaId: string
  title: string
  reason: string
}

/** Everything one export produced. */
export interface DetectionExportBundle {
  target: string
  label: string
  format: string
  emulationType: string
  queries: ExportedQuery[]
  skipped: SkippedQuery[]
  /** Requested rule ids the catalogue has no Sigma for. */
  missing: string[]
  counts: { converted: number; skipped: number; missing: number }
  /** Present on the run-scoped export: what this file is. */
  note?: string
}
