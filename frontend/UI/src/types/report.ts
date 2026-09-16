/** Types for the evidence packet and two-run comparison (/api/emulations/). */

import type { CoverageTrendPoint, RegressionReport } from './coverageHistory'

export type ReportVerdict = 'fired' | 'silent' | 'no_logs'

export interface ReportFinding {
  ruleId: string
  title: string
  verdict: ReportVerdict
  severity: string | null
  matchCount: number | null
  evaluableDocuments: number | null
  requiredSources: string[]
  technique: {
    id: string | null
    name: string | null
    tactic: string | null
  }
}

/**
 * A technique the campaign executes that no rule in the pack looks for.
 *
 * Deliberately separate from a `silent` finding: a rule that ran and stayed
 * quiet is a gap in the customer's detection, while this is a gap in ours, and
 * the coverage percentage does not count it at all.
 */
export interface UncoveredTechnique {
  id: string
  name: string
  phase: number | null
  phaseName: string | null
}

export interface RunReport {
  generatedAt: string
  run: {
    id: string
    emulationType: string
    displayName: string
    status: string
    stackName: string | null
    region: string | null
    startedAt: string | null
    completedAt: string | null
    phaseCurrent: number | null
    phaseTotal: number | null
    operator: string | null
  }
  coverage: {
    fired: number
    silent: number
    noLogs: number
    ruleCount: number
    /** Fired / rules evaluated, 0..1, or null when nothing was judged. */
    fidelity: number | null
    checkStatus: string | null
  }
  findings: ReportFinding[]
  /** Findings whose verdict is not `fired` — what needs acting on. */
  gaps: ReportFinding[]
  uncovered: UncoveredTechnique[]
  attackPath: {
    phase: number
    name: string
    techniques: { id: string; name: string }[]
  }[]
  change: RegressionReport
  trend: CoverageTrendPoint[]
}

export type VerdictChangeKind =
  | 'regressed'
  | 'improved'
  | 'changed'
  | 'unchanged'
  | 'added'
  | 'removed'

export interface ComparisonRow {
  ruleId: string
  title: string
  /** Verdict in the baseline run, or null if the rule was not in it. */
  a: ReportVerdict | null
  /** Verdict in the compared run, or null if the rule is no longer in it. */
  b: ReportVerdict | null
  change: VerdictChangeKind
}

export interface RunComparison {
  a: CoverageTrendPoint | null
  b: CoverageTrendPoint | null
  /** b.fidelity − a.fidelity, or null when either run was not judged. */
  fidelityDelta: number | null
  rows: ComparisonRow[]
  summary: Record<VerdictChangeKind, number>
  emulationType: string
  /** False when the two runs are of different campaigns — comparable, but noisy. */
  sameEmulation: boolean
}
