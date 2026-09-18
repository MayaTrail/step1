/**
 * The evidence packet for one workflow run.
 *
 * Mirrors GET /api/workflows/runs/<id>/report/. Assembly over data the run
 * already stored, so nothing here can disagree with the run drawer.
 */

import type { ScoreStatus, RuleVerdict, MatchTier, WorkflowStatus } from './workflow'

/** The alert a client's SIEM sent, behind one fired verdict. */
export interface ReportEvidence {
  alertId: string
  ruleId: string
  ruleName: string
  severity: string
  firedAt: string | null
  receivedAt: string | null
}

/** One expected detection and what the client's SIEM did about it. */
export interface ReportRule {
  ruleId: string
  title: string
  verdict: RuleVerdict
  severity: string
  technique: string
  /** How confidently the alert was tied to this rule. Empty when nothing was. */
  matchTier: MatchTier
  evidence: ReportEvidence | null
}

/**
 * A technique the emulation executes that no MayaTrail rule looks for.
 *
 * Reported separately from a rule that ran and stayed silent, because the two
 * are different failures: this one is a gap in our content, not the client's.
 */
export interface UncoveredTechnique {
  id: string
  name: string
  phase: number
  phaseName: string
}

export interface WorkflowReport {
  run: {
    id: string
    emulationType: string
    displayName: string
    status: WorkflowStatus
    failedStep: string
    createdAt: string | null
    startedAt: string | null
    completedAt: string | null
    windowStart: string | null
    windowEnd: string | null
    stackName: string | null
    owner: string
  }
  score: {
    status: ScoreStatus | null
    counts: Partial<Record<RuleVerdict, number>>
    ruleCount: number
    alertsReceived: number
    /** Null, never zero, when nothing was exercised. */
    detectionCoverage: number | null
    integrationHealth: boolean
  }
  rules: ReportRule[]
  uncovered: UncoveredTechnique[]
  unattributed: {
    count: number
    truncated: boolean
    alerts: ReportEvidence[]
  }
  /**
   * Coverage in words. Always "n of m rules evaluated" and never a bare
   * percentage, and it names what the figure excludes. Render this rather than
   * composing your own sentence from the counts.
   */
  coverageSentence: string
}
