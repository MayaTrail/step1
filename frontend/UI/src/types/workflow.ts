/**
 * Workflow types.
 *
 * Mirrors /api/workflows/. A workflow is one end-to-end validation of a single
 * emulation against the detections a client already runs: deploy, attack, wait
 * for their SIEM to report what it caught, then score the difference.
 */

/** Lifecycle of a workflow, in the order a run passes through it. */
export type WorkflowStatus =
  | 'pending'
  | 'deploying'
  | 'attacking'
  | 'awaiting_alerts'
  | 'completed'
  | 'failed'

/**
 * What a run established, which is not the same as whether it finished.
 *
 *   ok              detections were exercised and the result is real.
 *   no_endpoint     no webhook is configured, so nothing could be validated.
 *   no_alerts       the endpoint exists but the SIEM sent nothing.
 *   no_rules        this emulation ships no detections to validate.
 */
export type ScoreStatus = 'ok' | 'no_endpoint' | 'no_alerts' | 'no_rules'

/** Per-rule outcome. `not_integrated` is a connection problem, never a miss. */
export type RuleVerdict = 'fired' | 'silent' | 'not_integrated'

/** How confidently an alert was tied to an expected detection. */
export type MatchTier = 'exact' | 'technique' | 'weak' | ''

/** The alert behind a verdict, so a claim can always be traced to evidence. */
export interface AlertEvidence {
  alertId: string
  ruleId: string
  ruleName: string
  technique: string
  severity: string
  firedAt: string | null
  receivedAt: string | null
}

/** One expected detection and what the client's SIEM did about it. */
export interface RuleOutcome {
  ruleId: string
  title: string
  severity: string
  technique: string
  verdict: RuleVerdict
  matchTier: MatchTier
  evidence: AlertEvidence | null
}

/** The figures a finished run produces. */
export interface WorkflowScore {
  status: ScoreStatus
  counts: Record<RuleVerdict, number>
  ruleCount: number
  alertsReceived: number
  /**
   * Percentage of exercised detections the SIEM reported, or null when nothing
   * was exercised. Null is deliberately not zero: a zero reads as "your
   * detections failed", which is a different and much worse claim.
   */
  detectionCoverage: number | null
  integrationHealth: boolean
  unattributedCount: number
  /** True when more alerts arrived than the report stores. */
  unattributedTruncated: boolean
  rules: RuleOutcome[]
  unattributed: AlertEvidence[]
}

/** A workflow as a list row. */
export interface WorkflowRun {
  id: string
  emulationType: string
  /** Platform of the emulation, for links into its pages. */
  platform: string
  status: WorkflowStatus
  detail: string
  /** Which step abandoned a failed run, recorded rather than inferred. */
  failedStep: string
  score: WorkflowScore | null
  /** One-sentence result, empty while the run is still open. */
  summary: string
  alertDeadline: string | null
  createdAt: string
  startedAt: string | null
  completedAt: string | null
}

/** A workflow with its per-rule verdicts. */
export interface WorkflowRunDetail extends WorkflowRun {
  report: { rules: RuleOutcome[]; unmatched: AlertEvidence[] } | null
  windowStart: string | null
  windowEnd: string | null
  stackId: string | null
  stackStatus: string
  emulationRunId: string | null
  emulationRunStatus: string
}

/** A webhook a client's SIEM posts alerts to. Never carries the secret. */
export interface AlertEndpoint {
  id: string
  name: string
  enabled: boolean
  /** Last few characters, so two endpoints can be told apart. */
  secretHint: string
  lastAlertAt: string | null
  createdAt: string
  /** Username of whoever created it, so a team can tell endpoints apart. */
  createdBy: string
  /** Alerts accepted so far, which is how a client confirms setup works. */
  alertCount: number
}

/**
 * The create response, which is the only time the secret exists client-side.
 * It is stored encrypted and cannot be read back.
 */
export interface AlertEndpointCreated extends AlertEndpoint {
  secret: string
}
