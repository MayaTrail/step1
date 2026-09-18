/**
 * Types for coverage history (/api/workflows/coverage/).
 *
 * Two views of the same runs. `runs` slices by run, one gauge each, and
 * `rules` slices by detection, one bullet each. Keeping them apart is the
 * point: a run tells you what a single attack proved, a rule tells you what
 * you can rely on.
 *
 * Nullable numbers here mean "never measured", never zero. A rule nothing
 * reached has no reliability, and rendering that as 0% would assert a
 * detection failure where the real problem was a missing connection.
 */

/** How a detection has behaved across every judged run. */
export type StandingState =
  /** No confirmed hit in any judged run. */
  | 'never_fired'
  /** Fired before, did not fire in the latest judged run. */
  | 'silent_now'
  /** Fired, stopped, and came back at least once. */
  | 'flaky'
  /** Firing, and has not dropped. */
  | 'firing'
  /** No run has judged it. */
  | 'no_data'

/** One run, as a single gauge. */
export interface CoverageRun {
  runId: string
  completedAt: string | null
  /** The score's own status: "ok", "no_endpoint" or "no_alerts". */
  status: string
  /** False when no alert reached this run, so nothing could be scored. */
  judged: boolean
  /** Fired share as a percentage, or null when the run was never judged. */
  coverage: number | null
  fired: number
  silent: number
  notIntegrated: number
  ruleCount: number
  alertsReceived: number
  /** Alerts that arrived but matched no expected detection. */
  unattributedCount: number
  /** False when nothing reached this run at all. */
  integrationHealth: boolean
  /**
   * This run's verdict per rule, so the page can recompute reliability over
   * any window of runs locally. Selecting a gauge scrubs through history, and
   * a request per click would make that feel broken.
   */
  verdicts: Record<string, string>
  /** Match tier and the alert behind each verdict, read only when comparing. */
  outcomes: Record<string, RuleOutcome>
  /** Attack start. Alert latency is measured from windowEnd, not from here. */
  windowStart: string | null
  /** Attack end. The zero point the comparison timeline is drawn against. */
  windowEnd: string | null
  /** When the run stopped waiting for alerts. */
  alertDeadline: string | null
  /** False when the attack step never completed, so nothing was exercised. */
  attackCompleted: boolean
}

/** The alert behind one verdict, or its absence. */
export interface RuleOutcome {
  /** "exact" for a Sigma id citation, "technique" for a technique match. */
  matchTier: string
  /** Null for a rule nothing reported, which is a fact worth stating. */
  evidence: {
    ruleName: string | null
    severity: string | null
    firedAt: string | null
    receivedAt: string | null
  } | null
}

/** One detection, as a single bullet. */
export interface CoverageRule {
  ruleId: string
  title: string
  severity: string
  technique: string
  /** Share of judged runs this rule fired in, or null when never judged. */
  reliability: number | null
  firedRuns: number
  judgedRuns: number
  /** Reliability before the most recent judged run, for the direction marker. */
  previousReliability: number | null
  meetsTarget: boolean
  state: StandingState
  /** Consecutive trailing runs in which it fired. */
  streak: number
  /** Fired-to-not-fired transitions, which is what makes a rule flaky. */
  dips: number
}

/** Everything the coverage history page renders. */
export interface CoverageHistory {
  emulationType: string
  /** Platform the emulation belongs to, for links into its detection pages. */
  platform: string
  /** Reliability a detection is expected to meet, as a percentage. */
  target: number
  runs: CoverageRun[]
  rules: CoverageRule[]
  counts: {
    runs: number
    judged: number
    belowTarget: number
  }
}
