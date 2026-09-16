/** Types for coverage-over-time and detection regressions (/api/emulations/). */

export interface CoverageTrendPoint {
  runId: string
  emulationType: string
  completedAt: string | null
  counts: { fired: number; silent: number; no_logs: number }
  ruleCount: number
  /** Fired / rules-evaluated (0..1), or null. */
  fidelity: number | null
}

export interface RuleVerdictChange {
  ruleId: string
  title: string
  from: string
  to: string
}

export interface RegressionReport {
  hasPrevious: boolean
  regressions: RuleVerdictChange[]
  improvements: RuleVerdictChange[]
  unchanged: number
  previousRunId?: string
  currentRunId?: string
  previousCompletedAt?: string | null
}

export type ScheduleCadence = 'daily' | 'weekly' | 'monthly'

export interface ScheduledRun {
  id: string
  emulation_type: string
  cadence: ScheduleCadence
  enabled: boolean
  next_run_at: string
  last_run_at: string | null
  last_run: string | null
  owner_username: string
  created_at: string
  updated_at: string
}

/** Dashboard portfolio assurance summary (/api/emulations/assurance/). */
export interface AssuranceSummary {
  hasRuns: boolean
  coverage: {
    fired: number
    /** silent: activity happened, no rule caught it. */
    missed: number
    /** no_logs: the rule could not even be judged. */
    noData: number
    total: number
    /** Fired / total across the latest run of each emulation, 0..1, or null. */
    pct: number | null
    emulationsScored: number
  }
  regressions: {
    emulationType: string
    runId: string
    ruleId: string
    title: string
    from: string
    to: string
  }[]
  improvements: number
  failedRunCount: number
  schedules: { emulationType: string; cadence: string; nextRunAt: string | null }[]
  scheduleCount: number
}
