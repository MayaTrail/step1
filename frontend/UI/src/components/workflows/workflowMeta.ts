import type { RuleVerdict, ScoreStatus, WorkflowRun, WorkflowStatus } from '@/types/workflow'

/**
 * Presentation logic for workflows, kept out of the components.
 *
 * The step derivation in particular is a small state machine, and reading it
 * inline in JSX would make it easy to get the failure case wrong.
 */

/** A step's state in the pipeline, for rendering a progress rail. */
export type StepState = 'done' | 'active' | 'pending' | 'failed'

/** The pipeline, in the order a run passes through it. */
export const STEPS = [
  { key: 'deploy', label: 'Deploy infrastructure' },
  { key: 'attack', label: 'Run emulation' },
  { key: 'alerts', label: 'Collect SIEM alerts' },
  { key: 'score', label: 'Score' },
] as const

/** Which step each status is sitting on. -1 means not started. */
const STATUS_STEP: Record<WorkflowStatus, number> = {
  pending: -1,
  deploying: 0,
  attacking: 1,
  awaiting_alerts: 2,
  completed: 4,
  failed: -1,
}

/** Runs in these states are still moving, so their page polls. */
export function isOpen(status: WorkflowStatus): boolean {
  return status !== 'completed' && status !== 'failed'
}

/**
 * Decide how to render each step of the pipeline for a given run.
 *
 * A failed run marks the step it died on rather than showing everything as
 * pending, because "it failed" is far less useful than "it failed deploying".
 * Which step that was comes from the run itself, not from this function.
 *
 * @param run - The workflow being rendered.
 * @returns One state per entry in STEPS.
 */
export function stepStates(run: WorkflowRun): StepState[] {
  if (run.status === 'failed') {
    // The backend records which step gave up, because only the code that gave
    // up knows. An earlier version inferred it from startedAt, which is set
    // when deploying begins rather than when it succeeds, so a failed deploy
    // rendered green and the blame landed on a step that never ran.
    const failedIndex = STEPS.findIndex((step) => step.key === run.failedStep)
    const reached = failedIndex >= 0 ? failedIndex : 0
    return STEPS.map((_, index) =>
      index < reached ? 'done' : index === reached ? 'failed' : 'pending',
    )
  }

  const current = STATUS_STEP[run.status]
  return STEPS.map((_, index) => {
    if (current < 0) return 'pending'
    if (index < current) return 'done'
    if (index === current) return 'active'
    return 'pending'
  })
}

/** Label for each status, phrased for a reader rather than as a field value. */
export const STATUS_LABEL: Record<WorkflowStatus, string> = {
  pending: 'Queued',
  deploying: 'Deploying infrastructure',
  attacking: 'Running emulation',
  awaiting_alerts: 'Waiting for your SIEM',
  completed: 'Completed',
  failed: 'Failed',
}

/** Tone per status. Waiting is informational, not a warning. */
export const STATUS_TONE: Record<WorkflowStatus, 'neutral' | 'blue' | 'green' | 'red'> = {
  pending: 'neutral',
  deploying: 'blue',
  attacking: 'blue',
  awaiting_alerts: 'blue',
  completed: 'green',
  failed: 'red',
}

/** Label for each per-rule verdict. */
export const VERDICT_LABEL: Record<RuleVerdict, string> = {
  fired: 'Caught',
  silent: 'Missed',
  not_integrated: 'Not exercised',
}

/**
 * Colour per verdict, carrying meaning rather than decoration.
 *
 * `not_integrated` is deliberately neutral, not red. It means no alert route
 * existed, which is a setup task, and painting it as a failure would accuse a
 * detection team of something their webhook configuration caused.
 */
export const VERDICT_CLASS: Record<RuleVerdict, string> = {
  fired: 'text-safe bg-safe-dim border-safe/25',
  silent: 'text-warning bg-warning-dim border-warning/25',
  not_integrated: 'text-content-dim bg-surface-elevated border-border',
}

/**
 * Explain what a score status means and what to do about it.
 *
 * Each unfinished state gets its own sentence, because they call for
 * completely different actions: one is a setup task, one is a pipeline
 * question, and one is not the client's problem at all.
 */
export const SCORE_STATUS_NOTE: Record<ScoreStatus, string> = {
  ok: '',
  no_endpoint:
    'No alert endpoint is configured, so nothing could be validated. Create one below and point your SIEM at it.',
  no_alerts:
    'Your SIEM sent no alerts during this run. That is a question for your alert pipeline, not for your detection rules.',
  no_rules: 'This emulation ships no detection rules, so there was nothing to validate.',
}

/**
 * Render a coverage percentage.
 *
 * @param value - The percentage, or null when nothing was exercised.
 * @returns The figure, or a dash. Never "0%" for an absent measurement: a zero
 *   reads as "your detections failed", which is a different claim entirely.
 */
export function formatCoverage(value: number | null): string {
  return value === null ? '—' : `${value}%`
}

/**
 * Describe how long until a waiting run settles.
 *
 * @param deadline - ISO timestamp the run stops collecting alerts.
 * @returns A short phrase, or an empty string once the deadline has passed.
 */
export function untilDeadline(deadline: string | null): string {
  if (!deadline) return ''
  const remaining = new Date(deadline).getTime() - Date.now()
  if (Number.isNaN(remaining) || remaining <= 0) return ''
  const minutes = Math.ceil(remaining / 60_000)
  return minutes < 60 ? `about ${minutes} min left` : `about ${Math.ceil(minutes / 60)} h left`
}
