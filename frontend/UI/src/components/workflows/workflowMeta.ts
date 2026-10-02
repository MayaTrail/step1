import type { RuleVerdict, ScoreStatus, WorkflowRunDetail, WorkflowStatus } from '@/types/workflow'

/**
 * Presentation logic for workflows, kept out of the components.
 *
 * The step derivation in particular is a small state machine, and reading it
 * inline in JSX would make it easy to get the failure case wrong.
 */

/**
 * A step's state in the pipeline, for rendering a progress rail. `skipped` and
 * `unchecked` belong to the account check alone: it can be skipped without
 * stopping the run, and runs older than the check never had one.
 */
export type StepState = 'done' | 'active' | 'pending' | 'failed' | 'skipped' | 'unchecked'

/**
 * The pipeline, in the order a run passes through it. `stage` names the
 * column and `label` the single job inside it.
 */
export const STEPS = [
  { key: 'check', stage: 'Check account', label: 'Check your policies' },
  { key: 'deploy', stage: 'Deploy', label: 'Provision infrastructure' },
  { key: 'attack', stage: 'Attack', label: 'Run emulation' },
  { key: 'alerts', stage: 'Collect alerts', label: 'Wait for SIEM alerts' },
  { key: 'score', stage: 'Score', label: 'Score detections' },
] as const

/** One pipeline stage key. */
export type StepKey = (typeof STEPS)[number]['key']

/**
 * The steps the run's status moves through, in order. The account check is
 * not among them: it has no status of its own, because it runs in the same
 * tick that starts the deploy.
 */
const RUN_STEPS: StepKey[] = ['deploy', 'attack', 'alerts', 'score']

/** Which of RUN_STEPS each status is sitting on. -1 means not started. */
const STATUS_STEP: Record<WorkflowStatus, number> = {
  scheduled: -1,
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
 * The account check's state, read from what the run stored.
 *
 * No record means one of two things: the run has not reached its deploy yet,
 * or it started before workflows ran the check (or gave up before it ran).
 */
function checkState(run: WorkflowRunDetail): StepState {
  if (run.accountCheck) return run.accountCheck.status === 'checked' ? 'done' : 'skipped'
  return run.status === 'scheduled' || run.status === 'pending' ? 'pending' : 'unchecked'
}

/**
 * Decide how to render one step of the pipeline for a given run.
 *
 * Steps are found by key, never by position, so adding a step cannot shift a
 * caller onto the wrong one.
 *
 * A failed run marks the step it died on rather than showing everything as
 * pending, because "it failed" is far less useful than "it failed deploying".
 * Which step that was comes from the run itself, not from this function.
 *
 * @param run - The workflow being rendered.
 * @param key - The step to describe.
 * @returns The step's state.
 */
export function stageState(run: WorkflowRunDetail, key: StepKey): StepState {
  if (key === 'check') return checkState(run)
  const index = RUN_STEPS.indexOf(key)

  if (run.status === 'failed') {
    // The backend records which step gave up, because only the code that gave
    // up knows. An earlier version inferred it from startedAt, which is set
    // when deploying begins rather than when it succeeds, so a failed deploy
    // rendered green and the blame landed on a step that never ran.
    const failedIndex = RUN_STEPS.indexOf(run.failedStep as StepKey)
    const reached = failedIndex >= 0 ? failedIndex : 0
    return index < reached ? 'done' : index === reached ? 'failed' : 'pending'
  }

  const current = STATUS_STEP[run.status]
  if (current < 0) return 'pending'
  if (index < current) return 'done'
  if (index === current) return 'active'
  return 'pending'
}

/**
 * Every step's state, in STEPS order.
 *
 * @param run - The workflow being rendered.
 * @returns One state per entry in STEPS.
 */
export function stepStates(run: WorkflowRunDetail): StepState[] {
  return STEPS.map((step) => stageState(run, step.key))
}

/** Label for each status, phrased for a reader rather than as a field value. */
export const STATUS_LABEL: Record<WorkflowStatus, string> = {
  scheduled: 'Scheduled',
  pending: 'Queued',
  deploying: 'Deploying infrastructure',
  attacking: 'Running emulation',
  awaiting_alerts: 'Waiting for your SIEM',
  completed: 'Completed',
  failed: 'Failed',
}

/** Tone per status. Waiting is informational, not a warning. */
export const STATUS_TONE: Record<WorkflowStatus, 'neutral' | 'blue' | 'green' | 'red'> = {
  scheduled: 'neutral',
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

/**
 * Describe how long until a scheduled run starts.
 *
 * A scheduled run looks identical to a stuck one in a table, so the row has to
 * say when it is due or the reader assumes it has hung.
 *
 * @param scheduledFor - ISO timestamp the run is due to start.
 * @returns A short phrase, or "starting now" once the time has passed and the
 *   next beat tick has yet to pick it up.
 */
export function untilScheduled(scheduledFor: string | null): string {
  if (!scheduledFor) return ''
  const remaining = new Date(scheduledFor).getTime() - Date.now()
  if (Number.isNaN(remaining)) return ''
  if (remaining <= 0) return 'starting now'
  const minutes = Math.ceil(remaining / 60_000)
  if (minutes < 60) return `starts in ${minutes} min`
  const hours = Math.round(remaining / 3_600_000)
  if (hours < 24) return `starts in ${hours} h`
  return `starts in ${Math.round(hours / 24)} d`
}
