import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { PreventionAnalysis } from '@/types/prevention'
import type { AccountCheckSkipReason, WorkflowRunDetail } from '@/types/workflow'
import { Card } from '@/components/ui/Card'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { AccountCheckDrawer, CheckHeadline } from '@/components/emulations/AccountCheckDrawer'
import { settleWorkflowRun } from '@/services/workflow.service'
import { STEPS, stepStates, untilDeadline, type StepKey, type StepState } from './workflowMeta'
import { AlertsDrawer } from './AlertsDrawer'
import { JobIcon } from './JobIcon'

/**
 * The stages a workflow passes through, laid out left to right.
 *
 * Each stage holds one job, and selecting a job opens what is known about it
 * underneath. A failed run opens on the job that failed, because the reason it
 * stopped is the first thing a reader needs. Records are reached through links
 * that name them ("View stack"), never through raw IDs, which mean nothing to
 * a reader and invite copying the wrong one.
 *
 * Red appears here only when the pipeline itself breaks. A detection that
 * stayed silent is a finding about the client's coverage, not a broken run,
 * and it is reported further down the page in amber. A skipped account check
 * is grey for the same reason: the run carried on without it.
 *
 * While the run waits for alerts, that job opens by default: what has arrived
 * so far, and the way to stop waiting, are what a reader at that point wants.
 *
 * Every job is the same, fixed size. The spacing between columns is a shared
 * gap rather than padding on all but the last, which made the last job wider,
 * and a label too long for its job is cut with an ellipsis, shown in full on
 * hover, so one long label never resizes the whole row.
 */

const STATE_WORD: Record<StepState, string> = {
  done: 'passed',
  active: 'running',
  failed: 'failed',
  pending: 'pending',
  skipped: 'skipped',
  unchecked: 'not checked',
}

/** Why the account check was skipped: a few words for the job, a sentence for its details. */
const SKIP_TEXT: Record<AccountCheckSkipReason, { short: string; detail: string }> = {
  no_connected_role: {
    short: 'no connected role',
    detail: 'No AWS role was connected when this run started, so there was nothing to ask AWS about.',
  },
  nothing_to_check: {
    short: 'nothing to check',
    detail: 'This emulation makes no call that an IAM policy decides, so there was nothing to ask AWS.',
  },
  missing_permission: {
    short: 'missing permission',
    detail:
      'Your connected role cannot run this check yet. Add iam:SimulatePrincipalPolicy to it; it is '
      + 'read-only and changes nothing in your account. The policy on the connect page already includes it.',
  },
  aws_error: {
    short: 'AWS refused',
    detail: 'AWS refused the check. Nothing was wrong with this run, and the next run will ask again.',
  },
  check_failed: {
    short: 'check failed',
    detail: 'The check could not be completed. Nothing was wrong with this run, and the next run will ask again.',
  },
}

/** The second line of a job: its state, or for the account check, what it found. */
function jobSubtitle(run: WorkflowRunDetail, key: StepKey, state: StepState): string {
  const check = run.accountCheck
  if (key === 'check' && check) {
    if (check.status === 'skipped') return `skipped · ${SKIP_TEXT[check.reason].short}`
    if (!check.afterDeploy) return 'checked before deploy'
    const { actionsChecked, prevented } = check.result.summary
    if (actionsChecked === 0) return 'nothing checkable'
    return `${actionsChecked} checked · ${prevented.length} refused`
  }
  return STATE_WORD[state]
}

/** The stage a failed run gave up on, as recorded by the backend. */
function failedStage(run: WorkflowRunDetail): StepKey {
  return STEPS.find((step) => step.key === run.failedStep)?.key ?? 'deploy'
}

/**
 * When the alert window closes. formatWhen only describes the past and reads
 * "just now" for any future time, so a deadline still ahead shows its clock time.
 */
function deadlineText(iso: string): string {
  const when = new Date(iso)
  if (when.getTime() <= Date.now()) return formatWhen(iso)
  return when.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

/** The job a run opens on before the reader has picked one, if any. */
function defaultStage(run: WorkflowRunDetail): StepKey | null {
  if (run.status === 'failed') return failedStage(run)
  if (run.status === 'awaiting_alerts') return 'alerts'
  return null
}

/**
 * @param run - The workflow whose stages are drawn.
 * @param prevention - The emulation's declared phases and actions, which the
 *   account check's details need; null until loaded.
 * @param onSettled - Receives the scored run after the reader stops waiting.
 */
export function PipelineGraph({
  run,
  prevention,
  onSettled,
}: {
  run: WorkflowRunDetail
  prevention: PreventionAnalysis | null
  onSettled: (run: WorkflowRunDetail) => void
}) {
  const states = stepStates(run)
  const [alertsOpen, setAlertsOpen] = useState(false)
  /*
   * Undefined means the reader has not picked a job yet, so the default
   * applies (defaultStage). Null means the reader closed it, which must stick
   * even on a failed run.
   */
  const [chosen, setChosen] = useState<StepKey | null | undefined>(undefined)
  const open = chosen === undefined ? defaultStage(run) : chosen

  return (
    <Card className="p-5">
      <div className="font-mono text-2xs uppercase tracking-label text-content-dim">Pipeline</div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-x-7 gap-y-4 mt-3.5">
        {STEPS.map((step, index) => {
          const state = states[index] ?? 'pending'
          const selected = open === step.key
          const border = selected
            ? 'border-accent-blue'
            : state === 'active'
              ? 'border-accent-blue/35'
              : 'border-border'
          return (
            <div key={step.key}>
              <div className="text-xs text-content-secondary tracking-body mb-2">{step.stage}</div>
              <div className="relative">
                <button
                  type="button"
                  aria-expanded={selected}
                  onClick={() => setChosen(selected ? null : step.key)}
                  title={`${step.label}: ${jobSubtitle(run, step.key, state)}`}
                  className={`w-full h-14 flex items-center gap-3 text-left px-3 rounded-xl
                    bg-surface-base border transition-opacity hover:opacity-60 ${border}`}
                >
                  <JobIcon stage={step.key} state={state} />
                  <span className="min-w-0">
                    <span
                      className={`block truncate text-sm tracking-body ${
                        state === 'unchecked' ? 'text-content-dim' : 'text-content-primary'
                      }`}
                    >
                      {step.label}
                    </span>
                    <span className="block truncate font-mono text-2xs text-content-dim mt-0.5">
                      {jobSubtitle(run, step.key, state)}
                    </span>
                  </span>
                </button>
                {/* The link to the next job, drawn inside the column gap. */}
                {index < STEPS.length - 1 && (
                  <span aria-hidden="true" className="hidden lg:block absolute top-1/2 left-full ml-1.5 w-4 h-px bg-border" />
                )}
              </div>
            </div>
          )
        })}
      </div>

      {open && (
        <div className="mt-4 pt-4 border-t border-border">
          {open === 'check' ? (
            <CheckDetail run={run} prevention={prevention} />
          ) : (
            <StageDetail run={run} stage={open} onViewAlerts={() => setAlertsOpen(true)} onSettled={onSettled} />
          )}
        </div>
      )}

      <AlertsDrawer
        open={alertsOpen}
        workflowId={run.id}
        emulationType={run.emulationType}
        waiting={run.status === 'awaiting_alerts'}
        onClose={() => setAlertsOpen(false)}
      />
    </Card>
  )
}

/**
 * A value is plain text, a link to the record that owns it, or text with a
 * button that opens more about it on the same page.
 */
type DetailValue = string | { label: string; to: string } | { text: string; onView: () => void }

/**
 * What is known about one stage, pointing at the record that holds its state.
 *
 * @param run - The workflow being shown.
 * @param stage - The stage to describe.
 * @param onViewAlerts - Opens the alerts drawer.
 * @param onSettled - Receives the scored run after the reader stops waiting.
 */
function StageDetail({
  run,
  stage,
  onViewAlerts,
  onSettled,
}: {
  run: WorkflowRunDetail
  stage: StepKey
  onViewAlerts: () => void
  onSettled: (run: WorkflowRunDetail) => void
}) {
  const failedHere = run.status === 'failed' && failedStage(run) === stage
  const waiting = run.status === 'awaiting_alerts'
  let rows: [string, DetailValue][]

  if (stage === 'deploy') {
    rows = [
      ['Stack', run.stackId ? { label: 'View stack', to: `/stacks?stack=${run.stackId}` } : 'not created'],
      ['Stack status', run.stackStatus || 'unknown'],
      ['Started', run.startedAt ? formatWhen(run.startedAt) : 'not started'],
    ]
  } else if (stage === 'attack') {
    rows = [
      [
        'Emulation run',
        run.emulationRunId
          ? { label: 'View emulation run', to: `/${run.platform}/emulations/${run.emulationType}?tab=live` }
          : 'never started',
      ],
      ['Run status', run.emulationRunStatus || 'not started'],
      [
        'Window',
        run.windowStart
          ? `${formatWhen(run.windowStart)} to ${run.windowEnd ? formatWhen(run.windowEnd) : 'open'}`
          : 'not opened',
      ],
    ]
  } else if (stage === 'alerts') {
    const received = run.score ? run.score.alertsReceived : run.alertCount
    const attributed = waiting ? `${received} so far` : run.score ? String(received) : 'still collecting'
    rows = [
      ['Alerts attributed', received > 0 ? { text: attributed, onView: onViewAlerts } : attributed],
      ['Collecting until', run.alertDeadline ? deadlineText(run.alertDeadline) : 'not started'],
      [
        'Integration',
        run.score
          ? (run.score.integrationHealth ? 'your SIEM reported' : 'nothing received')
          : waiting
            ? (received > 0 ? 'receiving alerts' : 'nothing yet')
            : 'unknown',
      ],
    ]
  } else {
    rows = [
      ['Result', run.score ? run.summary : 'not scored yet'],
      ['Expected detections', run.score ? String(run.score.ruleCount) : '-'],
      ['Unattributed alerts', run.score ? String(run.score.unattributedCount) : '-'],
    ]
  }

  return (
    <div>
      <dl className="grid grid-cols-1 sm:grid-cols-3 gap-x-4 gap-y-3">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt className="font-mono text-2xs uppercase tracking-caps text-content-dim">{label}</dt>
            <dd className="text-xs tracking-body mt-1.5 break-words">
              {typeof value === 'string' ? (
                <span className="text-content-secondary">{value}</span>
              ) : 'onView' in value ? (
                <>
                  <span className="text-content-secondary">{value.text}</span>
                  <button
                    type="button"
                    onClick={value.onView}
                    className="ml-2 text-xs tracking-body text-accent-blue transition-opacity hover:opacity-60"
                  >
                    View alerts
                  </button>
                </>
              ) : (
                <Link
                  to={value.to}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-btn border border-white/10
                    text-content-primary no-underline transition-opacity hover:opacity-60"
                >
                  {value.label}
                  <span className="text-content-dim">&rsaquo;</span>
                </Link>
              )}
            </dd>
          </div>
        ))}
      </dl>
      {stage === 'alerts' && waiting && (
        <div className="flex flex-wrap items-center justify-between gap-3 mt-3 pt-3 border-t border-border">
          <span className="text-xs text-content-dim tracking-body">
            Not expecting more alerts? You can score this run now.
          </span>
          <StopWaiting run={run} onSettled={onSettled} />
        </div>
      )}
      {failedHere && run.detail && (
        <p className="text-xs text-danger leading-relaxed tracking-body mt-3">{run.detail}</p>
      )}
    </div>
  )
}

/**
 * Ending the alert wait early, after an inline confirm.
 *
 * The window is a fixed wait, and a reader whose SIEM has already reported
 * should not sit through the rest of it. Scoring early is final: the window
 * closes, so anything the SIEM posts afterwards does not count, which is why
 * it asks once before doing it.
 *
 * @param run - The waiting run.
 * @param onSettled - Receives the scored run.
 */
function StopWaiting({ run, onSettled }: { run: WorkflowRunDetail; onSettled: (run: WorkflowRunDetail) => void }) {
  const [confirming, setConfirming] = useState(false)
  const [scoring, setScoring] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function score() {
    if (scoring) return
    setScoring(true)
    setError(null)
    try {
      onSettled(await settleWorkflowRun(run.id))
    } catch (caught) {
      const detail = (caught as { response?: { data?: { detail?: string } } }).response?.data?.detail
      setError(detail ?? 'Could not score this run.')
      setConfirming(false)
      setScoring(false)
    }
  }

  const left = untilDeadline(run.alertDeadline)
  const button = 'px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn transition-opacity hover:opacity-60'
  return (
    <div className="flex flex-col items-end gap-1.5">
      <div className="flex items-center gap-2">
        {confirming ? (
          <>
            <button type="button" onClick={() => setConfirming(false)} className={`${button} text-content-dim`}>
              Keep waiting
            </button>
            <button
              type="button"
              onClick={score}
              disabled={scoring}
              className={`${button} border border-accent-blue/40 text-accent-blue disabled:opacity-30 disabled:cursor-not-allowed`}
            >
              {scoring ? 'Scoring…' : 'Score now'}
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={() => setConfirming(true)}
            className={`${button} border border-white/15 text-content-primary`}
          >
            Stop waiting
          </button>
        )}
      </div>
      <span className="text-2xs text-content-muted">
        {confirming
          ? 'Alerts that arrive after this are not counted.'
          : `Score now rather than waiting out the window${left ? ` (${left})` : ''}.`}
      </span>
      {error && <span className="text-xs text-danger">{error}</span>}
    </div>
  )
}

/**
 * What the account check found before deploy, or why it did not run.
 *
 * Its details open the same drawer as the emulation page, read-only: the
 * check is a record of the policies in force when this run began, and a
 * recheck here would replace what the run was judged on.
 *
 * @param run - The workflow being shown.
 * @param prevention - Each phase's declared actions, for the drawer.
 */
function CheckDetail({ run, prevention }: { run: WorkflowRunDetail; prevention: PreventionAnalysis | null }) {
  const [drawerOpen, setDrawerOpen] = useState(false)
  const check = run.accountCheck

  if (!check) {
    const text = ['scheduled', 'pending', 'deploying'].includes(run.status)
      ? 'Runs once the lab is deployed, just before the attack: by then the lab\'s own identities exist, '
        + 'so they are checked in this run\'s lab, with your organisation\'s SCPs applied. Nothing is '
        + 'performed in your account.'
      : 'This run has no account check: it started before workflows ran one, or stopped before its '
        + 'attack began.'
    return <p className="text-xs text-content-secondary leading-relaxed tracking-body">{text}</p>
  }

  if (check.status === 'skipped') {
    return (
      <div>
        <p className="text-xs text-content-secondary leading-relaxed tracking-body">
          {SKIP_TEXT[check.reason].detail}
          {check.errorCode && <span className="font-mono text-content-dim"> ({check.errorCode})</span>}
        </p>
        <p className="text-xs text-content-dim leading-relaxed tracking-body mt-2">
          The workflow carried on without it, so the Prevention lane shows library advice only.
        </p>
        {check.reason === 'missing_permission' && (
          <Link
            to="/me"
            className="inline-flex items-center gap-1.5 mt-3 px-2.5 py-1 rounded-btn border border-white/10
              text-xs text-content-primary no-underline transition-opacity hover:opacity-60"
          >
            Open the connect page
            <span className="text-content-dim">&rsaquo;</span>
          </Link>
        )}
      </div>
    )
  }

  const { result } = check
  return (
    <div>
      <CheckHeadline check={result} className="mb-3" />
      <p className="text-xs text-content-dim leading-relaxed tracking-body mb-3">
        {check.afterDeploy
          ? "Checked in this run's own lab, just before the attack."
          : 'This run is older than lab-identity checks: it was checked before its deploy, as your connected role only.'}
      </p>
      <dl className="grid grid-cols-1 sm:grid-cols-3 gap-x-4 gap-y-3">
        {[
          ['Acting as', result.identity],
          ['Region', result.region],
          ['Checked', `${formatWhen(check.checkedAt)}, ${check.afterDeploy ? 'before the attack' : 'before deploy'}`],
        ].map(([label, value]) => (
          <div key={label}>
            <dt className="font-mono text-2xs uppercase tracking-caps text-content-dim">{label}</dt>
            <dd className="text-xs tracking-body mt-1.5 break-words text-content-secondary">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="flex flex-wrap items-center gap-x-3.5 gap-y-2 mt-3.5">
        {prevention && (
          <button
            type="button"
            onClick={() => setDrawerOpen(true)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-btn border border-white/10
              text-xs text-content-primary transition-opacity hover:opacity-60"
          >
            View details
            <span className="text-content-dim">&rsaquo;</span>
          </button>
        )}
        <span className="text-xs text-content-dim tracking-body">Simulated, not observed. Never part of the score.</span>
      </div>
      {prevention && (
        <AccountCheckDrawer
          open={drawerOpen}
          running={false}
          check={result}
          refusal={null}
          prevention={prevention}
          checkedAt={new Date(check.checkedAt)}
          onClose={() => setDrawerOpen(false)}
        />
      )}
    </div>
  )
}
