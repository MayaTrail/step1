import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { WorkflowRunDetail } from '@/types/workflow'
import { Card } from '@/components/ui/Card'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { STEPS, stepStates, type StepKey, type StepState } from './workflowMeta'
import { JobIcon } from './JobIcon'

/**
 * The four stages a workflow passes through, laid out left to right.
 *
 * Each stage holds one job, and selecting a job opens what is known about it
 * underneath. A failed run opens on the job that failed, because the reason it
 * stopped is the first thing a reader needs. Records are reached through links
 * that name them ("View stack"), never through raw IDs, which mean nothing to
 * a reader and invite copying the wrong one.
 *
 * Red appears here only when the pipeline itself breaks. A detection that
 * stayed silent is a finding about the client's coverage, not a broken run,
 * and it is reported further down the page in amber.
 */

const STATE_WORD: Record<StepState, string> = {
  done: 'passed',
  active: 'running',
  failed: 'failed',
  pending: 'pending',
}

/** The stage a failed run gave up on, as recorded by the backend. */
function failedStage(run: WorkflowRunDetail): StepKey {
  return STEPS.find((step) => step.key === run.failedStep)?.key ?? 'deploy'
}

/** @param run - The workflow whose stages are drawn. */
export function PipelineGraph({ run }: { run: WorkflowRunDetail }) {
  const states = stepStates(run)
  /*
   * Undefined means the reader has not picked a job yet, so the default
   * applies: a failed run opens on its failed job, anything else stays closed.
   * Null means the reader closed it, which must stick even on a failed run.
   */
  const [chosen, setChosen] = useState<StepKey | null | undefined>(undefined)
  const open = chosen === undefined ? (run.status === 'failed' ? failedStage(run) : null) : chosen

  return (
    <Card className="p-5">
      <div className="font-mono text-2xs uppercase tracking-label text-content-dim">Pipeline</div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-y-4 mt-3.5">
        {STEPS.map((step, index) => {
          const state = states[index] ?? 'pending'
          const selected = open === step.key
          const border = selected
            ? 'border-accent-blue'
            : state === 'active'
              ? 'border-accent-blue/35'
              : 'border-border'
          return (
            <div key={step.key} className="pr-7 last:pr-0">
              <div className="text-xs text-content-secondary tracking-body mb-2">{step.stage}</div>
              <div className="relative">
                <button
                  type="button"
                  aria-expanded={selected}
                  onClick={() => setChosen(selected ? null : step.key)}
                  className={`w-full flex items-center gap-3 text-left px-3 py-2.5 rounded-xl
                    bg-surface-base border transition-opacity hover:opacity-60 ${border}`}
                >
                  <JobIcon stage={step.key} state={state} />
                  <span className="min-w-0">
                    <span className="block text-sm text-content-primary tracking-body">{step.label}</span>
                    <span className="block font-mono text-2xs text-content-dim mt-0.5">{STATE_WORD[state]}</span>
                  </span>
                </button>
                {/* The link to the next job, in the gap the column padding leaves. */}
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
          <StageDetail run={run} stage={open} />
        </div>
      )}
    </Card>
  )
}

/** A value is either plain text or a link to the record that owns it. */
type DetailValue = string | { label: string; to: string }

/**
 * What is known about one stage, pointing at the record that holds its state.
 *
 * @param run - The workflow being shown.
 * @param stage - The stage to describe.
 */
function StageDetail({ run, stage }: { run: WorkflowRunDetail; stage: StepKey }) {
  const failedHere = run.status === 'failed' && failedStage(run) === stage
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
    rows = [
      ['Alerts attributed', run.score ? String(run.score.alertsReceived) : 'still collecting'],
      ['Collecting until', run.alertDeadline ? formatWhen(run.alertDeadline) : 'not started'],
      ['Integration', run.score ? (run.score.integrationHealth ? 'your SIEM reported' : 'nothing received') : 'unknown'],
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
      {failedHere && run.detail && (
        <p className="text-xs text-danger leading-relaxed tracking-body mt-3">{run.detail}</p>
      )}
    </div>
  )
}
