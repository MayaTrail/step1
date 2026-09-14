import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { AlertEvidence, RuleOutcome, WorkflowRunDetail } from '@/types/workflow'
import { Card } from '@/components/ui/Card'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import {
  SCORE_STATUS_NOTE,
  STEPS,
  VERDICT_CLASS,
  VERDICT_LABEL,
  formatCoverage,
  stepStates,
} from './workflowMeta'

/**
 * The body of a workflow: where it is, and what it found.
 *
 * Shared by the slide-over on the Workflows page and the standalone route, so
 * a workflow reads identically whether it was opened from the list or from a
 * pasted link. Only the surrounding chrome differs.
 *
 * Ordering of verdicts is deliberate: caught first, then missed, then never
 * exercised. A reader takes the good news, then the actionable gap, then the
 * rows that are a setup task rather than a detection failure.
 */

const VERDICT_ORDER = ['fired', 'silent', 'not_integrated'] as const

export function WorkflowDetailBody({ run }: { run: WorkflowRunDetail }) {
  return (
    <div>
      <PipelineRail run={run} />

      {run.score ? <Result run={run} /> : <Pending run={run} />}
    </div>
  )
}

/**
 * The four steps, with the one in progress marked and every step clickable.
 *
 * Selecting a step opens what is known about it underneath. Without that, a
 * failed run said only that it failed, and the reader had to go and find the
 * stack or the emulation run themselves to learn why.
 */
function PipelineRail({ run }: { run: WorkflowRunDetail }) {
  const states = stepStates(run)
  /*
   * A failed run opens on the step that failed, so its reason is visible
   * without a click. That reason used to also sit in a red panel of its own
   * below the rail, which printed the same sentence twice and detached it from
   * the step it described.
   */
  const [openStep, setOpenStep] = useState<string | null>(
    run.status === 'failed' ? run.failedStep || 'deploy' : null,
  )

  return (
    <Card className="p-4 mb-4">
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        {STEPS.map((step, index) => {
          const state = states[index] ?? 'pending'
          const selected = openStep === step.key
          const tone =
            state === 'done'
              ? 'text-safe'
              : state === 'active'
                ? 'text-accent-blue'
                : state === 'failed'
                  ? 'text-danger'
                  : 'text-content-dim'
          return (
            <button
              key={step.key}
              type="button"
              aria-expanded={selected}
              onClick={() => setOpenStep(selected ? null : step.key)}
              /* Selection is a bottom rail and brighter text, not a filled
                 box. Four bordered rectangles appearing under the cursor made
                 the rail look like a toolbar rather than a progress trail. */
              className={`group flex items-start gap-2 text-left px-1 py-1.5 border-b-2
                transition-colors ${selected ? 'border-b-accent-blue' : 'border-b-transparent'}`}
            >
              <span className={`mt-1 w-2 h-2 rounded-full shrink-0 bg-current ${tone}
                ${state === 'active' ? 'animate-pulse' : ''}`} />
              <span className="min-w-0">
                <span className={`block text-xs font-medium tracking-body transition-opacity
                  ${tone} ${selected ? '' : 'group-hover:opacity-70'}`}>
                  {step.label}
                </span>
                <span className="block font-mono text-2xs text-content-muted mt-0.5">
                  {state === 'done' ? 'done' : state}
                </span>
              </span>
            </button>
          )
        })}
      </div>

      {openStep && (
        <div className="mt-3 pt-3 border-t border-border">
          <StepDetail run={run} stepKey={openStep} />
        </div>
      )}
    </Card>
  )
}

/**
 * What is known about one step.
 *
 * Each step points at the record that actually holds its state, so a reader can
 * open the stack or the run rather than being told only that something failed.
 */
function StepDetail({ run, stepKey }: { run: WorkflowRunDetail; stepKey: string }) {
  const failedHere = run.status === 'failed' && run.failedStep === stepKey

  if (stepKey === 'deploy') {
    return (
      <Detail
        rows={[
          [
            'Stack',
            // Deep link rather than an id. What a reader wants from this step is
            // which resources were provisioned, and that lives on the stack.
            run.stackId
              ? { label: run.stackId.slice(0, 8), to: `/stacks?stack=${run.stackId}` }
              : 'not created',
          ],
          ['Stack status', run.stackStatus || 'unknown'],
          ['Started', run.startedAt ? formatWhen(run.startedAt) : 'not started'],
        ]}
        note={failedHere ? run.detail : ''}
      />
    )
  }

  if (stepKey === 'attack') {
    const window = run.windowStart
      ? `${formatWhen(run.windowStart)} to ${run.windowEnd ? formatWhen(run.windowEnd) : 'open'}`
      : 'not opened'
    return (
      <Detail
        rows={[
          [
            'Emulation run',
            run.emulationRunId
              ? {
                  label: run.emulationRunId.slice(0, 8),
                  to: `/${run.platform}/emulations/${run.emulationType}?tab=live`,
                }
              : 'never started',
          ],
          ['Run status', run.emulationRunStatus || 'not started'],
          ['Window', window],
        ]}
        note={failedHere ? run.detail : ''}
      />
    )
  }

  if (stepKey === 'alerts') {
    const integration = run.score
      ? run.score.integrationHealth
        ? 'your SIEM reported'
        : 'nothing received'
      : 'unknown'
    return (
      <Detail
        rows={[
          ['Alerts attributed', run.score ? String(run.score.alertsReceived) : 'still collecting'],
          ['Collecting until', run.alertDeadline ? formatWhen(run.alertDeadline) : 'not started'],
          ['Integration', integration],
        ]}
        note={failedHere ? run.detail : ''}
      />
    )
  }

  return (
    <Detail
      rows={[
        ['Result', run.score ? run.summary : 'not scored yet'],
        ['Expected detections', run.score ? String(run.score.ruleCount) : '-'],
        ['Unattributed alerts', run.score ? String(run.score.unattributedCount) : '-'],
      ]}
      note={failedHere ? run.detail : ''}
    />
  )
}

/** A value is either plain text or a link to the record that owns it. */
type DetailValue = string | { label: string; to: string }

/** A small label and value list, with an optional failure note. */
function Detail({ rows, note }: { rows: [string, DetailValue][]; note?: string }) {
  return (
    <div>
      <dl className="grid grid-cols-1 sm:grid-cols-3 gap-x-4 gap-y-2">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt className="font-mono text-2xs uppercase tracking-caps text-content-dim">{label}</dt>
            <dd className="text-xs tracking-body mt-0.5 break-words">
              {typeof value === 'string' ? (
                <span className="text-content-secondary">{value}</span>
              ) : (
                <Link
                  to={value.to}
                  className="font-mono text-accent-blue no-underline transition-opacity hover:opacity-60"
                >
                  {value.label}
                </Link>
              )}
            </dd>
          </div>
        ))}
      </dl>
      {note && <p className="text-xs text-danger leading-relaxed mt-3">{note}</p>}
    </div>
  )
}

/**
 * What a run without a result is waiting on.
 *
 * Renders nothing for a failed run: the rail already marks the step that gave
 * up and shows its reason, and a second panel saying "this stopped" adds a box
 * without adding a fact. Plain text rather than a card, because one sentence
 * does not need a container of its own.
 */
function Pending({ run }: { run: WorkflowRunDetail }) {
  if (run.status === 'failed') return null

  const message =
    run.status === 'awaiting_alerts'
      ? 'The attack has finished. MayaTrail is collecting alerts from your SIEM, which evaluates on its own schedule, so this can take tens of minutes. You can leave this page.'
      : 'This run is still in progress. You can leave this page and come back.'

  return (
    <p className="text-sm text-content-secondary leading-relaxed tracking-body px-1">
      {message}
    </p>
  )
}

/** The finished result: figures, then per-rule verdicts, then loose alerts. */
function Result({ run }: { run: WorkflowRunDetail }) {
  const score = run.score
  if (!score) return null

  const note = SCORE_STATUS_NOTE[score.status]
  const ordered = VERDICT_ORDER.flatMap((verdict) =>
    score.rules.filter((rule) => rule.verdict === verdict),
  )

  return (
    <div className="flex flex-col gap-4">
      <Card className="p-5">
        <div className="flex flex-wrap gap-6">
          <Figure label="Detection coverage" value={formatCoverage(score.detectionCoverage)} big />
          <Figure label="Caught" value={String(score.counts.fired ?? 0)} />
          <Figure label="Missed" value={String(score.counts.silent ?? 0)} />
          <Figure label="Not exercised" value={String(score.counts.not_integrated ?? 0)} />
          <Figure label="Alerts received" value={String(score.alertsReceived)} />
        </div>
        {note && (
          <p className="text-sm text-warning leading-relaxed tracking-body mt-4 pt-4 border-t border-border">
            {note}
          </p>
        )}
      </Card>

      {ordered.length > 0 && (
        <Card className="p-5">
          <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">
            Expected detections
          </h2>
          <div className="flex flex-col divide-y divide-border">
            {ordered.map((rule) => (
              <RuleRow key={`${rule.ruleId}-${rule.title}`} rule={rule} />
            ))}
          </div>
        </Card>
      )}

      {score.unattributedCount > 0 && <Unattributed score={score} />}
    </div>
  )
}

/** Rows shown before the list collapses behind a control. */
const UNATTRIBUTED_PREVIEW = 5

/**
 * Alerts that arrived in the window but map to no expected detection.
 *
 * A busy SIEM can raise hundreds of these during a thirty minute window, which
 * would bury the verdicts above them, so only a few are shown and the rest are
 * behind a control. The count is always the true total, even when the report
 * stores fewer: a trimmed list must never read as a smaller number.
 */
function Unattributed({ score }: { score: NonNullable<WorkflowRunDetail['score']> }) {
  const [expanded, setExpanded] = useState(false)
  const stored = score.unattributed
  const shown = expanded ? stored : stored.slice(0, UNATTRIBUTED_PREVIEW)
  const hidden = score.unattributedCount - shown.length

  return (
    <Card className="p-5">
      <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-1">
        Other alerts during this run
        <span className="ml-2 text-content-muted">{score.unattributedCount}</span>
      </h2>
      {/* Shown so a reader can judge them, never counted. They may be the
          customer's own coverage of something we did not expect, or noise from
          real activity that happened to overlap the window. */}
      <p className="text-xs text-content-dim leading-relaxed mb-3">
        Your SIEM sent these while the emulation was running, but they do not map to any
        detection this emulation expects. They are not counted in the score.
      </p>

      <div className="flex flex-col divide-y divide-border">
        {shown.map((alert) => (
          <div key={alert.alertId} className="py-2">
            <span className="block text-xs text-content-secondary tracking-body">
              {alert.ruleName || alert.ruleId || 'Unnamed alert'}
            </span>
            <span className="block font-mono text-2xs text-content-muted mt-0.5">
              {alert.technique || 'no technique'}
              {alert.receivedAt ? ` · ${formatWhen(alert.receivedAt)}` : ''}
            </span>
          </div>
        ))}
      </div>

      {stored.length > UNATTRIBUTED_PREVIEW && (
        <button
          type="button"
          onClick={() => setExpanded((open) => !open)}
          className="mt-3 text-xs font-medium tracking-btn text-accent-blue
            transition-opacity hover:opacity-60"
        >
          {expanded ? 'Show fewer' : `Show all ${stored.length}`}
        </button>
      )}

      {/* The report keeps a sample, not the whole flood. Saying so is the
          difference between a trimmed list and a wrong one. */}
      {score.unattributedTruncated && expanded && (
        <p className="text-xs text-content-dim leading-relaxed mt-3">
          {hidden > 0 ? `${hidden} further alerts arrived and are not listed here. ` : ''}
          This run stored a sample rather than every alert. The count above is the true total.
        </p>
      )}
    </Card>
  )
}

/** One expected detection and what the client's SIEM did about it. */
function RuleRow({ rule }: { rule: RuleOutcome }) {
  return (
    <div className="flex items-start gap-3 py-3">
      <span className={`shrink-0 font-mono text-2xs uppercase tracking-caps rounded-btn border
        px-2 py-0.5 ${VERDICT_CLASS[rule.verdict]}`}>
        {VERDICT_LABEL[rule.verdict]}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-sm text-content-primary leading-snug tracking-body">
          {rule.title}
        </span>
        <span className="block font-mono text-2xs text-content-muted mt-1">
          {rule.technique || rule.ruleId}
          {rule.severity ? ` · ${rule.severity}` : ''}
        </span>
        {rule.evidence && <Evidence evidence={rule.evidence} tier={rule.matchTier} />}
      </span>
    </div>
  )
}

/**
 * The alert behind a verdict.
 *
 * Always shown for a caught detection, because this feature grades a client's
 * own detection engineering and a claim about their coverage has to be
 * traceable to the alert that produced it. The tier says how the link was made,
 * so a technique-level match is not mistaken for an exact one.
 */
function Evidence({ evidence, tier }: { evidence: AlertEvidence; tier: string }) {
  const explain =
    tier === 'exact'
      ? 'matched your alert by rule id'
      : tier === 'technique'
        ? 'matched by ATT&CK technique, so a rule of yours covers this'
        : 'matched during the run window'

  return (
    <span className="block mt-2 bg-surface-elevated border border-border rounded-btn px-3 py-2">
      <span className="block text-xs text-content-secondary tracking-body">
        {evidence.ruleName || evidence.ruleId || 'Alert'}
      </span>
      <span className="block font-mono text-2xs text-content-muted mt-0.5">
        {explain}
        {evidence.receivedAt ? ` · ${formatWhen(evidence.receivedAt)}` : ''}
      </span>
    </span>
  )
}

/** One labelled figure. `big` marks the headline number. */
function Figure({ label, value, big = false }: { label: string; value: string; big?: boolean }) {
  return (
    <span className="flex flex-col">
      <span className="font-mono text-2xs uppercase tracking-caps text-content-dim">{label}</span>
      <span className={`font-display font-semibold text-content-primary ${big ? 'text-2xl' : 'text-lg'}`}>
        {value}
      </span>
    </span>
  )
}
