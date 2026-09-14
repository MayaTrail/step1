import { useParams } from 'react-router-dom'
import { useWorkflowRun } from '@/hooks/useWorkflows'
import type { AlertEvidence, RuleOutcome, WorkflowRunDetail } from '@/types/workflow'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import {
  SCORE_STATUS_NOTE,
  STATUS_LABEL,
  STATUS_TONE,
  STEPS,
  VERDICT_CLASS,
  VERDICT_LABEL,
  formatCoverage,
  isOpen,
  stepStates,
  untilDeadline,
} from './workflowMeta'

/**
 * One workflow: where it is, and what it found.
 *
 * The page has to be readable while the run is still moving, because a run
 * takes minutes to deploy and attack and then waits tens of minutes for a SIEM
 * that evaluates on its own schedule. So the pipeline rail is always shown and
 * the result appears beneath it when there is one.
 *
 * Ordering of verdicts is deliberate: caught first, then missed, then never
 * exercised. A client reads the good news, then the actionable gap, then the
 * rows that are a setup task rather than a detection failure.
 */

const VERDICT_ORDER = ['fired', 'silent', 'not_integrated'] as const

export function WorkflowRunPage() {
  const { workflowId } = useParams<{ workflowId: string }>()
  // Polling is decided by the previous response, so a finished run stops
  // re-fetching rather than polling a result that can no longer change.
  const { data: run, loading } = useWorkflowRun(workflowId ?? null, true)
  const open = run ? isOpen(run.status) : true

  if (loading && !run) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading workflow…</div>
  }
  if (!run) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Workflow not found.</div>
  }

  return (
    <div className="animate-fadeIn">
      <Breadcrumb items={[{ label: 'Workflows', to: '/workflows' }, { label: run.emulationType }]} />

      <div className="mt-6 mb-6">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
            {run.emulationType}
          </h1>
          <Badge tone={STATUS_TONE[run.status]} mono dot pulse={open}>
            {STATUS_LABEL[run.status]}
          </Badge>
        </div>
        <p className="text-sm text-content-dim mt-1">
          Started {formatWhen(run.createdAt)}
          {run.status === 'awaiting_alerts' && untilDeadline(run.alertDeadline)
            ? ` · ${untilDeadline(run.alertDeadline)}`
            : ''}
        </p>
      </div>

      <PipelineRail run={run} />

      {run.status === 'failed' && run.detail && (
        <Card accent="red" className="p-4 mb-4">
          <p className="text-sm text-content-secondary leading-relaxed">{run.detail}</p>
        </Card>
      )}

      {run.score ? <Result run={run} /> : <Pending run={run} />}
    </div>
  )
}

/** The four steps, with the one in progress marked. */
function PipelineRail({ run }: { run: WorkflowRunDetail }) {
  const states = stepStates(run)

  return (
    <Card className="p-4 mb-4">
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        {STEPS.map((step, index) => {
          const state = states[index] ?? 'pending'
          const tone =
            state === 'done'
              ? 'text-safe'
              : state === 'active'
                ? 'text-accent-blue'
                : state === 'failed'
                  ? 'text-danger'
                  : 'text-content-dim'
          return (
            <div key={step.key} className="flex items-start gap-2">
              <span className={`mt-1 w-2 h-2 rounded-full shrink-0 bg-current ${tone}
                ${state === 'active' ? 'animate-pulse' : ''}`} />
              <span className="min-w-0">
                <span className={`block text-xs font-medium tracking-body ${tone}`}>
                  {step.label}
                </span>
                <span className="block font-mono text-2xs text-content-muted mt-0.5">
                  {state === 'done' ? 'done' : state}
                </span>
              </span>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

/** Shown while a run has no result yet, saying what it is waiting on. */
function Pending({ run }: { run: WorkflowRunDetail }) {
  const message =
    run.status === 'awaiting_alerts'
      ? 'The attack has finished. MayaTrail is collecting alerts from your SIEM, which evaluates on its own schedule, so this can take tens of minutes. You can leave this page.'
      : run.status === 'failed'
        ? 'This run stopped before it could report anything.'
        : 'This run is still in progress. You can leave this page and come back.'

  return (
    <Card className="p-6">
      <p className="text-sm text-content-secondary leading-relaxed tracking-body">{message}</p>
    </Card>
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

      {score.unattributed.length > 0 && (
        <Card className="p-5">
          <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-1">
            Other alerts during this run
          </h2>
          {/* Shown so a reader can judge them, never counted. They may be the
              client's own coverage of something we did not expect, or noise
              from real activity that happened to overlap the window. */}
          <p className="text-xs text-content-dim leading-relaxed mb-3">
            Your SIEM sent these while the emulation was running, but they do not map to any
            detection this emulation expects. They are not counted in the score.
          </p>
          <div className="flex flex-col divide-y divide-border">
            {score.unattributed.map((alert) => (
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
        </Card>
      )}
    </div>
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
