import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import type { ReportRule, WorkflowReport } from '@/types'
import { getWorkflowReport } from '@/services/workflow.service'
import { VERDICT_CLASS, VERDICT_LABEL } from '@/components/workflows/workflowMeta'
import { formatWhen } from '@/components/threatfeed/feedMeta'

/**
 * The evidence packet for one run, as a page a client can hand to an auditor.
 *
 * Printable rather than exportable to PDF server-side: a `@media print` block
 * drops the app chrome, so the browser's own Save as PDF produces the artifact
 * and there is no second renderer to keep in step with this one.
 *
 * Every figure here is phrased by the backend. `coverageSentence` is rendered
 * verbatim rather than recomposed from the counts, because the wording is the
 * product argument: "4 of 5 rules evaluated" and what the figure excludes,
 * never a bare percentage that invites a reader to over-read it.
 */

export function RunReportPage() {
  const { runId } = useParams<{ runId: string }>()
  const [report, setReport] = useState<WorkflowReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!runId) return
    let live = true
    setLoading(true)
    getWorkflowReport(runId)
      .then((data) => live && (setReport(data), setError(null)))
      .catch(() => live && setError('Could not load this report.'))
      .finally(() => live && setLoading(false))
    return () => {
      live = false
    }
  }, [runId])

  if (loading) {
    return <div className="py-16 text-center font-mono text-sm text-content-dim">Loading report…</div>
  }
  if (error || !report) {
    return (
      <div className="py-16 text-center">
        <p className="text-sm text-content-secondary">{error ?? 'Report not found.'}</p>
        <Link to="/reports" className="text-xs text-accent-blue no-underline mt-2 inline-block">
          Back to reports
        </Link>
      </div>
    )
  }

  const { run, score, rules, uncovered, unattributed } = report

  return (
    <div className="animate-fadeIn max-w-[64rem] print:max-w-none">
      <style>{`
        @media print {
          aside, nav, header, .no-print { display: none !important; }
          body { background: #fff !important; }
          main, main > div { overflow: visible !important; height: auto !important; }
        }
      `}</style>

      <div className="no-print mb-5 flex items-center gap-2">
        <Link to="/reports" className="font-mono text-2xs uppercase tracking-label
          text-content-dim no-underline transition-opacity hover:opacity-60">
          &larr; Reports
        </Link>
        <span className="flex-1" />
        <button
          type="button"
          onClick={() => window.print()}
          className="px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border border-border
            text-content-primary shadow-button transition-opacity hover:opacity-60"
        >
          Print or save as PDF
        </button>
      </div>

      <div className="mb-6">
        <div className="font-mono text-2xs uppercase tracking-label text-accent-blue mb-2">
          Detection validation report
        </div>
        <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
          {run.displayName}
        </h1>
        <p className="font-mono text-2xs text-content-muted mt-1.5">
          {run.stackName ?? run.emulationType} &middot; {formatWhen(run.completedAt ?? run.createdAt ?? '')}
          {' '}&middot; {run.owner}
        </p>
      </div>

      {/* The figure, in the words the backend chose. */}
      <div className="border border-border rounded-card bg-surface-card p-5 mb-6">
        <p className="text-sm text-content-primary leading-relaxed">{report.coverageSentence}</p>
        <div className="flex flex-wrap gap-x-8 gap-y-3 mt-4">
          <Figure label="Reported" value={String(score.counts.fired ?? 0)} tone="text-safe" />
          <Figure label="Silent" value={String(score.counts.silent ?? 0)} tone="text-warning" />
          <Figure
            label="Not exercised"
            value={String(score.counts.not_integrated ?? 0)}
            tone="text-content-dim"
          />
          <Figure label="Rules evaluated" value={String(score.ruleCount)} />
          <Figure label="Alerts received" value={String(score.alertsReceived)} />
        </div>
      </div>

      <Section title="Per-rule verdicts">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[720px]">
            <thead>
              <tr className="font-mono text-2xs uppercase tracking-caps text-content-dim">
                <th className="font-normal pb-2 pr-3">Verdict</th>
                <th className="font-normal pb-2 pr-3">Rule</th>
                <th className="font-normal pb-2 pr-3">Technique</th>
                <th className="font-normal pb-2">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => <RuleRow key={rule.ruleId} rule={rule} />)}
            </tbody>
          </table>
        </div>
      </Section>

      {uncovered.length > 0 && (
        <Section title="Techniques no rule watches">
          {/* Separated from silent rules on purpose. A silent rule is the
              client's detection gap; this is a gap in MayaTrail's content, and
              the report says so in as many words. */}
          <p className="text-xs text-content-secondary leading-relaxed mb-3">
            This emulation executes the techniques below, and MayaTrail ships no detection rule
            for them. They are excluded from the coverage figure above.
            <strong className="text-content-primary"> This is a gap in MayaTrail&apos;s content,
            not in your detection stack.</strong>
          </p>
          <div className="flex flex-col gap-1.5">
            {uncovered.map((t) => (
              <div key={t.id} className="flex items-baseline gap-3">
                <span className="font-mono text-2xs text-warning w-20 shrink-0">{t.id}</span>
                <span className="text-xs text-content-secondary flex-1">{t.name}</span>
                <span className="font-mono text-2xs text-content-muted">
                  phase {t.phase} &middot; {t.phaseName}
                </span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {unattributed.count > 0 && (
        <Section title="Other alerts during this run">
          <p className="text-xs text-content-dim leading-relaxed mb-2">
            {unattributed.count} alert{unattributed.count === 1 ? '' : 's'} arrived in the window
            without matching an expected detection
            {unattributed.truncated ? ', and more arrived than are listed here' : ''}.
          </p>
          <div className="flex flex-col gap-1">
            {unattributed.alerts.map((a) => (
              <span key={a.alertId} className="font-mono text-2xs text-content-muted">
                {a.ruleId || '(no rule id)'} &middot; {a.ruleName || '(no name)'}
              </span>
            ))}
          </div>
        </Section>
      )}
    </div>
  )
}

/** One figure, label under value. */
function Figure({ label, value, tone = 'text-content-primary' }: {
  label: string
  value: string
  tone?: string
}) {
  return (
    <div>
      <div className={`font-display text-xl font-semibold ${tone}`}>{value}</div>
      <div className="font-mono text-2xs uppercase tracking-caps text-content-muted mt-0.5">
        {label}
      </div>
    </div>
  )
}

/** A titled block. */
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-7">
      <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">{title}</h2>
      {children}
    </section>
  )
}

/** One rule, with the alert behind its verdict. */
function RuleRow({ rule }: { rule: ReportRule }) {
  return (
    <tr className="border-t border-border align-top">
      <td className="py-3 pr-3 whitespace-nowrap">
        <span className={`inline-block px-1.5 rounded border font-mono text-2xs uppercase
          tracking-caps ${VERDICT_CLASS[rule.verdict]}`}>
          {VERDICT_LABEL[rule.verdict]}
        </span>
      </td>
      <td className="py-3 pr-3">
        <span className="block text-xs text-content-primary leading-snug">{rule.title}</span>
        <span className="block font-mono text-2xs text-content-muted mt-0.5">{rule.ruleId}</span>
      </td>
      <td className="py-3 pr-3 font-mono text-2xs text-content-secondary whitespace-nowrap">
        {rule.technique || '—'}
      </td>
      <td className="py-3">
        {rule.evidence ? (
          <>
            <span className="block text-xs text-content-secondary leading-snug">
              {rule.evidence.ruleName || rule.evidence.ruleId}
            </span>
            <span className="block font-mono text-2xs text-content-muted mt-0.5">
              {formatWhen(rule.evidence.firedAt ?? rule.evidence.receivedAt ?? '')}
              {rule.matchTier ? ` · matched on ${rule.matchTier}` : ''}
            </span>
          </>
        ) : (
          <span className="font-mono text-2xs text-content-muted">no alert received</span>
        )}
      </td>
    </tr>
  )
}
