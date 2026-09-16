/**
 * The evidence packet for one run.
 *
 * Everything the run proved, on one page a team can read, print, or export:
 * coverage, every rule's verdict with the evidence behind it, the gaps, the
 * techniques no rule looks for, and what changed since the previous run.
 *
 * Two things it deliberately does:
 *
 *   * It separates "a rule ran and stayed silent" from "no rule exists". The
 *     first is a gap in the customer's detection; the second is a gap in ours,
 *     and the coverage percentage does not count it at all. A report that
 *     blurred them would be the kind of number this product exists to disprove.
 *
 *   * It states its own scope. The percentage is always shown as "n of m rules",
 *     never as a bare score, so nobody reads it as a grade out of everything
 *     that could have been tested.
 */

import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { Card } from '@/components/ui/Card'
import { useUiMode } from '@/context/UiModeContext'
import { getRunReport } from '@/services/report.service'
import type { ReportFinding, RunReport } from '@/types'
import { IconSearch } from '@/components/ui/Icons'
import { SectionHead, Spec, VerdictText, pct, stamp } from './reportHelpers'

export function RunReportPage() {
  const { runId = '' } = useParams()
  const navigate = useNavigate()
  const { plain } = useUiMode()

  const [report, setReport] = useState<RunReport | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setReport(null)
    setError(null)
    getRunReport(runId)
      .then((r) => !cancelled && setReport(r))
      .catch(() => !cancelled && setError('That run could not be loaded. It may have been deleted, or it belongs to another account.'))
    return () => { cancelled = true }
  }, [runId])

  if (error) {
    return (
      <div className="max-w-xl">
        <div className="font-display text-lg font-semibold text-content-primary">Report unavailable</div>
        <p className="text-[0.9rem] text-content-secondary mt-1.5">{error}</p>
        <button
          type="button"
          onClick={() => navigate('/reports')}
          className="mt-4 bg-surface-card border border-border rounded-btn px-3 py-1.5 text-xs text-content-primary"
        >
          Back to reports
        </button>
      </div>
    )
  }

  if (!report) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Building report…</div>
  }

  const { run, coverage, findings, gaps, uncovered, change, trend } = report
  const judged = coverage.checkStatus === 'ok' && coverage.ruleCount > 0

  function downloadJson() {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mayatrail-${run.emulationType}-${run.id.slice(0, 8)}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="report-sheet animate-fadeIn max-w-[62rem]">
      {/* ── Header ── */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between mb-7">
        <div className="min-w-0">
          <div className="font-mono text-2xs uppercase tracking-label text-accent-blue mb-2">
            Evidence report
          </div>
          <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
            {run.displayName}
          </h1>
          <p className="text-[0.9rem] text-content-secondary mt-1.5">
            {judged ? (
              <>
                <span className="text-content-primary font-medium">
                  {coverage.fired} of {coverage.ruleCount} rules fired
                </span>
                {' '}on this run
                {uncovered.length > 0 && (
                  <>, and {uncovered.length} technique{uncovered.length === 1 ? '' : 's'} had no rule to fire</>
                )}.
              </>
            ) : (
              'This run has no detection check, so there are no verdicts to report.'
            )}
          </p>
        </div>

        <div className="flex flex-wrap gap-2 shrink-0 no-print">
          <button
            type="button"
            onClick={() => window.print()}
            className="bg-accent-blue text-button-fg rounded-btn px-3 py-1.5 text-xs font-medium"
          >
            Print / save PDF
          </button>
          <button
            type="button"
            onClick={downloadJson}
            className="bg-surface-card border border-border rounded-btn px-3 py-1.5 text-xs text-content-primary hover:border-accent-blue/40"
          >
            Download JSON
          </button>
        </div>
      </div>

      {/* ── Coverage + provenance ── */}
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_16rem] gap-5">
        <Card className="p-5">
          <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">
            {plain ? 'What your defences caught' : 'Detection coverage'}
          </div>
          {judged ? (
            <>
              <div className="flex items-baseline gap-3 flex-wrap">
                <span className="font-display text-3xl font-bold tabular-nums text-content-primary leading-none">
                  {pct(coverage.fidelity)}
                </span>
                <span className="text-[0.85rem] text-content-secondary">
                  {coverage.fired} fired · {coverage.silent} silent · {coverage.noLogs} no logs
                  <span className="text-content-dim"> — of {coverage.ruleCount} rules evaluated</span>
                </span>
              </div>
              {/* A single proportional bar: the whole width is the rules evaluated. */}
              <div className="flex h-2 mt-4 overflow-hidden rounded-btn border border-border">
                {([['fired', coverage.fired, 'bg-safe'],
                   ['silent', coverage.silent, 'bg-danger'],
                   ['no_logs', coverage.noLogs, 'bg-content-muted']] as const).map(([key, value, cls]) =>
                  value > 0 ? (
                    <div
                      key={key}
                      className={cls}
                      style={{ width: `${(value / coverage.ruleCount) * 100}%` }}
                      title={`${value} ${key}`}
                    />
                  ) : null,
                )}
              </div>
              <p className="text-xs text-content-dim mt-3">
                This share counts only the {coverage.ruleCount} rules this pack ships for {run.displayName}.
                {uncovered.length > 0 && ' Techniques with no rule are excluded from it, and listed below.'}
              </p>
            </>
          ) : (
            <p className="text-[0.9rem] text-content-secondary">
              No detection check completed for this run, so no coverage can be reported. Re-run the
              emulation with logging connected to produce verdicts.
            </p>
          )}
        </Card>

        <Card className="p-5">
          <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-2">
            Provenance
          </div>
          <Spec label="Run">
            <span className="font-mono text-xs">{run.id.slice(0, 8)}</span>
          </Spec>
          <Spec label="Emulation">{run.displayName}</Spec>
          <Spec label="Stack">{run.stackName ?? '—'}</Spec>
          <Spec label="Region">{run.region ?? '—'}</Spec>
          <Spec label="Phases">
            {run.phaseCurrent ?? '—'} / {run.phaseTotal ?? '—'}
          </Spec>
          <Spec label="Completed">{stamp(run.completedAt)}</Spec>
          <Spec label="Operator">{run.operator ?? '—'}</Spec>
          <Spec label="Generated">{stamp(report.generatedAt)}</Spec>
        </Card>
      </div>

      {/* ── What needs acting on ── */}
      <SectionHead
        title={plain ? 'What got through' : 'Gaps'}
        note={`${gaps.length} of ${coverage.ruleCount}`}
      />
      {gaps.length === 0 ? (
        <p className="text-[0.9rem] text-content-secondary">
          Every rule evaluated on this run fired. Nothing in this pack went unseen.
        </p>
      ) : (
        <FindingTable rows={gaps} plain={plain} />
      )}

      {/* ── Our own gap: techniques with no rule at all ── */}
      {uncovered.length > 0 && (
        <>
          <SectionHead title="Techniques with no rule" note={`${uncovered.length}`} />
          <p className="text-[0.85rem] text-content-secondary mb-3 max-w-[70ch]">
            {run.displayName} executes these steps and this detection pack ships nothing that looks
            for them, so they produced no verdict and are not counted in the share above. This is a
            gap in MayaTrail&rsquo;s content, not in your detection stack.
          </p>
          <div className="border border-border rounded-btn overflow-hidden">
            {uncovered.map((t) => (
              <div
                key={t.id}
                className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-2.5 border-b border-border last:border-b-0"
              >
                <span className="font-mono text-xs text-warning font-medium">{t.id}</span>
                <span className="text-[0.85rem] text-content-primary">{t.name}</span>
                {t.phaseName && (
                  <span className="text-xs text-content-dim ml-auto">
                    Phase {t.phase} · {t.phaseName}
                  </span>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {/* ── Change since the previous run ── */}
      <SectionHead
        title={plain ? 'What changed since last time' : 'Change since previous run'}
        note={change.hasPrevious ? stamp(change.previousCompletedAt) : 'first run'}
      />
      {!change.hasPrevious ? (
        <p className="text-[0.9rem] text-content-secondary">
          This is the first completed run of {run.displayName}, so there is nothing to compare it to
          yet. Run it again to start building a trend.
        </p>
      ) : (
        <div className="flex flex-col gap-2">
          {change.regressions.length === 0 && change.improvements.length === 0 && (
            <p className="text-[0.9rem] text-content-secondary">
              No verdict changed since the previous run. {change.unchanged} rule
              {change.unchanged === 1 ? '' : 's'} held steady.
            </p>
          )}
          {change.regressions.map((r) => (
            <div key={r.ruleId} className="flex flex-wrap items-baseline gap-2 text-[0.85rem]">
              <span className="font-mono text-2xs uppercase tracking-label text-danger">Regressed</span>
              <span className="font-mono text-xs text-content-primary">{r.ruleId}</span>
              <span className="text-content-secondary min-w-0">{r.title}</span>
            </div>
          ))}
          {change.improvements.map((r) => (
            <div key={r.ruleId} className="flex flex-wrap items-baseline gap-2 text-[0.85rem]">
              <span className="font-mono text-2xs uppercase tracking-label text-safe">Improved</span>
              <span className="font-mono text-xs text-content-primary">{r.ruleId}</span>
              <span className="text-content-secondary min-w-0">{r.title}</span>
            </div>
          ))}
          {change.previousRunId && (
            <Link
              to={`/reports/compare?a=${change.previousRunId}&b=${run.id}`}
              className="no-print inline-flex items-center gap-1.5 mt-2 font-mono text-2xs uppercase tracking-label text-accent-blue hover:underline"
            >
              <IconSearch size={12} /> Compare the two runs in full
            </Link>
          )}
        </div>
      )}

      {/* ── Coverage history ── */}
      {trend.length > 1 && (
        <>
          <SectionHead title="Coverage over runs" note={`${trend.length} runs`} />
          <div className="border border-border rounded-btn overflow-hidden">
            {trend.map((point) => (
              <div
                key={point.runId}
                className="flex items-center gap-4 px-4 py-2 border-b border-border last:border-b-0"
              >
                <span className="font-mono text-xs text-content-dim w-36 shrink-0">
                  {stamp(point.completedAt)}
                </span>
                <div className="flex-1 h-1.5 bg-surface-deep rounded-btn overflow-hidden min-w-0">
                  <div
                    className="h-full bg-accent-blue"
                    style={{ width: `${(point.fidelity ?? 0) * 100}%` }}
                  />
                </div>
                <span
                  className={`font-mono text-xs tabular-nums w-12 text-right shrink-0 ${
                    point.runId === run.id ? 'text-content-primary font-bold' : 'text-content-secondary'
                  }`}
                >
                  {pct(point.fidelity)}
                </span>
              </div>
            ))}
          </div>
        </>
      )}

      {/* ── Full result table ── */}
      <SectionHead
        title={plain ? 'Every check we ran' : 'All findings'}
        note={`${findings.length} rules`}
      />
      <FindingTable rows={findings} plain={plain} />

      <p className="text-xs text-content-dim mt-8 pt-3 border-t border-border">
        Generated by MayaTrail from run {run.id} on {stamp(report.generatedAt)}. Every figure is read
        from what the run recorded; nothing here is estimated.
      </p>
    </div>
  )
}

/** The findings table — verdict first, because that is what is being read for. */
function FindingTable({ rows, plain }: { rows: ReportFinding[]; plain: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-[0.85rem]">
        <thead>
          <tr>
            {['Verdict', 'Technique', 'Rule', 'Severity', 'Evidence'].map((h, i) => (
              <th
                key={h}
                className={`font-mono text-2xs uppercase tracking-label text-content-dim font-medium
                  text-left pb-2 pr-3 border-b border-border ${i === 4 ? 'text-right pr-0' : ''}`}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((f) => (
            <tr key={f.ruleId} className="align-baseline">
              <td className="py-2 pr-3 border-b border-border whitespace-nowrap">
                <VerdictText verdict={f.verdict} plain={plain} />
              </td>
              <td className="py-2 pr-3 border-b border-border whitespace-nowrap">
                <span className="font-mono text-xs text-content-primary">{f.technique.id ?? '—'}</span>
                {f.technique.tactic && (
                  <span className="block text-2xs text-content-dim">{f.technique.tactic}</span>
                )}
              </td>
              <td className="py-2 pr-3 border-b border-border text-content-secondary">
                {f.title}
              </td>
              <td className="py-2 pr-3 border-b border-border whitespace-nowrap text-content-dim">
                {f.severity ?? '—'}
              </td>
              <td className="py-2 border-b border-border text-right whitespace-nowrap text-content-dim font-mono text-xs">
                {f.verdict === 'no_logs'
                  ? 'no logs'
                  : `${f.matchCount ?? 0} match${f.matchCount === 1 ? '' : 'es'}`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
