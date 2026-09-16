/**
 * Two runs, side by side.
 *
 * The regression banner answers "what broke since last time". This answers the
 * question a team asks straight after acting on it: "I wrote the rule / fixed
 * the trail — did it actually work?"
 *
 * So every rule is on the table, not only the ones that moved. A page that
 * showed only the changes would leave you unable to tell "nothing regressed"
 * apart from "nothing was evaluated".
 */

import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { Card } from '@/components/ui/Card'
import { useUiMode } from '@/context/UiModeContext'
import { compareRuns } from '@/services/report.service'
import type { RunComparison, VerdictChangeKind } from '@/types'
import {
  SectionHead, VerdictText, changeClass, changeLabel, deltaPoints, pct, stamp,
} from './reportHelpers'

/** Changes worth leading with, in the order a reader cares about them. */
const NOTABLE: VerdictChangeKind[] = ['regressed', 'improved', 'changed', 'added', 'removed']

export function RunComparePage() {
  const [params] = useSearchParams()
  const a = params.get('a') ?? ''
  const b = params.get('b') ?? ''
  const { plain } = useUiMode()

  const [data, setData] = useState<RunComparison | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showAll, setShowAll] = useState(false)

  useEffect(() => {
    let cancelled = false
    setData(null)
    setError(null)
    if (!a || !b) {
      setError('Pick two runs to compare from the Reports list.')
      return
    }
    compareRuns(a, b)
      .then((d) => !cancelled && setData(d))
      .catch((err) => {
        if (cancelled) return
        const detail = err?.response?.data?.detail
        setError(detail || 'Those runs could not be compared.')
      })
    return () => { cancelled = true }
  }, [a, b])

  if (error) {
    return (
      <div className="max-w-xl">
        <h1 className="font-display text-lg font-semibold text-content-primary">
          Nothing to compare
        </h1>
        <p className="text-[0.9rem] text-content-secondary mt-1.5">{error}</p>
        <Link
          to="/reports"
          className="inline-block mt-4 bg-surface-card border border-border rounded-btn px-3 py-1.5 text-xs text-content-primary no-underline"
        >
          Back to reports
        </Link>
      </div>
    )
  }

  if (!data) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Comparing…</div>
  }

  const notable = data.rows.filter((r) => NOTABLE.includes(r.change))
  const rows = showAll ? data.rows : notable
  const regressed = data.summary.regressed ?? 0
  const improved = data.summary.improved ?? 0

  /** One sentence that says what happened, before any table. */
  const headline = (() => {
    if (regressed && improved) {
      return `${improved} detection${improved === 1 ? '' : 's'} recovered, but ${regressed} regressed.`
    }
    if (regressed) {
      return `${regressed} detection${regressed === 1 ? ' that used to fire has' : 's that used to fire have'} gone quiet.`
    }
    if (improved) {
      return `${improved} detection${improved === 1 ? '' : 's'} started firing that did not before.`
    }
    if (notable.length) return 'The rule set moved, but no detection was gained or lost.'
    return 'Nothing changed between these two runs.'
  })()

  return (
    <div className="animate-fadeIn max-w-[62rem]">
      <div className="mb-6">
        <div className="font-mono text-2xs uppercase tracking-label text-accent-blue mb-2">
          Run comparison
        </div>
        <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
          {headline}
        </h1>
        {!data.sameEmulation && (
          <p className="text-[0.85rem] text-warning mt-2">
            These runs are of different emulations, so most rules will show as added or removed
            rather than changed.
          </p>
        )}
      </div>

      {/* Both runs' own figures, side by side. */}
      <div className="grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] gap-4 items-center mb-2">
        <RunColumn label="Baseline" point={data.a} />
        <div className="text-center">
          <div
            className={`font-display text-xl font-bold tabular-nums ${
              (data.fidelityDelta ?? 0) < 0
                ? 'text-danger'
                : (data.fidelityDelta ?? 0) > 0
                  ? 'text-safe'
                  : 'text-content-dim'
            }`}
          >
            {deltaPoints(data.fidelityDelta)}
          </div>
          <div className="font-mono text-2xs uppercase tracking-label text-content-dim mt-0.5">
            change
          </div>
        </div>
        <RunColumn label="Compared" point={data.b} />
      </div>

      <SectionHead
        title={plain ? 'What moved' : 'Verdict changes'}
        note={`${notable.length} of ${data.rows.length} rules`}
      />

      {data.rows.length === 0 ? (
        <p className="text-[0.9rem] text-content-secondary">
          Neither run recorded a detection check, so there are no verdicts to line up.
        </p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[0.85rem]">
              <thead>
                <tr>
                  {['Change', 'Rule', 'Baseline', 'Compared'].map((h, i) => (
                    <th
                      key={h}
                      className={`font-mono text-2xs uppercase tracking-label text-content-dim font-medium
                        text-left pb-2 pr-3 border-b border-border ${i >= 2 ? 'w-24' : ''}`}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.ruleId} className="align-baseline">
                    <td className="py-2 pr-3 border-b border-border whitespace-nowrap">
                      <span
                        className={`font-mono text-2xs uppercase tracking-label ${changeClass(row.change)}`}
                      >
                        {changeLabel(row.change)}
                      </span>
                    </td>
                    <td className="py-2 pr-3 border-b border-border">
                      <span className="font-mono text-xs text-content-primary">{row.ruleId}</span>
                      <span className="block text-2xs text-content-dim">{row.title}</span>
                    </td>
                    <td className="py-2 pr-3 border-b border-border">
                      <VerdictText verdict={row.a} plain={plain} />
                    </td>
                    <td className="py-2 border-b border-border">
                      <VerdictText verdict={row.b} plain={plain} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {notable.length < data.rows.length && (
            <button
              type="button"
              onClick={() => setShowAll((v) => !v)}
              className="mt-3 font-mono text-2xs uppercase tracking-label text-accent-blue hover:underline"
            >
              {showAll
                ? 'Show only what moved'
                : `Show all ${data.rows.length} rules (${data.summary.unchanged} unchanged)`}
            </button>
          )}
        </>
      )}

      <div className="flex flex-wrap gap-3 mt-8">
        {data.a && (
          <Link
            to={`/reports/${data.a.runId}`}
            className="border border-border rounded-btn px-3 py-1.5 text-xs text-content-primary no-underline hover:border-accent-blue/40"
          >
            Baseline report
          </Link>
        )}
        {data.b && (
          <Link
            to={`/reports/${data.b.runId}`}
            className="border border-border rounded-btn px-3 py-1.5 text-xs text-content-primary no-underline hover:border-accent-blue/40"
          >
            Compared report
          </Link>
        )}
      </div>
    </div>
  )
}

/** One run's own figures — the numbers being compared, not a summary of them. */
function RunColumn({
  label,
  point,
}: {
  label: string
  point: RunComparison['a']
}) {
  return (
    <Card className="p-4">
      <div className="font-mono text-2xs uppercase tracking-label text-content-dim">{label}</div>
      {point ? (
        <>
          <div className="font-display text-2xl font-bold tabular-nums text-content-primary leading-none mt-1.5">
            {pct(point.fidelity)}
          </div>
          <div className="text-xs text-content-secondary mt-1.5">
            {point.counts.fired} fired · {point.counts.silent} silent · {point.counts.no_logs} no logs
          </div>
          <div className="text-2xs text-content-dim mt-1 font-mono">
            {point.runId.slice(0, 8)} · {stamp(point.completedAt)}
          </div>
        </>
      ) : (
        <div className="text-[0.85rem] text-content-dim mt-2">Not judged</div>
      )}
    </Card>
  )
}
