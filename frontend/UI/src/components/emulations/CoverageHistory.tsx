import { useEffect, useState } from 'react'

import { getCoverageTrend, getRunRegressions } from '@/services/coverageHistory.service'
import { useUiMode } from '@/context/UiModeContext'
import type { CoverageTrendPoint, RegressionReport } from '@/types'

/**
 * Plain-English name for a raw verdict string ('fired'/'silent'/'no_logs'),
 * for Simple UI mode. Defined locally rather than shared with
 * DetectionCoveragePage to avoid an import cycle between the two.
 */
const VERDICT_PLAIN: Record<string, string> = {
  fired: 'caught',
  silent: 'missed',
  no_logs: 'no data',
}
const verdictWord = (v: string, plain: boolean): string =>
  plain ? VERDICT_PLAIN[v] ?? v : v

/**
 * The continuous-assurance surface on a run's coverage page.
 *
 * Two things a single run cannot show:
 *  - RegressionBanner: what stopped firing since the last run of this emulation
 *    ("T1496 fired last week and is silent today") - the alert that matters.
 *  - CoverageTrend: fired-share across this emulation's runs over time, so a
 *    slow decay is visible rather than discovered during an incident.
 */

export function RegressionBanner({ runId }: { runId: string }) {
  const { plain } = useUiMode()
  const [report, setReport] = useState<RegressionReport | null>(null)

  useEffect(() => {
    let cancelled = false
    getRunRegressions(runId)
      .then((r) => !cancelled && setReport(r))
      .catch(() => !cancelled && setReport(null))
    return () => {
      cancelled = true
    }
  }, [runId])

  if (!report || !report.hasPrevious) return null

  const { regressions, improvements } = report
  if (regressions.length === 0 && improvements.length === 0) {
    return (
      <div className="mt-5 rounded-card border border-border bg-surface-card px-4 py-3 text-[0.85rem] text-content-secondary">
        {plain
          ? 'Nothing changed since the last time you ran this — every detection held its result.'
          : 'No change since the previous run of this emulation — every rule holds the same verdict.'}
      </div>
    )
  }

  return (
    <div className="mt-5 flex flex-col gap-4">
      {regressions.length > 0 && (
        <div className="rounded-card border border-danger/40 bg-danger/[0.07] p-4">
          <div className="font-mono text-2xs uppercase tracking-label text-danger mb-2">
            {plain ? (
              <>{regressions.length} detection{regressions.length === 1 ? '' : 's'} stopped
                catching {regressions.length === 1 ? 'its' : 'their'} attack</>
            ) : (
              <>{regressions.length} detection{regressions.length === 1 ? '' : 's'} regressed
                since the last run</>
            )}
          </div>
          <div className="text-[0.82rem] text-content-secondary mb-3">
            {plain ? (
              <>{regressions.length === 1 ? 'This detection' : 'These detections'} caught the
                attack before and {regressions.length === 1 ? "doesn't" : "don't"} now. Something
                changed — look into it before it hides a real attack.</>
            ) : (
              <>{regressions.length === 1 ? 'This rule' : 'These rules'} fired before and{' '}
                {regressions.length === 1 ? 'does' : 'do'} not now. Something changed in
                the environment or the rule — investigate before it hides a real attack.</>
            )}
          </div>
          <ul className="flex flex-col gap-1.5">
            {regressions.map((r) => (
              <li key={r.ruleId} className="flex items-baseline gap-2 text-[0.85rem]">
                <span className="font-mono text-2xs text-danger shrink-0">
                  {verdictWord(r.from, plain)} → {verdictWord(r.to, plain)}
                </span>
                <span className="font-mono text-2xs text-content-dim shrink-0">{r.ruleId}</span>
                <span className="text-content-primary">{r.title}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {improvements.length > 0 && (
        <div className="rounded-card border border-safe/40 bg-safe/[0.06] px-4 py-3">
          <div className="font-mono text-2xs uppercase tracking-label text-safe mb-1.5">
            {improvements.length} detection{improvements.length === 1 ? '' : 's'}{' '}
            {plain ? 'now catching their attack' : 'now firing'}
          </div>
          <ul className="flex flex-col gap-1">
            {improvements.map((r) => (
              <li key={r.ruleId} className="text-[0.85rem] text-content-secondary">
                <span className="font-mono text-2xs text-content-dim mr-2">{r.ruleId}</span>
                {r.title}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export function CoverageTrend({ emulationType }: { emulationType: string }) {
  const { plain } = useUiMode()
  const [points, setPoints] = useState<CoverageTrendPoint[] | null>(null)

  useEffect(() => {
    let cancelled = false
    getCoverageTrend(emulationType)
      .then((p) => !cancelled && setPoints(p))
      .catch(() => !cancelled && setPoints([]))
    return () => {
      cancelled = true
    }
  }, [emulationType])

  // A trend needs at least two points to be a trend.
  if (!points || points.length < 2) return null

  // One metric, one line: the share of this emulation's rules that fired, per
  // run. The old stacked bars asked the reader to eyeball three quantities at
  // once with no axis; the question that actually matters - "is my coverage
  // going up or down?" - is a single number over time, so plot that and put the
  // fired/silent/no_logs breakdown in each point's hover instead.
  const pct = (p: CoverageTrendPoint) => Math.round((p.fidelity ?? 0) * 100)
  const first = pct(points[0]!)
  const last = pct(points[points.length - 1]!)
  const delta = last - first

  // SVG geometry. Fixed viewBox, scales to width. y maps 0-100% to the plot band.
  const W = 640
  const H = 180
  const padL = 34   // room for the % axis labels
  const padR = 12
  const padT = 14
  const padB = 26   // room for the date labels
  const plotW = W - padL - padR
  const plotH = H - padT - padB
  const x = (i: number) => padL + (points.length === 1 ? plotW / 2 : (i / (points.length - 1)) * plotW)
  const y = (percent: number) => padT + plotH * (1 - percent / 100)

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${x(i)} ${y(pct(p))}`).join(' ')
  const areaPath =
    `${linePath} L ${x(points.length - 1)} ${padT + plotH} L ${x(0)} ${padT + plotH} Z`

  const fmtDate = (iso: string | null) =>
    iso ? new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : ''

  const trendColor = delta < 0 ? 'var(--danger)' : delta > 0 ? 'var(--safe)' : 'var(--accent-blue)'

  return (
    <div className="mt-5 rounded-card border border-border bg-surface-card p-5">
      {/* Headline: the current number and where it moved, stated plainly. */}
      <div className="flex items-end justify-between gap-4 mb-1">
        <div>
          <div className="text-[0.85rem] font-semibold text-content-primary">
            {plain ? 'Are you catching more over time?' : 'Detection coverage over time'}
          </div>
          <div className="text-[0.78rem] text-content-secondary mt-0.5">
            {plain
              ? 'The share of this attack your defences caught, each time you ran it.'
              : "Share of this emulation’s rules that fired, per run."}
          </div>
        </div>
        <div className="text-right shrink-0">
          <div className="font-mono text-[1.6rem] font-bold leading-none text-content-primary tabular-nums">
            {last}%
          </div>
          <div
            className="font-mono text-2xs mt-1"
            style={{ color: delta === 0 ? 'var(--content-dim)' : trendColor }}
          >
            {delta > 0 ? '▲ +' : delta < 0 ? '▼ ' : ''}{delta === 0 ? 'no change' : `${delta} pts`}
            {' '}since {fmtDate(points[0]!.completedAt)}
          </div>
        </div>
      </div>

      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto mt-2" role="img"
        aria-label={`Coverage from ${first}% to ${last}% over ${points.length} runs`}>
        {/* y gridlines + labels at 0 / 50 / 100% */}
        {[0, 50, 100].map((g) => (
          <g key={g}>
            <line x1={padL} y1={y(g)} x2={W - padR} y2={y(g)} stroke="var(--border-subtle)" strokeWidth="1" />
            <text x={padL - 6} y={y(g) + 3} textAnchor="end" fontSize="10"
              fill="var(--content-dim)" fontFamily="monospace">{g}%</text>
          </g>
        ))}

        <path d={areaPath} fill={trendColor} fillOpacity="0.08" />
        <path d={linePath} fill="none" stroke={trendColor} strokeWidth="2"
          strokeLinejoin="round" strokeLinecap="round" />

        {points.map((p, i) => (
          <g key={p.runId}>
            <circle cx={x(i)} cy={y(pct(p))} r="3.5" fill="var(--surface-card)"
              stroke={trendColor} strokeWidth="2">
              <title>{plain
                ? `${fmtDate(p.completedAt)} — caught ${pct(p)}% (${p.counts.fired} of ${p.ruleCount}); ${p.counts.silent} missed, ${p.counts.no_logs} no data`
                : `${fmtDate(p.completedAt)} — ${pct(p)}% fired (${p.counts.fired} of ${p.ruleCount}); ${p.counts.silent} silent, ${p.counts.no_logs} no logs`}</title>
            </circle>
            {/* date label only on first, last, and endpoints to avoid crowding */}
            {(i === 0 || i === points.length - 1) && (
              <text x={x(i)} y={H - 8} textAnchor={i === 0 ? 'start' : 'end'} fontSize="10"
                fill="var(--content-dim)" fontFamily="monospace">{fmtDate(p.completedAt)}</text>
            )}
          </g>
        ))}
      </svg>

      <div className="font-mono text-2xs text-content-dim mt-1">
        {points.length} runs · hover a point for its {plain ? 'caught / missed / no-data' : 'fired / silent / no-logs'} breakdown
      </div>
    </div>
  )
}
