import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { Card } from '@/components/ui/Card'
import { getAssuranceSummary } from '@/services/coverageHistory.service'
import type { AssuranceSummary } from '@/types'

/**
 * Command Center — the "New" dashboard lead.
 *
 * Written for a non-technical reader first. The headline is a plain English
 * sentence, not a metric name; the coverage gauge is a shape you read in a
 * glance; and the body is a single prioritised "needs your attention" feed
 * where every row is a sentence plus one action. The MITRE heatmaps and KPI
 * grid still exist - they move below this, under "Technical detail", for the
 * engineers. This answers "is my security holding, and what do I do?" before it
 * shows a single acronym.
 */

/** Plain-English band for a coverage percentage. */
function postureWord(pct: number): { word: string; tone: string; ring: string } {
  if (pct >= 0.85) return { word: 'Strong', tone: 'text-safe', ring: 'var(--safe)' }
  if (pct >= 0.6) return { word: 'Holding', tone: 'text-safe', ring: 'var(--safe)' }
  if (pct >= 0.4) return { word: 'Patchy', tone: 'text-warning', ring: 'var(--warning)' }
  return { word: 'Weak', tone: 'text-danger', ring: 'var(--danger)' }
}

/** A semicircular gauge — a shape anyone reads without a legend. */
function CoverageGauge({ pct, ring }: { pct: number; ring: string }) {
  const size = 140
  const stroke = 12
  const r = (size - stroke) / 2
  const cx = size / 2
  const cy = size / 2
  // Semicircle from left (180°) to right (0°); sweep the top half.
  const semi = Math.PI * r
  const dash = semi * pct
  const arc = (frac: number) => {
    const a = Math.PI - Math.PI * frac
    return [cx + r * Math.cos(a), cy - r * Math.sin(a)]
  }
  const [sx, sy] = arc(0)
  const [ex, ey] = arc(1)
  return (
    <svg width={size} height={size / 2 + 8} viewBox={`0 0 ${size} ${size / 2 + 8}`} aria-hidden="true">
      <path d={`M ${sx} ${sy} A ${r} ${r} 0 0 1 ${ex} ${ey}`}
        fill="none" stroke="var(--surface-elevated)" strokeWidth={stroke} strokeLinecap="round" />
      <path d={`M ${sx} ${sy} A ${r} ${r} 0 0 1 ${ex} ${ey}`}
        fill="none" stroke={ring} strokeWidth={stroke} strokeLinecap="round"
        strokeDasharray={`${dash} ${semi}`} style={{ transition: 'stroke-dasharray 0.6s ease' }} />
    </svg>
  )
}

/** One row in the attention feed: severity dot, a sentence, an action. */
function AttentionRow({
  tone,
  children,
  to,
  action,
}: {
  tone: 'danger' | 'warning' | 'info'
  children: React.ReactNode
  to: string
  action: string
}) {
  const dot = tone === 'danger' ? 'bg-danger' : tone === 'warning' ? 'bg-warning' : 'bg-accent-blue'
  return (
    <div className="flex items-center gap-3 px-4 py-3 border-b border-border last:border-b-0">
      <span className={`w-2 h-2 rounded-full shrink-0 ${dot}`} />
      <span className="text-[0.9rem] text-content-secondary min-w-0 flex-1">{children}</span>
      <Link
        to={to}
        className="shrink-0 font-mono text-2xs uppercase tracking-label text-accent-blue hover:underline no-underline"
      >
        {action} →
      </Link>
    </div>
  )
}

export function CommandCenter() {
  const [data, setData] = useState<AssuranceSummary | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    getAssuranceSummary()
      .then((d) => !cancelled && setData(d))
      .catch(() => !cancelled && setFailed(true))
    return () => {
      cancelled = true
    }
  }, [])

  if (failed) return null
  if (!data) {
    return <Card className="px-5 py-12 text-center text-sm text-content-dim">Loading your security posture…</Card>
  }

  // First run: a path, not a wall of zeros.
  if (!data.hasRuns) {
    return (
      <Card className="p-8">
        <div className="font-display text-lg font-semibold text-content-primary">
          Let&rsquo;s find your blind spots
        </div>
        <p className="text-[0.9rem] text-content-secondary mt-1.5 max-w-xl">
          MayaTrail safely runs real attack techniques in your own AWS account and
          tells you which your defences caught and which they missed. You haven&rsquo;t
          run one yet — here&rsquo;s the path:
        </p>
        <ol className="mt-4 flex flex-col gap-2 text-[0.9rem] text-content-secondary">
          <li><span className="font-mono text-accent-blue mr-2">1</span> Pick an attack to simulate</li>
          <li><span className="font-mono text-accent-blue mr-2">2</span> Run it — it cleans up after itself</li>
          <li><span className="font-mono text-accent-blue mr-2">3</span> Read which detections fired, and fix the gaps</li>
        </ol>
        <Link
          to="/emulations"
          className="inline-block mt-5 bg-accent-blue text-button-fg rounded-btn px-4 py-2 text-[0.85rem] font-medium no-underline"
        >
          Run your first simulation
        </Link>
      </Card>
    )
  }

  const { coverage, regressions, improvements, failedRunCount, schedules } = data
  const pct = coverage.pct ?? 0
  const posture = postureWord(pct)
  const next = schedules[0]

  // Assemble the attention feed, most urgent first.
  const items: React.ReactNode[] = []
  regressions.slice(0, 3).forEach((r) =>
    items.push(
      <AttentionRow key={`reg-${r.emulationType}-${r.ruleId}`} tone="danger"
        to={`/aws/emulations/${r.emulationType}/logging/${r.runId}`} action="Look">
        A detection that was working has <span className="text-danger font-medium">stopped</span>:{' '}
        <span className="text-content-primary">{r.title}</span>
      </AttentionRow>,
    ),
  )
  if (regressions.length > 3) {
    items.push(
      <AttentionRow key="reg-more" tone="danger" to="/results" action="See all">
        <span className="text-content-primary">{regressions.length - 3} more</span> detections have
        stopped firing since their last test
      </AttentionRow>,
    )
  }
  if (coverage.missed > 0) {
    items.push(
      <AttentionRow key="missed" tone="warning" to="/results" action="See gaps">
        <span className="text-content-primary">{coverage.missed} attack step
        {coverage.missed === 1 ? '' : 's'}</span> went undetected in your latest tests
      </AttentionRow>,
    )
  }
  if (failedRunCount > 0) {
    items.push(
      <AttentionRow key="failed" tone="warning" to="/results" action="Review">
        <span className="text-content-primary">{failedRunCount} simulation
        {failedRunCount === 1 ? '' : 's'}</span> failed to finish — those left blind spots
      </AttentionRow>,
    )
  }
  if (data.scheduleCount === 0) {
    items.push(
      <AttentionRow key="noschedule" tone="info" to="/emulations" action="Set up">
        Nothing is scheduled — turn on automatic re-tests to catch regressions on their own
      </AttentionRow>,
    )
  }

  return (
    <div className="flex flex-col gap-4 animate-fadeIn">
      {/* Hero: a sentence + a gauge, readable by anyone. */}
      <Card className="p-6">
        <div className="flex flex-col sm:flex-row sm:items-center gap-6">
          <div className="shrink-0 flex flex-col items-center">
            <CoverageGauge pct={pct} ring={posture.ring} />
            <div className={`-mt-6 font-display text-3xl font-bold tabular-nums ${posture.tone}`}>
              {coverage.total ? `${Math.round(pct * 100)}%` : '—'}
            </div>
          </div>
          <div className="min-w-0">
            <div className={`font-mono text-2xs uppercase tracking-label ${posture.tone}`}>
              Posture: {posture.word}
            </div>
            <h2 className="font-display text-xl font-semibold text-content-primary leading-snug mt-1">
              Your defences caught {coverage.total ? Math.round(pct * 100) : 0}% of the attacks we
              simulated
            </h2>
            <p className="text-[0.9rem] text-content-secondary mt-1.5">
              {coverage.fired} of {coverage.total} checks fired across your latest test of{' '}
              {coverage.emulationsScored} attack{coverage.emulationsScored === 1 ? '' : 's'}.
              {improvements > 0 && (
                <span className="text-safe"> {improvements} improved since last time.</span>
              )}
              {regressions.length > 0 && (
                <span className="text-danger"> {regressions.length} got worse.</span>
              )}
            </p>
          </div>
        </div>
      </Card>

      {/* Needs your attention — the point of the page. */}
      <Card className="overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-surface-deep font-mono text-2xs uppercase tracking-label text-content-dim">
          Needs your attention
        </div>
        {items.length === 0 ? (
          <div className="flex items-center gap-3 px-4 py-5">
            <span className="w-2.5 h-2.5 rounded-full bg-safe shrink-0" />
            <span className="text-[0.9rem] text-content-secondary">
              Everything&rsquo;s holding. Every detection that fired before still fires, nothing
              failed, and re-tests are scheduled. Nothing needs you right now.
            </span>
          </div>
        ) : (
          items
        )}
      </Card>

      {/* Next scheduled — quiet reassurance the loop keeps running. */}
      {next && (
        <div className="font-mono text-2xs text-content-dim px-1">
          Next automatic re-test: <span className="text-content-secondary">{next.emulationType}</span>
          {next.nextRunAt ? ` on ${new Date(next.nextRunAt).toLocaleDateString()}` : ''} ·{' '}
          <Link to="/schedules" className="text-accent-blue hover:underline">manage</Link>
        </div>
      )}
    </div>
  )
}
