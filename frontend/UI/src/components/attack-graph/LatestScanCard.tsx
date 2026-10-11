/**
 * Where the newest scan stands, on the Attack Graph overview.
 *
 * The overview's only view of scans: one line on the latest one and a link to
 * it on the Scans page. Counts come from that scan's stored result, fetched
 * under the same cache key the Scans page uses, so opening it costs nothing.
 */

import type { ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { formatWhen } from '@/components/threatfeed/feedMeta'
import { useCachedResource } from '@/hooks/useCachedResource'
import * as attackGraph from '@/services/attackGraph.service'
import type { ScanDetail, ScanSummary } from '@/types/attackGraph'
import { isTooNewToRender } from '@/types/attackGraph'

import { SEVERITY_TEXT, severityOf } from './pathModel'
import type { Severity } from './pathModel'
import { Radar, useElapsed } from './ScanningCard'
import { UNFINISHED, scanUrl, useRunScan } from './useScans'

const FULL_COMPROMISE = 'FULL_ACCOUNT_COMPROMISE'
const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low']

const CARD = 'flex flex-wrap items-center gap-x-5 gap-y-3 rounded-card border border-border bg-surface-card px-6 py-4 shadow-ring'
const EYEBROW = 'font-mono text-2xs uppercase tracking-label text-accent-blue'
const PILL = 'rounded-pill bg-white/80 px-4 py-1.5 text-xs font-semibold text-button-fg no-underline transition-opacity hover:opacity-60'
const SECONDARY = 'rounded-btn border border-border px-3 py-1.5 text-xs text-content-secondary no-underline transition-opacity hover:opacity-60'

export function LatestScanCard({ scans }: { scans: ScanSummary[] | undefined }) {
  const navigate = useNavigate()
  const { runScan, starting, error } = useRunScan((scanId) => navigate(scanUrl(scanId)))
  const latest = scans?.[0]

  if (!scans) return null

  if (!latest) {
    return (
      <div className={CARD}>
        <div className="min-w-0 flex-1">
          <div className={EYEBROW}>Latest scan</div>
          <div className="text-base font-semibold text-content-primary">No scans yet</div>
          <p className="text-xs text-content-dim">The first scan takes one to four minutes and only reads IAM.</p>
          {error && <p className="mt-1 text-xs text-danger">{error}</p>}
        </div>
        <button type="button" onClick={runScan} disabled={starting} className={`${PILL} disabled:cursor-not-allowed disabled:opacity-40`}>
          {starting ? 'Starting…' : 'Run first scan'}
        </button>
      </div>
    )
  }

  if (UNFINISHED.includes(latest.status)) return <RunningLatest scan={latest} />

  if (latest.status === 'failed') {
    return (
      <div className={CARD}>
        <div className="min-w-0 flex-1">
          <div className={EYEBROW}>Latest scan · {formatWhen(latest.created_at)}</div>
          <div className="text-base font-semibold text-content-primary">The last scan did not finish</div>
          <p className="truncate text-xs text-content-dim">{latest.error_message || 'It failed with no further detail.'}</p>
        </div>
        <Link to={scanUrl(latest.id)} className={SECONDARY}>View scan</Link>
      </div>
    )
  }

  return <CompletedLatest scan={latest} />
}

function RunningLatest({ scan }: { scan: ScanSummary }) {
  const elapsed = useElapsed(scan)
  const queued = scan.status === 'pending'
  return (
    <div className={CARD}>
      <Radar size={40} queued={queued} />
      <div className="min-w-0 flex-1">
        <div className={EYEBROW}>Latest scan</div>
        <div className="flex flex-wrap items-baseline gap-x-3">
          <span className="text-base font-semibold text-content-primary">{queued ? 'Waiting for a worker' : 'Scanning your account'}</span>
          <span className="font-mono text-xs text-content-dim">{elapsed} elapsed</span>
        </div>
        <p className="text-xs text-content-dim">Results open on the Scans page when it finishes.</p>
      </div>
      <Link to={scanUrl(scan.id)} className={SECONDARY}>Watch it</Link>
    </div>
  )
}

function CompletedLatest({ scan }: { scan: ScanSummary }) {
  const { data: detail } = useCachedResource<ScanDetail>(
    `attack-graph:scan:${scan.id}`,
    () => attackGraph.getScan(scan.id),
  )
  const envelope = detail?.result && !isTooNewToRender(detail.result) ? detail.result : null
  const when = formatWhen(scan.completed_at ?? scan.created_at)

  let headline = <span>Completed</span>
  let breakdown: ReactNode = null
  if (envelope?.state === 'findings') {
    const chains = envelope.chains
    const compromise = chains.filter((chain) => chain.terminal_impact === FULL_COMPROMISE).length
    const counts = SEVERITIES
      .map((severity) => ({ severity, count: chains.filter((chain) => severityOf(chain.score) === severity).length }))
      .filter(({ count }) => count > 0)
    headline = (
      <span>
        <span className="text-danger">
          {chains.length}{envelope.truncated ? '+' : ''} escalation path{chains.length === 1 ? '' : 's'}
        </span>
        {compromise > 0 ? `, ${compromise} reach full account compromise` : ', none reaches full account compromise'}
      </span>
    )
    breakdown = counts.map(({ severity, count }, i) => (
      <span key={severity}>
        {i > 0 && ' · '}
        <span className={SEVERITY_TEXT[severity]}>{count} {severity.toLowerCase()}</span>
      </span>
    ))
  } else if (envelope?.state === 'clean') {
    headline = <span className="text-safe">No escalation paths found</span>
  } else if (envelope?.state === 'partial') {
    headline = <span className="text-warning">Partial: this scan does not cover your whole account</span>
  }

  return (
    <div className={CARD}>
      <div className="min-w-0 flex-1">
        <div className={EYEBROW}>Latest scan · {when}</div>
        <div className="text-base font-semibold text-content-primary">{headline}</div>
        {breakdown && <p className="text-xs text-content-dim">{breakdown}</p>}
      </div>
      <Link to={scanUrl(scan.id)} className={envelope?.state === 'findings' ? PILL : SECONDARY}>
        {envelope?.state === 'findings' ? 'Review paths' : 'View scan'}
      </Link>
    </div>
  )
}
