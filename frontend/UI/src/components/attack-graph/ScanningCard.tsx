/**
 * The live state of a scan that has not finished.
 *
 * A compact card with a radar sweep, the same animation the workflow pipeline
 * uses while an attack runs. No progress bar: the Scout service reports only
 * queued, running or done, so the card says what a scan does rather than
 * pretending to know how far along it is.
 */

import { useEffect, useState } from 'react'
import type { CSSProperties } from 'react'

import type { ScanDetail, ScanSummary } from '@/types/attackGraph'

const STILL = 'motion-reduce:animate-none'

/** SVG groups rotate around their own centre, not the corner of the drawing. */
const PIVOT: CSSProperties = { transformBox: 'view-box', transformOrigin: '36px 36px' }

/** "m:ss" since the scan was queued (or started), ticking every second. */
export function useElapsed(scan: ScanSummary): string {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [])

  const since = scan.status === 'pending' ? scan.created_at : scan.started_at ?? scan.created_at
  const seconds = Math.max(0, Math.floor((now - new Date(since).getTime()) / 1000))
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`
}

/** The radar drawing; it sweeps only once the scan is running. */
export function Radar({ size, queued }: { size: number; queued: boolean }) {
  return (
    <svg width={size} height={size} viewBox="0 0 72 72" fill="none" aria-hidden className="shrink-0 text-accent-blue">
      <circle cx="36" cy="36" r="34" stroke="currentColor" strokeOpacity="0.3" />
      <circle cx="36" cy="36" r="22" stroke="currentColor" strokeOpacity="0.15" />
      <circle cx="36" cy="36" r="10" stroke="currentColor" strokeOpacity="0.15" />
      {!queued && (
        <>
          <g className={`animate-radarSweep ${STILL}`} style={PIVOT}>
            <line x1="36" y1="36" x2="36" y2="3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </g>
          <circle cx="50" cy="20" r="2.4" fill="currentColor" className={`animate-radarBlip ${STILL}`} />
          <circle cx="20" cy="46" r="2.4" fill="currentColor" className={`animate-radarBlip ${STILL}`} style={{ animationDelay: '0.7s' }} />
          <circle cx="52" cy="50" r="2.4" fill="currentColor" className={`animate-radarBlip ${STILL}`} style={{ animationDelay: '1.1s' }} />
        </>
      )}
    </svg>
  )
}

export function ScanningCard({ scan, regions }: { scan: ScanDetail; regions: string[] }) {
  const elapsed = useElapsed(scan)
  const queued = scan.status === 'pending'

  return (
    <div className="flex items-center gap-6 rounded-card border border-border bg-surface-card px-6 py-5 shadow-ring">
      <Radar size={72} queued={queued} />

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-3">
          <span className="text-base font-semibold text-content-primary">
            {queued ? 'Waiting for a worker' : 'Scanning your account'}
          </span>
          <span className="font-mono text-xs text-content-dim">{elapsed} elapsed</span>
        </div>
        <p className="mt-0.5 text-xs text-content-dim">
          {queued
            ? 'The worker runs a few tasks at a time alongside emulation deploys, so a scan can wait briefly before it starts.'
            : 'Usually one to four minutes. You can leave this page; the result will be in Past scans.'}
        </p>
        <ul className="mt-2.5 flex flex-wrap gap-x-5 gap-y-1 text-xs text-content-dim">
          <ScanTask text="Reading IAM users, roles and policies" />
          <ScanTask text={regions.length > 0 ? `Reading resources in ${regions.join(', ')}` : 'IAM only, no regions read'} />
          <ScanTask text="Ranking escalation paths" />
        </ul>
      </div>
    </div>
  )
}

function ScanTask({ text }: { text: string }) {
  return (
    <li className="flex items-center gap-1.5">
      <span aria-hidden className="h-1 w-1 rounded-full bg-content-dim" />
      {text}
    </li>
  )
}
