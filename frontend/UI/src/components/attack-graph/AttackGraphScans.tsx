/**
 * The Attack Graph Scans page: run a scan, watch it, read its paths.
 *
 * The scan on screen is in the address (/attack-graph/scans/:scanId), so a
 * reload, the back button and a shared link all land on the same scan. With
 * no id in the address the newest scan is shown. What the feature is and how
 * to connect it live on the overview, not here.
 */

import { useCallback, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { useScoutConnection } from '@/components/common/ConnectGate'
import { IconHistory } from '@/components/ui/Icons'
import { useAuth } from '@/context/AuthContext'
import { useCachedResource } from '@/hooks/useCachedResource'
import * as attackGraph from '@/services/attackGraph.service'
import type { ScanDetail } from '@/types/attackGraph'
import { isTooNewToRender } from '@/types/attackGraph'

import { PastScansDrawer } from './PastScansDrawer'
import { ScanningCard } from './ScanningCard'
import { ScanResult } from './ScanResult'
import { UNFINISHED, scanUrl, useRunScan, useScanList } from './useScans'

// A scan takes minutes, so a few seconds of latency on completion costs nothing.
const POLL_MS = 3000

const STATE_CARD = 'rounded-card border border-border bg-surface-card px-7 py-6 shadow-ring'

export function AttackGraphScans() {
  const { connected } = useScoutConnection()
  const { user } = useAuth()
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [removedIds, setRemovedIds] = useState<string[]>([])
  const [drawerOpen, setDrawerOpen] = useState(false)

  const openScan = useCallback((id: string) => navigate(scanUrl(id)), [navigate])
  const { runScan, starting, error } = useRunScan(openScan)

  const fetchedScans = useScanList(connected)
  // Scans deleted here are hidden at once, not on the list's next poll.
  const scans = fetchedScans?.filter((scan) => !removedIds.includes(scan.id)) ?? []

  const viewingId = scanId ?? scans[0]?.id ?? null
  // Poll the open scan only while it is unfinished, read from the cheaper list.
  // A scan just started may not be in the list yet; poll it straight away.
  const viewing = scans.find((scan) => scan.id === viewingId)
  const live = viewingId !== null && (!viewing || UNFINISHED.includes(viewing.status))

  const { data: current, failed } = useCachedResource<ScanDetail>(
    viewingId ? `attack-graph:scan:${viewingId}` : null,
    () => attackGraph.getScan(viewingId as string),
    { pollMs: live ? POLL_MS : undefined },
  )

  const onDeleted = useCallback((id: string) => {
    setRemovedIds((ids) => [...ids, id])
    if (id === scanId) navigate(scanUrl(), { replace: true })
  }, [scanId, navigate])

  const closeDrawer = useCallback(() => setDrawerOpen(false), [])

  const shown = current && current.id === viewingId ? current : undefined
  const regions = user?.auditRegions ?? []

  let body
  if (!connected) {
    body = (
      <div className={STATE_CARD}>
        <div className="mb-1.5 font-mono text-2xs uppercase tracking-label text-content-dim">Not connected</div>
        <div className="text-lg font-semibold text-content-primary">Connect the Scout role to scan</div>
        <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">
          Scans read your account through a read-only role. Connect it on the Attack Graph overview, then come back here.
        </p>
        <Link to="/attack-graph" className="mt-3 inline-block text-sm text-accent-blue no-underline transition-opacity hover:opacity-60">
          Go to the overview
        </Link>
      </div>
    )
  } else if (fetchedScans && scans.length === 0 && !live) {
    body = (
      <div className={STATE_CARD}>
        <div className="mb-1.5 font-mono text-2xs uppercase tracking-label text-accent-blue">No scans yet</div>
        <div className="text-lg font-semibold text-content-primary">Run your first scan</div>
        <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">
          It takes one to four minutes, only reads IAM, and lands here when it finishes.
        </p>
      </div>
    )
  } else if (scanId && failed && !shown) {
    body = (
      <div className={STATE_CARD}>
        <div className="text-lg font-semibold text-content-primary">This scan is no longer available</div>
        <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">
          It may have been deleted, or replaced by newer scans: only your 10 most recent are kept.
        </p>
        <Link to={scanUrl()} className="mt-3 inline-block text-sm text-accent-blue no-underline transition-opacity hover:opacity-60">
          Open the newest scan
        </Link>
      </div>
    )
  } else {
    body = <OpenScan scan={shown} regions={regions} />
  }

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 font-mono text-2xs uppercase tracking-label text-content-dim">
            <Link to="/attack-graph" className="text-accent-blue no-underline transition-opacity hover:opacity-60">Attack Graph</Link>
            <span aria-hidden>/</span>
            Scans
          </div>
          <h1 className="font-display text-2xl font-semibold leading-tight text-content-primary">Scans</h1>
          <p className="mt-1.5 max-w-3xl text-sm text-content-secondary">
            Escalation paths Scout found in your account, newest scan first.
          </p>
        </div>
        {connected && (
          <div className="flex flex-col items-end gap-1.5">
            <div className="flex items-center gap-2.5">
              <button
                type="button"
                onClick={() => setDrawerOpen(true)}
                className="flex items-center gap-1.5 rounded-btn border border-border bg-transparent px-3 py-1.5 text-xs text-content-secondary
                  transition-opacity hover:opacity-60"
              >
                <IconHistory size={13} />Past scans ({scans.length})
              </button>
              <button
                type="button"
                onClick={runScan}
                disabled={starting || live}
                className="rounded-pill bg-white/80 px-4 py-1.5 text-xs font-semibold text-button-fg transition-opacity hover:opacity-60
                  disabled:cursor-not-allowed disabled:opacity-40"
              >
                {live ? 'Scan running' : starting ? 'Starting…' : 'Run scan'}
              </button>
            </div>
            {error && <div className="max-w-xs text-right text-xs text-danger">{error}</div>}
          </div>
        )}
      </div>

      {body}

      <PastScansDrawer
        open={drawerOpen}
        scans={scans}
        openId={viewingId}
        onOpen={(id) => { openScan(id); setDrawerOpen(false) }}
        onDeleted={onDeleted}
        onClose={closeDrawer}
      />
    </div>
  )
}

function OpenScan({ scan, regions }: { scan: ScanDetail | undefined; regions: string[] }) {
  if (!scan) return null
  if (UNFINISHED.includes(scan.status)) return <ScanningCard scan={scan} regions={regions} />
  if (scan.status === 'failed') {
    return (
      <div className={STATE_CARD}>
        <div className="mb-1.5 font-mono text-2xs uppercase tracking-label text-danger">Failed</div>
        <div className="text-lg font-semibold text-content-primary">The scan did not finish</div>
        <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">
          {scan.error_message || 'The scan failed with no further detail.'}
        </p>
      </div>
    )
  }
  if (!scan.result) {
    return (
      <div className={`${STATE_CARD} text-sm text-content-secondary`}>
        This scan completed but recorded no result. Contact support.
      </div>
    )
  }
  if (isTooNewToRender(scan.result)) {
    return (
      <div className={`${STATE_CARD} text-sm text-content-secondary`}>
        This scan was produced by a newer version of MayaTrail. Update the app to view it.
      </div>
    )
  }
  return <ScanResult envelope={scan.result} scanId={scan.id} related={scan.related ?? {}} />
}
