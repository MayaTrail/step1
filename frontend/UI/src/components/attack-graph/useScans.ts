/**
 * Scan list and scan start, shared by the Attack Graph overview and the Scans page.
 */

import { useCallback, useState } from 'react'

import { useCachedResource } from '@/hooks/useCachedResource'
import * as attackGraph from '@/services/attackGraph.service'
import type { ScanStatus, ScanSummary } from '@/types/attackGraph'

export const UNFINISHED: ScanStatus[] = ['pending', 'running']

// The list only has to notice that a scan finished, or started in another tab.
const LIST_POLL_MS = 10000

/** The Scans page, or one scan on it. */
export function scanUrl(scanId?: string): string {
  return scanId ? `/attack-graph/scans/${scanId}` : '/attack-graph/scans'
}

/** The user's scans, newest first; undefined until the first response, or while not connected. */
export function useScanList(enabled: boolean): ScanSummary[] | undefined {
  const { data } = useCachedResource<ScanSummary[]>(
    enabled ? 'attack-graph:scans' : null,
    attackGraph.listScans,
    { pollMs: LIST_POLL_MS },
  )
  return data
}

/**
 * Start a scan and hand its id to `onStarted`.
 *
 * A 409 names the scan already running; that one is handed over instead of
 * showing an error, since opening it is what the user wanted.
 */
export function useRunScan(onStarted: (scanId: string) => void) {
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const runScan = useCallback(async () => {
    setStarting(true)
    setError(null)
    try {
      const { scanId } = await attackGraph.triggerScan()
      onStarted(scanId)
    } catch (err: any) {
      const inFlight = err?.response?.data?.scanId
      if (inFlight) onStarted(inFlight)
      else setError(err?.response?.data?.detail ?? 'Could not start the scan.')
    } finally {
      setStarting(false)
    }
  }, [onStarted])

  return { runScan, starting, error }
}
