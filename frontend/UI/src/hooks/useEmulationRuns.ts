import { useState, useEffect } from 'react'
import type { EmulationRunListItem, EmulationRunStatus } from '@/types'
import { listEmulationRuns } from '@/services/emulation.service'

interface RunsState {
  data: EmulationRunListItem[] | null
  loading: boolean
}

/**
 * Fetch the current user's emulation runs for the given statuses.
 *
 * When `pollMs` is provided the list re-fetches on that interval (used by the
 * Active Runs page so in-flight progress updates without a manual refresh,
 * mirroring the StacksPage live-poll pattern). Polling refreshes silently —
 * the loading flag is only set for the initial load so the table doesn't flash.
 *
 * @param statuses - Statuses to request (server-side status__in filter).
 * @param pollMs   - Optional refresh interval in milliseconds.
 */
export function useEmulationRuns(
  statuses: EmulationRunStatus[],
  pollMs?: number,
): RunsState {
  const [state, setState] = useState<RunsState>({ data: null, loading: true })

  // Stable primitive dependency so the effect doesn't re-run on every render
  // (a new array literal would otherwise change identity each time).
  const key = statuses.join(',')

  useEffect(() => {
    let cancelled = false
    const requested = key ? (key.split(',') as EmulationRunStatus[]) : []

    const fetchRuns = (initial: boolean) => {
      if (initial) setState((s) => ({ ...s, loading: true }))
      listEmulationRuns(requested)
        .then((runs) => {
          if (!cancelled) setState({ data: runs, loading: false })
        })
        .catch(() => {
          if (!cancelled) setState({ data: [], loading: false })
        })
    }

    fetchRuns(true)

    if (!pollMs) return () => { cancelled = true }

    const id = setInterval(() => fetchRuns(false), pollMs)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [key, pollMs])

  return state
}
