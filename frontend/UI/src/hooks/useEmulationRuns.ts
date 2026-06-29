import type { EmulationRunListItem, EmulationRunStatus } from '@/types'
import { listEmulationRuns } from '@/services/emulation.service'
import { useCachedResource } from './useCachedResource'

interface RunsState {
  data: EmulationRunListItem[] | null
  loading: boolean
}

/**
 * Fetch the current user's emulation runs for the given statuses.
 *
 * Backed by useCachedResource, so revisiting (e.g. switching Active Runs <->
 * Results) shows the last list immediately and revalidates in the background
 * instead of flashing a "Loading..." placeholder. When `pollMs` is provided the
 * list re-fetches on that interval, silently, so in-flight progress updates
 * without a manual refresh and without a flash.
 *
 * @param statuses - Statuses to request (server-side status__in filter).
 * @param pollMs   - Optional refresh interval in milliseconds.
 */
export function useEmulationRuns(
  statuses: EmulationRunStatus[],
  pollMs?: number,
): RunsState {
  // Stable primitive key so the cache (and effect) key on the actual inputs
  // rather than a new array literal's identity each render.
  const key = statuses.join(',')

  const { data, loading } = useCachedResource<EmulationRunListItem[]>(
    `runs:${key}`,
    () => listEmulationRuns(key ? (key.split(',') as EmulationRunStatus[]) : []),
    pollMs ? { pollMs } : undefined,
  )

  return { data: data ?? null, loading }
}
