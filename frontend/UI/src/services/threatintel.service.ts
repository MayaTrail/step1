import api from './api'
import type { ThreatIntelFeed, ThreatIntelSources } from '@/types'

/**
 * Threat Intel API client.
 *
 * Every call resolves to null on failure rather than throwing, matching
 * platform.service.ts: the section's panels render an empty state for a
 * missing library, and a backend that has not yet run its first ingest is not
 * an error worth surfacing as one.
 */

/** Items returned when the caller does not ask for a specific page size. */
const DEFAULT_LIMIT = 100

/**
 * Fetch the aggregated RSS items from the most recent ingest run.
 *
 * @param limit - Maximum items to return; the backend clamps this to 600.
 */
export async function fetchThreatIntelFeed(limit: number = DEFAULT_LIMIT): Promise<ThreatIntelFeed | null> {
  try {
    const { data } = await api.get<ThreatIntelFeed>('/threat-intel/feed/', { params: { limit } })
    return data
  } catch {
    return null
  }
}

/**
 * Fetch the subscription list, each entry carrying the latest run's outcome.
 *
 * Served from the static catalogue, so this succeeds even before the first
 * ingest run has written a snapshot.
 */
export async function fetchThreatIntelSources(): Promise<ThreatIntelSources | null> {
  try {
    const { data } = await api.get<ThreatIntelSources>('/threat-intel/sources/')
    return data
  } catch {
    return null
  }
}
