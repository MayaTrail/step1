import api from './api'
import type { AdvisoryDetail, AdvisoryLibrary, ThreatIntelFeed, ThreatIntelSources } from '@/types'

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

/**
 * Fetch the advisory library — one card per APT dossier.
 *
 * Empty until `manage.py sync_advisories` has published the dossiers.
 */
export async function fetchAdvisories(): Promise<AdvisoryLibrary | null> {
  try {
    const { data } = await api.get<AdvisoryLibrary>('/threat-intel/advisories/')
    return data
  } catch {
    return null
  }
}

/**
 * Fetch one advisory with its full dossier markdown.
 *
 * @param advisoryId - The card's `id`, e.g. "lazarus-group".
 * @returns The dossier, or null when no advisory has that id.
 */
export async function fetchAdvisory(advisoryId: string): Promise<AdvisoryDetail | null> {
  try {
    const { data } = await api.get<AdvisoryDetail>(`/threat-intel/advisories/${advisoryId}/`)
    return data
  } catch {
    return null
  }
}
