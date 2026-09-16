/**
 * Threat Feed Service, API calls for the aggregated security feed.
 *
 * Endpoints (read-only, require an authenticated user):
 *   GET /api/threat-intel/feed/     rolling window of items, with emulation matches
 *   GET /api/threat-intel/sources/  subscription list with each feed's last outcome
 *
 * Both are served from a document the daily ingest wrote, so neither call
 * waits on a publisher.
 */

import api from './api'
import type { FeedKind, ThreatFeed, ThreatFeedSources } from '@/types/threatintel'

/** Items requested per page load. The backend clamps this to 600. */
export const FEED_LIMIT = 300

export interface FeedQuery {
  limit?: number
  /** Restrict to one content kind. Omit for everything. */
  kind?: FeedKind
  /** Restrict to one publication. */
  feed?: string
  /** Restrict to items that relate to an emulation. */
  related?: boolean
}

/**
 * Fetch the aggregated feed from the most recent ingest run.
 *
 * @param query - Optional filters, all applied backend-side.
 */
export async function getThreatFeed(query: FeedQuery = {}): Promise<ThreatFeed> {
  const params: Record<string, string> = { limit: String(query.limit ?? FEED_LIMIT) }
  if (query.kind) params.kind = query.kind
  if (query.feed) params.feed = query.feed
  if (query.related) params.related = 'true'

  const { data } = await api.get<ThreatFeed>('/threat-intel/feed/', { params })
  return data
}

/**
 * Fetch the subscription list, each entry carrying the latest run's outcome.
 *
 * Served from the static catalogue merged with the stored run report, so this
 * succeeds even before the first ingest has written a snapshot.
 */
export async function getThreatFeedSources(): Promise<ThreatFeedSources> {
  const { data } = await api.get<ThreatFeedSources>('/threat-intel/sources/')
  return data
}
