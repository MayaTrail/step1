import { useCachedResource } from './useCachedResource'
import * as threatFeedService from '@/services/threatintel.service'
import type { FeedQuery } from '@/services/threatintel.service'
import type { ThreatFeed, ThreatFeedSources } from '@/types/threatintel'

/**
 * Data hooks for the Threat Feed.
 *
 * Both wrap the shared useCachedResource, so switching tabs shows the previous
 * result immediately and swaps it when the new one lands, rather than blanking
 * the rail on every filter change.
 */

/**
 * Fetch the aggregated feed.
 *
 * The kind filter is applied backend-side rather than in the browser so the
 * response stays inside the item limit: filtering a 300-item page client-side
 * would silently show only the advisories that happened to fall in the first
 * 300 items of the window.
 *
 * @param query - Filters; every field is encoded into the cache key.
 */
export function useThreatFeed(query: FeedQuery = {}) {
  const key = `threatfeed:${query.kind ?? 'all'}:${query.feed ?? 'any'}:${query.related ? 'rel' : 'all'}:${query.limit ?? 'default'}`
  return useCachedResource<ThreatFeed>(key, () => threatFeedService.getThreatFeed(query))
}

/** Fetch the subscription list with each feed's latest ingest outcome. */
export function useThreatFeedSources() {
  return useCachedResource<ThreatFeedSources>(
    'threatfeed:sources',
    threatFeedService.getThreatFeedSources,
  )
}
