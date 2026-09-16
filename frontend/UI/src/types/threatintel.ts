/**
 * Threat Feed types.
 *
 * Mirrors the payloads served by /api/threat-intel/. Every field is already
 * normalised backend-side across RSS 2.0 and Atom: `summary` is plain text with
 * the publisher's HTML stripped, `publishedAt` is UTC ISO-8601, and `matches`
 * was resolved against the emulation catalogue at ingest time rather than in
 * the browser.
 */

/**
 * Shape of the content, and the axis the page groups by.
 *
 *   advisory    provider bulletins, mostly CVEs
 *   newsletter  weekly roundups of other people's writing
 *   research    original writing by a researcher, vendor or IR team
 */
export type FeedKind = 'advisory' | 'newsletter' | 'research'

/** How an item was tied to an emulation, in descending order of precision. */
export type MatchKind = 'cited' | 'technique' | 'campaign'

/** One emulation a feed item relates to. */
export interface ThreatFeedMatch {
  emulationId: string
  displayName: string
  platform: string
  severity: string
  kind: MatchKind
  /**
   * What produced the match: the technique id, the campaign token, or the
   * article URL. Shown to the reader so a link can be judged, not just taken.
   */
  evidence: string
}

/** One post from a subscribed publication. */
export interface ThreatFeedItem {
  /** Stable across ingest runs, so re-fetching never duplicates a post. */
  id: string
  feedId: string
  feedTitle: string
  /** True when the publisher is the cloud provider rather than a researcher. */
  official: boolean
  /** True when the feed is in the current curated list, not just the older one. */
  curated: boolean
  /** Resolved from the feed catalogue on read, so it is always current. */
  kind: FeedKind
  title: string
  link: string
  /** Plain text, truncated backend-side. Never HTML. */
  summary: string
  author: string
  /** UTC ISO-8601, or null when the feed publishes no usable date. */
  publishedAt: string | null
  tags: string[]
  /** Empty for an item that relates to nothing in the catalogue. */
  matches: ThreatFeedMatch[]
}

/** The aggregated feed as served by /api/threat-intel/feed/. */
export interface ThreatFeed {
  items: ThreatFeedItem[]
  /** Items matching the active filters, before the limit was applied. */
  itemCount: number
  /** Items in the whole stored window. */
  totalCount: number
  /** Of the filtered items, how many relate to an emulation. */
  relatedCount: number
  /** Per-kind sizes, counted before the kind filter so every tab has a number. */
  kindCounts: Partial<Record<FeedKind, number>>
  /** Date of the last ingest, or null if it has never run. */
  fetchedOn: string | null
  fetchedAt: string | null
  feedsOk: number
  feedsFailed: number
  feedCount: number
}

/** One subscription, with the latest run's outcome for it. */
export interface ThreatFeedSource {
  id: string
  title: string
  url: string
  curated: boolean
  official: boolean
  kind: FeedKind
  /** 'ok' | 'empty' | 'error' | 'unknown', the last being before any run. */
  status: string
  itemCount: number
  /** Failure reason when status is 'error', otherwise empty. */
  detail: string
}

/** The subscription list as served by /api/threat-intel/sources/. */
export interface ThreatFeedSources {
  sources: ThreatFeedSource[]
  totalCount: number
  failingCount: number
  fetchedAt: string | null
}
