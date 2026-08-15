/**
 * Threat Intel types.
 *
 * Mirrors the payloads served by /api/threat-intel/. Items originate in the
 * daily S3 snapshot the ingest task writes, so every field here has already
 * been normalised backend-side across RSS 2.0 and Atom: `summary` is plain
 * text with the feed's HTML stripped, and `publishedAt` is UTC ISO-8601.
 */

/** The two panels of the Threat Intel section. */

/** One post from a subscribed publication. */
export interface ThreatIntelItem {
  /** Stable across ingest runs, so re-fetching never duplicates a post. */
  id: string
  feedId: string
  feedTitle: string
  /** True when the publisher is the cloud provider rather than a researcher. */
  official: boolean
  /** True when the feed is in the current curated list, not just the older one. */
  curated: boolean
  title: string
  link: string
  /** Plain text, truncated backend-side. Never HTML. */
  summary: string
  author: string
  /** UTC ISO-8601, or null when the feed publishes no usable date. */
  publishedAt: string | null
  tags: string[]
}

/** The aggregated feed as served by /api/threat-intel/feed/. */
export interface ThreatIntelFeed {
  items: ThreatIntelItem[]
  /** Items in this response. */
  itemCount: number
  /** Items available before the limit was applied. */
  totalCount: number
  /** Distinct publications represented in the snapshot. */
  sourceCount: number
  /** When the ingest task last ran, or null if it never has. */
  fetchedAt: string | null
  feedsOk: number
  feedsFailed: number
}

/** One subscription, with the latest run's outcome for it. */
export interface ThreatIntelSource {
  id: string
  title: string
  url: string
  curated: boolean
  official: boolean
  /** 'ok' | 'empty' | 'error' | 'unknown' — 'unknown' before the first run. */
  status: string
  itemCount: number
  detail: string
}

/** The subscription list as served by /api/threat-intel/sources/. */
export interface ThreatIntelSources {
  sources: ThreatIntelSource[]
  totalCount: number
  fetchedAt: string | null
}

/**
 * One APT threat-actor dossier, as a library card.
 *
 * Parsed backend-side at upload time from the dossier markdown, so every field
 * is already normalised: `origin` and `motivations` are canonicalised (the
 * upstream sources spell "Russia" and "Russian Federation" both ways), and any
 * field the dossier does not carry arrives empty rather than absent.
 */
