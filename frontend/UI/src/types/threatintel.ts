/**
 * Threat Intel types.
 *
 * Mirrors the payloads served by /api/threat-intel/. Items originate in the
 * daily S3 snapshot the ingest task writes, so every field here has already
 * been normalised backend-side across RSS 2.0 and Atom: `summary` is plain
 * text with the feed's HTML stripped, and `publishedAt` is UTC ISO-8601.
 */

/** The two panels of the Threat Intel section. */
export type ThreatIntelView = 'feed' | 'advisory'

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
export interface Advisory {
  /** URL-safe slug derived from the dossier filename, e.g. "lazarus-group". */
  id: string
  /** Actor name as the dossier titles it — the MITRE-canonical one. */
  name: string
  /**
   * The name the dossier is filed under, e.g. "APT10" for a file titled
   * "menuPass". Differs from `name` for six actors; shown and searchable so
   * either name finds the card.
   */
  reference: string
  /** MITRE ATT&CK group id, e.g. "G0016". Empty when the actor has none. */
  groupId: string
  /** Opening of the Intelligence Overview. Empty for dossiers without one. */
  summary: string
  origin: string
  /** Year first observed. Empty unless the dossier records a real one. */
  firstSeen: string
  motivations: string[]
  aliases: string[]
  /** MITRE tactics from the TTP table, in first-seen order. */
  tactics: string[]
  techniqueCount: number
  /** Known exploited CVEs (CISA KEV) attributed to the actor. */
  cveCount: number
  malwareCount: number
  sectors: string[]
  /** When the dossier was generated, as written, e.g. "2026-08-14 21:54 UTC". */
  generatedAt: string
  /** Upstream feeds merged into the dossier, e.g. ["mitre_attack"]. */
  sources: string[]
}

/** One advisory plus its full dossier, from /advisories/<id>/. */
export interface AdvisoryDetail extends Advisory {
  /** The dossier markdown, verbatim. */
  content: string
}

/** The advisory library as served by /api/threat-intel/advisories/. */
export interface AdvisoryLibrary {
  advisories: Advisory[]
  totalCount: number
}
