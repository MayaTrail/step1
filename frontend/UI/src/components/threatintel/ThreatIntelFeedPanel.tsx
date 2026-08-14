import { useMemo, useState } from 'react'
import { useThreatIntelFeed, useThreatIntelSources } from '@/hooks/useThreatIntel'
import type { ThreatIntelItem } from '@/types'
import { SearchInput } from '@/components/ui/SearchInput'
import { FilterDropdown, type DropdownOption } from '@/components/ui/FilterDropdown'
import { ComingSoon } from '@/components/common/ComingSoon'
import { IconBroadcast, IconExternalLink } from '@/components/ui/Icons'

/** Items requested per page load. The backend clamps this to 600. */
const FEED_LIMIT = 200

/** Tags shown on a card before the rest collapse into a "+N" chip. */
const VISIBLE_TAGS = 4

type SourceFilter = 'all' | 'official' | 'curated'

const SOURCE_OPTIONS: DropdownOption<SourceFilter>[] = [
  { value: 'all', label: 'All sources' },
  { value: 'official', label: 'Provider advisories' },
  { value: 'curated', label: 'Curated list' },
]

/**
 * The Threat Intel Feed panel.
 *
 * Renders the aggregated RSS items from the most recent daily ingest run. All
 * normalisation happened backend-side, so this component only filters and
 * lays out: summaries arrive as plain text and are rendered as text, never as
 * markup.
 */
export function ThreatIntelFeedPanel() {
  const { data: feed, loading } = useThreatIntelFeed(FEED_LIMIT)
  const { data: sources } = useThreatIntelSources()
  const [search, setSearch] = useState('')
  const [source, setSource] = useState<SourceFilter>('all')

  const items = feed?.items ?? []

  const filtered = useMemo(() => {
    let list = items
    if (source === 'official') list = list.filter((item) => item.official)
    if (source === 'curated') list = list.filter((item) => item.curated)

    const q = search.trim().toLowerCase()
    if (q) {
      list = list.filter(
        (item) =>
          item.title.toLowerCase().includes(q) ||
          item.summary.toLowerCase().includes(q) ||
          item.feedTitle.toLowerCase().includes(q) ||
          item.tags.some((tag) => tag.toLowerCase().includes(q)),
      )
    }
    return list
  }, [items, search, source])

  if (loading && items.length === 0) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading threat intel...</div>
  }

  // No snapshot yet: either the daily ingest has not run or the bucket is
  // unset. Both are the same thing to a reader, so say the honest version.
  if (items.length === 0) {
    return (
      <ComingSoon
        icon={<IconBroadcast size={32} />}
        title="No feed items yet"
        body={
          sources
            ? `${sources.totalCount} publications are subscribed. Items appear here after the daily ingest runs.`
            : 'Items appear here after the daily ingest runs.'
        }
      />
    )
  }

  return (
    <div>
      <FeedSummary
        itemCount={items.length}
        totalCount={feed?.totalCount ?? items.length}
        sourceCount={feed?.sourceCount ?? 0}
        subscribedCount={sources?.totalCount ?? 0}
        fetchedAt={feed?.fetchedAt ?? null}
      />

      <div className="flex flex-wrap items-center gap-3 mb-5">
        <SearchInput value={search} onChange={setSearch} placeholder="Search threat intel..." />
        <FilterDropdown label="Source" value={source} options={SOURCE_OPTIONS} onChange={setSource} />
        <span className="font-mono text-[11px] text-content-dim ml-auto">
          {filtered.length} of {items.length}
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-12 text-content-dim font-mono text-sm">
          No items match that filter.
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {filtered.map((item) => (
            <FeedItemCard key={item.id} item={item} />
          ))}
        </div>
      )}
    </div>
  )
}

/**
 * Freshness and coverage line above the toolbar.
 *
 * Reports what the run produced, not how it went: a dead subscription is an
 * operator's problem, visible in the per-feed report the sources endpoint
 * serves, and surfacing it here only told a reader something they could not
 * act on.
 */
function FeedSummary({
  itemCount,
  totalCount,
  sourceCount,
  subscribedCount,
  fetchedAt,
}: {
  itemCount: number
  totalCount: number
  sourceCount: number
  subscribedCount: number
  fetchedAt: string | null
}) {
  const shown = totalCount > itemCount ? `${itemCount} of ${totalCount} items` : `${itemCount} items`

  return (
    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-[0.85rem] text-content-secondary mb-4">
      <span>{shown}</span>
      <span className="text-content-dim">·</span>
      <span>
        {sourceCount} of {subscribedCount || sourceCount} publications
      </span>
      {fetchedAt && (
        <>
          <span className="text-content-dim">·</span>
          <span className="font-mono text-[11px] text-content-dim">
            updated {formatWhen(fetchedAt)}
          </span>
        </>
      )}
    </div>
  )
}

/** One post: publication, date, title linking out, summary, tags. */
function FeedItemCard({ item }: { item: ThreatIntelItem }) {
  const visibleTags = item.tags.slice(0, VISIBLE_TAGS)
  const overflow = item.tags.length - visibleTags.length

  return (
    <article
      className="bg-surface-card border border-border rounded-card p-5
        transition-all duration-[400ms] hover:border-[rgba(0,180,216,0.2)] hover:-translate-y-0.5"
    >
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <span className="font-mono text-[0.65rem] tracking-[1.5px] uppercase text-accent-blue font-medium">
          {item.feedTitle}
        </span>
        {item.official && (
          <span className="font-mono text-[0.6rem] tracking-[1px] uppercase text-accent-blue bg-accent-blue/[0.12] rounded-[6px] px-2 py-0.5">
            Provider
          </span>
        )}
        <span className="font-mono text-[0.65rem] text-content-dim ml-auto">
          {item.publishedAt ? formatWhen(item.publishedAt) : 'undated'}
        </span>
      </div>

      <a
        href={item.link || undefined}
        target="_blank"
        rel="noopener noreferrer"
        className="group inline-flex items-start gap-1.5 font-display text-[1.05rem] font-bold
          text-content-primary leading-snug no-underline hover:text-accent-blue transition-colors"
      >
        <span>{item.title}</span>
        {item.link && (
          <IconExternalLink
            size={13}
            className="mt-1 shrink-0 text-content-dim opacity-0 group-hover:opacity-100 transition-opacity"
          />
        )}
      </a>

      {item.summary && (
        <p className="text-[0.85rem] text-content-secondary leading-[1.6] mt-2">{item.summary}</p>
      )}

      {(visibleTags.length > 0 || item.author) && (
        <div className="flex flex-wrap items-center gap-1.5 mt-3">
          {visibleTags.map((tag) => (
            <span
              key={tag}
              className="font-mono text-[0.6rem] uppercase tracking-[0.5px] text-content-dim
                bg-white/[0.04] border border-border rounded-[6px] px-2 py-0.5"
            >
              {tag}
            </span>
          ))}
          {overflow > 0 && (
            <span
              title={item.tags.slice(VISIBLE_TAGS).join(', ')}
              className="font-mono text-[0.6rem] text-content-dim bg-white/[0.04] border border-border rounded-[6px] px-2 py-0.5"
            >
              +{overflow}
            </span>
          )}
          {item.author && (
            <span className="font-mono text-[0.6rem] text-content-dim ml-auto">{item.author}</span>
          )}
        </div>
      )}
    </article>
  )
}

/**
 * Render an ISO-8601 timestamp as a short relative age.
 *
 * @param iso - UTC ISO-8601 string from the backend.
 * @returns e.g. "3h ago", "5d ago", or a date once past a week.
 */
function formatWhen(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return ''

  const minutes = Math.floor((Date.now() - then) / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`

  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`

  const days = Math.floor(hours / 24)
  if (days < 7) return `${days}d ago`

  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}
