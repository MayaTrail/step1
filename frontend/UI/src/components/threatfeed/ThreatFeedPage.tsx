import { useMemo, useState } from 'react'
import { useThreatFeed, useThreatFeedSources } from '@/hooks/useThreatFeed'
import type { FeedKind, ThreatFeedItem } from '@/types/threatintel'
import { SearchInput } from '@/components/ui/SearchInput'
import { FilterDropdown } from '@/components/ui/FilterDropdown'
import { EmptyState } from '@/components/ui/EmptyState'
import { IconBroadcast } from '@/components/ui/Icons'
import { FeedMark } from './FeedMark'
import { FeedItemDetail } from './FeedItemDetail'
import { KIND_ORDER, KIND_TAB_LABEL, SORT_OPTIONS, formatWhen, sortByDate } from './feedMeta'
import type { SortOrder } from './feedMeta'

/**
 * Threat Feed, the aggregated cloud security reading list.
 *
 * Grouped by content kind rather than by publication or by emulation
 * relevance. That is what the corpus supports: a live ingest over 294 items
 * found no ATT&CK technique id anywhere and item summaries averaging 219
 * characters, so an emulation-relevance split would put one item in the first
 * bucket and everything else in the second. Kind separates the provider
 * advisories that can require action today from the roundups that cannot.
 *
 * Laid out as master-detail, matching DetectionsPage: a scannable index on the
 * left, the selection on the right.
 */

/** The tab strip: everything, then each kind in order of actionability. */
type Tab = 'all' | FeedKind

/*
 * Both columns are pinned to the same height so the page does not resize as
 * items of different lengths are selected. Each scrolls its own content. The
 * offset covers the app chrome plus this page's header, tabs and toolbar; the
 * floor keeps the panes usable on a short window. DetectionsPage sizes its
 * master-detail the same way.
 */
const PANE_HEIGHT = 'h-[calc(100vh-320px)] min-h-[480px]'

export function ThreatFeedPage() {
  const [tab, setTab] = useState<Tab>('all')
  const [search, setSearch] = useState('')
  const [relatedOnly, setRelatedOnly] = useState(false)
  const [sort, setSort] = useState<SortOrder>('newest')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const { data: feed, loading } = useThreatFeed({
    kind: tab === 'all' ? undefined : tab,
    related: relatedOnly || undefined,
  })
  const { data: sources } = useThreatFeedSources()

  const items = useMemo(() => feed?.items ?? [], [feed])

  // Search and sort stay client-side: both act on the items already on screen,
  // so neither needs a round trip and neither can narrow to a page the backend
  // did not send.
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    const matched = query
      ? items.filter(
          (item) =>
            item.title.toLowerCase().includes(query) ||
            item.summary.toLowerCase().includes(query) ||
            item.feedTitle.toLowerCase().includes(query),
        )
      : items
    return sortByDate(matched, sort)
  }, [items, search, sort])

  // Keep a valid selection as the list narrows, the same rule DetectionsPage
  // uses: the explicit choice if it is still visible, otherwise the first row.
  const active = filtered.find((item) => item.id === selectedId) ?? filtered[0] ?? null

  const counts = feed?.kindCounts ?? {}
  const total = feed?.totalCount ?? 0

  if (loading && items.length === 0) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading threat feed…</div>
  }

  if (total === 0) {
    return (
      <div>
        <PageHeader fetchedAt={null} />
        <EmptyState
          icon={<IconBroadcast size={32} />}
          title="No feed items yet"
          body={
            sources
              ? `${sources.totalCount} publications are subscribed. Items appear here after the daily ingest runs.`
              : 'Items appear here after the daily ingest runs.'
          }
        />
      </div>
    )
  }

  return (
    <div className="animate-fadeIn">
      <PageHeader fetchedAt={feed?.fetchedAt ?? null} />

      <div className="flex flex-wrap items-center gap-2 mb-4" role="tablist" aria-label="Content kind">
        <TabButton id="all" active={tab} count={total} onSelect={setTab}>
          All
        </TabButton>
        {KIND_ORDER.map((kind) => (
          <TabButton key={kind} id={kind} active={tab} count={counts[kind] ?? 0} onSelect={setTab}>
            {KIND_TAB_LABEL[kind]}
          </TabButton>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-4">
        <SearchInput value={search} onChange={setSearch} placeholder="Search this feed…" />
        <FilterDropdown label="Sort" value={sort} options={SORT_OPTIONS} onChange={setSort} />
        <button
          type="button"
          aria-pressed={relatedOnly}
          onClick={() => setRelatedOnly((on) => !on)}
          className={`px-3 py-2 rounded-btn text-xs font-medium tracking-btn border transition-opacity hover:opacity-60
            ${relatedOnly
              ? 'border-accent-blue/40 bg-accent-blue/[0.08] text-accent-blue'
              : 'border-border bg-surface-base text-content-secondary'}`}
        >
          Related to an emulation
          {feed ? ` (${feed.relatedCount})` : ''}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-4 items-start">
        <div className={`bg-surface-card border border-border rounded-card shadow-ring overflow-hidden
          flex flex-col ${PANE_HEIGHT}`}>
          <div className="px-3 py-2 border-b border-border font-mono text-2xs uppercase tracking-label text-content-dim">
            {filtered.length} {filtered.length === 1 ? 'item' : 'items'}
          </div>
          <div className="overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="text-center py-10 text-content-dim font-mono text-xs">No matches.</div>
            ) : (
              filtered.map((item) => (
                <FeedRow
                  key={item.id}
                  item={item}
                  active={active?.id === item.id}
                  onSelect={() => setSelectedId(item.id)}
                />
              ))
            )}
          </div>
        </div>

        {active ? (
          /* Deliberately not keyed on the item. A key would remount the pane on
             every selection, and a remounted subtree replays its entry
             animation, which reads as a flash. The pane re-renders with new
             props instead and resets its own scroll. */
          <FeedItemDetail item={active} className={PANE_HEIGHT} />
        ) : (
          <div className={`bg-surface-card border border-border rounded-card shadow-ring
            flex items-center justify-center text-sm text-content-dim ${PANE_HEIGHT}`}>
            Select an item to read it.
          </div>
        )}
      </div>
    </div>
  )
}

/** Section eyebrow, title and freshness line, matching the other content pages. */
function PageHeader({ fetchedAt }: { fetchedAt: string | null }) {
  return (
    <div className="mb-6">
      <div className="font-mono text-2xs uppercase tracking-label text-accent-blue font-medium mb-2">
        Dashboard
      </div>
      <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
        Threat Feed
      </h1>
      <p className="text-sm text-content-dim mt-1">
        Cloud security research, breach reporting and provider advisories
        {fetchedAt && `, updated ${formatWhen(fetchedAt)}`}
      </p>
    </div>
  )
}

interface TabButtonProps {
  id: Tab
  active: Tab
  count: number
  onSelect: (tab: Tab) => void
  children: React.ReactNode
}

function TabButton({ id, active, count, onSelect, children }: TabButtonProps) {
  const selected = active === id
  return (
    <button
      type="button"
      role="tab"
      aria-selected={selected}
      onClick={() => onSelect(id)}
      className={`px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border transition-opacity hover:opacity-60
        ${selected
          ? 'border-border-active bg-surface-card text-content-primary'
          : 'border-border bg-transparent text-content-secondary'}`}
    >
      {children}
      <span className="ml-1.5 font-mono text-content-dim">{count}</span>
    </button>
  )
}

interface FeedRowProps {
  item: ThreatFeedItem
  active: boolean
  onSelect: () => void
}

/**
 * One row in the index rail.
 *
 * The correlation indicator is a dot rather than a chip. At this width a chip
 * would push the title into a third line, and the rail's job is to be
 * scannable; the match itself is spelled out in the detail pane.
 */
function FeedRow({ item, active, onSelect }: FeedRowProps) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`w-full text-left flex items-start gap-2.5 px-3 py-2.5 border-l-2 border-b border-b-border
        transition-colors
        ${active
          ? 'border-l-accent-blue bg-accent-blue/[0.06]'
          : 'border-l-transparent hover:bg-surface-elevated'}`}
    >
      <FeedMark feedId={item.feedId} feedTitle={item.feedTitle} />
      <span className="min-w-0 flex-1">
        <span className="flex items-start gap-1.5">
          <span className={`text-xs leading-snug tracking-body line-clamp-2
            ${active ? 'text-content-primary font-medium' : 'text-content-secondary'}`}>
            {item.title}
          </span>
          {item.matches.length > 0 && (
            <span
              title={`Relates to ${item.matches.map((m) => m.displayName).join(', ')}`}
              className="mt-1 shrink-0 w-1.5 h-1.5 rounded-full bg-accent-blue"
            />
          )}
        </span>
        <span className="block font-mono text-2xs text-content-dim mt-1 truncate">
          {item.feedTitle}
          {item.publishedAt && ` · ${formatWhen(item.publishedAt)}`}
        </span>
      </span>
    </button>
  )
}
