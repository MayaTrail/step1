import type { FeedKind } from '@/types/threatintel'

/**
 * Presentation helpers shared by the Threat Feed page, the item detail pane and
 * the dashboard strip. Kept together so the three surfaces cannot drift on how
 * a content kind is named or how an age is phrased.
 */

/** Reader-facing name for each content kind. */
export const KIND_LABEL: Record<FeedKind, string> = {
  advisory: 'Provider advisory',
  newsletter: 'Newsletter',
  research: 'Research',
}

/** Plural form used on the tab strip. */
export const KIND_TAB_LABEL: Record<FeedKind, string> = {
  advisory: 'Advisories',
  newsletter: 'Newsletters',
  research: 'Research',
}

/**
 * Tab order, most actionable first.
 *
 * Advisories lead because a provider CVE bulletin is the only kind of item in
 * this feed that can require action today. Newsletters trail because they
 * aggregate writing that mostly appears under Research already.
 */
export const KIND_ORDER: FeedKind[] = ['advisory', 'research', 'newsletter']

/**
 * Render an ISO-8601 timestamp as a short relative age.
 *
 * @param iso - UTC ISO-8601 string from the backend.
 * @returns For example "3h ago" or "5d ago", falling back to a plain date once
 *   past a week, since "63d ago" is harder to place than a date.
 */
export function formatWhen(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return ''

  const minutes = Math.floor((Date.now() - then) / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`

  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`

  const days = Math.floor(hours / 24)
  if (days < 7) return `${days}d ago`

  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

/** Ordering the reader can choose for the index rail. */
export type SortOrder = 'newest' | 'oldest'

export const SORT_OPTIONS: { value: SortOrder; label: string }[] = [
  { value: 'newest', label: 'Newest first' },
  { value: 'oldest', label: 'Oldest first' },
]

/**
 * Order items by publication date.
 *
 * Undated items stay at the end in both directions rather than flipping to the
 * front on "oldest first". A missing date is a quirk of the publisher's feed,
 * not evidence that the post is ancient, so treating it as the oldest thing in
 * the window would be inventing a fact. This is the same rule the backend's
 * sort_items applies, which is why reversing the list would not have worked.
 *
 * @param items - Items to order; the input array is not modified.
 * @param order - Which end to start from.
 */
export function sortByDate<T extends { publishedAt: string | null }>(
  items: T[],
  order: SortOrder,
): T[] {
  return [...items].sort((a, b) => {
    if (a.publishedAt === null || b.publishedAt === null) {
      // Undated last, and stable between two undated items.
      return Number(a.publishedAt === null) - Number(b.publishedAt === null)
    }
    // Compare ascending first, then flip once for "newest". Folding the
    // direction into the comparison itself is what made an earlier version of
    // this return oldest-first for "newest": the sign was applied twice and the
    // two cancelled out. ISO-8601 timestamps are lexicographically ordered, so
    // string comparison is the date comparison.
    if (a.publishedAt === b.publishedAt) return 0
    const ascending = a.publishedAt < b.publishedAt ? -1 : 1
    return order === 'newest' ? -ascending : ascending
  })
}
