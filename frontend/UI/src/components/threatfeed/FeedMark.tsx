/**
 * Publication identity mark.
 *
 * A two-letter monogram on a tinted tile, standing in for a publisher logo.
 * Deliberately not a fetched favicon: reading a favicon from the publisher (or
 * from a favicon service) would tell forty third parties which security
 * publications this user reads, every time the page renders, and nine of the
 * forty subscribed domains are dead so a third of the column would be broken
 * images.
 *
 * The tint is drawn from the design system's existing semantic colors and
 * assigned by a hash of the feed id, so a publication keeps the same mark
 * across sessions and machines without anything being stored. It runs at low
 * opacity: the color is identity, not decoration, and the rail has to stay
 * calm with three hundred rows in it.
 */

/**
 * The six theme-aware accent tokens, used here only as identity tints.
 *
 * Every entry resolves through a CSS custom property, so the marks follow the
 * light and dark themes rather than being pinned to the dark palette.
 */
interface Tint {
  bg: string
  fg: string
}

/* Typed as a non-empty tuple so the first entry can serve as the fallback
   under noUncheckedIndexedAccess without a non-null assertion. */
const TINTS: readonly [Tint, ...Tint[]] = [
  { bg: 'bg-[var(--blue)]/[0.12]', fg: 'text-blue' },
  { bg: 'bg-[var(--purple)]/[0.12]', fg: 'text-purple' },
  { bg: 'bg-[var(--green)]/[0.12]', fg: 'text-green' },
  { bg: 'bg-[var(--cyan)]/[0.12]', fg: 'text-cyan' },
  { bg: 'bg-[var(--orange)]/[0.12]', fg: 'text-orange' },
  { bg: 'bg-[var(--yellow)]/[0.12]', fg: 'text-yellow' },
]

/**
 * Reduce a string to a stable index into TINTS.
 *
 * A plain FNV-style rolling hash. It only has to be deterministic and evenly
 * spread across six buckets, so nothing stronger is warranted. Kept in one
 * place because the dashboard strip uses the same marks and must agree with
 * the page on every publication's color.
 *
 * @param value - The feed id, which is stable across ingest runs.
 */
function tintIndex(value: string): number {
  let hash = 2166136261
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return Math.abs(hash) % TINTS.length
}

/**
 * Derive a two-letter monogram from a publication name.
 *
 * Multi-word names take the initial of each of the first two words. A single
 * word is read for internal capitals first, so "CloudSecList" becomes CS
 * rather than CL, then falls back to its first two characters.
 *
 * @param title - The publication's display name.
 */
export function monogram(title: string): string {
  const [first, second] = title.trim().split(/[^A-Za-z0-9]+/).filter(Boolean)
  if (!first) return '??'
  if (second) return (first.charAt(0) + second.charAt(0)).toUpperCase()

  const capitals = first.match(/[A-Z]/g)
  if (capitals && capitals.length >= 2) return capitals.slice(0, 2).join('').toUpperCase()
  return first.slice(0, 2).toUpperCase()
}

interface FeedMarkProps {
  feedId: string
  feedTitle: string
  /** Tile edge in pixels. 28 in list rows, 40 in the detail header. */
  size?: number
}

export function FeedMark({ feedId, feedTitle, size = 28 }: FeedMarkProps) {
  const tint = TINTS[tintIndex(feedId)] ?? TINTS[0]
  return (
    <span
      aria-hidden="true"
      title={feedTitle}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.36) }}
      className={`shrink-0 inline-flex items-center justify-center rounded-btn font-mono font-medium
        tracking-caps border border-border ${tint.bg} ${tint.fg}`}
    >
      {monogram(feedTitle)}
    </span>
  )
}
