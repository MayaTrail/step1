/**
 * Pieces shared by the two Scans page tabs, which both put a list beside a
 * card: the card's fixed height, the card surface, and the list's filter chip.
 */

import type { ReactNode } from 'react'

/**
 * The card's height in px. Fixed, so opening a path, a panel or a long list
 * of actions scrolls inside the card instead of moving the page. The list
 * beside it uses the same value as its max height: as tall as its rows,
 * never taller than the card.
 */
export const PANEL_HEIGHT = 620

export const CARD = 'rounded-card border border-border bg-surface-card shadow-ring'

/** The filter row pinned to the top of a list while it scrolls. */
export const FILTER_ROW = 'sticky top-0 z-10 flex flex-wrap gap-1.5 border-b border-border bg-surface-card px-4 py-3'

/** One filter of a list, with how many rows it leaves. Disabled when it leaves none. */
export function FilterChip({
  on, count, onClick, children,
}: { on: boolean; count: number; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={count === 0}
      aria-pressed={on}
      className={`rounded-btn border px-2 py-0.5 font-mono text-2xs transition-opacity hover:opacity-60
        disabled:cursor-default disabled:opacity-35 disabled:hover:opacity-35
        ${on ? 'border-accent-blue bg-accent-blue-glow text-accent-blue' : 'border-border bg-transparent text-content-dim'}`}
    >
      {children}
      <span className={`ml-1 ${on ? 'text-accent-blue' : 'text-content-secondary'}`}>{count}</span>
    </button>
  )
}
