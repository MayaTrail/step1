import type { TacticStatus } from '@/types/metrics'

/**
 * Shared coverage-status visual language for the MITRE coverage section.
 *
 * Green = covered, amber = partial, red = not covered.  Hex values are the
 * design-system accent palette (globals.css), needed where Recharts can't take
 * Tailwind classes; the class maps are used everywhere else.
 */

export const STATUS_HEX: Record<TacticStatus, string> = {
    covered: '#5fc992', // safe
    partial: '#ffbc33', // warning
    none: '#FF6363', // danger
}

export const STATUS_BAR: Record<TacticStatus, string> = {
    covered: 'bg-safe',
    partial: 'bg-warning',
    none: 'bg-danger',
}

export const STATUS_TEXT: Record<TacticStatus, string> = {
    covered: 'text-safe',
    partial: 'text-warning',
    none: 'text-danger',
}

/** Map a coverage percentage to a status, matching the backend thresholds. */
export function statusOf(pct: number): TacticStatus {
    if (pct >= 67) return 'covered'
    if (pct > 0) return 'partial'
    return 'none'
}
