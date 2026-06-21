import type { ReactNode } from 'react'
import { Card } from './Card'

/**
 * Dashboard metric tile.
 *
 * Tailwind-class adaptation of the design-system `components/security/MetricCard`
 * (claude.ai/design), composed on top of the `Card` primitive so the double-ring
 * surface and accent bar live in one place. Big tabular numeral over an
 * uppercase mono label, an accent icon chip, and an optional sub-caption.
 */

type MetricAccent = 'red' | 'blue' | 'green' | 'amber' | 'neutral'

interface MetricCardProps {
    value: ReactNode
    label: string
    accent?: MetricAccent
    loading?: boolean
    /** Optional secondary line under the label (e.g. "2 ready · 1 attacking"). */
    caption?: ReactNode
    /** Icon rendered in the accent chip; falls back to a colored dot. */
    icon?: ReactNode
    onClick?: () => void
}

const chipClass: Record<MetricAccent, string> = {
    red: 'bg-danger-dim border-danger/20 text-danger',
    blue: 'bg-accent-blue/10 border-accent-blue/20 text-accent-blue',
    green: 'bg-safe-dim border-safe/20 text-safe',
    amber: 'bg-warning-dim border-warning/20 text-warning',
    neutral: 'bg-surface-elevated border-border text-content-dim',
}

export function MetricCard({
    value,
    label,
    accent = 'red',
    loading = false,
    caption,
    icon,
    onClick,
}: MetricCardProps) {
    return (
        <Card accent={accent === 'neutral' ? null : accent} interactive={!!onClick} onClick={onClick} className="p-5 flex flex-col gap-1.5">
            <span className={`inline-flex items-center justify-center w-7 h-7 rounded-btn border mb-1 ${chipClass[accent]}`}>
                {icon ?? <span className="w-2 h-2 rounded-full bg-current" />}
            </span>
            <span
                className={`font-display text-3xl font-bold tabular-nums leading-none tracking-tight ${
                    loading ? 'text-content-muted' : 'text-content-primary'
                }`}
            >
                {loading ? '—' : value}
            </span>
            <span className="font-mono text-2xs uppercase tracking-label text-content-muted">{label}</span>
            {caption && <span className="text-xs text-content-dim mt-0.5">{caption}</span>}
        </Card>
    )
}
