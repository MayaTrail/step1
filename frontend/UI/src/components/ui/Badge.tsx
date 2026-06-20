import type { ReactNode, CSSProperties } from 'react'

/**
 * MayaTrail badge / tag.
 *
 * Tailwind-class adaptation of the design-system `components/core/Badge`
 * (claude.ai/design). Neutral elevated chip by default; pass a `tone` for a
 * translucent semantic surface. `mono` switches to Geist Mono for codes and
 * status labels; `dot` adds a leading status dot in the tone color.
 */

type BadgeTone = 'neutral' | 'red' | 'blue' | 'green' | 'yellow' | 'purple'

interface BadgeProps {
    children: ReactNode
    tone?: BadgeTone
    /** Use Geist Mono — for codes, status labels. */
    mono?: boolean
    /** Leading status dot in the tone color. */
    dot?: boolean
    /** Animate the status dot (e.g. an active session). */
    pulse?: boolean
    className?: string
    style?: CSSProperties
}

const toneClass: Record<BadgeTone, string> = {
    neutral: 'text-content-secondary bg-surface-elevated border-border',
    red: 'text-danger bg-danger-dim border-danger/25',
    blue: 'text-accent-blue bg-accent-blue/10 border-accent-blue/25',
    green: 'text-safe bg-safe-dim border-safe/25',
    yellow: 'text-warning bg-warning-dim border-warning/25',
    purple: 'text-purple bg-purple/10 border-purple/25',
}

export function Badge({
    children,
    tone = 'neutral',
    mono = false,
    dot = false,
    pulse = false,
    className = '',
    style,
}: BadgeProps) {
    return (
        <span
            style={style}
            className={`inline-flex items-center gap-1.5 border rounded-btn px-2 py-0.5 whitespace-nowrap
                ${mono ? 'font-mono text-2xs tracking-btn font-medium uppercase' : 'text-xs tracking-body font-semibold'}
                ${toneClass[tone]} ${className}`}
        >
            {dot && (
                <span className={`w-1.5 h-1.5 rounded-full bg-current shrink-0 ${pulse ? 'animate-pulse' : ''}`} />
            )}
            {children}
        </span>
    )
}
