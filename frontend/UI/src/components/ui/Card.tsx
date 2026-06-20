import type { ReactNode, MouseEvent, CSSProperties } from 'react'

/**
 * MayaTrail surface card.
 *
 * Tailwind-class adaptation of the design-system `components/core/Card`
 * (claude.ai/design). Containment comes from the double-ring `shadow-ring`
 * (the macOS-native technique that replaces a hard border), not a heavy border.
 * Pass an `accent` for a colored left bar and `interactive` for a clickable
 * card that lifts and tints its border on hover.
 */

type CardAccent = 'red' | 'blue' | 'green' | 'amber'

interface CardProps {
    children: ReactNode
    /** Left accent bar + hover border tint. */
    accent?: CardAccent | null
    /** Enables pointer cursor + hover lift. */
    interactive?: boolean
    /** Extra utility classes appended to the container. */
    className?: string
    style?: CSSProperties
    onClick?: (e: MouseEvent<HTMLDivElement>) => void
}

const accentBar: Record<CardAccent, string> = {
    red: 'bg-danger',
    blue: 'bg-accent-blue',
    green: 'bg-safe',
    amber: 'bg-warning',
}

export function Card({
    children,
    accent = null,
    interactive = false,
    className = '',
    style,
    onClick,
}: CardProps) {
    return (
        <div
            onClick={onClick}
            style={style}
            className={`relative bg-surface-card border border-border rounded-card shadow-ring overflow-hidden
                ${interactive ? 'cursor-pointer transition-all hover:border-border-active hover:-translate-y-px' : ''}
                ${className}`}
        >
            {accent && (
                <span
                    className={`absolute top-3.5 bottom-3.5 left-0 w-0.5 rounded-r-sm opacity-80 ${accentBar[accent]}`}
                    aria-hidden="true"
                />
            )}
            {children}
        </div>
    )
}
