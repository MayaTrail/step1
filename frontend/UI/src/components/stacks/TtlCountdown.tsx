import { useEffect, useState } from 'react'

/**
 * Live countdown to a stack's auto-destroy deadline.
 *
 * The existing expiry label was computed once at render and only refreshed
 * when the stacks page polled, and that poll runs only while a stack is
 * deploying or attacking. Once a stack reached ready_for_attack the number
 * froze at whatever it said on arrival, which is precisely when the TTL is the
 * only thing still moving. This ticks on its own clock instead.
 *
 * Granularity matters here too: the old helper floored to whole hours, so
 * anything between 4h00 and 4h59 read as "4h". A reader deciding whether they
 * have time to finish a run needs the minutes.
 */

/** How close to the deadline before the countdown changes colour. */
const SOON_MS = 60 * 60 * 1000
const CRITICAL_MS = 15 * 60 * 1000

export type TtlUrgency = 'normal' | 'soon' | 'critical' | 'expired'

/** Milliseconds until the deadline, negative once it has passed. */
function remaining(expiresAt: string): number {
    return new Date(expiresAt).getTime() - Date.now()
}

/** How alarmed the display should be about the time left. */
export function ttlUrgency(expiresAt?: string | null): TtlUrgency {
    if (!expiresAt) return 'normal'
    const ms = remaining(expiresAt)
    if (ms <= 0) return 'expired'
    if (ms <= CRITICAL_MS) return 'critical'
    if (ms <= SOON_MS) return 'soon'
    return 'normal'
}

/**
 * Format the time left, keeping the unit a reader needs at that range.
 *
 * Hours and minutes above an hour, minutes and seconds below it. Seconds only
 * appear in the last hour, where they are the difference between "I can start
 * another attack" and "I cannot".
 */
export function formatCountdown(expiresAt?: string | null): string {
    if (!expiresAt) return '--'
    const ms = remaining(expiresAt)
    if (ms <= 0) return 'expired'

    const totalSeconds = Math.floor(ms / 1000)
    const hours = Math.floor(totalSeconds / 3600)
    const minutes = Math.floor((totalSeconds % 3600) / 60)
    const seconds = totalSeconds % 60

    if (hours >= 1) return `${hours}h ${String(minutes).padStart(2, '0')}m`
    if (minutes >= 1) return `${minutes}m ${String(seconds).padStart(2, '0')}s`
    return `${seconds}s`
}

/** The deadline as a local wall-clock time, so a reader can plan around it. */
export function formatDeadline(expiresAt?: string | null): string {
    if (!expiresAt) return ''
    return new Date(expiresAt).toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
    })
}

const URGENCY_CLASS: Record<TtlUrgency, string> = {
    normal: 'text-content-secondary',
    soon: 'text-warning',
    critical: 'text-danger',
    expired: 'text-warning',
}

/**
 * Re-render once a second while a deadline is pending.
 *
 * Stops ticking once the deadline has passed, so an expired stack left on
 * screen does not hold a timer open indefinitely.
 */
function useTick(active: boolean): void {
    const [, setTick] = useState(0)
    useEffect(() => {
        if (!active) return undefined
        const id = setInterval(() => setTick((value) => value + 1), 1000)
        return () => clearInterval(id)
    }, [active])
}

interface TtlCountdownProps {
    expiresAt?: string | null
    /** Adds the absolute deadline beside the countdown. */
    showDeadline?: boolean
    className?: string
}

export function TtlCountdown({
    expiresAt,
    showDeadline = false,
    className = '',
}: TtlCountdownProps) {
    const urgency = ttlUrgency(expiresAt)
    useTick(Boolean(expiresAt) && urgency !== 'expired')

    if (!expiresAt) {
        return <span className={`text-content-muted ${className}`}>&ndash;</span>
    }

    return (
        <span className={`${URGENCY_CLASS[urgency]} ${className}`}>
            {formatCountdown(expiresAt)}
            {showDeadline && urgency !== 'expired' && (
                <span className="ml-1.5 text-content-muted">at {formatDeadline(expiresAt)}</span>
            )}
        </span>
    )
}
