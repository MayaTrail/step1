import type { Stack, StackStatus } from '@/types'

/**
 * Dashboard stack helpers.
 *
 * Centralizes the mapping from the backend `StackStatus` enum to the visual
 * language used across the dashboard (Badge tone, label, whether the dot
 * pulses) plus the small time/telemetry derivations the overview needs. Keeping
 * this in one place means a stack status renders identically everywhere.
 */

type StatusTone = 'neutral' | 'red' | 'blue' | 'green' | 'yellow'

interface StatusMeta {
    /** Human label shown in the status pill. */
    label: string
    /** Badge tone. */
    tone: StatusTone
    /** Animate the status dot (in-flight states). */
    pulse: boolean
    /** Currently consuming AWS resources (counts toward "active"). */
    active: boolean
}

export const STACK_STATUS: Record<StackStatus, StatusMeta> = {
    pending:          { label: 'Pending',    tone: 'neutral', pulse: false, active: true },
    deploying:        { label: 'Deploying',  tone: 'blue',    pulse: true,  active: true },
    ec2_booting:      { label: 'Booting',    tone: 'blue',    pulse: true,  active: true },
    ready:            { label: 'Ready',      tone: 'green',   pulse: false, active: true },
    ready_for_attack: { label: 'Armed',      tone: 'green',   pulse: false, active: true },
    attacking:        { label: 'Attacking',  tone: 'yellow',  pulse: true,  active: true },
    attack_complete:  { label: 'Complete',   tone: 'green',   pulse: false, active: true },
    refreshing:       { label: 'Refreshing', tone: 'blue',    pulse: true,  active: true },
    destroying:       { label: 'Destroying', tone: 'red',     pulse: true,  active: true },
    destroyed:        { label: 'Destroyed',  tone: 'neutral', pulse: false, active: false },
    failed:           { label: 'Failed',     tone: 'red',     pulse: false, active: false },
}

/** Telemetry counts derived from a stack list. */
export interface Telemetry {
    active: number
    ready: number
    attacking: number
    failed: number
    expiringSoon: number
}

/** One hour, in milliseconds — the "expiring soon" window. */
const EXPIRY_WINDOW_MS = 60 * 60 * 1000

/** True when a stack has a TTL inside the expiring-soon window. */
export function isExpiringSoon(expiresAt?: string | null, withinMs = EXPIRY_WINDOW_MS): boolean {
    if (!expiresAt) return false
    const ms = new Date(expiresAt).getTime() - Date.now()
    return ms > 0 && ms <= withinMs
}

/** Stacks that are live and consuming resources. */
export function activeStacks(stacks: Stack[]): Stack[] {
    return stacks.filter((s) => STACK_STATUS[s.status].active)
}

/** Stacks that need the operator's attention (failed, or expiring soon). */
export function attentionStacks(stacks: Stack[]): Stack[] {
    return stacks.filter(
        (s) => s.status === 'failed' || (STACK_STATUS[s.status].active && isExpiringSoon(s.expires_at)),
    )
}

/** Derive the overview telemetry counts from a stack list. */
export function deriveTelemetry(stacks: Stack[]): Telemetry {
    return {
        active: activeStacks(stacks).length,
        ready: stacks.filter((s) => s.status === 'ready' || s.status === 'ready_for_attack').length,
        attacking: stacks.filter((s) => s.status === 'attacking').length,
        failed: stacks.filter((s) => s.status === 'failed').length,
        expiringSoon: stacks.filter((s) => STACK_STATUS[s.status].active && isExpiringSoon(s.expires_at)).length,
    }
}

/** Compact M / H / D duration label for an elapsed millisecond span. */
function shortDuration(ms: number): string {
    const min = Math.floor(ms / 60000)
    if (min < 1) return '<1m'
    if (min < 60) return `${min}m`
    const hr = Math.floor(min / 60)
    if (hr < 24) return `${hr}h`
    return `${Math.floor(hr / 24)}d`
}

/** Age of a stack since creation, e.g. "12m", "3h". */
export function formatAge(createdAt: string): string {
    return shortDuration(Date.now() - new Date(createdAt).getTime())
}

/** Time until a stack's TTL expires, e.g. "48m"; "expired"/"—" at the edges. */
export function formatExpiry(expiresAt?: string | null): string {
    if (!expiresAt) return '—'
    const ms = new Date(expiresAt).getTime() - Date.now()
    if (ms <= 0) return 'expired'
    return shortDuration(ms)
}

/** Title-case an emulation_type slug for display ("s3_kms" -> "S3 Kms"). */
export function emulationLabel(slug?: string): string {
    if (!slug) return 'Unknown'
    return slug
        .replace(/[_-]+/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase())
}
