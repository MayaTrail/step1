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

/* ── Stack health labels (Milestone 1) ──────────────────────────────────────
 *
 * The backend carries 11 fine-grained lifecycle statuses. Operators, however,
 * only need to answer "is this stack OK, working, broken, or gone?" at a glance.
 * `deriveHealth` collapses the 11 statuses into the 6 PRD health labels.
 *
 * `Stale` has no backing status — it is derived: a stack that is past its
 * auto-destroy TTL (`expires_at`) but has not yet been torn down. That is the
 * one health state the raw status field cannot express.
 */

export type StackHealth =
    | 'active'
    | 'deploying'
    | 'failed'
    | 'stale'
    | 'destroying'
    | 'destroyed'

interface HealthMeta {
    /** Uppercase label shown on the badge. */
    label: string
    /** Badge tone (maps to the shared Badge component palette). */
    tone: StatusTone
    /** Pulse the badge dot — in-flight states only. */
    pulse: boolean
}

export const STACK_HEALTH: Record<StackHealth, HealthMeta> = {
    active:     { label: 'ACTIVE',     tone: 'green',   pulse: false },
    deploying:  { label: 'DEPLOYING',  tone: 'blue',    pulse: true },
    failed:     { label: 'FAILED',     tone: 'red',     pulse: false },
    stale:      { label: 'STALE',      tone: 'yellow',  pulse: false },
    destroying: { label: 'DESTROYING', tone: 'red',     pulse: true },
    destroyed:  { label: 'DESTROYED',  tone: 'neutral', pulse: false },
}

/** Live statuses that represent a successfully deployed, running stack. */
const ACTIVE_STATUSES = new Set<StackStatus>([
    'ready',
    'ready_for_attack',
    'attacking',
    'attack_complete',
])

/**
 * True when a stack has blown past its auto-destroy deadline but is still alive.
 *
 * Only meaningful for enterprise stacks (demo stacks have no `expires_at` and so
 * are never considered stale). Destroyed / destroying / failed stacks are
 * excluded — they are already terminal or being cleaned up.
 */
export function isTtlExpired(stack: Stack): boolean {
    if (!stack.expires_at) return false
    if (['destroyed', 'destroying', 'failed'].includes(stack.status)) return false
    return new Date(stack.expires_at).getTime() < Date.now()
}

/** Collapse a stack's fine-grained status into one of the 6 health labels. */
export function deriveHealth(stack: Stack): StackHealth {
    const { status } = stack
    if (status === 'destroyed') return 'destroyed'
    if (status === 'destroying') return 'destroying'
    if (status === 'failed') return 'failed'
    if (isTtlExpired(stack)) return 'stale'
    if (ACTIVE_STATUSES.has(status)) return 'active'
    // pending / deploying / ec2_booting / refreshing — all in-progress.
    return 'deploying'
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
