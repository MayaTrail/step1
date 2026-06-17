/**
 * LifecycleTimeline — deployment journey for a stack, shown in the detail panel.
 *
 * Milestone 1 renders an *illustrative* timeline derived from the stack's
 * current status and timestamps. The backend does not yet record per-phase
 * history (status is overwritten in place), so intermediate phases such as
 * "Provisioning Resources" and "Validating" are inferred, not measured.
 *
 * Phase 2 will persist the real per-phase events and the failure reason; this
 * component already accepts a `failureReason` prop so it can surface that the
 * moment it becomes available without a structural change.
 */

import type { Stack, StackStatus } from '@/types'

/** Ordered phases of a successful deployment. */
const PHASES = [
    'Created',
    'Queued',
    'Deploying',
    'Provisioning Resources',
    'Validating',
    'Ready',
] as const

/**
 * Map a status to the count of phases that are complete-or-current.
 * Index 0 (Created) is always reached once a record exists.
 */
function reachedCount(status: StackStatus): number {
    switch (status) {
        case 'pending':
            return 2 // Created, Queued
        case 'deploying':
        case 'refreshing':
            return 4 // …through Provisioning Resources
        case 'ec2_booting':
            return 5 // …through Validating
        case 'ready':
        case 'ready_for_attack':
        case 'attacking':
        case 'attack_complete':
            return 6 // all phases complete
        default:
            return 1
    }
}

type NodeState = 'done' | 'current' | 'pending'

interface LifecycleTimelineProps {
    stack: Stack
    /** Persisted failure reason (Phase 2). Falls back to a generic message. */
    failureReason?: string
}

export function LifecycleTimeline({ stack, failureReason }: LifecycleTimelineProps) {
    if (stack.status === 'failed') {
        return <FailureTimeline reason={failureReason} />
    }

    if (stack.status === 'destroyed' || stack.status === 'destroying') {
        return (
            <div className="font-mono text-[12px] text-content-dim">
                {stack.status === 'destroyed'
                    ? 'This stack has been torn down. No active deployment lifecycle.'
                    : 'Teardown in progress — resources are being destroyed.'}
            </div>
        )
    }

    const reached = reachedCount(stack.status)

    return (
        <div className="flex flex-col">
            {PHASES.map((phase, i) => {
                const state: NodeState =
                    i < reached - 1 ? 'done' : i === reached - 1 ? 'current' : 'pending'
                return (
                    <TimelineNode
                        key={phase}
                        label={phase}
                        state={state}
                        isLast={i === PHASES.length - 1}
                    />
                )
            })}
        </div>
    )
}

/* ── Failure path ── */

function FailureTimeline({ reason }: { reason?: string }) {
    return (
        <div className="flex flex-col">
            <TimelineNode label="Created" state="done" />
            <TimelineNode label="Deploying" state="done" />
            <TimelineNode label="Provisioning Resources" state="done" />
            <TimelineNode label="FAILED" state="failed" isLast />
            <div className="ml-[27px] mt-1">
                <div className="font-mono text-[10px] uppercase tracking-[1px] text-danger mb-1">Reason</div>
                <div className="font-mono text-[12px] text-content-secondary bg-danger/[0.06] border border-danger/20 rounded-btn px-3 py-2 leading-[1.5] break-words">
                    {reason ?? 'Deployment failed. Open View Logs for the detailed error.'}
                </div>
            </div>
        </div>
    )
}

/* ── Single node ── */

function TimelineNode({
    label,
    state,
    isLast = false,
}: {
    label: string
    state: NodeState | 'failed'
    isLast?: boolean
}) {
    const dot =
        state === 'done'
            ? 'bg-safe border-safe'
            : state === 'current'
                ? 'bg-accent-blue border-accent-blue'
                : state === 'failed'
                    ? 'bg-danger border-danger'
                    : 'bg-transparent border-border'

    const text =
        state === 'pending'
            ? 'text-content-dim'
            : state === 'failed'
                ? 'text-danger font-semibold'
                : 'text-content-primary'

    const connector =
        state === 'done' ? 'bg-safe/40' : state === 'failed' ? 'bg-danger/30' : 'bg-border'

    return (
        <div className="flex gap-3">
            {/* Rail */}
            <div className="flex flex-col items-center">
                <span
                    className={`w-3 h-3 rounded-full border-2 shrink-0 ${dot} ${state === 'current' ? 'animate-pulse' : ''}`}
                />
                {!isLast && <span className={`w-px flex-1 min-h-[18px] ${connector}`} />}
            </div>
            {/* Label */}
            <div className={`text-[13px] font-body pb-3 leading-none ${text}`}>{label}</div>
        </div>
    )
}
