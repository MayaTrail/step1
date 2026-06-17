/**
 * DeploymentProgress — live progress bar for an in-flight stack deployment.
 *
 * Polls the existing GET /api/stacks/{id}/progress/ endpoint (backed by the
 * deploy task's Celery PROGRESS state) every few seconds while the stack is in
 * an in-progress status, and renders a determinate bar plus a resource count.
 *
 * It self-suspends polling the moment the stack leaves an in-progress status,
 * so it is safe to mount unconditionally on a card.
 */

import { useEffect, useRef, useState } from 'react'
import type { StackProgress, StackStatus } from '@/types'
import { getStackProgress } from '@/services/stack.service'

/** Statuses during which a determinate progress bar is meaningful. */
const IN_PROGRESS = new Set<StackStatus>([
    'pending',
    'deploying',
    'ec2_booting',
    'refreshing',
])

const POLL_INTERVAL_MS = 3000

interface DeploymentProgressProps {
    stackId: string
    status: StackStatus
}

export function DeploymentProgress({ stackId, status }: DeploymentProgressProps) {
    const [progress, setProgress] = useState<StackProgress | null>(null)
    const activeRef = useRef(true)

    useEffect(() => {
        activeRef.current = true
        if (!IN_PROGRESS.has(status)) {
            setProgress(null)
            return
        }

        const poll = async () => {
            try {
                const p = await getStackProgress(stackId)
                if (activeRef.current) setProgress(p)
            } catch {
                // Transient errors are non-fatal — the next tick retries.
            }
        }

        poll()
        const timer = setInterval(poll, POLL_INTERVAL_MS)
        return () => {
            activeRef.current = false
            clearInterval(timer)
        }
    }, [stackId, status])

    if (!IN_PROGRESS.has(status)) return null

    const pct = Math.min(100, Math.max(0, progress?.percentage ?? 0))
    const created = progress?.resources_created ?? 0
    const total = progress?.total_resources ?? 0

    return (
        <div className="mt-3">
            <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-[10px] uppercase tracking-[1px] text-content-dim">
                    Deployment Progress
                </span>
                <span className="font-mono text-[11px] font-semibold text-accent-blue tabular-nums">
                    {pct}%
                </span>
            </div>
            <div className="h-2 w-full rounded-full bg-surface-base border border-border overflow-hidden">
                <div
                    className="h-full rounded-full bg-accent-blue transition-[width] duration-500 ease-out"
                    style={{
                        width: `${pct}%`,
                        boxShadow: '0 0 12px hsla(202,100%,67%,0.5)',
                    }}
                />
            </div>
            {total > 0 && (
                <div className="font-mono text-[10px] text-content-dim mt-1 tabular-nums">
                    {created} / {total} resources provisioned
                </div>
            )}
        </div>
    )
}
