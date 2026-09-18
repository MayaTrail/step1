import { useCallback, useEffect, useRef, useState } from 'react'
import type { StackLogEntry, StackStatus } from '@/types'
import { getStackProgress } from '@/services/stack.service'

/**
 * A stack's deployment log, as a panel rather than a modal.
 *
 * This replaced a modal opened from a Logs button. Logs are the first thing
 * anyone wants when a deploy is running or has just failed, so putting them
 * behind a button kept the answer one click further away than the question.
 *
 * Sources, in priority order:
 *   - While the stack is in an in-progress status it polls the live progress
 *     endpoint's `recent_logs`, so the view updates as the deploy runs.
 *   - Otherwise it shows the persisted `last_logs` from the stack record, plus
 *     the persisted failure reason.
 *
 * Persisted lines carry a timestamp; live lines do not, since they are the raw
 * tail held in Redis, so the timestamp column is rendered only when present.
 */

const LIVE_STATUSES = new Set<StackStatus>([
    'pending',
    'deploying',
    'ec2_booting',
    'refreshing',
    'destroying',
])

const POLL_INTERVAL_MS = 3000

/** A normalised log line. The timestamp is absent on live lines. */
interface LogLine {
    t?: string
    line: string
}

/** Heuristic: highlight lines that look like errors. */
function isErrorLine(line: string): boolean {
    return /\b(error|failed|denied|exception|cannot|unauthor)/i.test(line)
}

function formatTime(iso: string): string {
    const d = new Date(iso)
    return isNaN(d.getTime()) ? '' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

interface DeploymentLogsPanelProps {
    stackId: string
    status: StackStatus
    /** Persisted log of the most recent run, from the stack record. */
    initialLogs?: StackLogEntry[]
    /** Persisted failure reason, if the last run failed. */
    error?: string
    /** Tailwind max-height for the scroll region. */
    maxHeightClass?: string
}

export function DeploymentLogsPanel({
    stackId, status, initialLogs, error, maxHeightClass = 'max-h-[320px]',
}: DeploymentLogsPanelProps) {
    const isLive = LIVE_STATUSES.has(status)
    const persisted: LogLine[] = initialLogs ?? []

    const [liveLines, setLiveLines] = useState<LogLine[] | null>(null)
    const [loading, setLoading] = useState(isLive && persisted.length === 0)
    const preRef = useRef<HTMLPreElement>(null)
    const activeRef = useRef(true)

    const fetchLive = useCallback(async () => {
        try {
            const p = await getStackProgress(stackId)
            if (activeRef.current && p.recent_logs?.length) {
                setLiveLines(p.recent_logs.map((line) => ({ line })))
            }
        } catch {
            // Keep the last-known lines on a transient failure.
        } finally {
            if (activeRef.current) setLoading(false)
        }
    }, [stackId])

    useEffect(() => {
        activeRef.current = true
        if (!isLive) {
            setLoading(false)
            return
        }
        fetchLive()
        const timer = setInterval(fetchLive, POLL_INTERVAL_MS)
        return () => {
            activeRef.current = false
            clearInterval(timer)
        }
    }, [fetchLive, isLive])

    // Prefer live lines while deploying; otherwise show the persisted run.
    const lines: LogLine[] = isLive && liveLines ? liveLines : persisted

    // Auto-scroll to the newest line.
    useEffect(() => {
        if (preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight
    }, [lines])

    return (
        <div>
            {error && (
                <div className="bg-danger/[0.08] border border-danger/20 rounded-btn px-4 py-3 mb-3">
                    <div className="font-mono text-[10px] uppercase tracking-[1px] text-danger mb-1">
                        Failure Reason
                    </div>
                    <div className="font-mono text-[11px] text-content-secondary leading-[1.6] break-words whitespace-pre-wrap">
                        {error}
                    </div>
                </div>
            )}

            {loading ? (
                <div className="flex items-center gap-2 text-content-dim font-mono text-xs py-6">
                    <span className="inline-block w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
                    Loading logs…
                </div>
            ) : lines.length === 0 ? (
                <div className="bg-surface-base border border-border rounded-btn px-4 py-5 text-center">
                    <div className="text-[0.85rem] text-content-secondary mb-1">
                        No deployment logs yet.
                    </div>
                    <div className="font-mono text-[11px] text-content-dim leading-[1.6]">
                        Logs are captured on the next deploy, destroy, or refresh.
                    </div>
                </div>
            ) : (
                <pre
                    ref={preRef}
                    className={`bg-surface-deep border border-border rounded-btn p-3.5 font-mono text-[11px]
                        leading-[1.7] text-content-secondary overflow-auto whitespace-pre-wrap break-words
                        ${maxHeightClass}`}
                >
                    {lines.map((l, i) => (
                        <div key={i} className="flex gap-2">
                            {l.t && (
                                <span className="text-content-dim shrink-0 tabular-nums">{formatTime(l.t)}</span>
                            )}
                            <span className={isErrorLine(l.line) ? 'text-danger' : undefined}>
                                {l.line || ' '}
                            </span>
                        </div>
                    ))}
                </pre>
            )}
        </div>
    )
}

/** True when this stack's status means the log is still being written. */
export function isLogLive(status: StackStatus): boolean {
    return LIVE_STATUSES.has(status)
}
