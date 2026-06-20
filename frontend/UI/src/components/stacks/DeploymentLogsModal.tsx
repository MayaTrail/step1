/**
 * DeploymentLogsModal — chronological deployment activity for a stack.
 *
 * Sources, in priority order:
 *   - While the stack is in an in-progress status, it polls the live progress
 *     endpoint's `recent_logs` so the view updates as the deploy runs.
 *   - Otherwise it shows the persisted `last_logs` from the stack record (the
 *     full tail of the most recent run), plus the persisted failure reason.
 *
 * Persisted lines carry a timestamp; live lines do not (they are the raw tail
 * held in Redis), so the timestamp column is rendered only when present.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { StackLogEntry, StackStatus } from '@/types'
import { getStackProgress } from '@/services/stack.service'

const LIVE_STATUSES = new Set<StackStatus>([
    'pending',
    'deploying',
    'ec2_booting',
    'refreshing',
    'destroying',
])

const POLL_INTERVAL_MS = 3000

/** A normalized log line — timestamp optional (live lines have none). */
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

interface DeploymentLogsModalProps {
    stackId: string
    stackName: string
    status: StackStatus
    /** Persisted log of the most recent run (from the stack record). */
    initialLogs?: StackLogEntry[]
    /** Persisted failure reason, if the last run failed. */
    error?: string
    onClose: () => void
}

export function DeploymentLogsModal({
    stackId, stackName, status, initialLogs, error, onClose,
}: DeploymentLogsModalProps) {
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
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
            onClick={onClose}
        >
            <div
                className="bg-surface-card border border-border rounded-card w-full max-w-[680px] shadow-float max-h-[85vh] flex flex-col animate-modalIn"
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-border shrink-0">
                    <div>
                        <div className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim mb-1">
                            Deployment Logs
                        </div>
                        <div className="font-display text-[1.1rem] font-bold text-content-primary leading-tight">
                            {stackName}
                        </div>
                    </div>
                    <div className="flex items-center gap-3">
                        {isLive && (
                            <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-accent-blue">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-blue animate-pulse" />
                                LIVE
                            </span>
                        )}
                        <button
                            onClick={onClose}
                            className="text-content-dim hover:text-content-primary transition-opacity hover:opacity-60
                                text-xl leading-none cursor-pointer bg-transparent border-none p-1"
                            aria-label="Close"
                        >
                            &#10005;
                        </button>
                    </div>
                </div>

                {/* Body */}
                <div className="px-6 py-5 overflow-y-auto flex-1">
                    {/* Failure reason banner */}
                    {error && (
                        <div className="bg-danger/[0.08] border border-danger/20 rounded-btn px-4 py-3 mb-4">
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
                        <div className="bg-surface-base border border-border rounded-btn px-4 py-6 text-center">
                            <div className="font-body text-[0.9rem] text-content-secondary mb-1">
                                No deployment logs yet.
                            </div>
                            <div className="font-mono text-[11px] text-content-dim leading-[1.6]">
                                Logs are captured on the next deploy, destroy, or refresh.
                            </div>
                        </div>
                    ) : (
                        <pre
                            ref={preRef}
                            className="bg-[#07080a] border border-border rounded-btn p-4 font-mono text-[11px] leading-[1.7]
                                text-content-secondary overflow-auto max-h-[420px] whitespace-pre-wrap break-words"
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

                {/* Footer */}
                <div className="flex items-center justify-end px-6 py-4 border-t border-border shrink-0">
                    <button
                        onClick={onClose}
                        className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                            bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                            hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
    )
}
