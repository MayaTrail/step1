import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { IconActivity } from '@/components/ui/Icons'
import { listLogs } from '@/services/log.service'
import type { LogEntry, LogLevel } from '@/types/log'

/**
 * Recent Activity feed.
 *
 * Bound to the real audit log (/api/logs/): stack and emulation lifecycle
 * events relevant to the signed-in user, newest first.  Each row is toned by
 * its event (or severity level as a fallback) and deep-links to the Stacks
 * section when it references a stack.
 */

type FeedTone = 'red' | 'yellow' | 'blue' | 'green' | 'neutral'

/** Display label + tone for well-known events. */
const EVENT_META: Record<string, { label: string; tone: FeedTone }> = {
    'stack.deployed': { label: 'Stack deployed', tone: 'blue' },
    'stack.destroyed': { label: 'Stack destroyed', tone: 'neutral' },
    'emulation.started': { label: 'Emulation started', tone: 'blue' },
    'emulation.completed': { label: 'Emulation completed', tone: 'green' },
    'emulation.failed': { label: 'Emulation failed', tone: 'red' },
}

/** Fallback tone derived from the log level when the event is unknown. */
const LEVEL_TONE: Record<LogLevel, FeedTone> = {
    error: 'red',
    warning: 'yellow',
    info: 'neutral',
}

const dotClass: Record<FeedTone, string> = {
    red: 'text-danger',
    yellow: 'text-warning',
    blue: 'text-accent-blue',
    green: 'text-safe',
    neutral: 'text-content-dim',
}

/** Title-case a raw event name as a fallback label ("stack.deployed" -> "Stack Deployed"). */
function fallbackLabel(event: string): string {
    return event
        .replace(/[._-]+/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase())
}

/** Coarse "x ago" label from an ISO timestamp. */
function timeAgo(iso: string): string {
    const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
    if (Number.isNaN(seconds)) return ''
    if (seconds < 60) return 'just now'
    const minutes = Math.round(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.round(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    return `${Math.round(hours / 24)}d ago`
}

function FeedRow({ entry }: { entry: LogEntry }) {
    const navigate = useNavigate()
    const meta = EVENT_META[entry.event]
    const tone = meta?.tone ?? LEVEL_TONE[entry.level] ?? 'neutral'
    const label = meta?.label ?? fallbackLabel(entry.event)
    const linked = Boolean(entry.stack)

    const content = (
        <>
            <span className={`mt-1 shrink-0 ${dotClass[tone]}`}>
                <span className="block w-1.5 h-1.5 rounded-full bg-current" />
            </span>
            <span className="min-w-0">
                <span className="block text-xs text-content-secondary leading-relaxed">
                    <span className="font-mono uppercase text-content-dim">{label}</span>
                    {entry.message ? <> · {entry.message}</> : null}
                </span>
                <span className="block font-mono text-2xs text-content-muted mt-1">{timeAgo(entry.timestamp)}</span>
            </span>
        </>
    )

    if (!linked) {
        return <div className="flex items-start gap-3 px-4 py-3">{content}</div>
    }
    return (
        <button
            type="button"
            onClick={() => navigate('/stacks')}
            className="flex items-start gap-3 px-4 py-3 text-left transition-opacity hover:opacity-70"
        >
            {content}
        </button>
    )
}

export function ActivityFeed() {
    const [entries, setEntries] = useState<LogEntry[]>([])
    const [loading, setLoading] = useState(true)
    const [failed, setFailed] = useState(false)

    useEffect(() => {
        let active = true
        listLogs()
            .then((data) => active && setEntries(data))
            .catch(() => active && setFailed(true))
            .finally(() => active && setLoading(false))
        return () => {
            active = false
        }
    }, [])

    return (
        <Card className="flex flex-col">
            <div className="flex items-center justify-between px-4 py-3.5 border-b border-border">
                <span className="flex items-center gap-2 font-mono text-2xs uppercase tracking-label text-content-dim">
                    <IconActivity size={14} />
                    Recent Activity
                </span>
                {!loading && !failed && entries.length > 0 && (
                    <Badge tone="neutral" mono>
                        {entries.length}
                    </Badge>
                )}
            </div>

            {loading ? (
                <div className="flex flex-col divide-y divide-border" aria-hidden="true">
                    {Array.from({ length: 4 }).map((_, i) => (
                        <div key={i} className="flex items-start gap-3 px-4 py-3">
                            <span className="mt-1 block w-1.5 h-1.5 rounded-full bg-surface-elevated" />
                            <span className="flex flex-col gap-1.5 flex-1">
                                <span className="h-3 w-2/3 rounded-sm bg-surface-elevated" />
                                <span className="h-2 w-16 rounded-sm bg-surface-elevated" />
                            </span>
                        </div>
                    ))}
                </div>
            ) : failed ? (
                <div className="px-4 py-10 text-center text-sm text-content-dim">
                    Activity is unavailable right now.
                </div>
            ) : entries.length === 0 ? (
                <div className="px-4 py-10 text-center text-sm text-content-dim">
                    No recent activity yet.
                </div>
            ) : (
                <div className="flex flex-col divide-y divide-border max-h-96 overflow-y-auto">
                    {entries.map((entry) => (
                        <FeedRow key={entry.id} entry={entry} />
                    ))}
                </div>
            )}
        </Card>
    )
}
