import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import type { Stack, StackStatus } from '@/types'
import { Badge } from '@/components/ui/Badge'
import { IconClose } from '@/components/ui/Icons'
import {
    deriveHealth,
    STACK_HEALTH,
    formatAge,
    formatExpiry,
    emulationLabel,
    isTtlExpired,
} from '@/components/dashboard/stackHelpers'
import { ResourceMapModal } from '@/components/modals/ResourceMapModal'
import { DeploymentProgress } from './DeploymentProgress'
import { DeploymentLogsPanel, isLogLive } from './DeploymentLogsPanel'
import { LifecycleTrack } from './LifecycleTrack'
import { SecurityContextTab } from './SecurityContextTab'

/**
 * One stack's full detail, slid in from the right over the list.
 *
 * The list used to expand a card in place, which grew the page by the height of
 * a detail panel every time somebody opened one. With a dozen stacks that made
 * scrolling back to a filter bar a chore, and the panel a reader had open was
 * usually off-screen by the time they had scrolled to it. The panel is a fixed
 * surface: the list keeps its scroll position and its filters behind it.
 *
 * Deployment logs are rendered here rather than behind a button. They are the
 * first thing anyone wants while a deploy runs or after one fails, so putting
 * them one click away put the answer further from the reader than the question.
 *
 * Every fact and action the expanded card carried is here: health, metadata,
 * measured lifecycle, live progress, resource inventory and map, outputs,
 * security context, deploy, destroy and force destroy.
 */

/** Half the viewport, within bounds that stay readable on either extreme. */
const PANEL_WIDTH = 'w-full sm:w-[min(760px,52vw)] sm:min-w-[480px]'

/** Statuses where an emulation stack may hold live AWS resources to force-destroy. */
const EMULATION_DESTROYABLE = new Set<StackStatus>([
    'deploying',
    'ec2_booting',
    'ready_for_attack',
    'attacking',
    'attack_complete',
    'failed',
])

interface StackDrawerProps {
    stack: Stack
    isBusy: boolean
    actionMsg?: string
    onAction: (action: 'deploy' | 'destroy') => void
    onForceDestroy: () => void
    onClose: () => void
}

export function StackDrawer({
    stack, isBusy, actionMsg, onAction, onForceDestroy, onClose,
}: StackDrawerProps) {
    const [shown, setShown] = useState(false)
    const [mapOpen, setMapOpen] = useState(false)
    const [confirmForceDestroy, setConfirmForceDestroy] = useState(false)

    const health = deriveHealth(stack)
    const meta = STACK_HEALTH[health]
    const showForceDestroy = !!stack.emulation_type && EMULATION_DESTROYABLE.has(stack.status)
    const resources = stack.resource_summary

    // Mount off-screen, then slide in on the next frame.
    useEffect(() => {
        const frame = window.requestAnimationFrame(() => setShown(true))
        return () => window.cancelAnimationFrame(frame)
    }, [])

    useEffect(() => {
        function onKey(event: KeyboardEvent) {
            // The resource map sits above the panel, so it closes first.
            if (event.key === 'Escape' && !mapOpen) onClose()
        }
        document.addEventListener('keydown', onKey)
        const previous = document.body.style.overflow
        document.body.style.overflow = 'hidden'
        return () => {
            document.removeEventListener('keydown', onKey)
            document.body.style.overflow = previous
        }
    }, [onClose, mapOpen])

    return (
        <div className="fixed inset-0 z-[200] flex justify-end" role="dialog" aria-modal="true">
            <div
                onClick={onClose}
                aria-hidden="true"
                className={`absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300
                    ${shown ? 'opacity-100' : 'opacity-0'}`}
            />

            <aside
                className={`relative h-full ${PANEL_WIDTH} bg-surface-base border-l border-border
                    shadow-float flex flex-col transition-transform duration-300 ease-out
                    ${shown ? 'translate-x-0' : 'translate-x-full'}`}
            >
                <header className="flex items-start gap-3 px-5 py-4 border-b border-border shrink-0">
                    <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                            <h2 className="font-display text-lg font-semibold text-content-primary leading-tight truncate">
                                {stack.name}
                            </h2>
                            <Badge tone={meta.tone} mono dot pulse={meta.pulse}>
                                {meta.label}
                            </Badge>
                        </div>
                        {stack.emulation_type ? (
                            <Link
                                to={`/aws/emulations/${stack.emulation_type}`}
                                title="View this emulation"
                                className="inline-flex items-center gap-1 mt-1 font-mono text-[11px] text-content-dim
                                    no-underline transition-colors hover:text-accent-blue"
                            >
                                {emulationLabel(stack.emulation_type)}
                                <span aria-hidden="true">&#8599;</span>
                            </Link>
                        ) : (
                            <p className="mt-1 font-mono text-[11px] text-content-dim">Infrastructure Stack</p>
                        )}
                    </div>

                    <button
                        type="button"
                        onClick={onClose}
                        aria-label="Close"
                        className="shrink-0 p-1.5 rounded-btn text-content-dim
                            transition-colors hover:text-content-primary"
                    >
                        <IconClose size={16} />
                    </button>
                </header>

                <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-6">
                    {/* Live deploy bar, only while something is running. */}
                    <DeploymentProgress stackId={stack.id} status={stack.status} />

                    {/* Measured phases. Absent entirely when nothing was recorded. */}
                    {(stack.lifecycle?.length ?? 0) > 0 && (
                        <Section title="Lifecycle">
                            <LifecycleTrack stack={stack} />
                        </Section>
                    )}

                    <Section
                        title="Deployment logs"
                        aside={isLogLive(stack.status) ? <LiveTag /> : undefined}
                    >
                        <DeploymentLogsPanel
                            stackId={stack.id}
                            status={stack.status}
                            initialLogs={stack.last_logs}
                            error={stack.last_error}
                        />
                    </Section>

                    <Section title="Overview">
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-5 gap-y-3">
                            <Fact label="Region" value={stack.region} />
                            <Fact label="Owner" value={stack.owner} />
                            <Fact label="Status" value={stack.status.toUpperCase()} />
                            <Fact label="Created" value={new Date(stack.created_at).toLocaleString()} />
                            <Fact label="Last update" value={`${formatAge(stack.updated_at)} ago`} />
                            {stack.expires_at && (
                                <Fact
                                    label={isTtlExpired(stack) ? 'TTL' : 'Expires in'}
                                    value={isTtlExpired(stack) ? 'expired' : formatExpiry(stack.expires_at)}
                                    valueClass={isTtlExpired(stack) ? 'text-warning' : ''}
                                />
                            )}
                        </div>
                    </Section>

                    <Section title="Resources" aside={
                        resources && resources.total > 0
                            ? <span className="font-mono text-2xs text-content-secondary">{resources.total}</span>
                            : undefined
                    }>
                        {resources && resources.total > 0 ? (
                            <>
                                <div className="flex flex-wrap gap-1.5">
                                    {Object.entries(resources.by_type).map(([svc, count]) => (
                                        <span
                                            key={svc}
                                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-btn
                                                bg-surface-base border border-border font-mono text-[10px]
                                                text-content-secondary"
                                        >
                                            {svc} <span className="text-content-primary font-semibold">{count}</span>
                                        </span>
                                    ))}
                                </div>
                                <button
                                    type="button"
                                    onClick={() => setMapOpen(true)}
                                    disabled={!resources.resources?.length}
                                    className="mt-3 px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn
                                        border border-border text-content-primary shadow-button
                                        transition-opacity hover:opacity-60
                                        disabled:opacity-30 disabled:cursor-not-allowed"
                                >
                                    Open resource map
                                </button>
                            </>
                        ) : (
                            <p className="text-xs text-content-dim leading-relaxed">
                                No resource inventory yet. Deploy the stack to populate its resource map.
                            </p>
                        )}
                    </Section>

                    <Section title="Security context">
                        <SecurityContextTab emulationType={stack.emulation_type} />
                    </Section>

                    <Section title="Technical detail">
                        <div className="flex flex-col gap-3">
                            <Fact label="Stack ID" value={stack.id} mono />
                            <Fact
                                label="Phase history"
                                value={
                                    stack.lifecycle?.length
                                        ? `${stack.lifecycle.length} transitions recorded`
                                        : 'Not recorded. This stack predates phase timing; it is captured from the next status change onwards.'
                                }
                            />
                            <Fact
                                label="Outputs"
                                value={
                                    Object.keys(stack.outputs).length > 0
                                        ? JSON.stringify(stack.outputs, null, 2)
                                        : '(none)'
                                }
                                mono
                                pre
                            />
                        </div>
                    </Section>
                </div>

                <footer className="shrink-0 px-5 py-3.5 border-t border-border">
                    <div className="flex flex-wrap items-center gap-2">
                        <ActionBtn label="Deploy" variant="safe" disabled={isBusy} onClick={() => onAction('deploy')} />
                        <ActionBtn label="Destroy" variant="orange" disabled={isBusy} onClick={() => onAction('destroy')} />

                        {showForceDestroy && (
                            <>
                                <div className="w-px h-6 bg-border mx-0.5" />
                                {confirmForceDestroy ? (
                                    <>
                                        <button
                                            type="button"
                                            onClick={() => { setConfirmForceDestroy(false); onForceDestroy() }}
                                            className="px-3 py-1.5 rounded-btn font-mono text-[10px] font-medium
                                                border border-orange-500/60 text-orange-400 bg-transparent
                                                cursor-pointer transition-opacity hover:opacity-60"
                                        >
                                            Destroy AWS resources
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => setConfirmForceDestroy(false)}
                                            className="px-3 py-1.5 rounded-btn font-mono text-[10px]
                                                text-content-dim bg-transparent border-none cursor-pointer
                                                transition-opacity hover:opacity-60"
                                        >
                                            Cancel
                                        </button>
                                    </>
                                ) : (
                                    <button
                                        type="button"
                                        onClick={() => setConfirmForceDestroy(true)}
                                        disabled={stack.status === 'destroying'}
                                        title="Force-destroy emulation stack and all AWS resources"
                                        className="px-3 py-1.5 rounded-btn font-mono text-[10px] font-medium
                                            bg-transparent border border-orange-500/30 text-orange-400
                                            cursor-pointer transition-opacity hover:opacity-60
                                            disabled:opacity-30 disabled:cursor-not-allowed"
                                    >
                                        Force Destroy
                                    </button>
                                )}
                            </>
                        )}
                    </div>

                    {actionMsg && (
                        <div
                            className={`mt-2 font-mono text-[11px] flex items-center gap-2 ${
                                actionMsg.startsWith('Error')
                                    ? 'text-danger'
                                    : actionMsg.includes('successfully') || actionMsg.includes('completed')
                                        ? 'text-safe'
                                        : 'text-accent-blue'
                            }`}
                        >
                            {isBusy && (
                                <span className="inline-block w-2.5 h-2.5 border-2 border-current
                                    border-t-transparent rounded-full animate-spin" />
                            )}
                            {actionMsg}
                        </div>
                    )}
                </footer>
            </aside>

            {mapOpen && <ResourceMapModal stack={stack} onClose={() => setMapOpen(false)} />}
        </div>
    )
}

/* ── Sub-components ── */

/** A labelled block within the panel, with an optional right-hand note. */
function Section({
    title, aside, children,
}: {
    title: string
    aside?: React.ReactNode
    children: React.ReactNode
}) {
    return (
        <section>
            <div className="flex items-baseline gap-2 mb-2.5">
                <h3 className="font-mono text-2xs uppercase tracking-label text-content-dim">{title}</h3>
                {aside && <span className="ml-auto">{aside}</span>}
            </div>
            {children}
        </section>
    )
}

/** The live indicator beside the logs heading. */
function LiveTag() {
    return (
        <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-accent-blue">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-blue animate-pulse" />
            LIVE
        </span>
    )
}

/** One label and its value. */
function Fact({
    label, value, mono = false, pre = false, valueClass = '',
}: {
    label: string
    value: string
    mono?: boolean
    pre?: boolean
    valueClass?: string
}) {
    return (
        <div className="min-w-0">
            <div className="font-mono text-[9px] uppercase tracking-[1px] text-content-dim mb-0.5">
                {label}
            </div>
            <div
                className={`text-[11px] leading-relaxed text-content-secondary
                    ${mono ? 'font-mono' : ''}
                    ${pre ? 'whitespace-pre-wrap break-words' : 'break-words'}
                    ${valueClass}`}
                title={pre ? undefined : value}
            >
                {value}
            </div>
        </div>
    )
}

function ActionBtn({
    label, variant, disabled, onClick,
}: {
    label: string
    variant: 'safe' | 'orange'
    disabled: boolean
    onClick: () => void
}) {
    const tone = variant === 'safe'
        ? 'border-safe/30 text-safe'
        : 'border-orange-500/30 text-orange-400'

    return (
        <button
            type="button"
            onClick={onClick}
            disabled={disabled}
            className={`px-3 py-1.5 rounded-btn font-mono text-[10px] font-medium bg-transparent
                border cursor-pointer transition-opacity hover:opacity-60
                disabled:opacity-30 disabled:cursor-not-allowed ${tone}`}
        >
            {label}
        </button>
    )
}
