/**
 * StackCard — a single stack rendered as an operational card.
 *
 * Replaces the old dense list row. Surfaces — without expanding — the health
 * label, key metadata, and (while deploying) a live progress bar, so an
 * operator can answer "what is this and is it OK?" at a glance.
 *
 * Presentational: all stack operations are delegated to the parent via
 * callbacks. The only state owned here is the ephemeral two-click confirmation
 * for the destructive Destroy / Delete actions.
 *
 * Note: the resource-count summary from the wireframe is intentionally deferred
 * to Phase 2, when the backend persists an actual (Pulumi-state-derived)
 * inventory. Phase 1 does not fabricate counts.
 */

import { useState, lazy, Suspense } from 'react'
import type { Stack, StackStatus } from '@/types'
import { Badge } from '@/components/ui/Badge'
import {
    deriveHealth,
    STACK_HEALTH,
    formatAge,
    formatExpiry,
    emulationLabel,
    isTtlExpired,
} from '@/components/dashboard/stackHelpers'
import { DeploymentProgress } from './DeploymentProgress'
import { LifecycleTimeline } from './LifecycleTimeline'
import { SecurityContextTab } from './SecurityContextTab'

// Lazy-loaded so the dagre layout library (graphlib + lodash) is code-split
// into its own chunk and only fetched when a user opens the Resource Graph tab.
const InfraGraphView = lazy(() =>
    import('./InfraGraphView').then((m) => ({ default: m.InfraGraphView })),
)

export type StackDetailView = 'details' | 'lifecycle' | 'security' | 'graph'

/** Statuses where an emulation stack may hold live AWS resources to force-destroy. */
const EMULATION_DESTROYABLE = new Set<StackStatus>([
    'deploying',
    'ec2_booting',
    'ready_for_attack',
    'attacking',
    'attack_complete',
    'failed',
])

interface StackCardProps {
    stack: Stack
    isBusy: boolean
    isExpanded: boolean
    onToggleExpand: () => void
    detailView: StackDetailView
    onDetailViewChange: (v: StackDetailView) => void
    actionMsg?: string
    onAction: (action: 'deploy' | 'destroy') => void
    onOpenLogs: () => void
    onDelete: () => void
    onForceDestroy: () => void
}

export function StackCard({
    stack,
    isBusy,
    isExpanded,
    onToggleExpand,
    detailView,
    onDetailViewChange,
    actionMsg,
    onAction,
    onOpenLogs,
    onDelete,
    onForceDestroy,
}: StackCardProps) {
    const [confirmDelete, setConfirmDelete] = useState(false)
    const [confirmForceDestroy, setConfirmForceDestroy] = useState(false)

    const health = deriveHealth(stack)
    const meta = STACK_HEALTH[health]
    const accent =
        health === 'active' ? 'bg-safe'
            : health === 'failed' ? 'bg-danger'
                : health === 'deploying' ? 'bg-accent-blue'
                    : health === 'stale' ? 'bg-warning'
                        : 'bg-border'

    const showForceDestroy = !!stack.emulation_type && EMULATION_DESTROYABLE.has(stack.status)

    return (
        <div className="group">
            {/* Card */}
            <div
                className={`relative overflow-hidden bg-surface-card border rounded-card px-5 py-4 cursor-pointer
                    transition-all duration-200
                    ${isExpanded
                        ? 'border-accent-blue/30 rounded-b-none'
                        : 'border-border hover:border-border-active hover:-translate-y-px hover:shadow-[0_4px_20px_rgba(0,0,0,0.3)]'}`}
                onClick={onToggleExpand}
            >
                {/* Left health accent */}
                <div className={`absolute left-0 top-0 bottom-0 w-[3px] ${accent}`} />

                {/* Header: name + health badge */}
                <div className="flex items-start justify-between gap-3 ml-1.5">
                    <div className="min-w-0">
                        <div className="flex items-center gap-2.5 mb-0.5">
                            <span className="font-display text-[1rem] font-bold text-content-primary truncate">
                                {stack.name}
                            </span>
                            <Badge tone={meta.tone} mono dot pulse={meta.pulse}>
                                {meta.label}
                            </Badge>
                        </div>
                        <div className="font-mono text-[11px] text-content-dim">
                            {stack.emulation_type ? emulationLabel(stack.emulation_type) : 'Infrastructure Stack'}
                        </div>
                    </div>

                    {/* Logs quick action — always available */}
                    <div className="shrink-0" onClick={(e) => e.stopPropagation()}>
                        <button
                            onClick={onOpenLogs}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-btn font-mono text-[10px] font-medium cursor-pointer
                                bg-transparent border border-border text-content-secondary transition-all
                                hover:border-accent-blue/40 hover:text-accent-blue hover:bg-accent-blue/[0.06]"
                            title="View deployment logs"
                        >
                            <LogsIcon /> Logs
                        </button>
                    </div>
                </div>

                {/* Metadata grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-2 mt-3 ml-1.5">
                    <Meta label="Region" value={stack.region} />
                    <Meta label="Owner" value={stack.owner} />
                    <Meta label="Created" value={new Date(stack.created_at).toLocaleDateString()} />
                    <Meta
                        label="Last Update"
                        value={`${formatAge(stack.updated_at)} ago`}
                    />
                    {stack.expires_at && (
                        <Meta
                            label={isTtlExpired(stack) ? 'TTL' : 'Expires In'}
                            value={isTtlExpired(stack) ? 'expired' : formatExpiry(stack.expires_at)}
                            valueClass={isTtlExpired(stack) ? 'text-warning' : ''}
                        />
                    )}
                </div>

                {/* Resource summary (actual inventory from Pulumi state) */}
                {stack.resource_summary && stack.resource_summary.total > 0 && (
                    <div className="mt-3 ml-1.5">
                        <div className="font-mono text-[9px] uppercase tracking-[1px] text-content-dim mb-1.5">
                            Resources <span className="text-content-secondary">{stack.resource_summary.total}</span>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                            {Object.entries(stack.resource_summary.by_type).map(([svc, count]) => (
                                <span
                                    key={svc}
                                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-btn bg-surface-base border border-border
                                        font-mono text-[10px] text-content-secondary"
                                >
                                    {svc} <span className="text-content-primary font-semibold">{count}</span>
                                </span>
                            ))}
                        </div>
                    </div>
                )}

                {/* Live progress bar (deploying only) */}
                <div className="ml-1.5">
                    <DeploymentProgress stackId={stack.id} status={stack.status} />
                </div>

                {/* Action row */}
                <div
                    className="flex flex-wrap items-center gap-2 mt-4 ml-1.5"
                    onClick={(e) => e.stopPropagation()}
                >
                    <ActionBtn label="Deploy" variant="safe" disabled={isBusy} onClick={() => onAction('deploy')} />
                    <ActionBtn label="Destroy" variant="orange" disabled={isBusy} onClick={() => onAction('destroy')} />

                    {showForceDestroy && (
                        <>
                            <div className="w-px h-6 bg-border mx-0.5" />
                            {confirmForceDestroy ? (
                                <ConfirmPair
                                    prompt="Destroy AWS resources?"
                                    tone="orange"
                                    onConfirm={() => { setConfirmForceDestroy(false); onForceDestroy() }}
                                    onCancel={() => setConfirmForceDestroy(false)}
                                />
                            ) : (
                                <button
                                    onClick={() => setConfirmForceDestroy(true)}
                                    disabled={stack.status === 'destroying'}
                                    title="Force-destroy emulation stack and all AWS resources"
                                    className="px-3 py-1.5 rounded-btn font-mono text-[10px] font-medium cursor-pointer
                                        bg-transparent border border-orange-500/30 text-orange-400 transition-all
                                        hover:border-orange-500/60 hover:bg-orange-500/[0.08]
                                        disabled:opacity-30 disabled:cursor-not-allowed"
                                >
                                    Force Destroy
                                </button>
                            )}
                        </>
                    )}

                    <div className="flex-1" />

                    {confirmDelete ? (
                        <ConfirmPair
                            prompt="Delete record?"
                            tone="danger"
                            onConfirm={() => { setConfirmDelete(false); onDelete() }}
                            onCancel={() => setConfirmDelete(false)}
                        />
                    ) : (
                        <button
                            onClick={() => setConfirmDelete(true)}
                            disabled={isBusy}
                            title="Delete stack record"
                            className="px-2.5 py-1.5 rounded-btn font-mono text-[10px] text-content-dim cursor-pointer
                                bg-transparent border border-transparent transition-all
                                hover:border-danger/30 hover:text-danger hover:bg-danger/[0.06]
                                disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                            Delete
                        </button>
                    )}
                </div>

                {/* Action message */}
                {actionMsg && (
                    <div
                        className={`mt-2 ml-1.5 font-mono text-[11px] flex items-center gap-2 ${actionMsg.startsWith('Error')
                            ? 'text-danger'
                            : actionMsg.includes('successfully') || actionMsg.includes('completed')
                                ? 'text-safe'
                                : 'text-accent-blue'}`}
                    >
                        {isBusy && (
                            <span className="inline-block w-2.5 h-2.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
                        )}
                        {actionMsg}
                    </div>
                )}
            </div>

            {/* Expanded detail panel */}
            {isExpanded && (
                <div className="bg-surface-base border border-accent-blue/30 border-t-0 rounded-b-card px-6 py-4 animate-slideUp">
                    {/* Tabs */}
                    <div className="flex items-center gap-1 mb-4">
                        <DetailTab label="Details" active={detailView === 'details'} onClick={() => onDetailViewChange('details')} />
                        <DetailTab label="Lifecycle" active={detailView === 'lifecycle'} onClick={() => onDetailViewChange('lifecycle')} />
                        <DetailTab label="Security" active={detailView === 'security'} onClick={() => onDetailViewChange('security')} />
                        <DetailTab label="Resource Graph" active={detailView === 'graph'} onClick={() => onDetailViewChange('graph')} />
                        <div className="flex-1 h-px bg-border ml-2" />
                    </div>

                    {detailView === 'details' && (
                        <div className="grid grid-cols-2 gap-x-8 gap-y-3">
                            <DetailRow label="Stack ID" value={stack.id} mono />
                            <DetailRow label="Name" value={stack.name} />
                            <DetailRow label="Region" value={stack.region} />
                            <DetailRow label="Status" value={stack.status.toUpperCase()} />
                            <DetailRow label="Owner" value={stack.owner} />
                            <DetailRow label="Created" value={new Date(stack.created_at).toLocaleString()} />
                            <DetailRow label="Updated" value={new Date(stack.updated_at).toLocaleString()} />
                            <DetailRow
                                label="Outputs"
                                value={Object.keys(stack.outputs).length > 0 ? JSON.stringify(stack.outputs, null, 2) : '(none)'}
                                mono
                            />
                        </div>
                    )}

                    {detailView === 'lifecycle' && (
                        <LifecycleTimeline stack={stack} failureReason={stack.last_error} />
                    )}

                    {detailView === 'security' && <SecurityContextTab emulationType={stack.emulation_type} />}

                    {detailView === 'graph' && (
                        <Suspense fallback={
                            <div className="flex items-center gap-2 text-content-dim font-mono text-xs py-8 justify-center">
                                <span className="inline-block w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
                                Loading graph…
                            </div>
                        }>
                            <InfraGraphView stack={stack} />
                        </Suspense>
                    )}
                </div>
            )}
        </div>
    )
}

/* ── Sub-components ── */

function Meta({ label, value, valueClass = '' }: { label: string; value: string; valueClass?: string }) {
    return (
        <div className="min-w-0">
            <div className="font-mono text-[9px] uppercase tracking-[1px] text-content-dim mb-0.5">{label}</div>
            <div className={`font-mono text-[11px] text-content-secondary truncate ${valueClass}`} title={value}>
                {value}
            </div>
        </div>
    )
}

function ActionBtn({
    label, variant, disabled, onClick,
}: {
    label: string
    variant: 'safe' | 'orange' | 'blue' | 'purple'
    disabled: boolean
    onClick: () => void
}) {
    const styles: Record<string, string> = {
        safe: 'hover:border-safe/40 hover:text-safe hover:bg-safe/[0.06]',
        orange: 'hover:border-orange-500/40 hover:text-orange-400 hover:bg-orange-500/[0.06]',
        blue: 'hover:border-accent-blue/40 hover:text-accent-blue hover:bg-accent-blue/[0.06]',
        purple: 'hover:border-purple/40 hover:text-purple hover:bg-purple/[0.06]',
    }
    return (
        <button
            onClick={onClick}
            disabled={disabled}
            className={`px-3 py-1.5 rounded-btn font-mono text-[10px] font-medium cursor-pointer
                bg-transparent border border-border text-content-secondary transition-all ${styles[variant]}
                disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:border-border disabled:hover:bg-transparent disabled:hover:text-content-secondary`}
        >
            {label}
        </button>
    )
}

function ConfirmPair({
    prompt, tone, onConfirm, onCancel,
}: {
    prompt: string
    tone: 'danger' | 'orange'
    onConfirm: () => void
    onCancel: () => void
}) {
    const confirmCls =
        tone === 'danger'
            ? 'bg-danger text-white hover:shadow-[0_0_15px_rgba(255,99,99,0.4)]'
            : 'bg-orange-500 text-white hover:shadow-[0_0_15px_rgba(249,115,22,0.4)]'
    return (
        <div className="flex items-center gap-1.5">
            <span className={`font-mono text-[9px] mr-1 ${tone === 'danger' ? 'text-danger' : 'text-orange-400'}`}>
                {prompt}
            </span>
            <button
                onClick={onConfirm}
                className={`px-2.5 py-1.5 rounded-btn font-mono text-[10px] font-bold cursor-pointer border-none transition-all ${confirmCls}`}
            >
                Confirm
            </button>
            <button
                onClick={onCancel}
                className="px-2 py-1.5 rounded-btn font-mono text-[10px] cursor-pointer
                    bg-transparent border border-border text-content-dim hover:text-content-primary transition-colors"
            >
                &#10005;
            </button>
        </div>
    )
}

function DetailTab({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
    return (
        <button
            onClick={onClick}
            className={`px-3 py-1.5 rounded-btn font-mono text-[10px] font-medium cursor-pointer border transition-all
                ${active
                    ? 'bg-accent-blue/[0.1] border-accent-blue/30 text-accent-blue'
                    : 'bg-transparent border-transparent text-content-dim hover:text-content-primary hover:border-border'}`}
        >
            {label}
        </button>
    )
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
    return (
        <div>
            <div className="font-mono text-[9px] text-content-dim tracking-[1px] mb-0.5 uppercase">{label}</div>
            <div className={`text-[13px] text-content-primary ${mono ? 'font-mono text-[11px] break-all whitespace-pre-wrap' : 'font-body'}`}>
                {value}
            </div>
        </div>
    )
}

function LogsIcon() {
    return (
        <svg width="11" height="11" viewBox="0 0 12 12" fill="none" aria-hidden="true">
            <rect x="1.5" y="1.5" width="9" height="9" rx="1.5" stroke="currentColor" strokeWidth="1.1" />
            <path d="M3.5 4.5H8.5M3.5 6H8.5M3.5 7.5H6.5" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" />
        </svg>
    )
}
