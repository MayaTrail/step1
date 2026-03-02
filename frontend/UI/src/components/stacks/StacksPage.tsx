/**
 * StacksPage — full Infrastructure Stack management UI.
 *
 * Features:
 *   - List all stacks owned by the current user
 *   - Create a new stack
 *   - View stack details (expand row)
 *   - Deploy / Destroy / Refresh / Preview actions
 *   - Delete stack record
 *   - Live polling when an action is in progress
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import type { Stack, StackStatus, CreateStackRequest } from '@/types'
import {
    listStacks,
    getStack,
    createStack,
    deployStack,
    destroyStack,
    refreshStack,
    previewStack,
    deleteStack,
    pollStackUntilReady,
} from '@/services/stack.service'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { EmptyState } from '@/components/ui/EmptyState'

/* ── Status styling ── */
const STATUS_CONFIG: Record<StackStatus, { label: string; color: string; bg: string; dot?: string }> = {
    pending: { label: 'Pending', color: 'text-yellow-400', bg: 'bg-yellow-400/[0.08]', dot: 'bg-yellow-400' },
    deploying: { label: 'Deploying', color: 'text-accent-blue', bg: 'bg-accent-blue/[0.08]', dot: 'bg-accent-blue' },
    ready: { label: 'Ready', color: 'text-safe', bg: 'bg-safe/[0.08]', dot: 'bg-safe' },
    destroying: { label: 'Destroying', color: 'text-orange', bg: 'bg-orange/[0.08]', dot: 'bg-orange' },
    refreshing: { label: 'Refreshing', color: 'text-purple', bg: 'bg-purple/[0.08]', dot: 'bg-purple' },
    failed: { label: 'Failed', color: 'text-danger', bg: 'bg-danger/[0.08]', dot: 'bg-danger' },
}

const BUSY_STATUSES = new Set<StackStatus>(['deploying', 'destroying', 'refreshing'])

const REGIONS = [
    { value: 'ap-south-1', label: 'ap-south-1 (Mumbai)' },
    { value: 'us-east-1', label: 'us-east-1 (N. Virginia)' },
    { value: 'us-west-2', label: 'us-west-2 (Oregon)' },
    { value: 'eu-west-1', label: 'eu-west-1 (Ireland)' },
]

export function StacksPage() {
    const [stacks, setStacks] = useState<Stack[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    // Expanded detail row
    const [expandedId, setExpandedId] = useState<string | null>(null)

    // Create new stack
    const [showCreate, setShowCreate] = useState(false)
    const [newName, setNewName] = useState('')
    const [newRegion, setNewRegion] = useState('ap-south-1')
    const [creating, setCreating] = useState(false)

    // Action feedback
    const [actionMsg, setActionMsg] = useState<Record<string, string>>({})
    const [polling, setPolling] = useState<Set<string>>(new Set())
    const abortRefs = useRef<Map<string, AbortController>>(new Map())

    // Confirm delete
    const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)

    // ── Load stacks ──
    const loadStacks = useCallback(async () => {
        setLoading(true)
        setError(null)
        try {
            const data = await listStacks()
            setStacks(data)
        } catch {
            setError('Failed to load stacks.')
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { loadStacks() }, [loadStacks])

    // Cleanup all abort controllers on unmount
    useEffect(() => {
        return () => {
            abortRefs.current.forEach((c) => c.abort())
        }
    }, [])

    // ── Create stack ──
    const handleCreate = useCallback(async () => {
        if (!newName.trim()) return
        setCreating(true)
        setError(null)
        try {
            const payload: CreateStackRequest = { name: newName.trim(), region: newRegion }
            const stack = await createStack(payload)
            setStacks((prev) => [stack, ...prev])
            setNewName('')
            setShowCreate(false)
        } catch (err: unknown) {
            const apiErr = (err as { response?: { data?: Record<string, string[]> } })?.response?.data
            const msg = apiErr ? Object.values(apiErr).flat().join(' ') : 'Failed to create stack.'
            setError(msg)
        } finally {
            setCreating(false)
        }
    }, [newName, newRegion])

    // ── Stack action (deploy/destroy/refresh/preview) ──
    const handleAction = useCallback(async (
        stackId: string,
        action: 'deploy' | 'destroy' | 'refresh' | 'preview',
    ) => {
        const actionFn = { deploy: deployStack, destroy: destroyStack, refresh: refreshStack, preview: previewStack }[action]
        const label = action.charAt(0).toUpperCase() + action.slice(1)

        // Immediately mark as busy so all sibling action buttons get disabled
        setPolling((prev) => new Set(prev).add(stackId))
        setActionMsg((prev) => ({ ...prev, [stackId]: `${label} request sent...` }))
        setError(null)

        try {
            await actionFn(stackId)

            // Update status locally
            if (action !== 'preview') {
                const newStatus = action === 'deploy' ? 'deploying' : action === 'destroy' ? 'destroying' : 'refreshing'
                setStacks((prev) => prev.map((s) => s.id === stackId ? { ...s, status: newStatus as StackStatus } : s))
            }

            // Start polling
            const controller = new AbortController()
            abortRefs.current.set(stackId, controller)
            setActionMsg((prev) => ({
                ...prev,
                [stackId]: action === 'preview'
                    ? 'Preview running...'
                    : `${label}ing infrastructure... This may take a few minutes.`,
            }))

            const final = await pollStackUntilReady(
                stackId,
                3000,
                (updated) => {
                    setStacks((prev) => prev.map((s) => s.id === updated.id ? updated : s))
                },
                controller.signal,
            )

            setStacks((prev) => prev.map((s) => s.id === final.id ? final : s))
            setActionMsg((prev) => ({
                ...prev,
                [stackId]: final.status === 'ready'
                    ? `${label} completed successfully.`
                    : final.status === 'failed'
                        ? `${label} failed. Check logs.`
                        : `${label} finished. Status: ${final.status}`,
            }))
        } catch (err: unknown) {
            if (err instanceof DOMException && err.name === 'AbortError') return
            const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
            const msg = apiDetail ?? (err instanceof Error ? err.message : 'Action failed.')
            setActionMsg((prev) => ({ ...prev, [stackId]: `Error: ${msg}` }))
        } finally {
            setPolling((prev) => { const next = new Set(prev); next.delete(stackId); return next })
            abortRefs.current.delete(stackId)
        }
    }, [])

    // ── Delete stack record ──
    const handleDelete = useCallback(async (stackId: string) => {
        setActionMsg((prev) => ({ ...prev, [stackId]: 'Deleting stack record...' }))
        try {
            await deleteStack(stackId)
            setStacks((prev) => prev.filter((s) => s.id !== stackId))
            setConfirmDeleteId(null)
        } catch (err: unknown) {
            const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
            setActionMsg((prev) => ({ ...prev, [stackId]: `Delete failed: ${apiDetail ?? 'Unknown error'}` }))
        }
    }, [])

    // ── Refresh single stack details ──
    const handleRetrieve = useCallback(async (stackId: string) => {
        try {
            const fresh = await getStack(stackId)
            setStacks((prev) => prev.map((s) => s.id === fresh.id ? fresh : s))
            setExpandedId(stackId)
        } catch {
            setError('Failed to retrieve stack details.')
        }
    }, [])

    if (loading) {
        return (
            <div className="flex items-center justify-center h-full">
                <div className="flex flex-col items-center gap-4 animate-fadeIn">
                    <div className="w-10 h-10 border-[3px] border-accent-blue/30 border-t-accent-blue rounded-full animate-spin" />
                    <span className="font-mono text-xs text-content-dim tracking-[1px] uppercase">Loading stacks…</span>
                </div>
            </div>
        )
    }

    return (
        <div className="max-w-5xl mx-auto animate-fadeIn">
            <Breadcrumb items={[
                { label: 'Home', to: '/' },
                { label: 'Infrastructure Stacks' },
            ]} />

            {/* Page header */}
            <div className="flex items-start justify-between mb-6 gap-4">
                <div>
                    <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-cyan font-medium mb-2">
                        Infrastructure
                    </div>
                    <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
                        Pulumi Stacks
                    </div>
                    <div className="text-[0.9rem] text-content-secondary mt-1.5">
                        {stacks.length} stack{stacks.length !== 1 ? 's' : ''} &middot; Manage your cloud infrastructure
                    </div>
                </div>
                <div className="flex gap-3 shrink-0">
                    <button
                        onClick={loadStacks}
                        className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer
              bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
              hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
                    >
                        ↻ Refresh List
                    </button>
                    <button
                        onClick={() => setShowCreate((v) => !v)}
                        className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-semibold cursor-pointer border-none
              bg-accent-cyan text-[#07080c] transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(72,232,200,0.3)]"
                    >
                        + New Stack
                    </button>
                </div>
            </div>

            {/* Error banner */}
            {error && (
                <div className="bg-danger/[0.08] border border-danger/20 rounded-[8px] px-4 py-3 font-mono text-xs text-danger mb-5">
                    {error}
                    <button onClick={() => setError(null)} className="ml-3 text-content-dim hover:text-content-primary bg-transparent border-none cursor-pointer text-xs">✕</button>
                </div>
            )}

            {/* Create stack form */}
            {showCreate && (
                <div className="bg-surface-card border border-accent-cyan/20 rounded-card p-6 mb-6 animate-slideUp">
                    <div className="font-mono text-[10px] uppercase tracking-[1.5px] text-accent-cyan font-bold mb-4">
                        Create New Stack
                    </div>
                    <div className="grid grid-cols-[1fr_200px_auto] gap-3 items-end">
                        <div>
                            <label className="font-mono text-[10px] text-content-dim block mb-1">
                                Stack Name <span className="text-danger">*</span>
                            </label>
                            <input
                                type="text"
                                value={newName}
                                onChange={(e) => setNewName(e.target.value)}
                                placeholder="dev-yourname"
                                disabled={creating}
                                className="w-full font-mono text-sm text-content-primary bg-surface-base border border-border rounded-[6px] px-3 py-2.5
                  placeholder:text-content-dim/50 focus:outline-none focus:border-accent-cyan transition-colors disabled:opacity-50"
                            />
                        </div>
                        <div>
                            <label className="font-mono text-[10px] text-content-dim block mb-1">Region</label>
                            <select
                                value={newRegion}
                                onChange={(e) => setNewRegion(e.target.value)}
                                disabled={creating}
                                className="w-full font-mono text-sm text-content-primary bg-surface-base border border-border rounded-[6px] px-3 py-2.5
                  focus:outline-none focus:border-accent-cyan transition-colors appearance-none cursor-pointer disabled:opacity-50"
                            >
                                {REGIONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                            </select>
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={handleCreate}
                                disabled={!newName.trim() || creating}
                                className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                  bg-accent-cyan text-[#07080c] transition-all hover:-translate-y-px hover:shadow-[0_6px_30px_rgba(72,232,200,0.3)]
                  disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:translate-y-0"
                            >
                                {creating ? 'Creating...' : 'Create'}
                            </button>
                            <button
                                onClick={() => setShowCreate(false)}
                                className="px-4 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                  bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                  hover:bg-[rgba(255,255,255,0.05)]"
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Stacks list */}
            {stacks.length === 0 && !showCreate ? (
                <EmptyState
                    icon="&#9881;&#65039;"
                    title="No stacks yet"
                    body="Create your first infrastructure stack to deploy cloud resources for emulations."
                />
            ) : (
                <div className="flex flex-col gap-3">
                    {stacks.map((stack) => {
                        const cfg = STATUS_CONFIG[stack.status]
                        const isBusy = BUSY_STATUSES.has(stack.status) || polling.has(stack.id)
                        const isExpanded = expandedId === stack.id
                        const msg = actionMsg[stack.id]

                        return (
                            <div key={stack.id} className="group">
                                {/* Stack row */}
                                <div
                                    className={`bg-surface-card border rounded-card px-5 py-4 flex items-center gap-4 cursor-pointer
                    transition-all duration-[250ms] relative overflow-hidden
                    ${isExpanded ? 'border-accent-cyan/30 bg-accent-cyan/[0.02]' : 'border-border hover:border-[rgba(72,232,200,0.2)] hover:-translate-y-px hover:shadow-[0_4px_20px_rgba(0,0,0,0.3)]'}
                  `}
                                    onClick={() => handleRetrieve(stack.id)}
                                >
                                    {/* Left accent */}
                                    <div className={`absolute left-0 top-0 bottom-0 w-[3px] transition-colors ${isExpanded ? 'bg-accent-cyan' : stack.status === 'ready' ? 'bg-safe' : stack.status === 'failed' ? 'bg-danger' : 'bg-border group-hover:bg-accent-cyan/50'
                                        }`} />

                                    {/* Stack info */}
                                    <div className="flex-1 min-w-0 ml-1">
                                        <div className="flex items-center gap-3 mb-1">
                                            <span className="font-display text-[0.95rem] font-bold text-content-primary truncate">
                                                {stack.name}
                                            </span>
                                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full font-mono text-[10px] font-bold uppercase tracking-[0.5px] ${cfg.color} ${cfg.bg}`}>
                                                {isBusy && <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot} animate-pulse`} />}
                                                {cfg.label}
                                            </span>
                                        </div>
                                        <div className="flex items-center gap-4 font-mono text-[11px] text-content-dim">
                                            <span>📍 {stack.region}</span>
                                            <span>👤 {stack.owner}</span>
                                            <span title={stack.id}>🆔 {stack.id.slice(0, 8)}…</span>
                                            <span>🕐 {new Date(stack.created_at).toLocaleDateString()}</span>
                                        </div>
                                    </div>

                                    {/* Action buttons */}
                                    <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
                                        <ActionBtn
                                            label="Deploy" icon="🚀" variant="safe"
                                            disabled={isBusy}
                                            onClick={() => handleAction(stack.id, 'deploy')}
                                        />
                                        <ActionBtn
                                            label="Destroy" icon="🗑️" variant="orange"
                                            disabled={isBusy}
                                            onClick={() => handleAction(stack.id, 'destroy')}
                                        />
                                        <ActionBtn
                                            label="Refresh" icon="🔄" variant="blue"
                                            disabled={isBusy}
                                            onClick={() => handleAction(stack.id, 'refresh')}
                                        />
                                        <ActionBtn
                                            label="Preview" icon="👁️" variant="purple"
                                            disabled={isBusy}
                                            onClick={() => handleAction(stack.id, 'preview')}
                                        />
                                        <div className="w-px h-6 bg-border mx-1" />
                                        {confirmDeleteId === stack.id ? (
                                            <div className="flex items-center gap-1.5">
                                                <button
                                                    onClick={() => handleDelete(stack.id)}
                                                    className="px-2.5 py-1.5 rounded-[6px] font-mono text-[10px] font-bold cursor-pointer border-none
                            bg-danger text-white transition-all hover:shadow-[0_0_15px_rgba(255,34,68,0.4)]"
                                                >
                                                    Confirm
                                                </button>
                                                <button
                                                    onClick={() => setConfirmDeleteId(null)}
                                                    className="px-2 py-1.5 rounded-[6px] font-mono text-[10px] cursor-pointer
                            bg-transparent border border-border text-content-dim hover:text-content-primary transition-colors"
                                                >
                                                    ✕
                                                </button>
                                            </div>
                                        ) : (
                                            <button
                                                onClick={() => setConfirmDeleteId(stack.id)}
                                                disabled={isBusy}
                                                title="Delete stack record"
                                                className="px-2.5 py-1.5 rounded-[6px] font-mono text-[10px] text-content-dim cursor-pointer
                          bg-transparent border border-transparent transition-all
                          hover:border-danger/30 hover:text-danger hover:bg-danger/[0.06]
                          disabled:opacity-30 disabled:cursor-not-allowed"
                                            >
                                                ✕ Delete
                                            </button>
                                        )}
                                    </div>
                                </div>

                                {/* Action message */}
                                {msg && (
                                    <div className={`mx-5 mt-1 font-mono text-[11px] flex items-center gap-2 ${msg.startsWith('Error') ? 'text-danger' : msg.includes('successfully') || msg.includes('completed') ? 'text-safe' : 'text-accent-blue'
                                        }`}>
                                        {isBusy && <span className="inline-block w-2.5 h-2.5 border-2 border-current border-t-transparent rounded-full animate-spin" />}
                                        {msg}
                                    </div>
                                )}

                                {/* Expanded details */}
                                {isExpanded && (
                                    <div className="bg-surface-base border border-border border-t-0 rounded-b-card px-6 py-4 -mt-1 animate-slideUp">
                                        <div className="font-mono text-[10px] tracking-[1.5px] text-content-dim uppercase mb-3 flex items-center gap-2">
                                            Stack Details
                                            <div className="flex-1 h-px bg-border" />
                                        </div>
                                        <div className="grid grid-cols-2 gap-x-8 gap-y-3">
                                            <DetailRow label="Stack ID" value={stack.id} mono />
                                            <DetailRow label="Name" value={stack.name} />
                                            <DetailRow label="Region" value={stack.region} />
                                            <DetailRow label="Status" value={stack.status.toUpperCase()} valueClass={cfg.color} />
                                            <DetailRow label="Owner" value={stack.owner} />
                                            <DetailRow label="Created" value={new Date(stack.created_at).toLocaleString()} />
                                            <DetailRow label="Updated" value={new Date(stack.updated_at).toLocaleString()} />
                                            <DetailRow label="Outputs" value={Object.keys(stack.outputs).length > 0 ? JSON.stringify(stack.outputs, null, 2) : '(none)'} mono />
                                        </div>
                                    </div>
                                )}
                            </div>
                        )
                    })}
                </div>
            )}
        </div>
    )
}

/* ── Action Button ── */
function ActionBtn({
    label, icon, variant, disabled, onClick,
}: {
    label: string; icon: string; variant: 'safe' | 'orange' | 'blue' | 'purple'; disabled: boolean; onClick: () => void
}) {
    const styles: Record<string, string> = {
        safe: 'hover:border-safe/40 hover:text-safe hover:bg-safe/[0.06]',
        orange: 'hover:border-orange/40 hover:text-orange hover:bg-orange/[0.06]',
        blue: 'hover:border-accent-blue/40 hover:text-accent-blue hover:bg-accent-blue/[0.06]',
        purple: 'hover:border-purple/40 hover:text-purple hover:bg-purple/[0.06]',
    }
    return (
        <button
            onClick={onClick}
            disabled={disabled}
            title={label}
            className={`px-3 py-1.5 rounded-[6px] font-mono text-[10px] font-medium cursor-pointer
        bg-transparent border border-border text-content-secondary transition-all
        ${styles[variant]}
        disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:border-border disabled:hover:bg-transparent disabled:hover:text-content-secondary`}
        >
            {icon} {label}
        </button>
    )
}

/* ── Detail Row ── */
function DetailRow({ label, value, mono, valueClass = '' }: { label: string; value: string; mono?: boolean; valueClass?: string }) {
    return (
        <div>
            <div className="font-mono text-[9px] text-content-dim tracking-[1px] mb-0.5 uppercase">{label}</div>
            <div className={`text-[13px] text-content-primary ${mono ? 'font-mono text-[11px] break-all' : 'font-body'} ${valueClass}`}>
                {value}
            </div>
        </div>
    )
}
