/**
 * StacksPage — security-focused environment management for Pulumi stacks.
 *
 * Responsibilities:
 *   - List the user's stacks as operational cards (health, metadata, progress)
 *   - Search and filter the list (client-side)
 *   - Drive Deploy / Destroy / Refresh / Preview / Force-Destroy / Delete
 *   - Open a per-stack deployment logs modal
 *   - Live-poll while an action is in progress
 *
 * This page is manage/monitor-only. Stacks are created by deploying an emulation
 * (POST /api/emulations/deploy/, via RunEmulationModal on the emulation pages),
 * which is the only path that produces a deployable stack — the generic create
 * endpoint produced un-deployable records (no emulation_type) and was removed
 * from the UI.
 *
 * This page is the orchestrator: it owns all stack state and operations and
 * delegates presentation to StackCard, StackFilters, and DeploymentLogsModal.
 */

import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import type { Stack, StackStatus } from '@/types'
import { StackCard, type StackDetailView } from './StackCard'
import { StackFilters, filterStacks, EMPTY_FILTERS, type StackFilterState } from './StackFilters'
import { DeploymentLogsModal } from './DeploymentLogsModal'
import {
    listStacks,
    getStack,
    deployStack,
    destroyStack,
    refreshStack,
    previewStack,
    deleteStack,
    forceDestroyStack,
    pollStackUntilReady,
} from '@/services/stack.service'
import { destroyEmulationStack } from '@/services/emulation.service'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { EmptyState } from '@/components/ui/EmptyState'

const BUSY_STATUSES = new Set<StackStatus>(['deploying', 'destroying', 'refreshing'])

export function StacksPage() {
    const [stacks, setStacks] = useState<Stack[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    // Filters
    const [filters, setFilters] = useState<StackFilterState>(EMPTY_FILTERS)

    // Expanded detail row + active tab
    const [expandedId, setExpandedId] = useState<string | null>(null)
    const [detailView, setDetailView] = useState<StackDetailView>('details')
    useEffect(() => { setDetailView('details') }, [expandedId])

    // Logs modal
    const [logsStack, setLogsStack] = useState<Stack | null>(null)

    // Action feedback / busy tracking
    const [actionMsg, setActionMsg] = useState<Record<string, string>>({})
    const [polling, setPolling] = useState<Set<string>>(new Set())
    const abortRefs = useRef<Map<string, AbortController>>(new Map())

    // ── Load stacks ──
    const loadStacks = useCallback(async () => {
        setLoading(true)
        setError(null)
        try {
            setStacks(await listStacks())
        } catch {
            setError('Failed to load stacks.')
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { loadStacks() }, [loadStacks])

    // Cleanup all abort controllers on unmount
    useEffect(() => () => { abortRefs.current.forEach((c) => c.abort()) }, [])

    const filtered = useMemo(() => filterStacks(stacks, filters), [stacks, filters])

    // ── Stack action (deploy/destroy/refresh/preview) ──
    const handleAction = useCallback(async (
        stackId: string,
        action: 'deploy' | 'destroy' | 'refresh' | 'preview',
    ) => {
        const actionFn = { deploy: deployStack, destroy: destroyStack, refresh: refreshStack, preview: previewStack }[action]
        const label = action.charAt(0).toUpperCase() + action.slice(1)

        setPolling((prev) => new Set(prev).add(stackId))
        setActionMsg((prev) => ({ ...prev, [stackId]: `${label} request sent...` }))
        setError(null)

        try {
            await actionFn(stackId)

            if (action !== 'preview') {
                const newStatus = action === 'deploy' ? 'deploying' : action === 'destroy' ? 'destroying' : 'refreshing'
                setStacks((prev) => prev.map((s) => s.id === stackId ? { ...s, status: newStatus as StackStatus } : s))
            }

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
                (updated) => setStacks((prev) => prev.map((s) => s.id === updated.id ? updated : s)),
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
            setActionMsg((prev) => ({ ...prev, [stackId]: `Error: ${apiDetail ?? (err instanceof Error ? err.message : 'Action failed.')}` }))
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
        } catch (err: unknown) {
            const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
            setActionMsg((prev) => ({ ...prev, [stackId]: `Delete failed: ${apiDetail ?? 'Unknown error'}` }))
        }
    }, [])

    // ── Force-destroy a stuck or completed emulation stack ──
    const handleForceDestroy = useCallback(async (stack: Stack) => {
        setPolling((prev) => new Set(prev).add(stack.id))
        setActionMsg((prev) => ({ ...prev, [stack.id]: 'Destroy queued...' }))
        setError(null)

        try {
            // Enterprise emulation stacks use the STS-aware emulation destroy endpoint
            // so Pulumi runs in the user's account, not the platform account.
            if (stack.emulation_type) {
                await destroyEmulationStack(stack.id)
            } else {
                await forceDestroyStack(stack.id)
            }

            setStacks((prev) => prev.map((s) => s.id === stack.id ? { ...s, status: 'destroying' as StackStatus } : s))
            setActionMsg((prev) => ({ ...prev, [stack.id]: 'Destroying infrastructure... This may take a few minutes.' }))

            const controller = new AbortController()
            abortRefs.current.set(stack.id, controller)

            const final = await pollStackUntilReady(
                stack.id,
                3000,
                (updated) => setStacks((prev) => prev.map((s) => s.id === updated.id ? updated : s)),
                controller.signal,
            )

            setStacks((prev) => prev.map((s) => s.id === final.id ? final : s))
            setActionMsg((prev) => ({
                ...prev,
                [stack.id]: final.status === 'failed' ? 'Destroy failed. Check worker logs.' : 'Stack destroyed successfully.',
            }))
        } catch (err: unknown) {
            if (err instanceof DOMException && err.name === 'AbortError') return
            const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
            setActionMsg((prev) => ({ ...prev, [stack.id]: `Error: ${apiDetail ?? (err instanceof Error ? err.message : 'Force destroy failed.')}` }))
        } finally {
            setPolling((prev) => { const next = new Set(prev); next.delete(stack.id); return next })
            abortRefs.current.delete(stack.id)
        }
    }, [])

    // ── Toggle expand (fetches fresh detail when opening) ──
    const handleToggleExpand = useCallback(async (stackId: string) => {
        if (expandedId === stackId) {
            setExpandedId(null)
            return
        }
        setExpandedId(stackId)
        try {
            const fresh = await getStack(stackId)
            setStacks((prev) => prev.map((s) => s.id === fresh.id ? fresh : s))
        } catch {
            // Keep the existing record if the refresh fails — non-fatal.
        }
    }, [expandedId])

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
        <div className="animate-fadeIn">
            <Breadcrumb items={[{ label: 'Home', to: '/' }, { label: 'Infrastructure Stacks' }]} />

            {/* Page header */}
            <div className="flex items-start justify-between mb-6 gap-4">
                <div>
                    <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-cyan font-medium mb-2">
                        Infrastructure
                    </div>
                    <div className="font-display text-[1.8rem] font-extrabold text-content-primary leading-tight tracking-[-1px]">
                        Security Environments
                    </div>
                    <div className="text-[0.9rem] text-content-secondary mt-1.5">
                        {stacks.length} stack{stacks.length !== 1 ? 's' : ''} &middot; Manage and monitor your deployed infrastructure
                    </div>
                </div>
                <div className="flex gap-3 shrink-0">
                    <button
                        onClick={loadStacks}
                        className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer
                            bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                            hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
                    >
                        Refresh List
                    </button>
                </div>
            </div>

            {/* Error banner */}
            {error && (
                <div className="bg-danger/[0.08] border border-danger/20 rounded-btn px-4 py-3 font-mono text-xs text-danger mb-5">
                    {error}
                    <button onClick={() => setError(null)} className="ml-3 text-content-dim hover:text-content-primary bg-transparent border-none cursor-pointer text-xs">✕</button>
                </div>
            )}

            {/* Empty state (no stacks at all) */}
            {stacks.length === 0 ? (
                <EmptyState
                    icon="&#9881;&#65039;"
                    title="No stacks yet"
                    body="Stacks appear here once you deploy an emulation. Open a platform's emulations to launch one."
                />
            ) : (
                <>
                    <StackFilters
                        value={filters}
                        onChange={setFilters}
                        stacks={stacks}
                        resultCount={filtered.length}
                    />

                    {filtered.length === 0 ? (
                        <EmptyState
                            icon="&#128269;"
                            title="No matching stacks"
                            body="No stacks match the current filters. Try clearing or adjusting them."
                        />
                    ) : (
                        <div className="flex flex-col gap-3">
                            {filtered.map((stack) => {
                                const isBusy = BUSY_STATUSES.has(stack.status) || polling.has(stack.id)
                                return (
                                    <StackCard
                                        key={stack.id}
                                        stack={stack}
                                        isBusy={isBusy}
                                        isExpanded={expandedId === stack.id}
                                        onToggleExpand={() => handleToggleExpand(stack.id)}
                                        detailView={detailView}
                                        onDetailViewChange={setDetailView}
                                        actionMsg={actionMsg[stack.id]}
                                        onAction={(action) => handleAction(stack.id, action)}
                                        onOpenLogs={() => setLogsStack(stack)}
                                        onDelete={() => handleDelete(stack.id)}
                                        onForceDestroy={() => handleForceDestroy(stack)}
                                    />
                                )
                            })}
                        </div>
                    )}
                </>
            )}

            {/* Deployment logs modal */}
            {logsStack && (
                <DeploymentLogsModal
                    stackId={logsStack.id}
                    stackName={logsStack.name}
                    status={logsStack.status}
                    initialLogs={logsStack.last_logs}
                    error={logsStack.last_error}
                    onClose={() => setLogsStack(null)}
                />
            )}
        </div>
    )
}
