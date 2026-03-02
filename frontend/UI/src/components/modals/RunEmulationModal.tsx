/**
 * RunEmulationModal — dialog for triggering a simulation run.
 *
 * Flow:
 *  1. Modal opens → fetches user's stacks from GET /api/stacks/
 *  2. User picks an existing READY stack from dropdown, or creates a new one.
 *     - "Create New" shows inline fields for stack name + region + deploy.
 *  3. Click "Run" → POST /api/simulations/run/ with stack_id and module_id.
 *  4. Modal switches to "running" state, polling every 2 s until terminal.
 *  5. Shows stdout/stderr output in a live console.
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import type { SimulationRun, SimulationStatus, Stack } from '@/types'
import { EMULATION_MODULE_MAP } from '@/types'
import { triggerSimulation, pollSimulationUntilDone } from '@/services/emulation.service'
import {
  listStacks,
  createStack,
  deployStack,
  pollStackUntilReady,
} from '@/services/stack.service'

/* ── Props ── */
interface RunEmulationModalProps {
  /** UI emulation ID (e.g. "priv-esc-attach-role-policy") */
  emulationId: string
  /** Human-readable emulation name for display */
  emulationName: string
  /** Close callback */
  onClose: () => void
}

/* ── Status helpers ── */
const SIM_STATUS_LABELS: Record<SimulationStatus, string> = {
  pending: 'Queued',
  running: 'Running...',
  completed: 'Completed',
  failed: 'Failed',
}

const SIM_STATUS_COLORS: Record<SimulationStatus, string> = {
  pending: 'text-yellow-400',
  running: 'text-accent-blue',
  completed: 'text-safe',
  failed: 'text-danger',
}

const STACK_STATUS_COLORS: Record<string, string> = {
  ready: 'text-safe',
  pending: 'text-yellow-400',
  deploying: 'text-accent-blue',
  destroying: 'text-orange-400',
  failed: 'text-danger',
}

/* ── Component ── */
export function RunEmulationModal({ emulationId, emulationName, onClose }: RunEmulationModalProps) {
  // ── Stack picker state ──
  const [stacks, setStacks] = useState<Stack[]>([])
  const [stacksLoading, setStacksLoading] = useState(true)
  const [selectedStackId, setSelectedStackId] = useState('')
  const [showCreateNew, setShowCreateNew] = useState(false)

  // ── Create-new-stack state ──
  const [newStackName, setNewStackName] = useState('')
  const [newStackRegion, setNewStackRegion] = useState('ap-south-1')
  const [creatingStack, setCreatingStack] = useState(false)
  const [deployingStack, setDeployingStack] = useState(false)
  const [stackDeployMsg, setStackDeployMsg] = useState('')

  // ── Form state ──

  // ── Execution state ──
  type Phase = 'form' | 'running' | 'done'
  const [phase, setPhase] = useState<Phase>('form')
  const [run, setRun] = useState<SimulationRun | null>(null)
  const [error, setError] = useState<string | null>(null)

  const abortRef = useRef<AbortController | null>(null)
  const consoleRef = useRef<HTMLPreElement>(null)

  // Module ID from mapping
  const moduleId = EMULATION_MODULE_MAP[emulationId] ?? 0

  // Selected stack object
  const selectedStack = stacks.find((s) => s.id === selectedStackId)
  const canRun = selectedStack?.status === 'ready' && !deployingStack && moduleId > 0

  // Fetch stacks on mount
  useEffect(() => {
    let cancelled = false
    setStacksLoading(true)
    listStacks()
      .then((data) => {
        if (cancelled) return
        // Guard against non-array response (e.g. nginx SPA fallback serving HTML)
        if (!Array.isArray(data)) {
          setShowCreateNew(true)
          return
        }
        setStacks(data)
        // Auto-select first READY stack if available
        const firstReady = data.find((s) => s.status === 'ready')
        if (firstReady) {
          setSelectedStackId(firstReady.id)
        } else if (data.length === 0) {
          setShowCreateNew(true)
        }
      })
      .catch(() => {
        // Silently fail — user can still create a new stack
        setShowCreateNew(true)
      })
      .finally(() => {
        if (!cancelled) setStacksLoading(false)
      })
    return () => { cancelled = true }
  }, [])

  // Auto-scroll console output
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [run?.stdout, run?.stderr])

  // Cleanup abort controller on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort()
    }
  }, [])

  // ── Stack creation + deploy ──
  const handleCreateAndDeploy = useCallback(async () => {
    if (!newStackName.trim()) return
    setError(null)
    setCreatingStack(true)
    setStackDeployMsg('Creating stack record...')

    try {
      // 1. Create the stack record
      const stack = await createStack({
        name: newStackName.trim(),
        region: newStackRegion,
      })
      setStacks((prev) => [stack, ...prev])
      setSelectedStackId(stack.id)
      setCreatingStack(false)

      // 2. Trigger deploy
      setDeployingStack(true)
      setStackDeployMsg('Deploying infrastructure (pulumi up)... This may take a few minutes.')
      await deployStack(stack.id)

      // 3. Poll until ready
      const controller = new AbortController()
      abortRef.current = controller

      const finalStack = await pollStackUntilReady(
        stack.id,
        3000,
        (updated) => {
          setStacks((prev) => prev.map((s) => (s.id === updated.id ? updated : s)))
          setStackDeployMsg(
            updated.status === 'deploying'
              ? 'Infrastructure deploying... This may take a few minutes.'
              : `Stack status: ${updated.status}`,
          )
        },
        controller.signal,
      )

      setStacks((prev) => prev.map((s) => (s.id === finalStack.id ? finalStack : s)))
      setDeployingStack(false)
      setShowCreateNew(false)

      if (finalStack.status === 'ready') {
        setStackDeployMsg('')
      } else {
        setStackDeployMsg(`Stack deployment ended with status: ${finalStack.status}`)
      }
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      const msg = err instanceof Error ? err.message : 'Unknown error'
      const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(apiDetail ?? msg)
      setCreatingStack(false)
      setDeployingStack(false)
      setStackDeployMsg('')
    }
  }, [newStackName, newStackRegion])

  // ── Run simulation ──
  const handleRun = useCallback(async () => {
    setError(null)
    setPhase('running')

    try {
      const resp = await triggerSimulation({
        stack_id: selectedStackId,
        module_id: moduleId,
      })
      setRun(resp.run)

      // Start polling
      const controller = new AbortController()
      abortRef.current = controller

      const finalRun = await pollSimulationUntilDone(
        resp.run.id,
        2000,
        (updated) => setRun(updated),
        controller.signal,
      )
      setRun(finalRun)
      setPhase('done')
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      const msg = err instanceof Error ? err.message : 'Unknown error'
      const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(apiDetail ?? msg)
      setPhase('done')
    }
  }, [selectedStackId, moduleId])

  const handleClose = () => {
    abortRef.current?.abort()
    onClose()
  }



  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={handleClose}>
      <div
        className="bg-surface-card border border-border rounded-card w-full max-w-[640px] shadow-2xl max-h-[90vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border shrink-0">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim mb-1">
              Run Emulation
            </div>
            <div className="font-display text-[1.1rem] font-bold text-content-primary leading-tight">
              {emulationName}
            </div>
          </div>
          <button
            onClick={handleClose}
            className="text-content-dim hover:text-content-primary transition-colors text-xl leading-none cursor-pointer bg-transparent border-none p-1"
          >
            &#10005;
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 overflow-y-auto flex-1">
          {phase === 'form' && (
            <div className="flex flex-col gap-5">
              {/* Module info */}
              <div>
                <label className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim block mb-1.5">
                  Simulation Module
                </label>
                <div className="font-mono text-sm text-content-secondary bg-surface-base border border-border rounded-[6px] px-3 py-2">
                  Module #{moduleId}
                </div>
              </div>

              {/* ── Stack Picker ── */}
              <div>
                <label className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim block mb-1.5">
                  Target Stack <span className="text-danger">*</span>
                </label>

                {stacksLoading ? (
                  <div className="flex items-center gap-2 text-content-dim text-sm py-2">
                    <span className="inline-block w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
                    Loading stacks...
                  </div>
                ) : (
                  <>
                    {/* Dropdown of existing stacks */}
                    {stacks.length > 0 && !showCreateNew && (
                      <div className="flex flex-col gap-2">
                        <select
                          value={selectedStackId}
                          onChange={(e) => setSelectedStackId(e.target.value)}
                          className="w-full font-mono text-sm text-content-primary bg-surface-base border border-border rounded-[6px] px-3 py-2.5
                            focus:outline-none focus:border-accent-blue transition-colors appearance-none cursor-pointer"
                        >
                          <option value="">-- Select a stack --</option>
                          {stacks.map((s) => (
                            <option key={s.id} value={s.id}>
                              {s.name} [{s.status}] -- {s.region}
                            </option>
                          ))}
                        </select>

                        {/* Status indicator for selected stack */}
                        {selectedStack && (
                          <div className="flex items-center gap-2 font-mono text-[11px]">
                            <span className={`font-bold uppercase ${STACK_STATUS_COLORS[selectedStack.status] ?? 'text-content-dim'}`}>
                              {selectedStack.status === 'ready' && <span className="mr-1">●</span>}
                              {selectedStack.status}
                            </span>
                            <span className="text-content-dim">|</span>
                            <span className="text-content-dim">{selectedStack.region}</span>
                            <span className="text-content-dim">|</span>
                            <span className="text-content-dim font-mono text-[10px]">{selectedStack.id.slice(0, 8)}...</span>
                            {selectedStack.status !== 'ready' && (
                              <span className="text-yellow-400 text-[10px]">
                                Stack must be in READY state to run emulations
                              </span>
                            )}
                          </div>
                        )}

                        <button
                          type="button"
                          onClick={() => setShowCreateNew(true)}
                          className="self-start font-mono text-[11px] text-accent-blue hover:text-accent-blue/80 cursor-pointer
                            bg-transparent border-none p-0 underline underline-offset-2 transition-colors"
                        >
                          + Create &amp; deploy a new stack
                        </button>
                      </div>
                    )}

                    {/* Create new stack form */}
                    {(showCreateNew || stacks.length === 0) && (
                      <div className="bg-surface-base border border-border rounded-[8px] p-4 flex flex-col gap-3">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] uppercase tracking-[1.5px] text-accent-blue font-bold">
                            New Stack
                          </span>
                          {stacks.length > 0 && (
                            <button
                              type="button"
                              onClick={() => setShowCreateNew(false)}
                              className="font-mono text-[10px] text-content-dim hover:text-content-primary cursor-pointer
                                bg-transparent border-none transition-colors"
                            >
                              Cancel
                            </button>
                          )}
                        </div>

                        {/* Stack name */}
                        <div>
                          <label className="font-mono text-[10px] text-content-dim block mb-1">
                            Stack Name <span className="text-danger">*</span>
                          </label>
                          <input
                            type="text"
                            value={newStackName}
                            onChange={(e) => setNewStackName(e.target.value)}
                            placeholder="dev-yourname"
                            disabled={creatingStack || deployingStack}
                            className="w-full font-mono text-sm text-content-primary bg-[#0a0a0f] border border-border rounded-[6px] px-3 py-2
                              placeholder:text-content-dim/50 focus:outline-none focus:border-accent-blue transition-colors
                              disabled:opacity-50"
                          />
                          <div className="font-mono text-[10px] text-content-dim mt-0.5">
                            Pulumi stack name — convention: dev-&lt;username&gt;
                          </div>
                        </div>

                        {/* Region */}
                        <div>
                          <label className="font-mono text-[10px] text-content-dim block mb-1">
                            AWS Region
                          </label>
                          <select
                            value={newStackRegion}
                            onChange={(e) => setNewStackRegion(e.target.value)}
                            disabled={creatingStack || deployingStack}
                            className="w-full font-mono text-sm text-content-primary bg-[#0a0a0f] border border-border rounded-[6px] px-3 py-2
                              focus:outline-none focus:border-accent-blue transition-colors appearance-none cursor-pointer
                              disabled:opacity-50"
                          >
                            <option value="ap-south-1">ap-south-1 (Mumbai)</option>
                            <option value="us-east-1">us-east-1 (N. Virginia)</option>
                            <option value="us-west-2">us-west-2 (Oregon)</option>
                            <option value="eu-west-1">eu-west-1 (Ireland)</option>
                          </select>
                        </div>

                        {/* Deploy message */}
                        {stackDeployMsg && (
                          <div className="flex items-center gap-2 font-mono text-[11px] text-accent-blue">
                            {deployingStack && (
                              <span className="inline-block w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
                            )}
                            {stackDeployMsg}
                          </div>
                        )}

                        {/* Create & Deploy button */}
                        <button
                          type="button"
                          onClick={handleCreateAndDeploy}
                          disabled={!newStackName.trim() || creatingStack || deployingStack}
                          className="self-start px-4 py-2 rounded-btn font-body text-[0.8rem] font-semibold cursor-pointer border-none
                            bg-accent-blue text-white transition-all hover:-translate-y-px hover:shadow-[0_6px_30px_rgba(0,180,216,0.3)]
                            disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none"
                        >
                          {creatingStack ? 'Creating...' : deployingStack ? 'Deploying...' : 'Create & Deploy Stack'}
                        </button>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          )}

          {(phase === 'running' || phase === 'done') && (
            <div className="flex flex-col gap-4">
              {/* Status badge */}
              <div className="flex items-center gap-3">
                <div className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim">Status</div>
                <div className={`font-mono text-sm font-bold ${SIM_STATUS_COLORS[run?.status ?? 'pending']}`}>
                  {run?.status === 'running' && (
                    <span className="inline-block w-2 h-2 bg-accent-blue rounded-full mr-2 animate-pulse" />
                  )}
                  {SIM_STATUS_LABELS[run?.status ?? 'pending']}
                </div>
              </div>

              {/* Console output */}
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim mb-1.5">
                  Console Output
                </div>
                <pre
                  ref={consoleRef}
                  className="bg-[#0a0a0f] border border-border rounded-[6px] p-4 font-mono text-[11px] leading-[1.7]
                    text-content-secondary overflow-auto max-h-[300px] min-h-[150px] whitespace-pre-wrap"
                >
                  {run?.stdout || (phase === 'running' ? 'Waiting for output...' : '(no output)')}
                  {run?.stderr && (
                    <span className="text-danger block mt-2">
                      {run.stderr}
                    </span>
                  )}
                </pre>
              </div>

              {/* Error message from API */}
              {error && (
                <div className="bg-danger/[0.08] border border-danger/20 rounded-[6px] px-4 py-3 font-mono text-xs text-danger">
                  {error}
                </div>
              )}

              {/* Timing info */}
              {run?.started_at && (
                <div className="flex gap-6 font-mono text-[10px] text-content-dim">
                  <span>Started: {new Date(run.started_at).toLocaleTimeString()}</span>
                  {run.completed_at && (
                    <span>Completed: {new Date(run.completed_at).toLocaleTimeString()}</span>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-border shrink-0">
          {phase === 'form' && (
            <>
              {/* Error display */}
              {error && (
                <div className="flex-1 font-mono text-[11px] text-danger truncate mr-2">
                  {error}
                </div>
              )}
              <button
                onClick={handleClose}
                className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                  bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                  hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
              >
                Cancel
              </button>
              <button
                onClick={handleRun}
                disabled={!canRun}
                className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                  bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]
                  disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none"
              >
                &#9654; Run Emulation
              </button>
            </>
          )}
          {phase === 'running' && (
            <button
              onClick={handleClose}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
            >
              Close (keeps running)
            </button>
          )}
          {phase === 'done' && (
            <button
              onClick={handleClose}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]"
            >
              Close
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
