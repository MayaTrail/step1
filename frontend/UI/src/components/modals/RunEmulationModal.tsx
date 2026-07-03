/**
 * RunEmulationModal — drives the full enterprise emulation lifecycle.
 *
 * Flow:
 *  1. Modal opens → fetches cost estimate for the emulation type.
 *  2. User enters a stack name and reviews cost breakdown.
 *  3. Click "Deploy Stack" → POST /api/emulations/deploy/
 *  4. Poll the Stack status until ready_for_attack (or failed).
 *  5. Trigger attack → POST /api/emulations/<stack_id>/attack/
 *  6. Poll EmulationRun until terminal state (completed/failed).
 *  7. Show stdout/stderr output.
 *
 * Non-enterprise users receive a 403 from the backend which is surfaced as
 * a clear "Enterprise account required" message rather than a generic error.
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import type { EmulationRunRecord, EmulationEstimate, StackStatus, Stack } from '@/types'
import {
  getEmulationEstimate,
  deployEmulationStack,
  triggerEmulationAttack,
  pollEmulationRunUntilDone,
  destroyEmulationStack,
} from '@/services/emulation.service'
import { getStack, listStacks } from '@/services/stack.service'

/* ── Props ── */
interface RunEmulationModalProps {
  emulationId: string
  emulationName: string
  onClose: () => void
}

/* ── Phase type ── */
type ModalPhase = 'form' | 'deploying' | 'destroying' | 'ready' | 'attacking' | 'done' | 'error'

/* ── Stack status helpers ── */
const TERMINAL_STACK_STATUSES = new Set<StackStatus>([
  'ready_for_attack',
  'attack_complete',
  'failed',
  'destroyed',
])

const STACK_STATUS_LABELS: Partial<Record<StackStatus, string>> = {
  deploying: 'Deploying infrastructure...',
  ec2_booting: 'EC2 instance booting...',
  ready_for_attack: 'Ready',
  attacking: 'Attacking...',
  attack_complete: 'Attack complete',
  failed: 'Failed',
}

/** Abortable timeout, so polling loops can be cancelled on close/unmount. */
function wait(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms)
    signal.addEventListener(
      'abort',
      () => { clearTimeout(t); reject(new DOMException('Aborted', 'AbortError')) },
      { once: true },
    )
  })
}

/* ── Component ── */
export function RunEmulationModal({ emulationId, emulationName, onClose }: RunEmulationModalProps) {
  const [phase, setPhase] = useState<ModalPhase>('form')
  // Form sub-mode: deploy a brand-new stack, or run against an existing ready one.
  const [formMode, setFormMode] = useState<'new' | 'existing'>('new')
  const [readyStacks, setReadyStacks] = useState<Stack[]>([])
  const [selectedStackId, setSelectedStackId] = useState<string>('')
  // A spent (attack_complete) stack blocks a fresh deploy; the form offers a
  // one-click "destroy and redeploy" when one exists for this emulation.
  const [blockingStack, setBlockingStack] = useState<{ id: string; name: string } | null>(null)
  // Positive confirmation shown in the form after a stack is destroyed.
  const [notice, setNotice] = useState<string | null>(null)
  const [estimate, setEstimate] = useState<EmulationEstimate | null>(null)
  const [estimateLoading, setEstimateLoading] = useState(true)
  const [stackName, setStackName] = useState(`${emulationId}-run`)
  const [stackStatus, setStackStatus] = useState<StackStatus | ''>('')
  const [deployedStackId, setDeployedStackId] = useState<string>('')
  const [run, setRun] = useState<EmulationRunRecord | null>(null)
  const [statusMsg, setStatusMsg] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isForbidden, setIsForbidden] = useState(false)

  const abortRef = useRef<AbortController | null>(null)
  const consoleRef = useRef<HTMLPreElement>(null)

  // Fetch cost estimate on mount
  useEffect(() => {
    let cancelled = false
    setEstimateLoading(true)
    getEmulationEstimate(emulationId)
      .then((data) => {
        if (!cancelled) setEstimate(data)
      })
      .catch((err) => {
        if (cancelled) return
        if (err?.response?.status === 403) setIsForbidden(true)
      })
      .finally(() => {
        if (!cancelled) setEstimateLoading(false)
      })
    return () => { cancelled = true }
  }, [emulationId])

  // Fetch the user's existing stacks for this emulation that are ready to attack,
  // so the user can run against one instead of deploying a fresh stack.
  useEffect(() => {
    let cancelled = false
    listStacks()
      .then((stacks) => {
        if (cancelled) return
        const mine = stacks.filter((s) => s.emulation_type === emulationId)
        // A deploy already in flight: resume watching it rather than prompting
        // for a redundant redeploy.
        const inFlight = mine.find((s) => s.status === 'deploying' || s.status === 'ec2_booting')
        if (inFlight) {
          resumeDeploy(inFlight.id, inFlight.status)
          return
        }
        setReadyStacks(mine.filter((s) => s.status === 'ready_for_attack'))
        // A completed run leaves the stack attack_complete: not reusable and it
        // blocks a new deploy, so surface it for destroy-and-redeploy.
        const spent = mine.find((s) => s.status === 'attack_complete')
        setBlockingStack(spent ? { id: spent.id, name: spent.name } : null)
      })
      .catch(() => { /* non-fatal: existing-stack selection just stays empty */ })
    return () => { cancelled = true }
    // resumeDeploy is a stable callback and is referenced only in the async
    // resolution above, so this fetch stays keyed to emulationId.
  }, [emulationId])

  // Auto-scroll console output
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [run?.stdout, run?.stderr, statusMsg])

  // Cleanup on unmount
  useEffect(() => {
    return () => { abortRef.current?.abort() }
  }, [])

  // Poll a stack until it is ready to attack (or reaches a terminal state).
  // Shared by a fresh deploy and by resuming a deploy already in flight.
  const pollStackToReady = useCallback(async (stackId: string) => {
    const controller = new AbortController()
    abortRef.current = controller

    let currentStatus: StackStatus = 'deploying'
    while (!TERMINAL_STACK_STATUSES.has(currentStatus)) {
      if (controller.signal.aborted) return
      await wait(4000, controller.signal)
      currentStatus = (await getStack(stackId)).status
      setStackStatus(currentStatus)
      setStatusMsg(STACK_STATUS_LABELS[currentStatus] ?? currentStatus)
    }

    if (currentStatus === 'ready_for_attack') {
      setPhase('ready')
      setStatusMsg('Stack is ready. Click "Run Attack" to begin the emulation.')
    } else {
      setPhase('error')
      setError(`Stack deployment ended in status: ${currentStatus}`)
    }
  }, [])

  // Re-attach to a deploy already in flight (e.g. the user closed the modal
  // mid-deploy and reopened it) instead of prompting for a redundant redeploy.
  const resumeDeploy = useCallback(async (stackId: string, currentStatus: StackStatus) => {
    setDeployedStackId(stackId)
    setPhase('deploying')
    setStackStatus(currentStatus)
    setStatusMsg('Deployment already in progress — resuming...')
    try {
      await pollStackToReady(stackId)
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setPhase('error')
      setError(detail ?? 'Failed while resuming deployment.')
    }
  }, [pollStackToReady])

  const handleDeploy = useCallback(async () => {
    if (!stackName.trim()) return
    setError(null)
    setNotice(null)
    setPhase('deploying')
    setStatusMsg('Deploying infrastructure...')

    try {
      const { stackId } = await deployEmulationStack(emulationId, stackName.trim())
      setDeployedStackId(stackId)
      await pollStackToReady(stackId)
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      const status = (err as { response?: { status?: number } })?.response?.status
      if (status === 403) {
        setIsForbidden(true)
        setPhase('error')
        return
      }
      // 409: an existing stack blocks a new deploy. Resolve by its state:
      // in-progress -> resume watching; ready -> use it; spent -> destroy+redeploy.
      if (status === 409) {
        const blockingId = (err as { response?: { data?: { stackId?: string } } })?.response?.data?.stackId
        if (blockingId) {
          let blocking: Stack | null = null
          try {
            blocking = await getStack(blockingId)
          } catch { /* status unknown -> fall through to destroy-and-redeploy */ }
          const st = blocking?.status ?? null

          if (st === 'deploying' || st === 'ec2_booting') {
            await resumeDeploy(blockingId, st)
            return
          }
          if (st === 'ready_for_attack' && blocking) {
            setReadyStacks((prev) => (prev.some((s) => s.id === blockingId) ? prev : [...prev, blocking!]))
            setSelectedStackId(blockingId)
            setFormMode('existing')
            setError('You already have a ready stack for this emulation. Run against it, or destroy it first.')
            setPhase('form')
            return
          }
          if (st === 'attacking') {
            setError('An attack is already running against a stack for this emulation. Watch it under Live Emulation.')
            setPhase('form')
            return
          }
          setBlockingStack({ id: blockingId, name: blocking?.name ?? 'the active stack' })
          setError(apiDetail ?? 'A previous stack is blocking a new deployment. Destroy and redeploy fresh.')
          setPhase('form')
          return
        }
      }
      setError(apiDetail ?? (err instanceof Error ? err.message : 'Deployment failed'))
      setPhase('error')
    }
  }, [emulationId, stackName, pollStackToReady, resumeDeploy])

  const handleDestroy = useCallback(async (stackId: string) => {
    setError(null)
    setNotice(null)
    setBlockingStack(null)
    setPhase('destroying')
    setStackStatus('destroying')
    setStatusMsg('Destroying stack...')

    const controller = new AbortController()
    abortRef.current = controller

    try {
      await destroyEmulationStack(stackId)

      // Poll until the record is gone (destroy deletes it) or teardown fails.
      // Unbounded like the deploy poll -- a real VPC/EC2 teardown can take
      // several minutes; cancellation is via the abort signal (close).
      const DESTROY_TERMINAL = new Set<StackStatus>(['destroyed', 'failed'])
      let current: StackStatus = 'destroying'
      while (!DESTROY_TERMINAL.has(current)) {
        if (controller.signal.aborted) return
        await wait(4000, controller.signal)
        try {
          current = (await getStack(stackId)).status
        } catch {
          current = 'destroyed' // record gone -> torn down
        }
        setStackStatus(current)
        setStatusMsg(`Destroying stack... (${current})`)
      }

      if (current !== 'destroyed') {
        setPhase('error')
        setError(`Could not destroy the stack (status: ${current}).`)
        return
      }
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setPhase('error')
      setError(detail ?? 'Failed to destroy the stack.')
      return
    }

    // Destroyed. Return to the form so the user can deploy a fresh stack.
    setStatusMsg('')
    setNotice('Previous stack destroyed. You can deploy a fresh stack below.')
    setPhase('form')
  }, [])

  const handleAttack = useCallback(async (stackIdArg?: string) => {
    const targetStackId = stackIdArg || deployedStackId
    if (!targetStackId) return
    setDeployedStackId(targetStackId)
    setError(null)
    setPhase('attacking')
    setStatusMsg('Attack in progress...')

    try {
      const { runId } = await triggerEmulationAttack(targetStackId)

      const controller = new AbortController()
      abortRef.current = controller

      const finalRun = await pollEmulationRunUntilDone(
        runId,
        3000,
        (updated) => {
          setRun(updated)
          setStatusMsg(
            updated.status === 'running'
              ? `Running phase ${updated.phase_current} / ${updated.phase_total}...`
              : updated.status,
          )
        },
        controller.signal,
      )
      setRun(finalRun)
      setPhase('done')

    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(apiDetail ?? (err instanceof Error ? err.message : 'Attack failed'))
      setPhase('done')
    }
  }, [deployedStackId])

  const handleDestroyAndClose = useCallback(async () => {
    if (deployedStackId) {
      try {
        await destroyEmulationStack(deployedStackId)
      } catch {
        // Best-effort destroy — don't block the user from closing
      }
    }
    abortRef.current?.abort()
    onClose()
  }, [deployedStackId, onClose])

  const handleClose = () => {
    abortRef.current?.abort()
    onClose()
  }

  // ── Forbidden state ──────────────────────────────────────────────────────
  if (isForbidden) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={handleClose}>
        <div
          className="bg-surface-card border border-border rounded-card w-full max-w-[480px] shadow-2xl p-8 flex flex-col items-center gap-4 text-center"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-danger font-medium">
            Access Restricted
          </div>
          <div className="font-display text-[1.2rem] font-bold text-content-primary">
            Enterprise Account Required
          </div>
          <div className="text-[0.85rem] text-content-secondary leading-[1.6]">
            APT emulations are available exclusively to enterprise users. Upgrade your account
            or contact your administrator to enable this feature.
          </div>
          <button
            onClick={handleClose}
            className="mt-2 px-6 py-2.5 rounded-btn font-body text-[0.9rem] font-semibold cursor-pointer border-none
              bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]"
          >
            Close
          </button>
        </div>
      </div>
    )
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

          {/* Persistent hint: deploys/teardowns run in the background. */}
          <div className="mb-4 font-mono text-[10px] text-content-dim bg-surface-base border border-border rounded-[6px] px-3 py-2 leading-[1.6]">
            Deploys and teardowns run in the background. You can track live stack status anytime in the
            <span className="text-accent-blue"> Stacks</span> section.
          </div>

          {/* ── Form ── */}
          {phase === 'form' && (
            <div className="flex flex-col gap-5">
              {notice && (
                <div className="font-mono text-[11px] text-safe bg-safe/[0.08] border border-safe/25 rounded-[6px] px-4 py-2.5">
                  {notice}
                </div>
              )}
              {/* Mode toggle: deploy a new stack vs. run against an existing ready one */}
              <div className="flex gap-1 p-1 bg-surface-base border border-border rounded-[8px]">
                <button
                  type="button"
                  onClick={() => setFormMode('new')}
                  className={`flex-1 px-3 py-1.5 rounded-[6px] font-mono text-[10px] uppercase tracking-[1.5px] transition-all ${
                    formMode === 'new'
                      ? 'bg-[rgba(255,255,255,0.06)] text-content-primary'
                      : 'text-content-dim hover:text-content-secondary'
                  }`}
                >
                  Deploy New
                </button>
                <button
                  type="button"
                  onClick={() => setFormMode('existing')}
                  className={`flex-1 px-3 py-1.5 rounded-[6px] font-mono text-[10px] uppercase tracking-[1.5px] transition-all ${
                    formMode === 'existing'
                      ? 'bg-[rgba(255,255,255,0.06)] text-content-primary'
                      : 'text-content-dim hover:text-content-secondary'
                  }`}
                >
                  Use Existing{readyStacks.length ? ` (${readyStacks.length})` : ''}
                </button>
              </div>

              {/* ── Deploy-new mode ── */}
              {formMode === 'new' && (
                <>
                  {/* A spent stack blocks a fresh deploy — offer to clear it */}
                  {blockingStack && (
                    <div className="bg-warning-dim border border-warning/25 rounded-[8px] px-4 py-3 flex flex-col gap-1">
                      <div className="font-mono text-[11px] text-warning">
                        A completed stack (<span className="text-content-primary">{blockingStack.name}</span>) is blocking a new deployment.
                      </div>
                      <div className="font-mono text-[10px] text-content-dim leading-[1.6]">
                        Emulations run against a clean baseline, so a spent stack must be torn down first.
                        Destroy it below, then deploy a fresh stack.
                      </div>
                    </div>
                  )}

                  {/* Cost estimate */}
                  <div>
                    <label className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim block mb-2">
                      Estimated Cost
                    </label>
                    {estimateLoading ? (
                      <div className="flex items-center gap-2 text-content-dim text-sm py-2">
                        <span className="inline-block w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
                        Loading estimate...
                      </div>
                    ) : estimate ? (
                      <div className="bg-surface-base border border-border rounded-[8px] p-4">
                        <div className="flex flex-col gap-1.5 mb-3 max-h-[200px] overflow-y-auto">
                          {(estimate.resources ?? []).map((r, i) => {
                            const cost = r.cost_per_hour_usd ?? 0
                            return (
                              <div key={i} className="flex justify-between items-baseline gap-3 font-mono text-[11px]">
                                <span className="text-content-dim truncate" title={r.name}>
                                  {r.name}{r.count ? ` x${r.count}` : ''}
                                </span>
                                <span className="text-content-secondary shrink-0">
                                  {cost === 0 ? 'Free' : cost < 0.0001 ? '<$0.0001/hr' : `$${cost.toFixed(4)}/hr`}
                                </span>
                              </div>
                            )
                          })}
                        </div>
                        <div className="border-t border-border pt-2 flex justify-between font-mono text-[12px]">
                          <span className="text-content-secondary font-medium">
                            Est. total ({estimate.defaultTtlHours}h TTL)
                          </span>
                          <span className="text-accent-blue font-bold">${(estimate.estimatedTotalUsd ?? 0).toFixed(4)}</span>
                        </div>
                        <div className="mt-2 font-mono text-[10px] text-content-dim">{estimate.note}</div>
                      </div>
                    ) : null}
                  </div>

                  {/* Stack name */}
                  <div>
                    <label className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim block mb-1.5">
                      Stack Name <span className="text-danger">*</span>
                    </label>
                    <input
                      type="text"
                      value={stackName}
                      onChange={(e) => setStackName(e.target.value)}
                      placeholder={`${emulationId}-yourname`}
                      className="w-full font-mono text-sm text-content-primary bg-[#0a0a0f] border border-border rounded-[6px] px-3 py-2
                        placeholder:text-content-dim/50 focus:outline-none focus:border-accent-blue transition-colors"
                    />
                    <div className="font-mono text-[10px] text-content-dim mt-0.5">
                      Pulumi stack name — convention: {emulationId}-&lt;username&gt;
                    </div>
                  </div>
                </>
              )}

              {/* ── Use-existing mode ── */}
              {formMode === 'existing' && (
                <div>
                  <label className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim block mb-2">
                    Ready Stacks
                  </label>
                  {readyStacks.length === 0 ? (
                    <div className="bg-surface-base border border-border rounded-[8px] px-4 py-6 text-center font-mono text-[11px] text-content-dim leading-[1.7]">
                      No ready stacks for this emulation.
                      <br />Switch to &ldquo;Deploy New&rdquo; to provision one.
                    </div>
                  ) : (
                    <div className="flex flex-col gap-1.5 max-h-[260px] overflow-y-auto">
                      {readyStacks.map((s) => (
                        <button
                          key={s.id}
                          type="button"
                          onClick={() => setSelectedStackId(s.id)}
                          className={`flex items-center justify-between gap-3 px-3 py-2.5 rounded-[6px] border text-left transition-all ${
                            selectedStackId === s.id
                              ? 'border-accent-blue bg-accent-blue/[0.08]'
                              : 'border-border hover:border-border-active'
                          }`}
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="w-2 h-2 rounded-full bg-safe shrink-0" />
                            <span className="font-mono text-[12px] text-content-primary truncate">{s.name}</span>
                          </div>
                          <span className="font-mono text-[10px] text-content-dim shrink-0">{s.region}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {error && (
                <div className="bg-danger/[0.08] border border-danger/20 rounded-[6px] px-4 py-3 font-mono text-xs text-danger">
                  {error}
                </div>
              )}
            </div>
          )}

          {/* ── Deploying ── */}
          {phase === 'deploying' && (
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-3">
                <span className="inline-block w-4 h-4 border-2 border-accent-blue border-t-transparent rounded-full animate-spin shrink-0" />
                <div>
                  <div className="font-mono text-[0.75rem] uppercase tracking-[1.5px] text-content-dim mb-0.5">
                    Deploying
                  </div>
                  <div className="font-mono text-sm text-content-secondary">{statusMsg}</div>
                </div>
              </div>
              <div className="bg-surface-base border border-border rounded-[6px] px-4 py-3 font-mono text-[11px] text-content-dim">
                Stack status: <span className="text-accent-blue">{stackStatus || 'deploying'}</span>
              </div>
            </div>
          )}

          {/* ── Destroying ── */}
          {phase === 'destroying' && (
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-3">
                <span className="inline-block w-4 h-4 border-2 border-danger border-t-transparent rounded-full animate-spin shrink-0" />
                <div>
                  <div className="font-mono text-[0.75rem] uppercase tracking-[1.5px] text-content-dim mb-0.5">
                    Destroying
                  </div>
                  <div className="font-mono text-sm text-content-secondary">{statusMsg}</div>
                </div>
              </div>
              <div className="bg-surface-base border border-border rounded-[6px] px-4 py-3 font-mono text-[11px] text-content-dim">
                Stack status: <span className="text-danger">{stackStatus || 'destroying'}</span>
              </div>
            </div>
          )}

          {/* ── Ready for attack ── */}
          {phase === 'ready' && (
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-3">
                <span className="inline-block w-3 h-3 rounded-full bg-safe shrink-0" />
                <div className="font-mono text-sm text-safe font-medium">{statusMsg}</div>
              </div>
              <div className="bg-surface-base border border-border rounded-[6px] px-4 py-3 font-mono text-[11px] text-content-dim">
                Stack: <span className="text-content-secondary">{stackName}</span>
                <span className="mx-2 text-border">|</span>
                Status: <span className="text-safe">ready_for_attack</span>
              </div>
              {error && (
                <div className="bg-danger/[0.08] border border-danger/20 rounded-[6px] px-4 py-3 font-mono text-xs text-danger">
                  {error}
                </div>
              )}
            </div>
          )}

          {/* ── Attacking / done ── */}
          {(phase === 'attacking' || phase === 'done') && (
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-3">
                {phase === 'attacking' && (
                  <span className="inline-block w-3 h-3 rounded-full bg-accent-blue animate-pulse shrink-0" />
                )}
                <div>
                  <div className="font-mono text-[0.75rem] uppercase tracking-[1.5px] text-content-dim mb-0.5">
                    {phase === 'done' ? (run?.status === 'completed' ? 'Completed' : 'Failed') : 'Attacking'}
                  </div>
                  <div className="font-mono text-sm text-content-secondary">{statusMsg}</div>
                </div>
              </div>

              {run && (
                <div className="flex gap-4 font-mono text-[11px] text-content-dim">
                  <span>Phase: <span className="text-content-secondary">{run.phase_current}/{run.phase_total}</span></span>
                  {run.started_at && <span>Started: {new Date(run.started_at).toLocaleTimeString()}</span>}
                  {run.completed_at && <span>Completed: {new Date(run.completed_at).toLocaleTimeString()}</span>}
                </div>
              )}

              <div>
                <div className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim mb-1.5">
                  Console Output
                </div>
                <pre
                  ref={consoleRef}
                  className="bg-[#0a0a0f] border border-border rounded-[6px] p-4 font-mono text-[11px] leading-[1.7]
                    text-content-secondary overflow-auto max-h-[280px] min-h-[120px] whitespace-pre-wrap"
                >
                  {run?.stdout || (phase === 'attacking' ? 'Waiting for output...' : '(no output)')}
                  {run?.stderr && (
                    <span className="text-danger block mt-2">{run.stderr}</span>
                  )}
                </pre>
              </div>

              {error && (
                <div className="bg-danger/[0.08] border border-danger/20 rounded-[6px] px-4 py-3 font-mono text-xs text-danger">
                  {error}
                </div>
              )}
            </div>
          )}

          {/* ── Error ── */}
          {phase === 'error' && !isForbidden && (
            <div className="flex flex-col gap-4">
              <div className="bg-danger/[0.08] border border-danger/20 rounded-[6px] px-4 py-3 font-mono text-xs text-danger">
                {error ?? 'An unexpected error occurred.'}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-border shrink-0">
          {phase === 'form' && (
            <button
              onClick={handleClose}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
            >
              Cancel
            </button>
          )}
          {phase === 'form' && formMode === 'new' && blockingStack && (
            <button
              onClick={() => handleDestroy(blockingStack.id)}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]"
            >
              &#9851; Destroy Stack
            </button>
          )}
          {phase === 'form' && formMode === 'new' && !blockingStack && (
            <button
              onClick={handleDeploy}
              disabled={!stackName.trim() || estimateLoading}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                bg-accent-blue text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(0,180,216,0.3)]
                disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none"
            >
              Deploy Stack
            </button>
          )}
          {phase === 'form' && formMode === 'existing' && (
            <button
              onClick={() => handleAttack(selectedStackId)}
              disabled={!selectedStackId}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]
                disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none"
            >
              &#9654; Run Attack
            </button>
          )}
          {phase === 'deploying' && (
            <button
              onClick={handleClose}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
            >
              Close (keeps deploying)
            </button>
          )}
          {phase === 'destroying' && (
            <button
              onClick={handleClose}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
            >
              Close (keeps destroying)
            </button>
          )}
          {phase === 'ready' && (
            <>
              <button
                onClick={handleDestroyAndClose}
                className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                  bg-transparent border border-[rgba(255,255,255,0.15)] text-content-dim transition-all
                  hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
              >
                Abort &amp; Destroy
              </button>
              <button
                onClick={() => handleAttack()}
                className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                  bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]"
              >
                &#9654; Run Attack
              </button>
            </>
          )}
          {phase === 'attacking' && (
            <button
              onClick={handleClose}
              className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
            >
              Close (keeps running)
            </button>
          )}
          {(phase === 'done' || phase === 'error') && (
            <>
              {deployedStackId && (
                <button
                  onClick={handleDestroyAndClose}
                  className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                    bg-transparent border border-[rgba(255,255,255,0.15)] text-content-dim transition-all
                    hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
                >
                  Destroy Stack &amp; Close
                </button>
              )}
              <button
                onClick={handleClose}
                className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                  bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]"
              >
                Close
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
