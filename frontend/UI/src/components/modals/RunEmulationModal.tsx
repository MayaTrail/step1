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
import type { EmulationRunRecord, EmulationEstimate, StackStatus } from '@/types'
import {
  getEmulationEstimate,
  deployEmulationStack,
  triggerEmulationAttack,
  pollEmulationRunUntilDone,
  destroyEmulationStack,
} from '@/services/emulation.service'
import { getStack } from '@/services/stack.service'

/* ── Props ── */
interface RunEmulationModalProps {
  emulationId: string
  emulationName: string
  onClose: () => void
}

/* ── Phase type ── */
type ModalPhase = 'form' | 'deploying' | 'ready' | 'attacking' | 'done' | 'error'

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

/* ── Component ── */
export function RunEmulationModal({ emulationId, emulationName, onClose }: RunEmulationModalProps) {
  const [phase, setPhase] = useState<ModalPhase>('form')
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

  const handleDeploy = useCallback(async () => {
    if (!stackName.trim()) return
    setError(null)
    setPhase('deploying')
    setStatusMsg('Deploying infrastructure...')

    try {
      const { stackId } = await deployEmulationStack(emulationId, stackName.trim())
      setDeployedStackId(stackId)

      // Poll the Stack status until it reaches a terminal state.
      const controller = new AbortController()
      abortRef.current = controller

      let currentStatus: StackStatus = 'deploying'
      while (!TERMINAL_STACK_STATUSES.has(currentStatus)) {
        if (controller.signal.aborted) return

        await new Promise<void>((resolve, reject) => {
          const t = setTimeout(resolve, 4000)
          controller.signal.addEventListener('abort', () => { clearTimeout(t); reject(new DOMException('Aborted', 'AbortError')) }, { once: true })
        })

        const stack = await getStack(stackId)
        currentStatus = stack.status
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

    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      const apiDetail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      const status = (err as { response?: { status?: number } })?.response?.status
      if (status === 403) {
        setIsForbidden(true)
        setPhase('error')
        return
      }
      setError(apiDetail ?? (err instanceof Error ? err.message : 'Deployment failed'))
      setPhase('error')
    }
  }, [emulationId, stackName])

  const handleAttack = useCallback(async () => {
    if (!deployedStackId) return
    setError(null)
    setPhase('attacking')
    setStatusMsg('Attack in progress...')

    try {
      const { runId } = await triggerEmulationAttack(deployedStackId)

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

          {/* ── Form ── */}
          {phase === 'form' && (
            <div className="flex flex-col gap-5">
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
                    <div className="grid grid-cols-2 gap-2 mb-3">
                      {estimate.resources.map((r, i) => (
                        <div key={i} className="flex justify-between font-mono text-[11px]">
                          <span className="text-content-dim">{r.name} x{r.count}</span>
                          <span className="text-content-secondary">
                            {r.cost_per_hour_usd === 0 ? 'Free' : `$${r.cost_per_hour_usd.toFixed(4)}/hr`}
                          </span>
                        </div>
                      ))}
                    </div>
                    <div className="border-t border-border pt-2 flex justify-between font-mono text-[12px]">
                      <span className="text-content-secondary font-medium">
                        Est. total ({estimate.defaultTtlHours}h TTL)
                      </span>
                      <span className="text-accent-blue font-bold">${estimate.estimatedTotalUsd.toFixed(4)}</span>
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
            <>
              <button
                onClick={handleClose}
                className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
                  bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                  hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
              >
                Cancel
              </button>
              <button
                onClick={handleDeploy}
                disabled={!stackName.trim() || estimateLoading}
                className="px-5 py-2.5 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
                  bg-accent-blue text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(0,180,216,0.3)]
                  disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none"
              >
                Deploy Stack
              </button>
            </>
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
                onClick={handleAttack}
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
