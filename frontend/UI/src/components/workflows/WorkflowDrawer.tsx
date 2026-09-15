import { useEffect, useState } from 'react'
import { useWorkflowRun } from '@/hooks/useWorkflows'
import { deleteWorkflowRun } from '@/services/workflow.service'
import { Badge } from '@/components/ui/Badge'
import { IconClose } from '@/components/ui/Icons'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { WorkflowDetailBody } from './WorkflowDetailBody'
import { STATUS_LABEL, STATUS_TONE, isOpen, untilDeadline } from './workflowMeta'

/**
 * A workflow's detail, slid in from the right over the list.
 *
 * Chosen over navigating away because reading one run is almost always part of
 * scanning several: the list stays where it was, and closing the panel returns
 * the reader to the same scroll position and the same filter rather than to a
 * freshly mounted page.
 *
 * There is no standalone page behind it. The panel carries everything a run
 * has to say, so a second surface rendering the same body would be one more
 * place to keep in step for no additional fact.
 */

/** Half the viewport, within bounds that stay readable on either extreme. */
const PANEL_WIDTH = 'w-full sm:w-[min(720px,50vw)] sm:min-w-[460px]'

interface WorkflowDrawerProps {
  workflowId: string
  onClose: () => void
  /** Called once the run has been removed, so the list can refetch. */
  onDeleted: () => void
}

export function WorkflowDrawer({ workflowId, onClose, onDeleted }: WorkflowDrawerProps) {
  const { data: run, loading } = useWorkflowRun(workflowId, true)
  const [confirming, setConfirming] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [removeError, setRemoveError] = useState<string | null>(null)

  // Failed runs pile up while an integration is being set up, and a scheduled
  // run needs a way out before its time arrives. Neither owns anything: the
  // stack reference is SET_NULL, so any infrastructure stays on the Stacks page.
  const deletable = run?.status === 'failed' || run?.status === 'scheduled'

  async function remove() {
    if (removing) return
    setRemoving(true)
    setRemoveError(null)
    try {
      await deleteWorkflowRun(workflowId)
      onDeleted()
    } catch (caught) {
      const detail = (caught as { response?: { data?: { detail?: string } } })
        .response?.data?.detail
      setRemoveError(detail ?? 'Could not remove this run.')
      setConfirming(false)
    } finally {
      setRemoving(false)
    }
  }

  /*
   * Mount off-screen, then slide in on the next frame. Animating with a
   * transition rather than a keyframe keeps this to utilities the design system
   * already defines, instead of adding an animation to the Tailwind config for
   * one component.
   */
  const [shown, setShown] = useState(false)
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setShown(true))
    return () => window.cancelAnimationFrame(frame)
  }, [])

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    // The list behind the panel must not scroll under it.
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = previous
    }
  }, [onClose])

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
                {run?.emulationType ?? 'Workflow'}
              </h2>
              {run && (
                <Badge tone={STATUS_TONE[run.status]} mono dot pulse={isOpen(run.status)}>
                  {STATUS_LABEL[run.status]}
                </Badge>
              )}
            </div>
            {run && (
              <p className="text-xs text-content-dim mt-1">
                Started {formatWhen(run.createdAt)}
                {run.status === 'awaiting_alerts' && untilDeadline(run.alertDeadline)
                  ? ` · ${untilDeadline(run.alertDeadline)}`
                  : ''}
              </p>
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

        <div className="flex-1 overflow-y-auto px-5 py-4">
          {loading && !run ? (
            <div className="py-16 text-center font-mono text-sm text-content-dim">Loading…</div>
          ) : run ? (
            <WorkflowDetailBody run={run} />
          ) : (
            <div className="py-16 text-center font-mono text-sm text-content-dim">
              Workflow not found.
            </div>
          )}
        </div>

        {deletable && (
          <footer className="shrink-0 px-5 py-3.5 border-t border-border flex flex-wrap
            items-center gap-2.5">
            {confirming ? (
              <>
                <button
                  type="button"
                  onClick={remove}
                  disabled={removing}
                  className="px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border
                    border-danger/30 text-danger transition-opacity hover:opacity-60
                    disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  {removing ? 'Removing…' : 'Confirm remove'}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirming(false)}
                  className="px-3 py-1.5 rounded-btn text-xs tracking-btn text-content-dim
                    transition-opacity hover:opacity-60"
                >
                  Cancel
                </button>
              </>
            ) : (
              <button
                type="button"
                onClick={() => setConfirming(true)}
                className="px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border
                  border-danger/30 text-danger transition-opacity hover:opacity-60"
              >
                {run?.status === 'scheduled' ? 'Cancel this run' : 'Remove this run'}
              </button>
            )}

            <span className="text-2xs text-content-muted">
              {run?.stackId
                ? 'Any infrastructure it created stays on the Stacks page.'
                : 'Nothing was deployed by this run.'}
            </span>

            {removeError && (
              <span className="w-full text-xs text-danger">{removeError}</span>
            )}
          </footer>
        )}
      </aside>
    </div>
  )
}
