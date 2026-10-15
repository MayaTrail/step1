import { useEffect, useState } from 'react'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { IconClose } from '@/components/ui/Icons'
import { useCachedResource } from '@/hooks/useCachedResource'
import { getWindowAlerts } from '@/services/workflow.service'
import type { WindowAlert } from '@/types/workflow'

/**
 * The alerts a run has received, read from the side so the page keeps its
 * place behind them.
 *
 * A drawer rather than rows under the pipeline because an alert body is the
 * client's own payload and can run to hundreds of lines; inline, one long body
 * would push the rest of the page out of view. Selecting a row opens its body,
 * one at a time, the newest first.
 *
 * The drawer stays mounted while it slides out, so closing animates the same
 * way opening does instead of vanishing in one frame.
 */

const PANEL_STYLE = { width: 'clamp(min(420px, 100vw), 34vw, 520px)' }
const OVERLAY_STYLE = { zIndex: 200 }

/** Matches duration-300 on the panel and backdrop. */
const SLIDE_MS = 300

/** How often an open drawer refreshes while the run is still collecting. */
const LIVE_POLL_MS = 15_000

interface AlertsDrawerProps {
  open: boolean
  workflowId: string
  emulationType: string
  /** True while the run is still collecting, which keeps the list refreshing. */
  waiting: boolean
  onClose: () => void
}

export function AlertsDrawer({ open, workflowId, emulationType, waiting, onClose }: AlertsDrawerProps) {
  const [mounted, setMounted] = useState(open)
  const [shown, setShown] = useState(false)
  // Undefined until the reader picks a row, so the newest alert opens by default.
  const [chosen, setChosen] = useState<string | null | undefined>(undefined)

  const { data, loading, failed } = useCachedResource(
    open ? `workflow-alerts:${workflowId}` : null,
    () => getWindowAlerts(workflowId),
    open && waiting ? { pollMs: LIVE_POLL_MS } : undefined,
  )

  /*
   * Opening mounts the panel off-screen and slides it in two frames later:
   * the first frame commits the mount, the second starts the transition from
   * there. Closing slides it out first and unmounts once the slide is over.
   */
  useEffect(() => {
    if (open) {
      setMounted(true)
      let inner = 0
      const outer = requestAnimationFrame(() => {
        inner = requestAnimationFrame(() => setShown(true))
      })
      return () => {
        cancelAnimationFrame(outer)
        cancelAnimationFrame(inner)
      }
    }
    setShown(false)
    const timer = window.setTimeout(() => {
      setMounted(false)
      setChosen(undefined)
    }, SLIDE_MS)
    return () => window.clearTimeout(timer)
  }, [open])

  useEffect(() => {
    if (!open) return undefined
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = previous
    }
  }, [open, onClose])

  if (!mounted) return null

  const alerts = data?.alerts ?? []
  const count = data?.count ?? 0
  const more = Math.max(0, count - alerts.length)
  const selected = chosen === undefined ? (alerts[0]?.id ?? null) : chosen

  return (
    <div
      className={`fixed inset-0 flex justify-end ${shown ? '' : 'pointer-events-none'}`}
      style={OVERLAY_STYLE}
      role="dialog"
      aria-modal="true"
      aria-label="Alerts received"
    >
      <div
        onClick={onClose}
        aria-hidden="true"
        className={`absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300
          motion-reduce:transition-none ${shown ? 'opacity-100' : 'opacity-0'}`}
      />
      <aside
        style={PANEL_STYLE}
        className={`relative flex h-full flex-col border-l border-border bg-surface-card transition-transform duration-300 ease-out
          motion-reduce:transition-none ${shown ? 'translate-x-0' : 'translate-x-full'}`}
      >
        <button type="button" onClick={onClose} aria-label="Close"
          className="absolute right-5 top-5 z-10 text-content-dim transition-opacity hover:opacity-60">
          <IconClose size={16} />
        </button>

        <div className="border-b border-border px-6 pb-4 pt-5">
          <div className="mb-2 font-mono text-2xs uppercase tracking-label text-content-dim">
            Workflow · {emulationType}
          </div>
          <div className="pr-8 text-lg font-semibold text-content-primary">Alerts received</div>
          <div className="mt-1.5 text-xs text-content-dim">
            {count === 0
              ? 'Alerts your SIEM posts during this run appear here.'
              : `${count} in this window, newest first, exactly as your SIEM posted them. Select one to read its body.`}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-6 pb-8 pt-2">
          {failed && !data && <p className="mt-4 text-sm text-content-dim">The alerts could not be loaded.</p>}
          {loading && !data && <p className="mt-4 text-sm text-content-dim">Loading…</p>}
          {data && alerts.length === 0 && (
            <p className="mt-4 text-sm text-content-dim">
              {waiting ? 'Nothing has arrived in this window yet.' : 'Nothing arrived in this window.'}
            </p>
          )}
          <ul className="divide-y divide-border">
            {alerts.map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                selected={selected === alert.id}
                onSelect={() => setChosen(selected === alert.id ? null : alert.id)}
              />
            ))}
          </ul>
          {more > 0 && <p className="pt-3 text-xs text-content-dim">+ {more} more in this window</p>}
        </div>
      </aside>
    </div>
  )
}

/**
 * One alert: its rule, when it arrived, and when selected, its body.
 *
 * @param alert - The alert as stored.
 * @param selected - Whether its body is open.
 * @param onSelect - Toggles the body.
 */
function AlertRow({ alert, selected, onSelect }: { alert: WindowAlert; selected: boolean; onSelect: () => void }) {
  return (
    <li className="py-3">
      <button
        type="button"
        onClick={onSelect}
        aria-expanded={selected}
        className="w-full min-w-0 bg-transparent text-left transition-opacity hover:opacity-60"
      >
        <span className="flex items-baseline justify-between gap-3">
          <span className={`block truncate text-sm font-semibold ${selected ? 'text-accent-blue' : 'text-content-primary'}`}>
            {alert.ruleName || alert.ruleId || 'Unnamed alert'}
          </span>
          <span className="shrink-0 font-mono text-2xs text-content-dim" title={new Date(alert.receivedAt).toLocaleString()}>
            {formatWhen(alert.receivedAt)}
          </span>
        </span>
        <span className="block truncate text-xs text-content-dim mt-0.5">
          {alert.technique || 'no technique'} · {alert.severity || 'no severity'}
        </span>
      </button>
      {selected && (
        <pre className="animate-fadeIn mt-2.5 max-h-56 overflow-auto whitespace-pre rounded-xl border border-border bg-surface-base p-3
          font-mono text-2xs text-content-secondary">
          {JSON.stringify(alert.raw, null, 2)}
        </pre>
      )}
    </li>
  )
}
