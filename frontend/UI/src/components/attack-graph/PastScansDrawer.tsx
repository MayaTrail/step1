/**
 * Past scans, opened on request from the page header.
 *
 * Framed like the account check drawer: mounted first so it slides in, closed
 * by Escape or the backdrop. Each row opens its scan; a finished scan can be
 * deleted after an inline confirm.
 */

import { useEffect, useState } from 'react'

import { formatWhen } from '@/components/threatfeed/feedMeta'
import { IconClose, IconTrash } from '@/components/ui/Icons'
import * as attackGraph from '@/services/attackGraph.service'
import type { ScanState, ScanStatus, ScanSummary } from '@/types/attackGraph'

const PANEL_STYLE = { width: 'clamp(min(420px, 100vw), 34vw, 520px)' }
const OVERLAY_STYLE = { zIndex: 200 }

// Matches SCANS_KEPT_PER_USER in backend/apps/attack_graph/models.py, which
// deletes the oldest scan when a new one starts.
export const SCANS_KEPT = 10

const OUTCOME: Record<ScanState, { word: string; tone: string }> = {
  findings: { word: 'Findings', tone: 'text-danger' },
  clean: { word: 'Clean', tone: 'text-safe' },
  partial: { word: 'Partial', tone: 'text-warning' },
}

const STATUS: Record<ScanStatus, { word: string; tone: string }> = {
  pending: { word: 'Queued', tone: 'text-content-dim' },
  running: { word: 'Scanning', tone: 'text-accent-blue' },
  completed: { word: 'Completed', tone: 'text-content-secondary' },
  failed: { word: 'Failed', tone: 'text-content-dim' },
}

export function PastScansDrawer({
  open,
  scans,
  openId,
  onOpen,
  onDeleted,
  onClose,
}: {
  open: boolean
  scans: ScanSummary[]
  /** The scan shown on the page, marked in the list. */
  openId: string | null
  onOpen: (scanId: string) => void
  onDeleted: (scanId: string) => void
  onClose: () => void
}) {
  const [shown, setShown] = useState(false)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) {
      setShown(false)
      return undefined
    }
    const id = requestAnimationFrame(() => setShown(true))
    return () => cancelAnimationFrame(id)
  }, [open])

  useEffect(() => {
    if (!open) return undefined
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  const remove = async (scanId: string) => {
    setDeleting(true)
    setError(null)
    try {
      await attackGraph.deleteScan(scanId)
      setConfirming(null)
      onDeleted(scanId)
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? 'Could not delete the scan.')
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="fixed inset-0 flex justify-end" style={OVERLAY_STYLE} role="dialog" aria-modal="true" aria-label="Past scans">
      <div
        onClick={onClose}
        className={`absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300 ${shown ? 'opacity-100' : 'opacity-0'}`}
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
          <div className="mb-2 font-mono text-2xs uppercase tracking-label text-content-dim">Attack Graph</div>
          <div className="pr-8 text-lg font-semibold text-content-primary">Past scans</div>
          <div className="mt-1.5 text-xs text-content-dim">
            Each scan stores a map of your account&apos;s IAM, so only your {SCANS_KEPT} most recent are kept.
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-6 pb-8 pt-2">
          {error && <p className="mt-3 text-xs text-danger">{error}</p>}
          {scans.length === 0 && <p className="mt-4 text-sm text-content-dim">No scans yet.</p>}
          <ul className="divide-y divide-border">
            {scans.map((scan) => {
              const outcome = scan.status === 'completed' && scan.state ? OUTCOME[scan.state] : STATUS[scan.status]
              const finished = scan.status === 'completed' || scan.status === 'failed'
              const isOpen = scan.id === openId
              return (
                <li key={scan.id} className="flex items-center gap-3 py-3">
                  <button type="button" onClick={() => onOpen(scan.id)}
                    className="min-w-0 flex-1 bg-transparent text-left transition-opacity hover:opacity-60">
                    <span className={`block text-sm font-semibold ${isOpen ? 'text-accent-blue' : 'text-content-primary'}`}>
                      {new Date(scan.created_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
                    </span>
                    <span className="block truncate text-xs text-content-dim">
                      {scan.status === 'failed' && scan.error_message ? scan.error_message : formatWhen(scan.created_at)}
                    </span>
                  </button>
                  <span className={`text-xs font-semibold ${outcome.tone}`}>{outcome.word}</span>
                  {finished && confirming !== scan.id && (
                    <button type="button" onClick={() => setConfirming(scan.id)} aria-label="Delete scan"
                      className="rounded-btn border border-border bg-transparent p-1.5 text-content-dim transition-opacity hover:opacity-60">
                      <IconTrash size={13} />
                    </button>
                  )}
                  {confirming === scan.id && (
                    <span className="flex items-center gap-1.5">
                      <button type="button" onClick={() => remove(scan.id)} disabled={deleting}
                        className="rounded-btn border border-danger bg-transparent px-2.5 py-1 text-xs font-semibold text-danger transition-opacity hover:opacity-60">
                        {deleting ? 'Deleting…' : 'Delete'}
                      </button>
                      <button type="button" onClick={() => setConfirming(null)} disabled={deleting}
                        className="rounded-btn border border-border bg-transparent px-2.5 py-1 text-xs text-content-secondary transition-opacity hover:opacity-60">
                        Cancel
                      </button>
                    </span>
                  )}
                </li>
              )
            })}
          </ul>
        </div>
      </aside>
    </div>
  )
}
