import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { EmptyState } from '@/components/ui/EmptyState'
import { IconClock } from '@/components/ui/Icons'
import {
  deleteSchedule,
  listSchedules,
  updateSchedule,
} from '@/services/coverageHistory.service'
import type { ScheduleCadence, ScheduledRun } from '@/types'

/**
 * The home for continuous assurance: everything running on a cadence, in one
 * place. Individual schedules are created and tuned on each emulation's
 * overview; this is the "what do I have running, and when is it next?" view the
 * per-emulation toggle could not give.
 */

const CADENCES: ScheduleCadence[] = ['daily', 'weekly', 'monthly']

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function relativeTo(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now()
  if (ms <= 0) return 'due now'
  const days = Math.round(ms / 86_400_000)
  if (days >= 1) return `in ${days} day${days === 1 ? '' : 's'}`
  const hours = Math.round(ms / 3_600_000)
  return `in ${hours} hour${hours === 1 ? '' : 's'}`
}

export function SchedulesPage() {
  const [schedules, setSchedules] = useState<ScheduledRun[] | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    listSchedules()
      .then((rows) => !cancelled && setSchedules(rows))
      .catch(() => !cancelled && setSchedules([]))
    return () => {
      cancelled = true
    }
  }, [])

  async function patch(id: string, body: { enabled?: boolean; cadence?: ScheduleCadence }) {
    setBusyId(id)
    try {
      const updated = await updateSchedule(id, body)
      setSchedules((rows) => (rows ?? []).map((r) => (r.id === id ? updated : r)))
    } finally {
      setBusyId(null)
    }
  }

  async function remove(id: string) {
    if (!window.confirm('Stop this schedule? It will no longer run on its own.')) return
    setBusyId(id)
    try {
      await deleteSchedule(id)
      setSchedules((rows) => (rows ?? []).filter((r) => r.id !== id))
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div>
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Operations
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Schedules
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          Emulations that re-run on a cadence. Each run is compared to the last,
          so a detection that stops firing is caught on its own.
        </div>
      </div>

      {schedules === null ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading schedules...</div>
      ) : schedules.length === 0 ? (
        <EmptyState
          icon={<IconClock size={32} />}
          title="Nothing scheduled yet"
          body="Open an emulation and turn on Continuous assurance in its Detection Readiness card to have it re-run automatically."
        />
      ) : (
        <div className="rounded-card border border-border bg-surface-card overflow-hidden">
          <div className="grid grid-cols-[1.4fr_0.8fr_1fr_0.8fr_auto] gap-3 px-4 py-2.5 border-b border-border bg-surface-deep font-mono text-2xs uppercase tracking-label text-content-dim">
            <div>Emulation</div>
            <div>Cadence</div>
            <div>Next run</div>
            <div>Last run</div>
            <div />
          </div>
          {schedules.map((s) => (
            <div
              key={s.id}
              className="grid grid-cols-[1.4fr_0.8fr_1fr_0.8fr_auto] gap-3 px-4 py-3 items-center border-b border-border last:border-b-0"
            >
              <div className="min-w-0">
                <Link
                  to={`/aws/emulations/${s.emulation_type}`}
                  className="text-[0.9rem] font-medium text-content-primary hover:text-accent-blue transition-colors no-underline"
                >
                  {s.emulation_type}
                </Link>
                {!s.enabled && (
                  <span className="ml-2 font-mono text-2xs uppercase tracking-label text-content-dim">
                    paused
                  </span>
                )}
              </div>

              <select
                value={s.cadence}
                disabled={busyId === s.id}
                onChange={(e) => void patch(s.id, { cadence: e.target.value as ScheduleCadence })}
                className="bg-surface-base border border-border rounded-btn px-2 py-1 text-[0.8rem] text-content-primary focus:outline-none focus:border-accent-blue"
              >
                {CADENCES.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>

              <div className="font-mono text-xs text-content-secondary">
                {s.enabled ? (
                  <>
                    {fmtDate(s.next_run_at)}
                    <span className="text-content-dim"> · {relativeTo(s.next_run_at)}</span>
                  </>
                ) : (
                  <span className="text-content-dim">paused</span>
                )}
              </div>

              <div className="font-mono text-xs text-content-secondary">
                {s.last_run ? (
                  <Link
                    to={`/aws/emulations/${s.emulation_type}/logging/${s.last_run}`}
                    className="text-accent-blue hover:underline"
                  >
                    {fmtDate(s.last_run_at)}
                  </Link>
                ) : (
                  <span className="text-content-dim">never</span>
                )}
              </div>

              <div className="flex items-center gap-3 justify-end">
                <button
                  type="button"
                  disabled={busyId === s.id}
                  onClick={() => void patch(s.id, { enabled: !s.enabled })}
                  className="font-mono text-2xs uppercase tracking-label text-content-secondary hover:text-content-primary transition-colors disabled:opacity-40"
                >
                  {s.enabled ? 'Pause' : 'Resume'}
                </button>
                <button
                  type="button"
                  disabled={busyId === s.id}
                  onClick={() => void remove(s.id)}
                  className="font-mono text-2xs uppercase tracking-label text-content-dim hover:text-danger transition-colors disabled:opacity-40"
                >
                  Stop
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
