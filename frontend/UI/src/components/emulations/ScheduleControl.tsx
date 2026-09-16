import { useEffect, useState } from 'react'

import {
  createSchedule,
  deleteSchedule,
  listSchedules,
  updateSchedule,
} from '@/services/coverageHistory.service'
import type { ScheduleCadence, ScheduledRun } from '@/types'

/**
 * Turn an emulation into a recurring one.
 *
 * This is the control that makes the product continuous rather than
 * point-in-time: schedule the emulation, and every run's detection check is
 * compared to the last, so a regression is caught on its own. Compact by
 * design - it lives inside the emulation's Detection Readiness card.
 */

const CADENCES: { value: ScheduleCadence; label: string }[] = [
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
]

export function ScheduleControl({ emulationType }: { emulationType: string }) {
  const [schedule, setSchedule] = useState<ScheduledRun | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [cadence, setCadence] = useState<ScheduleCadence>('weekly')

  useEffect(() => {
    let cancelled = false
    listSchedules()
      .then((rows) => {
        if (cancelled) return
        const mine = rows.find((r) => r.emulation_type === emulationType) ?? null
        setSchedule(mine)
        if (mine) setCadence(mine.cadence)
      })
      .catch(() => {})
      .finally(() => !cancelled && setLoaded(true))
    return () => {
      cancelled = true
    }
  }, [emulationType])

  if (!loaded) return null

  const active = schedule?.enabled

  async function enable() {
    setBusy(true)
    try {
      setSchedule(await createSchedule(emulationType, cadence))
    } finally {
      setBusy(false)
    }
  }

  async function changeCadence(next: ScheduleCadence) {
    setCadence(next)
    if (!schedule) return
    setBusy(true)
    try {
      setSchedule(await updateSchedule(schedule.id, { cadence: next }))
    } finally {
      setBusy(false)
    }
  }

  async function toggleOff() {
    if (!schedule) return
    setBusy(true)
    try {
      await deleteSchedule(schedule.id)
      setSchedule(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mt-4 pt-4 border-t border-border">
      <div className="flex items-center justify-between gap-3">
        <div className="font-mono text-[11px] uppercase tracking-[1.5px] text-content-dim">
          Continuous assurance
        </div>
        {active && (
          <span className="font-mono text-[10px] uppercase tracking-[1px] text-safe">
            scheduled {schedule!.cadence}
          </span>
        )}
      </div>

      {active ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span className="text-[0.8rem] text-content-secondary">
            Runs {schedule!.cadence}; next{' '}
            {new Date(schedule!.next_run_at).toLocaleDateString()}. Each run is
            compared to the last for regressions.
          </span>
          <select
            value={cadence}
            disabled={busy}
            onChange={(e) => void changeCadence(e.target.value as ScheduleCadence)}
            className="bg-surface-base border border-border rounded-btn px-2 py-1 text-[0.78rem] text-content-primary focus:outline-none focus:border-accent-blue"
          >
            {CADENCES.map((c) => (
              <option key={c.value} value={c.value}>{c.label}</option>
            ))}
          </select>
          <button
            type="button"
            onClick={toggleOff}
            disabled={busy}
            className="font-mono text-[11px] text-content-dim hover:text-danger transition-colors disabled:opacity-40"
          >
            Stop
          </button>
        </div>
      ) : (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span className="text-[0.8rem] text-content-secondary">
            Re-run this on a schedule and get alerted when a detection that used
            to fire goes silent.
          </span>
          <select
            value={cadence}
            disabled={busy}
            onChange={(e) => setCadence(e.target.value as ScheduleCadence)}
            className="bg-surface-base border border-border rounded-btn px-2 py-1 text-[0.78rem] text-content-primary focus:outline-none focus:border-accent-blue"
          >
            {CADENCES.map((c) => (
              <option key={c.value} value={c.value}>{c.label}</option>
            ))}
          </select>
          <button
            type="button"
            onClick={enable}
            disabled={busy}
            className="bg-accent-blue text-button-fg rounded-btn px-3 py-1.5 text-[0.8rem] font-medium disabled:opacity-40"
          >
            {busy ? 'Scheduling...' : 'Schedule it'}
          </button>
        </div>
      )}
    </div>
  )
}
