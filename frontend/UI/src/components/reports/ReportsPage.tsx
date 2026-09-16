/**
 * Reports — pick a run, get its evidence packet.
 *
 * Replaces the "coming soon" stub. There is nothing to configure: every
 * completed run already holds everything a report needs, so this is a list of
 * runs and a way into each one, plus the entry point for comparing two.
 */

import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { useEmulationRuns } from '@/hooks/useEmulationRuns'
import { useUiMode } from '@/context/UiModeContext'
import { EmptyState } from '@/components/ui/EmptyState'
import { IconBarChart } from '@/components/ui/Icons'
import { stamp } from './reportHelpers'

export function ReportsPage() {
  const { data: runs, loading } = useEmulationRuns(['completed'])
  const { plain } = useUiMode()
  const navigate = useNavigate()

  /** Runs chosen for comparison, oldest-first once both are picked. */
  const [picked, setPicked] = useState<string[]>([])

  const completed = useMemo(() => runs ?? [], [runs])

  function togglePick(runId: string) {
    setPicked((current) => {
      if (current.includes(runId)) return current.filter((id) => id !== runId)
      // Keep at most two; picking a third replaces the older selection.
      return [...current, runId].slice(-2)
    })
  }

  const canCompare = picked.length === 2

  return (
    <div className="animate-fadeIn">
      <div className="mb-6">
        <div className="font-mono text-2xs uppercase tracking-label text-accent-blue mb-2">
          Administration
        </div>
        <h1 className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Reports
        </h1>
        <p className="text-[0.9rem] text-content-secondary mt-1.5 max-w-[70ch]">
          {plain
            ? 'Every finished test can be turned into a report you can print or hand to someone else — what was caught, what got through, and what changed since last time.'
            : 'An evidence packet per completed run: coverage, every rule verdict, the gaps, techniques with no rule, and the change against the previous run.'}
        </p>
      </div>

      {/* Compare bar — appears only once something is selected, so it never
          sits there as dead chrome. */}
      {picked.length > 0 && (
        <div className="flex flex-wrap items-center gap-3 mb-5 px-4 py-3 border border-accent-blue/30 bg-accent-blue/[0.05] rounded-btn">
          <span className="text-[0.85rem] text-content-primary">
            {picked.length} run{picked.length === 1 ? '' : 's'} selected
            {!canCompare && <span className="text-content-dim"> — pick one more to compare</span>}
          </span>
          <div className="flex gap-2 ml-auto">
            <button
              type="button"
              onClick={() => setPicked([])}
              className="border border-border rounded-btn px-3 py-1.5 text-xs text-content-secondary hover:text-content-primary"
            >
              Clear
            </button>
            <button
              type="button"
              disabled={!canCompare}
              onClick={() => navigate(`/reports/compare?a=${picked[0]}&b=${picked[1]}`)}
              className={`rounded-btn px-3 py-1.5 text-xs font-medium ${
                canCompare
                  ? 'bg-accent-blue text-button-fg'
                  : 'border border-border text-content-muted cursor-not-allowed'
              }`}
            >
              Compare runs
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading runs…</div>
      ) : completed.length === 0 ? (
        <EmptyState
          icon={<IconBarChart size={32} />}
          title="No completed runs yet"
          body="Run an emulation to its end and its report will appear here."
        />
      ) : (
        <div className="border border-border rounded-btn overflow-hidden">
          {completed.map((run) => {
            const isPicked = picked.includes(run.id)
            return (
              <div
                key={run.id}
                className={`flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 border-b border-border
                  last:border-b-0 transition-colors ${isPicked ? 'bg-accent-blue/[0.06]' : 'hover:bg-surface-card'}`}
              >
                <label className="flex items-center gap-2.5 cursor-pointer shrink-0">
                  <input
                    type="checkbox"
                    checked={isPicked}
                    onChange={() => togglePick(run.id)}
                    aria-label={`Select ${run.emulation_name} for comparison`}
                    className="accent-accent-blue"
                  />
                  <span className="font-mono text-xs text-content-dim">{run.id.slice(0, 8)}</span>
                </label>

                <div className="min-w-0 flex-1">
                  <div className="text-[0.9rem] text-content-primary font-medium">
                    {run.emulation_name}
                  </div>
                  <div className="text-xs text-content-dim">
                    {run.stack_name ?? '—'} · {stamp(run.started_at)}
                  </div>
                </div>

                <Link
                  to={`/reports/${run.id}`}
                  className="shrink-0 font-mono text-2xs uppercase tracking-label text-accent-blue hover:underline no-underline"
                >
                  Open report →
                </Link>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
