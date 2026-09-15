import { useMemo, useState } from 'react'
import type { WorkflowRun, WorkflowStatus } from '@/types/workflow'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { IconChevron } from '@/components/ui/Icons'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { WorkflowDrawer } from './WorkflowDrawer'
import {
  STATUS_LABEL,
  STATUS_TONE,
  formatCoverage,
  isOpen,
  untilDeadline,
  untilScheduled,
} from './workflowMeta'

/**
 * Every workflow the user has started, past and present.
 *
 * A table rather than stacked cards. Each run carries a status, a result and
 * four figures, and as cards that was a screen apiece: ten runs pushed the one
 * being looked for below the fold. A table keeps a run to one line and makes
 * them comparable, which is the point of a history.
 */

/** The filters, phrased by what the reader is looking for. */
const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'scheduled', label: 'Scheduled' },
  { key: 'active', label: 'Running' },
  { key: 'awaiting', label: 'Waiting for alerts' },
  { key: 'completed', label: 'Completed' },
  { key: 'failed', label: 'Failed' },
] as const

type FilterKey = (typeof FILTERS)[number]['key']

/**
 * Decide whether a run belongs in a filter.
 *
 * "Running" deliberately excludes runs waiting on a SIEM: they are open, but
 * nothing is happening and nothing will for tens of minutes, so grouping them
 * with active work would bury the runs that are actually moving. A scheduled
 * run is excluded for the same reason, and gets its own filter because a run
 * due next Tuesday is otherwise indistinguishable from one that has hung.
 *
 * @param run - The workflow to test.
 * @param filter - The selected filter.
 */
function matches(run: WorkflowRun, filter: FilterKey): boolean {
  const active: WorkflowStatus[] = ['pending', 'deploying', 'attacking']
  switch (filter) {
    case 'scheduled':
      return run.status === 'scheduled'
    case 'active':
      return active.includes(run.status)
    case 'awaiting':
      return run.status === 'awaiting_alerts'
    case 'completed':
      return run.status === 'completed'
    case 'failed':
      return run.status === 'failed'
    default:
      return true
  }
}

interface RunsSectionProps {
  runs: WorkflowRun[]
  loading: boolean
  /** Called after a change the list has to refetch to show. */
  onChanged: () => void
}

export function RunsSection({ runs, loading, onChanged }: RunsSectionProps) {
  const [filter, setFilter] = useState<FilterKey>('all')
  // Held here rather than in the router, so closing the panel returns the
  // reader to the same scroll position and the same filter.
  const [openId, setOpenId] = useState<string | null>(null)

  const counts = useMemo(() => {
    const result = {} as Record<FilterKey, number>
    for (const { key } of FILTERS) result[key] = runs.filter((run) => matches(run, key)).length
    return result
  }, [runs])

  const filtered = useMemo(() => runs.filter((run) => matches(run, filter)), [runs, filter])

  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-center gap-2 mb-4">
        {FILTERS.map(({ key, label }) => {
          const selected = filter === key
          return (
            <button
              key={key}
              type="button"
              aria-pressed={selected}
              onClick={() => setFilter(key)}
              className={`px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border
                transition-opacity hover:opacity-60
                ${selected
                  ? 'border-border-active bg-surface-elevated text-content-primary'
                  : 'border-border bg-transparent text-content-secondary'}`}
            >
              {label}
              <span className="ml-1.5 font-mono text-content-dim">{counts[key]}</span>
            </button>
          )
        })}
      </div>

      {loading && runs.length === 0 ? (
        <div className="py-10 text-center font-mono text-xs text-content-dim">Loading…</div>
      ) : filtered.length === 0 ? (
        <div className="py-10 text-center text-sm text-content-dim">
          {runs.length === 0
            ? 'No workflows yet. Start one to validate an emulation against the detections you already run.'
            : 'No workflows match that filter.'}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[760px]">
            <thead>
              <tr className="font-mono text-2xs uppercase tracking-caps text-content-dim">
                <th className="font-normal pb-2 pr-3">Emulation</th>
                <th className="font-normal pb-2 pr-3">Status</th>
                <th className="font-normal pb-2 pr-3">Result</th>
                <th className="font-normal pb-2 pr-3 text-right">Coverage</th>
                <th className="font-normal pb-2 pr-3 text-right">Caught</th>
                <th className="font-normal pb-2 text-right">Started</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((run) => (
                <RunRow key={run.id} run={run} onOpen={() => setOpenId(run.id)} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {openId && (
        <WorkflowDrawer
          workflowId={openId}
          onClose={() => setOpenId(null)}
          onDeleted={() => {
            setOpenId(null)
            onChanged()
          }}
        />
      )}
    </Card>
  )
}

/** One workflow on one line. The whole row opens the detail panel. */
function RunRow({ run, onOpen }: { run: WorkflowRun; onOpen: () => void }) {
  // A scheduled run and a stuck one look identical on a row, so the status
  // cell has to say when it is due.
  const waiting =
    run.status === 'awaiting_alerts'
      ? untilDeadline(run.alertDeadline)
      : run.status === 'scheduled'
        ? untilScheduled(run.scheduledFor)
        : ''
  const caught = run.score ? `${run.score.counts.fired ?? 0} of ${run.score.ruleCount}` : '—'

  return (
    /*
     * align-middle, not align-top. The status cell holds a Badge whose border
     * and padding inset its text, so top-aligning put the plain text in the
     * neighbouring cells a few pixels above the badge's label and the row read
     * as crooked.
     *
     * Hover changes the content, not the container. The design system asks for
     * opacity and emphasis over background swaps, and a filled rectangle across
     * a row inside a rounded card is exactly what that rule exists to prevent.
     */
    <tr
      onClick={onOpen}
      className="group border-t border-border align-middle cursor-pointer"
    >
      <td className="py-3 pr-3">
        <span className="flex items-center gap-1.5">
          <span className="text-xs font-medium tracking-body text-content-primary
            transition-colors group-hover:text-accent-blue">
            {run.emulationType}
          </span>
          <span className="text-accent-blue opacity-0 -translate-x-1 transition-all
            group-hover:opacity-100 group-hover:translate-x-0">
            <IconChevron size={12} className="-rotate-90" />
          </span>
        </span>
      </td>
      <td className="py-3 pr-3 whitespace-nowrap">
        <Badge tone={STATUS_TONE[run.status]} mono dot pulse={isOpen(run.status)}>
          {STATUS_LABEL[run.status]}
        </Badge>
        {waiting && (
          <span className="block font-mono text-2xs text-content-muted mt-1">{waiting}</span>
        )}
      </td>
      <td className="py-3 pr-3 text-xs text-content-secondary leading-relaxed max-w-[320px]">
        {run.summary || run.detail || '—'}
      </td>
      <td className="py-3 pr-3 text-right font-mono text-xs text-content-secondary whitespace-nowrap">
        {run.score ? formatCoverage(run.score.detectionCoverage) : '—'}
      </td>
      <td className="py-3 pr-3 text-right font-mono text-xs text-content-secondary whitespace-nowrap">
        {caught}
      </td>
      <td className="py-3 text-right font-mono text-2xs text-content-muted whitespace-nowrap">
        {run.status === 'scheduled' && run.scheduledFor
          ? formatWhen(run.scheduledFor)
          : formatWhen(run.createdAt)}
      </td>
    </tr>
  )
}
