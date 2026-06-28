import { useMemo } from 'react'
import type { Emulation, EmulationRunListItem, EmulationRunStatus } from '@/types'
import { useEmulationRuns } from '@/hooks/useEmulationRuns'
import { Card } from '@/components/ui/Card'
import { MetricCard } from '@/components/ui/MetricCard'
import { Button } from '@/components/ui/Button'
import {
  RunStatusBadge,
  formatRelative,
  formatCompletion,
  RunsTable,
  RunsRow,
  RunsCell,
} from '@/components/operations/runHelpers'

/**
 * Past Findings tab. The execution history for this emulation: the user's runs
 * filtered to this emulation type, summarised and listed.
 *
 * Runs come from the existing runs endpoint (scoped to the current user); the
 * type filter is applied client-side since the endpoint has no type parameter.
 * Columns are limited to what an EmulationRun actually stores. The mockup's
 * detections / findings / cost columns have no backing data and are omitted
 * rather than faked, matching the rest of the detail page.
 */

/** All run statuses, so in-progress runs appear in the history too. */
const ALL_STATUSES: EmulationRunStatus[] = ['pending', 'running', 'completed', 'failed']

interface PastFindingsTabProps {
  emulation: Emulation
  /** Opens the Run Emulation modal (owned by the parent detail page). */
  onRun: () => void
}

/** Run duration as "Xm Ys" (or "Ys"); a dash when timestamps are incomplete. */
function formatDuration(start: string | null, end: string | null): string {
  if (!start || !end) return '-'
  const ms = new Date(end).getTime() - new Date(start).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '-'
  const s = Math.floor(ms / 1000)
  const m = Math.floor(s / 60)
  const rem = s % 60
  return m > 0 ? `${m}m ${rem}s` : `${rem}s`
}

export function PastFindingsTab({ emulation: em, onRun }: PastFindingsTabProps) {
  const { data, loading } = useEmulationRuns(ALL_STATUSES)

  const realRuns = useMemo(
    () => (data ?? []).filter((r) => r.emulation_type === em.id),
    [data, em.id],
  )

  // Preview: with no real runs yet, show sample rows so the populated layout is
  // reviewable. Enabled in dev OR when the URL carries ?preview=1 (so it can be
  // seen on a production build too); it only ever shows when there are zero real
  // runs, so it never masks actual history.
  const previewRequested =
    import.meta.env.DEV ||
    (typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('preview'))
  const preview = previewRequested && !loading && realRuns.length === 0
  const runs = preview ? sampleRuns(em) : realRuns

  if (loading && !data) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading run history...</div>
  }

  if (runs.length === 0) {
    return (
      <Card className="p-0">
        <div className="text-center py-20 px-5">
          <div className="w-16 h-16 rounded-card bg-surface-base border border-border mx-auto mb-4 flex items-center justify-center text-[30px] text-content-dim">
            {'▣'}
          </div>
          <div className="font-display text-lg font-bold text-content-primary mb-2">No previous runs found</div>
          <div className="text-[0.9rem] text-content-secondary leading-relaxed max-w-md mx-auto mb-6">
            Run this emulation to validate your cloud environment. Each execution is recorded here with its
            status, phase progress, and duration.
          </div>
          <Button variant="primary" size="lg" onClick={onRun}>
            Run Emulation
          </Button>
        </div>
      </Card>
    )
  }

  const total = runs.length
  const success = runs.filter((r) => r.status === 'completed').length
  const failed = runs.filter((r) => r.status === 'failed').length
  const lastRun = runs[0] // endpoint returns newest-first

  return (
    <div className="flex flex-col gap-4 animate-fadeIn">
      {preview && (
        <div className="font-mono text-[11px] text-warning bg-warning-dim border border-warning/25 rounded-btn px-4 py-2.5">
          Sample data shown for preview only (dev mode). Real runs appear here after you execute this emulation.
        </div>
      )}

      {/* ── Summary metrics ─────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <MetricCard accent="neutral" label="Total Runs" value={total} />
        <MetricCard accent="green" label="Successful" value={success} />
        <MetricCard accent={failed > 0 ? 'red' : 'neutral'} label="Failed" value={failed} />
        <MetricCard
          accent="neutral"
          label="Last Run"
          value={formatRelative(lastRun?.started_at ?? lastRun?.created_at ?? null)}
        />
      </div>

      {/* ── Execution history ───────────────────────────────────────── */}
      <RunsTable headers={['Run', 'Environment', 'Status', 'Started', 'Completion', 'Duration']}>
        {runs.map((r) => (
          <RunsRow key={r.id}>
            <RunsCell className="font-mono text-xs text-content-primary" title={r.id}>
              {r.id.slice(0, 8)}
            </RunsCell>
            <RunsCell className="font-mono text-xs">{r.stack_name}</RunsCell>
            <RunsCell>
              <RunStatusBadge status={r.status} />
            </RunsCell>
            <RunsCell className="whitespace-nowrap">
              {formatRelative(r.started_at ?? r.created_at)}
            </RunsCell>
            <RunsCell className="font-mono text-xs whitespace-nowrap">
              {formatCompletion(r.phase_current, r.phase_total)}
            </RunsCell>
            <RunsCell className="font-mono text-xs whitespace-nowrap">
              {formatDuration(r.started_at, r.completed_at)}
            </RunsCell>
          </RunsRow>
        ))}
      </RunsTable>
    </div>
  )
}

/**
 * Sample run history for the dev-mode preview only. Mirrors the
 * EmulationRunListItem shape so it flows through the same table as real data.
 * Covers the three visible states: completed, in-flight, and failed.
 */
function sampleRuns(em: Emulation): EmulationRunListItem[] {
  const now = Date.now()
  const iso = (msAgo: number) => new Date(now - msAgo).toISOString()
  const total = em.phaseCount ?? em.attackPath.length ?? 6
  const base = {
    emulation_type: em.id,
    emulation_name: em.name,
    platform: em.platform,
    triggered_by: 'you',
  }
  const MIN = 60 * 1000
  const HR = 60 * MIN
  const DAY = 24 * HR

  return [
    {
      ...base,
      id: 'a3f90b21-7c4e-4d11-9a2f-1b8e0c3d5f60',
      stack: 'stack-sample-1',
      stack_name: `${em.id}-dev`,
      status: 'running',
      phase_current: Math.max(1, Math.ceil(total / 2)),
      phase_total: total,
      started_at: iso(6 * MIN),
      completed_at: null,
      created_at: iso(6 * MIN),
    },
    {
      ...base,
      id: '7c1e04ab-2f33-4c80-8e10-6d9a2b4f1c05',
      stack: 'stack-sample-2',
      stack_name: `${em.id}-dev`,
      status: 'completed',
      phase_current: total,
      phase_total: total,
      started_at: iso(4 * DAY),
      completed_at: iso(4 * DAY - (18 * MIN + 4 * 1000)),
      created_at: iso(4 * DAY),
    },
    {
      ...base,
      id: 'f08b9d34-5a21-49ff-b3c7-0e2d1a6c8b44',
      stack: 'stack-sample-3',
      stack_name: `${em.id}-test`,
      status: 'failed',
      phase_current: 2,
      phase_total: total,
      started_at: iso(11 * DAY),
      completed_at: iso(11 * DAY - (4 * MIN + 12 * 1000)),
      created_at: iso(11 * DAY),
    },
  ]
}
