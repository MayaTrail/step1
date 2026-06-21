import { useState, useMemo } from 'react'
import { useEmulationRuns } from '@/hooks/useEmulationRuns'
import { platformRegistry, platformShortLabel } from '@/data'
import type { PlatformId, EmulationRunStatus } from '@/types'
import { PlatformIcon } from '@/components/ui/PlatformIcons'
import { FilterDropdown, type DropdownOption } from '@/components/ui/FilterDropdown'
import {
  RunStatusBadge,
  RunsTable,
  RunsRow,
  RunsCell,
  RunsSearchInput,
  formatRelative,
  formatCompletion,
} from './runHelpers'

/** Status filter options for Results (terminal runs only). */
const STATUS_OPTIONS: DropdownOption<'all' | EmulationRunStatus>[] = [
  { value: 'all', label: 'All' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
]

/** Platform filter options — "All" plus every registered platform with its icon. */
const PLATFORM_OPTIONS: DropdownOption<'all' | PlatformId>[] = [
  { value: 'all', label: 'All platforms' },
  ...platformRegistry.map((p) => ({
    value: p.id,
    label: platformShortLabel(p.id),
    icon: <PlatformIcon platformId={p.id} size={14} />,
  })),
]

/**
 * Results — outcomes of finished emulation runs (completed + failed).
 *
 * The "Completion" column is an honest proxy for the requested "Score": it
 * reports phases reached out of total rather than a fabricated number. A real
 * security score (detections fired / attack-path coverage) is deferred until
 * the backend computes it. Export is a deliberate "coming soon" placeholder.
 */
export function ResultsPage() {
  const { data: runs, loading } = useEmulationRuns(['completed', 'failed'])
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | EmulationRunStatus>('all')
  const [platformFilter, setPlatformFilter] = useState<'all' | PlatformId>('all')

  const filtered = useMemo(() => {
    let list = runs ?? []
    if (statusFilter !== 'all') list = list.filter((r) => r.status === statusFilter)
    if (platformFilter !== 'all') list = list.filter((r) => r.platform === platformFilter)
    const q = search.trim().toLowerCase()
    if (q) list = list.filter((r) => r.emulation_name.toLowerCase().includes(q))
    return list
  }, [runs, statusFilter, platformFilter, search])

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Operations
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Results
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          {(runs?.length ?? 0)} completed run{(runs?.length ?? 0) === 1 ? '' : 's'}
        </div>
      </div>

      {/* Toolbar: search + filter dropdowns */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        <RunsSearchInput value={search} onChange={setSearch} placeholder="Search emulations..." />
        <FilterDropdown label="Status" value={statusFilter} options={STATUS_OPTIONS} onChange={setStatusFilter} />
        <FilterDropdown label="Platform" value={platformFilter} options={PLATFORM_OPTIONS} onChange={setPlatformFilter} />
      </div>

      {/* Table */}
      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading results...</div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16">
          <div className="font-display text-base text-content-primary mb-1.5">No results yet</div>
          <div className="text-[0.9rem] text-content-secondary">
            Completed and failed runs will appear here.
          </div>
        </div>
      ) : (
        <RunsTable headers={['Emulation', 'Stack', 'Platform', 'Status', 'Completion', 'Completed At', '']}>
          {filtered.map((run) => (
            <RunsRow key={run.id}>
              <RunsCell className="!text-content-primary font-medium">{run.emulation_name}</RunsCell>
              <RunsCell className="font-mono text-xs">{run.stack_name}</RunsCell>
              <RunsCell>
                <span className="inline-flex items-center gap-1.5">
                  <PlatformIcon platformId={run.platform} size={14} />
                  {platformShortLabel(run.platform)}
                </span>
              </RunsCell>
              <RunsCell><RunStatusBadge status={run.status} /></RunsCell>
              <RunsCell className="font-mono text-xs">{formatCompletion(run.phase_current, run.phase_total)}</RunsCell>
              <RunsCell className="font-mono text-xs whitespace-nowrap" title={run.completed_at ?? ''}>
                {formatRelative(run.completed_at)}
              </RunsCell>
              <RunsCell className="text-right">
                <button
                  disabled
                  title="Export coming soon"
                  className="inline-flex items-center gap-1 text-content-dim text-xs font-medium cursor-not-allowed opacity-60"
                >
                  Export
                </button>
              </RunsCell>
            </RunsRow>
          ))}
        </RunsTable>
      )}
    </div>
  )
}
