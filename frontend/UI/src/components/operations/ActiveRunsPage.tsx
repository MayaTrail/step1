import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useEmulationRuns } from '@/hooks/useEmulationRuns'
import { platformRegistry, platformShortLabel } from '@/data'
import type { PlatformId, EmulationRunStatus } from '@/types'
import { PlatformIcon } from '@/components/ui/PlatformIcons'
import { IconChevron } from '@/components/ui/Icons'
import { FilterDropdown, type DropdownOption } from '@/components/ui/FilterDropdown'
import {
  RunStatusBadge,
  RunProgress,
  RunsTable,
  RunsRow,
  RunsCell,
  RunsSearchInput,
  formatRelative,
} from './runHelpers'

/** Status filter options for Active Runs (failed runs live in Results). */
const STATUS_OPTIONS: DropdownOption<'all' | EmulationRunStatus>[] = [
  { value: 'all', label: 'All' },
  { value: 'running', label: 'Running' },
  { value: 'pending', label: 'Pending' },
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
 * Active Runs — live execution monitoring for in-flight emulations.
 *
 * Shows only non-terminal runs (running + pending/scheduled) and auto-refreshes
 * every 4s so phase progress advances without a manual reload. Failed and
 * completed runs are terminal and live in Results instead.
 */
export function ActiveRunsPage() {
  const { data: runs, loading } = useEmulationRuns(['running', 'pending'], 4000)
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
          Active Runs
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          {(runs?.length ?? 0)} run{(runs?.length ?? 0) === 1 ? '' : 's'} in progress &middot; auto-refreshing
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
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading runs...</div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16">
          <div className="font-display text-base text-content-primary mb-1.5">No active runs</div>
          <div className="text-[0.9rem] text-content-secondary">
            Runs you start will appear here while they execute.
          </div>
        </div>
      ) : (
        <RunsTable headers={['Emulation', 'Stack', 'Platform', 'Status', 'Progress', 'Started', '']}>
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
              <RunsCell><RunProgress current={run.phase_current} total={run.phase_total} status={run.status} /></RunsCell>
              <RunsCell className="font-mono text-xs whitespace-nowrap" >{formatRelative(run.started_at ?? run.created_at)}</RunsCell>
              <RunsCell className="text-right">
                <Link
                  to={`/${run.platform}/emulations/${run.emulation_type}`}
                  className="inline-flex items-center gap-1 text-accent-blue text-xs font-medium no-underline transition-opacity hover:opacity-60"
                >
                  View <IconChevron size={14} />
                </Link>
              </RunsCell>
            </RunsRow>
          ))}
        </RunsTable>
      )}
    </div>
  )
}
