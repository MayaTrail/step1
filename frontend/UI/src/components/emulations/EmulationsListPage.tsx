import { useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useEmulations } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { PlatformId, Emulation } from '@/types'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { Tag } from '@/components/ui/Tag'
import { ThreatOriginBadge } from '@/components/ui/ThreatOriginBadge'
import { severityColorClass } from '@/components/ui/SeverityBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { RunEmulationModal } from '@/components/modals/RunEmulationModal'

export function EmulationsListPage() {
  const { platformId } = useParams<{ platformId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: emulations, loading } = useEmulations(pid)
  const [activeFilter, setActiveFilter] = useState('All')
  const [runTarget, setRunTarget] = useState<Emulation | null>(null)

  // Extract unique origins for filter chips
  const originFilters = useMemo(() => {
    if (!emulations) return []
    const origins = new Set<string>()
    for (const em of emulations) {
      if (em.originLabel) origins.add(em.originLabel)
    }
    return Array.from(origins)
  }, [emulations])

  // Apply filter
  const filtered = useMemo(() => {
    if (!emulations || activeFilter === 'All') return emulations ?? []
    return emulations.filter((em) => em.originLabel === activeFilter)
  }, [emulations, activeFilter])

  const platformLabel = meta?.label ?? platformId?.toUpperCase() ?? ''

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading emulations...</div>
  }

  if (!emulations || emulations.length === 0) {
    return (
      <EmptyState
        icon="&#128203;"
        title="No emulations available"
        body={`Emulations for ${platformLabel} are coming soon.`}
      />
    )
  }

  return (
    <div>
      <Breadcrumb items={[
        { label: 'Home', to: '/' },
        { label: platformLabel },
        { label: 'APT Emulations' },
      ]} />

      {/* Page header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            {platformLabel}
          </div>
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            APT Emulations
          </div>
          <div className="text-[0.9rem] text-content-secondary mt-1.5">
            {emulations.length} emulations available &middot; Sorted by threat severity
          </div>
        </div>
        <div className="flex gap-3 shrink-0">
          <button className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer
            bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
            hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active">
            &#11015; Export
          </button>
          <button className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-semibold cursor-pointer border-none
            bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]">
            &#9654; Run Custom
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex gap-2.5 mb-5 items-center flex-wrap">
        <span className="font-mono text-[10px] text-content-dim tracking-[1px]">FILTER:</span>
        <FilterChip label="All" active={activeFilter === 'All'} onClick={() => setActiveFilter('All')} />
        {originFilters.map((origin) => (
          <FilterChip
            key={origin}
            label={`${origin}-nexus`}
            active={activeFilter === origin}
            onClick={() => setActiveFilter(origin)}
          />
        ))}
      </div>

      {/* Emulation cards */}
      <div className="flex flex-col gap-2.5">
        {filtered.map((em) => (
          <EmulationCard key={em.id} emulation={em} platformId={pid} onRun={() => setRunTarget(em)} />
        ))}
      </div>

      {/* Run Emulation Modal */}
      {runTarget && (
        <RunEmulationModal
          emulationId={runTarget.id}
          emulationName={runTarget.name}
          onClose={() => setRunTarget(null)}
        />
      )}
    </div>
  )
}

function FilterChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`border rounded-full px-3.5 py-[5px] text-[0.7rem] font-mono cursor-pointer transition-all font-medium
        ${active
          ? 'bg-danger/[0.15] border-danger/30 text-danger'
          : 'bg-surface-elevated border-border text-content-secondary hover:border-border-active hover:text-content-primary'
        }`}
    >
      {label}
    </button>
  )
}

function EmulationCard({ emulation: em, platformId, onRun }: { emulation: Emulation; platformId: PlatformId; onRun: () => void }) {
  return (
    <Link
      to={`/${platformId}/emulations/${em.id}`}
      className="group bg-surface-card border border-border rounded-card px-5 py-5 flex items-center gap-4
        cursor-pointer transition-all duration-[250ms] relative overflow-hidden no-underline
        hover:border-[rgba(255,34,68,0.35)] hover:bg-[rgba(255,34,68,0.06)] hover:-translate-y-px
        hover:shadow-[0_4px_20px_rgba(0,0,0,0.3)]"
    >
      {/* Left accent bar */}
      <div className="absolute left-0 top-0 bottom-0 w-[3px] bg-border transition-colors group-hover:bg-danger" />

      {/* Meta */}
      <div className="flex-1 min-w-0">
        <div className="font-display text-[0.95rem] font-bold text-content-primary mb-[5px] flex items-center gap-2">
          {em.name}
          {em.originLabel && <ThreatOriginBadge origin={em.origin} label={em.originLabel} />}
        </div>
        <div className="flex gap-1.5 flex-wrap items-center">
          {em.tags.map((tag) => (
            <Tag key={tag}>{tag}</Tag>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="flex gap-5 shrink-0 text-center">
        <div className="font-mono">
          <div className={`text-base font-bold ${severityColorClass(em.severity)}`}>{em.techniqueCount}</div>
          <div className="text-[0.6rem] text-content-dim tracking-[1px] mt-0.5 uppercase font-medium">TECHNIQUES</div>
        </div>
        <div className="font-mono">
          <div className={`text-base font-bold ${severityColorClass(em.severity)}`}>{em.severity}</div>
          <div className="text-[0.6rem] text-content-dim tracking-[1px] mt-0.5 uppercase font-medium">SEVERITY</div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex flex-col gap-2 shrink-0">
        <button
          onClick={(e) => { e.preventDefault(); e.stopPropagation(); onRun() }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-btn font-body text-[0.85rem] font-semibold cursor-pointer border-none
            bg-danger text-white transition-all hover:shadow-[0_0_30px_rgba(255,34,68,0.4)] hover:-translate-y-px"
        >
          &#9654; Run
        </button>
        <Link
          to={`/${platformId}/playbooks/${em.id}`}
          onClick={(e) => e.stopPropagation()}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-btn font-body text-[0.85rem] font-medium cursor-pointer
            bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all no-underline
            hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
        >
          &#128203; Playbook
        </Link>
      </div>
    </Link>
  )
}
