import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useEmulations } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { PlatformId } from '@/types'
import { ThreatOriginBadge } from '@/components/ui/ThreatOriginBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { RunEmulationModal } from '@/components/modals/RunEmulationModal'
import { OverviewTab } from './OverviewTab'
import { AttackPathTab } from './AttackPathTab'
import { MitreMappingTab } from './MitreMappingTab'
import { ExplainPanel } from './ExplainPanel'
import { PastFindingsTab } from './PastFindingsTab'

type DetailTab = 'overview' | 'path' | 'mitre' | 'explain' | 'findings'

export function EmulationDetailPage() {
  const { platformId, emulationId } = useParams<{ platformId: string; emulationId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: emulations, loading } = useEmulations(pid)
  const [activeTab, setActiveTab] = useState<DetailTab>('overview')
  const [showRunModal, setShowRunModal] = useState(false)

  const platformLabel = meta?.label ?? platformId?.toUpperCase() ?? ''
  const em = emulations?.find((e) => e.id === emulationId)

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading...</div>
  }
  if (!em) {
    return <EmptyState icon="&#128269;" title="Emulation not found" body={`No emulation with ID "${emulationId}" found.`} />
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <div className="font-display text-[1.6rem] font-[800] text-content-primary leading-tight tracking-[-0.5px] flex items-center gap-2">
            {em.name}
            {em.originLabel && (
              <span className="text-xs align-middle ml-2">
                <ThreatOriginBadge origin={em.origin} label={em.originLabel} />
              </span>
            )}
          </div>
          <div className="text-[0.85rem] text-content-secondary mt-1.5">
            {em.aliases} &middot; {em.techniqueCount} MITRE Techniques &middot; {platformLabel} Kill Chain
          </div>
        </div>
        <div className="flex gap-3 shrink-0">
          <Link to={`/${pid}/emulations`}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline
              bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
              hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active">
            &#8592; Back
          </Link>
          <Link to={`/${pid}/emulations/${em.id}/playbook`}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline
              bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
              hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active">
            &#128203; Playbook
          </Link>
          <button
            onClick={() => setShowRunModal(true)}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-semibold cursor-pointer border-none
            bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]">
            &#9654; Run Emulation
          </button>
        </div>
      </div>

      {/* Run Emulation Modal */}
      {showRunModal && (
        <RunEmulationModal
          emulationId={em.id}
          emulationName={em.name}
          onClose={() => setShowRunModal(false)}
        />
      )}

      {/* Tabs */}
      <div className="flex border-b border-border mb-5">
        {(['overview', 'path', 'mitre', 'explain', 'findings'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-[18px] py-2.5 text-xs font-semibold cursor-pointer border-b-2 -mb-px transition-all font-mono tracking-wider
              ${activeTab === tab
                ? 'text-danger border-b-danger'
                : 'text-content-dim border-b-transparent hover:text-content-secondary'
              }`}
          >
            {tab === 'overview' ? 'Overview' : tab === 'path' ? 'Attack Path' : tab === 'mitre' ? 'MITRE Mapping' : tab === 'explain' ? 'Ask AI' : 'Past Findings'}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <OverviewTab
          emulation={em}
          platformLabel={platformLabel}
          onRun={() => setShowRunModal(true)}
          onOpenAttackPath={() => setActiveTab('path')}
          onOpenReferences={() => setActiveTab('explain')}
          playbookHref={`/${pid}/emulations/${em.id}/playbook`}
        />
      )}
      {activeTab === 'path' && <AttackPathTab emulation={em} />}
      {activeTab === 'mitre' && <MitreMappingTab emulation={em} platformLabel={platformLabel} />}
      {activeTab === 'explain' && <ExplainPanel emulation={em} />}
      {activeTab === 'findings' && (
        <PastFindingsTab emulation={em} onRun={() => setShowRunModal(true)} />
      )}
    </div>
  )
}

