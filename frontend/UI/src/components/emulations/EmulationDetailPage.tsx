import { useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { useEmulations } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { PlatformId } from '@/types'
import { ThreatOriginBadge } from '@/components/ui/ThreatOriginBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { RunEmulationModal } from '@/components/modals/RunEmulationModal'
import { OverviewTab } from './OverviewTab'
import { LiveEmulationTab } from './LiveEmulationTab'
import { AttackPathTab } from './AttackPathTab'
import { MitreMappingTab } from './MitreMappingTab'
import { ExplainPanel } from './ExplainPanel'
import { PastFindingsTab } from './PastFindingsTab'
import { ConnectGate } from '@/components/common/ConnectGate'

type DetailTab = 'overview' | 'live' | 'path' | 'mitre' | 'explain' | 'findings'

const TAB_LABELS: Record<DetailTab, string> = {
  overview: 'Overview',
  live: 'Live Emulation',
  path: 'Attack Path',
  mitre: 'MITRE Mapping',
  explain: 'Ask AI',
  findings: 'Past Findings',
}

export function EmulationDetailPage() {
  const { platformId, emulationId } = useParams<{ platformId: string; emulationId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: emulations, loading } = useEmulations(pid)
  const [searchParams, setSearchParams] = useSearchParams()
  // The `?tab=` param is the source of truth rather than component state, so a
  // reload or a shared link lands on the tab the user was actually looking at.
  // Falls back to Overview for absent/unknown values so a stray param can never
  // render a blank page.
  const tabParam = searchParams.get('tab')
  const activeTab: DetailTab =
    tabParam && tabParam in TAB_LABELS ? (tabParam as DetailTab) : 'overview'

  // Tabs replace the history entry instead of pushing one, so Back leaves the
  // page rather than stepping through every tab the user tried.
  const setActiveTab = (tab: DetailTab) => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', tab)
    setSearchParams(next, { replace: true })
  }

  const [showRunModal, setShowRunModal] = useState(false)
  // Bumped whenever a run is triggered or the run modal closes, so the live tab
  // refetches instead of showing whatever it loaded when it first mounted.
  const [runNonce, setRunNonce] = useState(0)

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
          <ConnectGate>
            <button
              onClick={() => setShowRunModal(true)}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-semibold cursor-pointer border-none
              bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]">
              &#9654; Run Emulation
            </button>
          </ConnectGate>
        </div>
      </div>

      {/* Run Emulation Modal */}
      {showRunModal && (
        <RunEmulationModal
          emulationId={em.id}
          emulationName={em.name}
          onRunStarted={() => {
            setRunNonce((n) => n + 1)
            setActiveTab('live')
          }}
          onClose={() => {
            setShowRunModal(false)
            setRunNonce((n) => n + 1)
          }}
        />
      )}

      {/* Tabs */}
      <div className="flex border-b border-border mb-5">
        {(['overview', 'live', 'path', 'mitre', 'explain', 'findings'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-[18px] py-2.5 text-xs font-semibold cursor-pointer border-b-2 -mb-px transition-all font-mono tracking-wider
              ${activeTab === tab
                ? 'text-danger border-b-danger'
                : 'text-content-dim border-b-transparent hover:text-content-secondary'
              }`}
          >
            {TAB_LABELS[tab]}
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
      {activeTab === 'live' && (
        <LiveEmulationTab emulation={em} onRun={() => setShowRunModal(true)} refreshKey={runNonce} />
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

