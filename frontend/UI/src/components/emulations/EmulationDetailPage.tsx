import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useEmulations } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { PlatformId, Emulation } from '@/types'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { ThreatOriginBadge } from '@/components/ui/ThreatOriginBadge'
import { TacticBadge } from '@/components/ui/TacticBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { RunEmulationModal } from '@/components/modals/RunEmulationModal'
import { OverviewTab } from './OverviewTab'
import { AttackPathTab } from './AttackPathTab'

type DetailTab = 'overview' | 'path' | 'mitre' | 'refs' | 'findings'

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
      <Breadcrumb items={[
        { label: 'Home', to: '/' },
        { label: `${platformLabel} \u00B7 APT Emulations`, to: `/${pid}/emulations` },
        { label: em.name },
      ]} />

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
        {(['overview', 'path', 'mitre', 'refs', 'findings'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-[18px] py-2.5 text-xs font-semibold cursor-pointer border-b-2 -mb-px transition-all font-mono tracking-wider
              ${activeTab === tab
                ? 'text-danger border-b-danger'
                : 'text-content-dim border-b-transparent hover:text-content-secondary'
              }`}
          >
            {tab === 'overview' ? 'Overview' : tab === 'path' ? 'Attack Path' : tab === 'mitre' ? 'MITRE Mapping' : tab === 'refs' ? 'References' : 'Past Findings'}
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
          onOpenReferences={() => setActiveTab('refs')}
          playbookHref={`/${pid}/emulations/${em.id}/playbook`}
        />
      )}
      {activeTab === 'path' && <AttackPathTab emulation={em} />}
      {activeTab === 'mitre' && <MitreTab emulation={em} platformLabel={platformLabel} />}
      {activeTab === 'refs' && <ReferencesTab emulation={em} />}
      {activeTab === 'findings' && (
        <EmptyState
          icon="&#128202;"
          title="No previous runs found"
          body="Run this emulation to generate findings and track your security posture over time.<br>Findings will appear here after each execution."
        />
      )}
    </div>
  )
}

/* ── MITRE Mapping Tab ── */
function MitreTab({ emulation: em, platformLabel }: { emulation: Emulation; platformLabel: string }) {
  return (
    <div className="bg-surface-card border border-border rounded-card p-5">
      <SectionTitle>MITRE ATT&CK Mapping &mdash; {platformLabel}</SectionTitle>
      <table className="w-full border-collapse">
        <thead>
          <tr>
            {['Technique ID', 'Technique Name', 'Tactic', 'Platform', 'Description'].map((h) => (
              <th key={h} className="text-left px-3 py-2 font-mono text-[9px] tracking-[1px] text-content-dim uppercase border-b border-border">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {em.mitreMappings.map((mt) => (
            <tr key={mt.id} className="hover:bg-white/[0.02]">
              <td className="px-3 py-2.5 text-xs border-b border-border/40">
                <span className="font-mono text-[10px] text-danger bg-danger/[0.06] border border-danger/15 rounded-[3px] px-[7px] py-0.5">
                  {mt.id}
                </span>
              </td>
              <td className="px-3 py-2.5 text-xs border-b border-border/40 text-content-primary">{mt.name}</td>
              <td className="px-3 py-2.5 text-xs border-b border-border/40">
                <TacticBadge tactic={mt.tactic} />
              </td>
              <td className="px-3 py-2.5 text-xs border-b border-border/40 text-content-secondary">{mt.platform}</td>
              <td className="px-3 py-2.5 text-xs border-b border-border/40 font-mono text-[11px] text-content-dim">{mt.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ── References Tab ── */
function ReferencesTab({ emulation: em }: { emulation: Emulation }) {
  return (
    <div className="bg-surface-card border border-border rounded-card p-5">
      <SectionTitle>APT Advisories & Intelligence Reports</SectionTitle>
      <div className="flex flex-col gap-2">
        {em.references.map((ref, i) => (
          <div key={i} className="flex items-center gap-3 bg-surface-base border border-border rounded-[7px] px-4 py-3
            cursor-pointer transition-all hover:border-border-active">
            <div className="text-base shrink-0">{ref.icon}</div>
            <div className="flex-1">
              <div className="text-[13px] font-semibold text-content-primary mb-[3px]">{ref.title}</div>
              <div className="font-mono text-[10px] text-content-dim">{ref.source}</div>
            </div>
            <span className="font-mono text-[9px] px-[7px] py-0.5 rounded-[3px] border"
              style={{ borderColor: ref.color, color: ref.color }}>
              {ref.type}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Shared small components ── */
function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-mono text-[10px] tracking-[1.5px] text-content-dim uppercase mb-3.5 flex items-center gap-2">
      {children}
      <div className="flex-1 h-px bg-border" />
    </div>
  )
}
