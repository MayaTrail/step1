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

const PHASE_COLORS = ['#f87171', '#ff6b35', '#fbbf24', '#00d4ff', '#a78bfa', '#10b981']

type DetailTab = 'path' | 'mitre' | 'refs' | 'findings'

export function EmulationDetailPage() {
  const { platformId, emulationId } = useParams<{ platformId: string; emulationId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: emulations, loading } = useEmulations(pid)
  const [activeTab, setActiveTab] = useState<DetailTab>('path')
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
          <Link to={`/${pid}/playbooks/${em.id}`}
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
        {(['path', 'mitre', 'refs', 'findings'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-[18px] py-2.5 text-xs font-semibold cursor-pointer border-b-2 -mb-px transition-all font-mono tracking-wider
              ${activeTab === tab
                ? 'text-danger border-b-danger'
                : 'text-content-dim border-b-transparent hover:text-content-secondary'
              }`}
          >
            {tab === 'path' ? 'Attack Path' : tab === 'mitre' ? 'MITRE Mapping' : tab === 'refs' ? 'References' : 'Past Findings'}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'path' && <AttackPathTab emulation={em} platformLabel={platformLabel} />}
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

/* ── Attack Path Tab ── */
function AttackPathTab({ emulation: em, platformLabel: _platformLabel }: { emulation: Emulation; platformLabel: string }) {
  return (
    <div className="grid grid-cols-[1fr_300px] gap-4 mb-4">
      {/* Kill Chain */}
      <div className="bg-surface-card border border-border rounded-card p-5">
        <SectionTitle>Kill Chain Visualization</SectionTitle>
        <div className="flex flex-col gap-3">
          {em.attackPath.map((phase, i) => {
            const color = PHASE_COLORS[i % PHASE_COLORS.length]
            const isLast = i === em.attackPath.length - 1
            return (
              <div key={i} className="flex gap-2 items-start">
                <div className="flex flex-col items-center shrink-0">
                  <div className="w-2.5 h-2.5 rounded-full shrink-0 mt-[3px]" style={{ background: color }} />
                  {!isLast && <div className="w-px flex-1 min-h-[20px] bg-border mt-1" />}
                </div>
                <div className="flex-1">
                  <div className="text-[11px] font-bold font-mono mb-1.5 uppercase tracking-wide" style={{ color }}>
                    Phase {phase.phase} &middot; {phase.name}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {phase.techniques.map((tech) => (
                      <div key={tech.id} className="bg-surface-base border border-border rounded-[5px] px-2.5 py-1
                        font-mono text-[10px] text-content-secondary cursor-pointer transition-all
                        hover:border-[rgba(255,34,68,0.35)] hover:text-danger hover:bg-[rgba(255,34,68,0.06)]">
                        <span className="text-content-dim mr-[5px]">{tech.id}</span>
                        {tech.name}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Summary Sidebar */}
      <div className="bg-surface-card border border-border rounded-card p-5">
        <SectionTitle>Emulation Summary</SectionTitle>
        <div className="flex flex-col gap-3">
          {em.name && <MetaItem label="THREAT ACTOR" value={em.name.split(' \u2014 ')[0] ?? em.name} />}
          {em.attribution && <MetaItem label="ATTRIBUTION" value={em.attribution} valueClass="text-danger" />}
          {em.activeSince && <MetaItem label="ACTIVE SINCE" value={em.activeSince} valueClass="text-content-secondary" />}
          {em.targets && <MetaItem label="TARGETS" value={em.targets} valueClass="text-content-secondary text-xs" />}
          {em.incidents.length > 0 && (
            <div>
              <div className="font-mono text-[9px] text-content-dim tracking-[1px] mb-1">NOTABLE INCIDENTS</div>
              <div className="font-mono text-[10px] text-content-dim leading-relaxed">
                {em.incidents.map((inc, i) => <div key={i}>{inc}</div>)}
              </div>
            </div>
          )}
        </div>
      </div>
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

function MetaItem({ label, value, valueClass = '' }: { label: string; value: string; valueClass?: string }) {
  return (
    <div>
      <div className="font-mono text-[9px] text-content-dim tracking-[1px] mb-1">{label}</div>
      <div className={`text-[13px] font-semibold text-content-primary ${valueClass}`}>{value}</div>
    </div>
  )
}
