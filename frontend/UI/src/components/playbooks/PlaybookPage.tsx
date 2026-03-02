import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useEmulations, usePlaybooks } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { PlatformId } from '@/types'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { EmptyState } from '@/components/ui/EmptyState'
import { RunEmulationModal } from '@/components/modals/RunEmulationModal'

export function PlaybookPage() {
  const { platformId, playbookId } = useParams<{ platformId: string; playbookId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: emulations } = useEmulations(pid)
  const { data: playbooks, loading } = usePlaybooks(pid)

  const platformLabel = meta?.label ?? platformId?.toUpperCase() ?? ''

  // Resolve playbook: playbookId can be a numeric index or an emulation ID
  let playbookIndex = Number(playbookId)
  if (isNaN(playbookIndex) && emulations && playbookId) {
    playbookIndex = emulations.findIndex((em) => em.id === playbookId)
  }

  const playbook = playbooks?.[playbookIndex]
  const emulation = emulations?.[playbookIndex]
  const emName = emulation?.name ?? ''
  const [showRunModal, setShowRunModal] = useState(false)

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading playbook...</div>
  }
  if (!playbook) {
    return <EmptyState icon="&#128203;" title="Playbook not found" body="This playbook does not exist yet." />
  }

  return (
    <div>
      <Breadcrumb items={[
        { label: 'Home', to: '/' },
        { label: `${platformLabel} \u00B7 APT Emulations`, to: `/${pid}/emulations` },
        ...(emulation ? [{ label: emName, to: `/${pid}/emulations/${emulation.id}` }] : []),
        { label: 'Playbook' },
      ]} />

      {/* Header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            Incident Response
          </div>
          <div className="font-display text-[1.6rem] font-[800] text-content-primary leading-tight tracking-[-0.5px]">
            &#128203; IR Playbook
          </div>
          <div className="text-[0.85rem] text-content-secondary mt-1.5">
            {emName} &middot; {platformLabel} Cloud Environment &middot; Last updated Feb 2025
          </div>
        </div>
        <div className="flex gap-3 shrink-0">
          {emulation && (
            <Link to={`/${pid}/emulations/${emulation.id}`}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline
                bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active">
              &#8592; Back
            </Link>
          )}
          <button className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer
            bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
            hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active">
            &#11015; Export PDF
          </button>
          <button
            onClick={() => setShowRunModal(true)}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-semibold cursor-pointer border-none
            bg-danger text-white transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]">
            &#9654; Run Emulation
          </button>
        </div>
      </div>

      {/* Run Emulation Modal */}
      {showRunModal && emulation && (
        <RunEmulationModal
          emulationId={emulation.id}
          emulationName={emulation.name}
          onClose={() => setShowRunModal(false)}
        />
      )}

      {/* Steps */}
      <div className="flex flex-col gap-3">
        {playbook.steps.map((step, i) => (
          <div key={i} className="flex gap-4 bg-surface-card border border-border rounded-card px-6 py-5
            transition-all duration-[400ms] hover:border-[rgba(0,180,216,0.2)] hover:-translate-y-0.5">
            <div className="w-10 h-10 rounded-btn bg-danger/[0.15] flex items-center justify-center
              font-mono text-[13px] font-bold text-danger shrink-0">
              {String(i + 1).padStart(2, '0')}
            </div>
            <div className="flex-1">
              <div className="font-display text-[0.95rem] font-bold text-content-primary mb-1.5 tracking-[-0.2px]">{step.title}</div>
              <div className="text-[0.85rem] text-content-secondary leading-[1.6]">{step.body}</div>
              {step.code && <CodeBlock code={step.code} />}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
