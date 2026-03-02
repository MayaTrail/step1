import { useParams } from 'react-router-dom'
import { useGuardrails } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { PlatformId } from '@/types'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { EmptyState } from '@/components/ui/EmptyState'

export function GuardrailsPage() {
  const { platformId } = useParams<{ platformId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: guardrails, loading } = useGuardrails(pid)

  const platformLabel = meta?.label ?? platformId?.toUpperCase() ?? ''

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading guardrails...</div>
  }
  if (!guardrails) {
    return <EmptyState icon="&#128737;" title="No guardrails configured" body={`Guardrails for ${platformLabel} are coming soon.`} />
  }

  return (
    <div>
      <Breadcrumb items={[
        { label: 'Home', to: '/' },
        { label: platformLabel },
        { label: 'Guardrails' },
      ]} />

      {/* Header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            {platformLabel}
          </div>
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            Guardrails Configuration
          </div>
          <div className="text-[0.9rem] text-content-secondary mt-1.5">
            Define emulation scope, boundaries, and auto-block policies
          </div>
        </div>
        <div className="flex gap-3 shrink-0">
          <button className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-semibold cursor-pointer border-none
            bg-safe text-surface-deep transition-all hover:-translate-y-px hover:shadow-[0_8px_40px_rgba(0,230,118,0.4)]">
            &#128190; Save Config
          </button>
        </div>
      </div>

      {/* Excluded Resources */}
      <div className="bg-surface-card border border-border rounded-card p-6 mb-4
        transition-all duration-[400ms] hover:border-[rgba(255,34,68,0.2)] hover:-translate-y-0.5">
        <SectionTitle>Excluded Resources</SectionTitle>
        <div className="text-[0.85rem] text-content-secondary leading-8">
          {guardrails.excluded.map((item, i) => (
            <div key={i}>&#128683; {item}</div>
          ))}
        </div>
      </div>

      {/* Allowed Window */}
      <div className="bg-surface-card border border-border rounded-card p-6 mb-4
        transition-all duration-[400ms] hover:border-[rgba(0,180,216,0.2)] hover:-translate-y-0.5">
        <SectionTitle>Allowed Emulation Window</SectionTitle>
        <div className="text-[0.85rem] text-content-secondary">
          {guardrails.schedule}
        </div>
      </div>

      {/* Scope Limits */}
      {guardrails.scopeLimits.length > 0 && (
        <div className="bg-surface-card border border-border rounded-card p-6 mb-4
          transition-all duration-[400ms] hover:border-[rgba(255,34,68,0.2)] hover:-translate-y-0.5">
          <SectionTitle>Scope Limits</SectionTitle>
          <div className="text-[0.85rem] text-content-secondary leading-8">
            {guardrails.scopeLimits.map((limit, i) => (
              <div key={i}>&#9888;&#65039; {limit}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-mono text-[0.7rem] tracking-[1.5px] text-content-dim uppercase mb-3.5 flex items-center gap-2 font-medium">
      {children}
      <div className="flex-1 h-px bg-border" />
    </div>
  )
}
