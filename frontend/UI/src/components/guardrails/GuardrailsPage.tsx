import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useGuardrails } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { GuardrailPolicy, GuardrailType, PlatformId } from '@/types'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { EmptyState } from '@/components/ui/EmptyState'
import { Tag } from '@/components/ui/Tag'

/** Service tags shown inline before the list collapses into a "+N more" chip. */
const VISIBLE_SERVICE_TAGS = 5

/**
 * Scoped guardrails page.
 *
 * Without a :guardrailId it is the full SCP/RCP library — an SCP/RCP toggle
 * over one card per policy, matching how the detections library presents rules.
 * With a :guardrailId (the hub's "View Policy" destination) it shows that one
 * policy on its own.
 */
export function GuardrailsPage() {
  const { platformId, guardrailId } = useParams<{ platformId: string; guardrailId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: library, loading } = useGuardrails(pid)
  const [activeType, setActiveType] = useState<GuardrailType>('SCP')

  const platformLabel = meta?.label ?? platformId?.toUpperCase() ?? ''

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading guardrails...</div>
  }

  if (!library || library.totalCount === 0) {
    return (
      <EmptyState
        icon="&#128737;"
        title="No guardrails available"
        body={`Guardrails for ${platformLabel} are coming soon.`}
      />
    )
  }

  const selected = guardrailId
    ? [...library.scp, ...library.rcp].find((g) => g.id === guardrailId)
    : undefined

  if (guardrailId && !selected) {
    return (
      <EmptyState
        icon="&#128737;"
        title="Guardrail not found"
        body={`No policy with id "${guardrailId}" exists in the library.`}
      />
    )
  }

  const crumbs = [
    { label: 'Home', to: '/' },
    { label: 'Guardrails', to: '/guardrails' },
    ...(selected
      ? [{ label: platformLabel, to: `/${pid}/guardrails` }, { label: selected.type }]
      : [{ label: platformLabel }]),
  ]

  const policies = activeType === 'SCP' ? library.scp : library.rcp

  return (
    <div>
      <Breadcrumb items={crumbs} />

      {/* Header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            {platformLabel}
          </div>
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            {selected ? selected.name : 'Guardrail Library'}
          </div>
          <div className="text-[0.9rem] text-content-secondary mt-1.5">
            {selected
              ? `Source: ${selected.source}`
              : `${library.totalCount} policies · ${library.formats}`}
          </div>
        </div>
        {selected && (
          <Link
            to={`/${pid}/guardrails`}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline
              bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all shrink-0
              hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
          >
            &#8592; All guardrails
          </Link>
        )}
      </div>

      {selected ? (
        <PolicyCard policy={selected} />
      ) : (
        <>
          {/* Type toggle */}
          <div className="flex gap-2 mb-5">
            {(['SCP', 'RCP'] as GuardrailType[]).map((type) => {
              const count = type === 'SCP' ? library.scp.length : library.rcp.length
              const isActive = activeType === type
              return (
                <button
                  key={type}
                  onClick={() => setActiveType(type)}
                  className={`px-4 py-2 rounded-btn font-mono text-[0.75rem] uppercase tracking-[1.5px] font-medium cursor-pointer border transition-all
                    ${isActive
                      ? 'bg-accent-blue/[0.15] border-accent-blue/40 text-accent-blue'
                      : 'bg-transparent border-[rgba(255,255,255,0.1)] text-content-dim hover:border-[rgba(255,255,255,0.2)] hover:text-content-secondary'
                    }`}
                >
                  {type} ({count})
                </button>
              )
            })}
          </div>

          {policies.length === 0 ? (
            <div className="text-center py-12 text-content-dim font-mono text-sm">
              No {activeType} policies in the library.
            </div>
          ) : (
            policies.map((policy) => <PolicyCard key={policy.id} policy={policy} showTitle />)
          )}
        </>
      )}
    </div>
  )
}

/** One policy: title (in list view), service tags, the document, and its source. */
function PolicyCard({ policy, showTitle = false }: { policy: GuardrailPolicy; showTitle?: boolean }) {
  return (
    <div className="bg-surface-card border border-border rounded-card p-6 mb-4
      transition-all duration-[400ms] hover:border-[rgba(0,180,216,0.2)] hover:-translate-y-0.5">
      {showTitle && (
        <div className="font-mono text-[0.7rem] tracking-[1.5px] text-content-dim uppercase mb-3.5 flex items-center gap-2 font-medium">
          {policy.name}
          <div className="flex-1 h-px bg-border" />
        </div>
      )}
      <ServiceTags services={policy.services} />
      <CodeBlock code={policy.code} className="mt-0" />
      <div className="font-mono text-[0.65rem] text-content-dim mt-2.5">
        Source: {policy.source}
      </div>
    </div>
  )
}

/** The AWS services a policy targets, rendered as small chips. */
function ServiceTags({ services }: { services: string[] }) {
  if (services.length === 0) return null
  const visible = services.slice(0, VISIBLE_SERVICE_TAGS)
  const overflow = services.length - visible.length

  return (
    <div className="flex flex-wrap gap-1.5 mb-3">
      {visible.map((service) => (
        <Tag key={service} tone="info">{service}</Tag>
      ))}
      {overflow > 0 && (
        <Tag tone="muted" title={services.slice(VISIBLE_SERVICE_TAGS).join(', ')}>
          +{overflow} more
        </Tag>
      )}
    </div>
  )
}
