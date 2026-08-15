import { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useGuardrail, useGuardrails } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { GuardrailSummary, GuardrailType, PlatformId } from '@/types'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { EmptyState } from '@/components/ui/EmptyState'
import { IconShield } from '@/components/ui/Icons'
import { downloadText } from '@/utils/download'

type TypeFilter = 'all' | GuardrailType

const TYPE_FILTERS: TypeFilter[] = ['all', 'SCP', 'RCP']

/**
 * Guardrail library for one platform, rendered as a master-detail view to
 * match the detections library: a searchable policy index on the left, the
 * selected policy document on the right.
 *
 * The index carries no policy text, so the pane resolves each document as it
 * is selected. At 97 policies a scannable rail beats a stack of full cards,
 * and it keeps the initial payload to metadata alone.
 *
 * A :guardrailId in the route preselects that policy, which is where the
 * hub's "View Policy" action lands.
 */
export function GuardrailsPage() {
  const { platformId, guardrailId } = useParams<{ platformId: string; guardrailId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: library, loading } = useGuardrails(pid)

  const [selectedId, setSelectedId] = useState<string | null>(guardrailId ?? null)
  const [type, setType] = useState<TypeFilter>('all')
  const [query, setQuery] = useState('')

  const policies = useMemo(() => library?.guardrails ?? [], [library])

  const filtered = useMemo(() => {
    let list = policies
    if (type !== 'all') list = list.filter((g) => g.type === type)
    const q = query.trim().toLowerCase()
    if (q) {
      list = list.filter(
        (g) =>
          g.purpose.toLowerCase().includes(q) ||
          g.services.some((s) => s.toLowerCase().includes(q)),
      )
    }
    return list
  }, [policies, type, query])

  // Keep a valid selection as the filters narrow: fall back to the first
  // visible policy whenever the chosen one is filtered out.
  const active = filtered.find((g) => g.id === selectedId) ?? filtered[0] ?? null

  const platformLabel = meta?.label ?? platformId?.toUpperCase() ?? ''

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading guardrails...</div>
  }

  if (!library || library.totalCount === 0) {
    return (
      <EmptyState
        icon={<IconShield size={32} />}
        title="No guardrails available"
        body={`Guardrails for ${platformLabel} are coming soon.`}
      />
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          {platformLabel}
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Guardrail Library
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          {library.totalCount} preventive policies &middot; {library.formats}
        </div>
      </div>

      {/* Master-detail shell */}
      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-4 items-start">
        {/* Policy index rail */}
        <div className="bg-surface-card border border-border rounded-card overflow-hidden flex flex-col h-[calc(100vh-280px)] min-h-[560px]">
          <div className="p-3 border-b border-border">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search policies..."
              className="w-full bg-[rgba(0,0,0,0.3)] border border-border rounded-btn px-3 py-2 text-[0.8rem] text-content-primary
                placeholder:text-content-dim outline-none focus:border-border-active"
            />
            <div className="flex gap-0.5 bg-[rgba(0,0,0,0.3)] border border-border rounded-btn p-0.5 mt-2">
              {TYPE_FILTERS.map((value) => {
                const isActive = type === value
                const count =
                  value === 'all' ? policies.length : policies.filter((g) => g.type === value).length
                return (
                  <button
                    key={value}
                    onClick={() => setType(value)}
                    className={`flex-1 font-mono text-[0.65rem] uppercase tracking-[1px] font-semibold py-1.5 rounded-btn cursor-pointer transition-colors
                      ${isActive ? 'bg-accent-blue/[0.15] text-accent-blue' : 'text-content-dim hover:text-content-secondary'}`}
                  >
                    {value === 'all' ? 'All' : value} ({count})
                  </button>
                )
              })}
            </div>
          </div>
          <div className="overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="text-center py-8 text-content-dim font-mono text-xs">No matches.</div>
            ) : (
              filtered.map((policy) => (
                <PolicyRow
                  key={policy.id}
                  policy={policy}
                  active={active?.id === policy.id}
                  onSelect={() => setSelectedId(policy.id)}
                />
              ))
            )}
          </div>
        </div>

        {/* Policy document pane */}
        {active && <PolicyPane policy={active} />}
      </div>
    </div>
  )
}

function PolicyRow({
  policy,
  active,
  onSelect,
}: {
  policy: GuardrailSummary
  active: boolean
  onSelect: () => void
}) {
  return (
    <button
      onClick={onSelect}
      className={`w-full text-left px-3.5 py-3 border-b border-border cursor-pointer transition-colors border-l-2
        ${active ? 'bg-accent-blue/[0.07] border-l-accent-blue' : 'border-l-transparent hover:bg-[rgba(255,255,255,0.02)]'}`}
    >
      <div className="font-mono text-[0.7rem] text-accent-blue font-semibold">{policy.type}</div>
      <div className="text-[0.78rem] text-content-secondary mt-1 leading-snug">{policy.purpose}</div>
      <div className="font-mono text-[0.62rem] text-content-dim mt-1.5 truncate">
        {policy.services.join(' · ')}
      </div>
    </button>
  )
}

/**
 * The selected policy's document, resolved on demand.
 *
 * Falls back to the index metadata while the document loads so the header does
 * not flicker between selections.
 */
function PolicyPane({ policy }: { policy: GuardrailSummary }) {
  const { data: detail, loading } = useGuardrail(policy.id)
  const code = detail?.code ?? null
  const exportName = `${policy.id}.json`

  return (
    <div className="bg-surface-card border border-border rounded-card overflow-hidden flex flex-col h-[calc(100vh-280px)] min-h-[560px]">
      {/* Pane header */}
      <div className="p-5 border-b border-border">
        <div className="font-mono text-[0.72rem] text-accent-blue font-semibold">{policy.type}</div>
        <div className="text-[1.05rem] font-[700] text-content-primary mt-1 leading-snug">{policy.purpose}</div>
        <div className="flex flex-wrap gap-1.5 mt-2.5">
          {policy.services.map((service) => (
            <Tag key={service} className="text-accent-blue">{service}</Tag>
          ))}
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-5 py-3 border-b border-border flex-wrap">
        <a
          href={policy.source.url}
          target="_blank"
          rel="noreferrer"
          className="text-[0.78rem] text-content-secondary no-underline transition-opacity hover:opacity-60"
        >
          Source: {policy.source.label}
        </a>
        <div className="flex gap-2 ml-auto">
          {code && (
            <>
              <ToolButton onClick={() => navigator.clipboard.writeText(code)}>Copy</ToolButton>
              <ToolButton onClick={() => downloadText(exportName, code)}>Download</ToolButton>
            </>
          )}
        </div>
      </div>

      {/* Document, scrolls within the fixed-height pane */}
      {code ? (
        <div className="flex-1 min-h-0 overflow-y-auto">
          <CodeBlock code={code} className="mt-0 rounded-none border-0" />
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-content-dim font-mono text-sm">
          {loading ? 'Loading policy...' : 'Policy document unavailable.'}
        </div>
      )}
    </div>
  )
}

function Tag({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`font-mono text-[0.62rem] font-semibold tracking-[0.4px] uppercase px-2 py-0.5 rounded bg-[rgba(255,255,255,0.05)] ${className || 'text-content-dim'}`}>
      {children}
    </span>
  )
}

function ToolButton({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="font-body text-[0.78rem] text-content-secondary bg-transparent border border-border rounded-btn px-3 py-1.5 cursor-pointer transition-opacity hover:opacity-60"
    >
      {children}
    </button>
  )
}
