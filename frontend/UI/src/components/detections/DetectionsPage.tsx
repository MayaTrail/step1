import { useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useDetections } from '@/hooks/usePlatformData'
import type { PlatformId, DetectionRuleSummary } from '@/types'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { EmptyState } from '@/components/ui/EmptyState'
import { severityDotClass, severityTextClass } from './severity'
import { downloadText } from '@/utils/download'

type RuleFormat = 'sigma' | 'kql'

/** Pick the format to show for a rule, preferring Sigma when both exist. */
function defaultFormat(rule: DetectionRuleSummary): RuleFormat {
  return rule.formats.sigma ? 'sigma' : 'kql'
}

/**
 * Detection library for one emulation, rendered as a master-detail view:
 * a scannable rule index on the left, the selected rule's source on the right.
 * Rule metadata and both code bodies arrive in a single payload, so selecting
 * a rule is instant and needs no follow-up request.
 */
export function DetectionsPage() {
  const { platformId, emulationId } = useParams<{ platformId: string; emulationId: string }>()
  const pid = platformId as PlatformId
  const { data: detections, loading } = useDetections(emulationId)

  const rules = useMemo(() => detections?.rules ?? [], [detections])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [format, setFormat] = useState<RuleFormat>('sigma')
  const [query, setQuery] = useState('')

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return rules
    return rules.filter(
      (r) => r.title.toLowerCase().includes(q) || r.technique.id.toLowerCase().includes(q),
    )
  }, [rules, query])

  // Resolve the active rule: the explicit selection if still visible, else the
  // first rule in the (filtered) list. Keeps a valid selection as search narrows.
  const active =
    filtered.find((r) => r.ruleId === selectedId) ?? filtered[0] ?? null

  const emulationLabel = detections?.displayName ?? emulationId?.toUpperCase() ?? ''

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading detections...</div>
  }

  if (!detections || rules.length === 0) {
    return (
      <EmptyState
        icon="&#128269;"
        title="No detections available"
        body={`Detection rules for ${emulationLabel} are coming soon.`}
      />
    )
  }

  const activeFormat: RuleFormat = active && !active.formats[format] ? defaultFormat(active) : format

  return (
    <div>
      {/* Header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            {emulationLabel}
          </div>
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            Detection Library
          </div>
          <div className="text-[0.9rem] text-content-secondary mt-1.5">
            {rules.length} rules &middot; {detections.formats}
          </div>
        </div>
        {emulationId && (
          <Link
            to={`/${pid}/emulations/${emulationId}`}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline shrink-0
              bg-transparent border border-border text-content-primary transition-all
              hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
          >
            &#8592; Back
          </Link>
        )}
      </div>

      {/* Master-detail shell */}
      <div className="grid grid-cols-1 lg:grid-cols-[290px_1fr] gap-4 items-start">
        {/* Rule index rail */}
        <div className="bg-surface-card border border-border rounded-card overflow-hidden flex flex-col h-[calc(100vh-280px)] min-h-[560px]">
          <div className="p-3 border-b border-border">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search rules..."
              className="w-full bg-[rgba(0,0,0,0.3)] border border-border rounded-btn px-3 py-2 text-[0.8rem] text-content-primary
                placeholder:text-content-dim outline-none focus:border-border-active"
            />
          </div>
          <div className="overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="text-center py-8 text-content-dim font-mono text-xs">No matches.</div>
            ) : (
              filtered.map((rule) => (
                <RuleRow
                  key={rule.ruleId}
                  rule={rule}
                  active={active?.ruleId === rule.ruleId}
                  onSelect={() => {
                    setSelectedId(rule.ruleId)
                    setFormat(defaultFormat(rule))
                  }}
                />
              ))
            )}
          </div>
        </div>

        {/* Source preview pane */}
        {active && (
          <SourcePane
            rule={active}
            format={activeFormat}
            onFormat={setFormat}
            detailTo={emulationId ? `/${pid}/emulations/${emulationId}/detections/${active.ruleId}` : undefined}
          />
        )}
      </div>
    </div>
  )
}

function RuleRow({
  rule,
  active,
  onSelect,
}: {
  rule: DetectionRuleSummary
  active: boolean
  onSelect: () => void
}) {
  return (
    <button
      onClick={onSelect}
      className={`w-full text-left px-3.5 py-3 border-b border-border cursor-pointer transition-colors border-l-2
        ${active ? 'bg-accent-blue/[0.07] border-l-accent-blue' : 'border-l-transparent hover:bg-[rgba(255,255,255,0.02)]'}`}
    >
      <div className="flex items-center gap-2">
        <span className="font-mono text-[0.7rem] text-accent-blue font-semibold">{rule.technique.id}</span>
        {rule.severity && (
          <span className={`w-1.5 h-1.5 rounded-full ml-auto ${severityDotClass(rule.severity)}`} />
        )}
      </div>
      <div className="text-[0.78rem] text-content-secondary mt-1 leading-snug">{rule.title}</div>
      <div className="flex items-center gap-1.5 mt-1.5">
        {rule.logSource.service && (
          <span className="font-mono text-[0.62rem] text-content-dim">{rule.logSource.service}</span>
        )}
        <span className={`font-mono text-[0.58rem] font-bold tracking-[0.5px] px-1.5 py-0.5 rounded ${rule.formats.sigma ? 'bg-surface-elevated text-content-secondary' : 'bg-surface-elevated text-content-dim opacity-40'}`}>S</span>
        <span className={`font-mono text-[0.58rem] font-bold tracking-[0.5px] px-1.5 py-0.5 rounded ${rule.formats.kql ? 'bg-surface-elevated text-content-secondary' : 'bg-surface-elevated text-content-dim opacity-40'}`}>K</span>
      </div>
    </button>
  )
}

function SourcePane({
  rule,
  format,
  onFormat,
  detailTo,
}: {
  rule: DetectionRuleSummary
  format: RuleFormat
  onFormat: (f: RuleFormat) => void
  detailTo?: string
}) {
  const code = format === 'sigma' ? rule.sigma : rule.kql
  const platform = [rule.logSource.product, rule.logSource.service].filter(Boolean).join(' · ').toUpperCase()
  const exportName = `${format}_${rule.ruleId}.${format === 'sigma' ? 'yml' : 'kql'}`

  return (
    <div className="bg-surface-card border border-border rounded-card overflow-hidden flex flex-col h-[calc(100vh-280px)] min-h-[560px]">
      {/* Pane header */}
      <div className="p-5 border-b border-border">
        <div className="font-mono text-[0.72rem] text-accent-blue font-semibold">{rule.technique.id}</div>
        <div className="text-[1.05rem] font-[700] text-content-primary mt-1 leading-snug">{rule.title}</div>
        <div className="flex flex-wrap gap-1.5 mt-2.5">
          {rule.severity && (
            <Tag className={severityTextClass(rule.severity)}>{rule.severity.toUpperCase()}</Tag>
          )}
          {platform && <Tag>AWS · {platform}</Tag>}
          {rule.technique.tactic && <Tag className="text-accent-blue">{rule.technique.tactic}</Tag>}
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-5 py-3 border-b border-border flex-wrap">
        <div className="flex gap-0.5 bg-[rgba(0,0,0,0.3)] border border-border rounded-btn p-0.5">
          {(['sigma', 'kql'] as RuleFormat[]).map((fmt) => {
            const available = rule.formats[fmt]
            const isActive = format === fmt && available
            return (
              <button
                key={fmt}
                disabled={!available}
                onClick={() => onFormat(fmt)}
                className={`font-mono text-[0.7rem] uppercase tracking-[1px] font-semibold px-3.5 py-1.5 rounded-btn transition-colors
                  ${isActive ? 'bg-accent-blue/[0.15] text-accent-blue' : 'text-content-dim hover:text-content-secondary'}
                  ${!available ? 'opacity-35 cursor-not-allowed' : 'cursor-pointer'}`}
              >
                {fmt.toUpperCase()}
              </button>
            )
          })}
        </div>
        <div className="flex gap-2 ml-auto">
          {code && (
            <>
              <ToolButton onClick={() => navigator.clipboard.writeText(code)}>Copy</ToolButton>
              <ToolButton onClick={() => downloadText(exportName, code)}>Download</ToolButton>
            </>
          )}
          {detailTo && (
            <Link
              to={detailTo}
              className="inline-flex items-center text-[0.8rem] text-accent-blue no-underline hover:underline px-2"
            >
              View full detail &#8594;
            </Link>
          )}
        </div>
      </div>

      {/* Code — scrolls within the fixed-height pane */}
      {code ? (
        <div className="flex-1 min-h-0 overflow-y-auto">
          <CodeBlock code={code} className="mt-0 rounded-none border-0" />
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-content-dim font-mono text-sm">
          No {format.toUpperCase()} rule for this detection.
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
