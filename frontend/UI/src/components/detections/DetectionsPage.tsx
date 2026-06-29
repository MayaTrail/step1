import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useDetections } from '@/hooks/usePlatformData'
import type { PlatformId } from '@/types'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { EmptyState } from '@/components/ui/EmptyState'

type RuleFormat = 'sigma' | 'kql'

export function DetectionsPage() {
  const { platformId, emulationId } = useParams<{ platformId: string; emulationId: string }>()
  const pid = platformId as PlatformId
  const { data: detections, loading } = useDetections(emulationId)
  const [activeFormat, setActiveFormat] = useState<RuleFormat>('sigma')

  const emulationLabel = detections?.displayName ?? emulationId?.toUpperCase() ?? ''

  const rules = activeFormat === 'sigma' ? (detections?.sigma ?? []) : (detections?.kql ?? [])

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading detections...</div>
  }

  if (!detections || detections.totalCount === 0) {
    return (
      <EmptyState
        icon="&#128269;"
        title="No detections available"
        body={`Detection rules for ${emulationLabel} are coming soon.`}
      />
    )
  }

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
            {detections.totalCount} rules &middot; {detections.formats}
          </div>
        </div>
        <div className="flex gap-3 shrink-0">
          {emulationId && (
            <Link
              to={`/${pid}/emulations/${emulationId}`}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline
                bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
                hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
            >
              &#8592; Back
            </Link>
          )}
          <button className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer
            bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
            hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active">
            &#11015; Export All Rules
          </button>
        </div>
      </div>

      {/* Format toggle */}
      <div className="flex gap-2 mb-5">
        {(['sigma', 'kql'] as RuleFormat[]).map((fmt) => {
          const count = fmt === 'sigma' ? detections.sigma.length : detections.kql.length
          const isActive = activeFormat === fmt
          return (
            <button
              key={fmt}
              onClick={() => setActiveFormat(fmt)}
              className={`px-4 py-2 rounded-btn font-mono text-[0.75rem] uppercase tracking-[1.5px] font-medium cursor-pointer border transition-all
                ${isActive
                  ? 'bg-accent-blue/[0.15] border-accent-blue/40 text-accent-blue'
                  : 'bg-transparent border-[rgba(255,255,255,0.1)] text-content-dim hover:border-[rgba(255,255,255,0.2)] hover:text-content-secondary'
                }`}
            >
              {fmt.toUpperCase()} ({count})
            </button>
          )
        })}
      </div>

      {/* Rules */}
      {rules.length === 0 ? (
        <div className="text-center py-12 text-content-dim font-mono text-sm">
          No {activeFormat.toUpperCase()} rules for this emulation.
        </div>
      ) : (
        rules.map((rule, i) => (
          <div key={i} className="bg-surface-card border border-border rounded-card p-6 mb-4
            transition-all duration-[400ms] hover:border-[rgba(0,180,216,0.2)] hover:-translate-y-0.5">
            <div className="font-mono text-[0.7rem] tracking-[1.5px] text-content-dim uppercase mb-3.5 flex items-center gap-2 font-medium">
              {rule.title}
              <div className="flex-1 h-px bg-border" />
            </div>
            <CodeBlock code={rule.code} className="mt-0" />
          </div>
        ))
      )}
    </div>
  )
}
