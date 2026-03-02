import { useParams } from 'react-router-dom'
import { useDetections } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { PlatformId } from '@/types'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { EmptyState } from '@/components/ui/EmptyState'

export function DetectionsPage() {
  const { platformId } = useParams<{ platformId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const { data: detections, loading } = useDetections(pid)

  const platformLabel = meta?.label ?? platformId?.toUpperCase() ?? ''

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading detections...</div>
  }
  if (!detections) {
    return <EmptyState icon="&#128269;" title="No detections available" body={`Detection rules for ${platformLabel} are coming soon.`} />
  }

  return (
    <div>
      <Breadcrumb items={[
        { label: 'Home', to: '/' },
        { label: platformLabel },
        { label: 'Detections' },
      ]} />

      {/* Header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            {platformLabel}
          </div>
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            Detection Library
          </div>
          <div className="text-[0.9rem] text-content-secondary mt-1.5">
            {detections.ruleCount} rules &middot; {detections.formats}
          </div>
        </div>
        <div className="flex gap-3 shrink-0">
          <button className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer
            bg-transparent border border-[rgba(255,255,255,0.15)] text-content-primary transition-all
            hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active">
            &#11015; Export All Rules
          </button>
        </div>
      </div>

      {/* Rules */}
      {detections.rules.map((rule, i) => (
        <div key={i} className="bg-surface-card border border-border rounded-card p-6 mb-4
          transition-all duration-[400ms] hover:border-[rgba(0,180,216,0.2)] hover:-translate-y-0.5">
          <div className="font-mono text-[0.7rem] tracking-[1.5px] text-content-dim uppercase mb-3.5 flex items-center gap-2 font-medium">
            {rule.title}
            <div className="flex-1 h-px bg-border" />
          </div>
          <CodeBlock code={rule.code} className="mt-0" />
        </div>
      ))}
    </div>
  )
}
