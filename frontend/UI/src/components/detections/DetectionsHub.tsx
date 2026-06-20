import { useEmulations } from '@/hooks/usePlatformData'
import { ContentIndexRow } from '@/components/common/ContentIndexRow'

/**
 * Detections content hub — detection-engineering discovery layer.
 *
 * Detection rules (SIGMA + KQL) are authored per emulation, so this hub lists
 * the emulations that ship detections and links into each one's existing
 * scoped detections page. No rule data is duplicated here.
 */
export function DetectionsHub() {
  const { data: emulations, loading } = useEmulations('aws')

  return (
    <div>
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Security Content
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Detections
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          Browse SIGMA and KQL detection coverage by emulation
        </div>
      </div>

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading detections...</div>
      ) : (
        <div className="flex flex-col gap-2.5">
          {(emulations ?? []).map((em) => (
            <ContentIndexRow
              key={em.id}
              to={`/aws/emulations/${em.id}/detections`}
              title={em.name}
              subtitle={em.tags.join(' · ')}
              badge="SIGMA + KQL"
            />
          ))}
        </div>
      )}
    </div>
  )
}
