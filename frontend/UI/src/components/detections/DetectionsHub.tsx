import { useEmulations } from '@/hooks/usePlatformData'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryToolbar } from '@/components/common/LibraryToolbar'
import { useLibraryFilter, emulationTactics } from '@/components/common/useLibraryFilter'
import { LibraryEmpty } from '@/components/emulations/EmulationsHub'
import { IconSearch } from '@/components/ui/Icons'

/**
 * Detections content hub — detection-engineering discovery library.
 *
 * Detection rules (SIGMA + KQL) are authored per emulation, so each card
 * represents an emulation and links into its existing scoped detections page.
 * No rule data is duplicated here.
 */
export function DetectionsHub() {
  const { data: emulations, loading } = useEmulations('aws')
  const { filtered, toolbar } = useLibraryFilter(emulations ?? [])

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

      <LibraryToolbar {...toolbar} searchPlaceholder="Search detections..." />

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading detections...</div>
      ) : filtered.length === 0 ? (
        <LibraryEmpty noun="detections" />
      ) : (
        <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
          {filtered.map((em) => (
            <LibraryCard
              key={em.id}
              name={em.name}
              eyebrow="SIGMA + KQL · Detections"
              severity={em.severity}
              description={em.description}
              tactics={emulationTactics(em)}
              actions={[
                {
                  label: 'View Detections',
                  icon: <IconSearch size={14} />,
                  to: `/aws/emulations/${em.id}/detections`,
                  variant: 'secondary',
                },
              ]}
            />
          ))}
        </div>
      )}
    </div>
  )
}
