import { useState } from 'react'
import { useEmulations } from '@/hooks/usePlatformData'
import type { Emulation } from '@/types'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryToolbar } from '@/components/common/LibraryToolbar'
import { useLibraryFilter, emulationTactics } from '@/components/common/useLibraryFilter'
import { platformShortLabel } from '@/data'
import { RunEmulationModal } from '@/components/modals/RunEmulationModal'
import { IconLaunch } from '@/components/ui/Icons'

/**
 * Emulations content hub — a cross-platform card library of every emulation
 * the platform supports. Each card runs its emulation via the existing modal.
 *
 * The backend catalogue is AWS-only today (fetchEmulations returns the whole
 * list regardless of platform), so the Platform filter shows real content for
 * AWS and an empty result for the others.
 */
export function EmulationsHub() {
  const { data: emulations, loading } = useEmulations('aws')
  const { filtered, toolbar } = useLibraryFilter(emulations ?? [])
  const [runTarget, setRunTarget] = useState<Emulation | null>(null)

  return (
    <div>
      {/* Page header */}
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Security Content
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Emulations
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          {(emulations?.length ?? 0)} emulations available &middot; Browse the full library across platforms
        </div>
      </div>

      <LibraryToolbar {...toolbar} searchPlaceholder="Search emulations..." />

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading emulations...</div>
      ) : filtered.length === 0 ? (
        <LibraryEmpty noun="emulations" />
      ) : (
        <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
          {filtered.map((em) => (
            <LibraryCard
              key={em.id}
              name={em.name}
              eyebrow={`${em.originLabel || 'Emulation'} · ${platformShortLabel(em.platform)}`}
              severity={em.severity}
              description={em.description}
              tactics={emulationTactics(em)}
              actions={[
                { label: 'View Emulation', to: `/aws/emulations/${em.id}`, variant: 'secondary' },
                { label: 'Run', icon: <IconLaunch size={14} />, onClick: () => setRunTarget(em), variant: 'primary' },
              ]}
            />
          ))}
        </div>
      )}

      {runTarget && (
        <RunEmulationModal
          emulationId={runTarget.id}
          emulationName={runTarget.name}
          onClose={() => setRunTarget(null)}
        />
      )}
    </div>
  )
}

/** Shared "no results" state for the library hubs. */
export function LibraryEmpty({ noun }: { noun: string }) {
  return (
    <div className="text-center py-16">
      <div className="font-display text-base text-content-primary mb-1.5">No {noun} match your filters</div>
      <div className="text-[0.9rem] text-content-secondary">Try clearing the search or filters.</div>
    </div>
  )
}
