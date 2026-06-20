import { useState } from 'react'
import { useEmulations } from '@/hooks/usePlatformData'
import { platformRegistry } from '@/data'
import type { PlatformId, Emulation } from '@/types'
import { EmulationCard } from '@/components/emulations/EmulationsListPage'
import { RunEmulationModal } from '@/components/modals/RunEmulationModal'
import { PlatformIcon } from '@/components/ui/PlatformIcons'

/** Short sidebar/chip label for each platform id. */
const SHORT_LABEL: Record<PlatformId, string> = {
  aws: 'AWS',
  gcp: 'GCP',
  azure: 'Azure',
  k8s: 'Kubernetes',
  ai: 'AI',
}

/**
 * Emulations content hub — a single, cross-platform library of every emulation
 * the platform supports, replacing the per-platform APT Emulations sub-pages.
 *
 * The backend emulation catalogue is AWS-only today (fetchEmulations returns
 * the full list regardless of platform), so the platform filter shows real
 * content for AWS and an honest "coming soon" state for the others.
 */
export function EmulationsHub() {
  // The catalogue endpoint ignores the platform argument and returns every
  // emulation; we pass 'aws' simply to satisfy the hook signature.
  const { data: emulations, loading } = useEmulations('aws')
  const [platform, setPlatform] = useState<PlatformId>('aws')
  const [runTarget, setRunTarget] = useState<Emulation | null>(null)

  const list = platform === 'aws' ? (emulations ?? []) : []

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

      {/* Platform filter chips */}
      <div className="flex gap-2.5 mb-5 items-center flex-wrap">
        <span className="font-mono text-[10px] text-content-dim tracking-[1px]">PLATFORM:</span>
        {platformRegistry.map((p) => {
          const active = platform === p.id
          return (
            <button
              key={p.id}
              onClick={() => setPlatform(p.id)}
              className={`inline-flex items-center gap-1.5 border rounded-full px-3.5 py-[5px] text-[0.7rem] font-mono cursor-pointer transition-all font-medium
                ${active
                  ? 'bg-accent-blue/[0.15] border-accent-blue/30 text-accent-blue'
                  : 'bg-surface-elevated border-border text-content-secondary hover:border-border-active hover:text-content-primary'
                }`}
            >
              <PlatformIcon platformId={p.id} size={13} />
              {SHORT_LABEL[p.id]}
            </button>
          )
        })}
      </div>

      {/* Content */}
      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading emulations...</div>
      ) : list.length === 0 ? (
        <div className="text-center py-16 text-content-dim">
          <div className="font-display text-base text-content-primary mb-1.5">
            {SHORT_LABEL[platform]} emulations coming soon
          </div>
          <div className="text-[0.9rem] text-content-secondary">
            Emulation coverage for this platform is on the roadmap.
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-2.5">
          {list.map((em) => (
            <EmulationCard key={em.id} emulation={em} platformId="aws" onRun={() => setRunTarget(em)} />
          ))}
        </div>
      )}

      {/* Run Emulation Modal */}
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
