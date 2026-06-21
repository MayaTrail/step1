import { useEmulations } from '@/hooks/usePlatformData'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryToolbar } from '@/components/common/LibraryToolbar'
import { useLibraryFilter, emulationTactics } from '@/components/common/useLibraryFilter'
import { LibraryEmpty } from '@/components/emulations/EmulationsHub'
import { IconClipboard } from '@/components/ui/Icons'

/**
 * Playbooks content hub — incident-response discovery library.
 *
 * Each emulation ships an IR playbook (parsed from PLAYBOOK.md). Each card
 * represents an emulation and links into its existing scoped playbook page
 * rather than duplicating playbook content.
 */
export function PlaybooksHub() {
  const { data: emulations, loading } = useEmulations('aws')
  const { filtered, toolbar } = useLibraryFilter(emulations ?? [])

  return (
    <div>
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Security Content
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Playbooks
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          Incident-response and remediation guidance by emulation
        </div>
      </div>

      <LibraryToolbar {...toolbar} searchPlaceholder="Search playbooks..." />

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading playbooks...</div>
      ) : filtered.length === 0 ? (
        <LibraryEmpty noun="playbooks" />
      ) : (
        <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
          {filtered.map((em) => (
            <LibraryCard
              key={em.id}
              name={em.name}
              eyebrow="IR Playbook · Response"
              severity={em.severity}
              description={em.description}
              tactics={emulationTactics(em)}
              actions={[
                {
                  label: 'View Playbook',
                  icon: <IconClipboard size={14} />,
                  to: `/aws/emulations/${em.id}/playbook`,
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
