import { useEmulations } from '@/hooks/usePlatformData'
import { ContentIndexRow } from '@/components/common/ContentIndexRow'

/**
 * Playbooks content hub — incident-response discovery layer.
 *
 * Each emulation ships an IR playbook (parsed from PLAYBOOK.md). This hub lists
 * the emulations and links into each one's existing scoped playbook page rather
 * than duplicating playbook content.
 */
export function PlaybooksHub() {
  const { data: emulations, loading } = useEmulations('aws')

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

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading playbooks...</div>
      ) : (
        <div className="flex flex-col gap-2.5">
          {(emulations ?? []).map((em) => (
            <ContentIndexRow
              key={em.id}
              to={`/aws/emulations/${em.id}/playbook`}
              title={em.name}
              subtitle={em.tags.join(' · ')}
              badge="IR Playbook"
            />
          ))}
        </div>
      )}
    </div>
  )
}
