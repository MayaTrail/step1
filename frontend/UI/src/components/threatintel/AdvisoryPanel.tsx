import { useAdvisories } from '@/hooks/useThreatIntel'
import { ComingSoon } from '@/components/common/ComingSoon'
import { IconWarning } from '@/components/ui/Icons'

/**
 * The Advisory panel.
 *
 * Advisories are MayaTrail-authored notices that tie an active threat to the
 * emulations, detections and guardrails covering it — distinct from the Feed,
 * which republishes other people's posts.
 *
 * No advisory content exists yet, so this renders an honest placeholder rather
 * than faking entries, the same treatment the other unbuilt destinations get.
 * The endpoint and the Advisory type are already in place, so the list below
 * starts rendering as soon as content lands.
 */
export function AdvisoryPanel() {
  const { data: library, loading } = useAdvisories()

  if (loading && !library) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading advisories...</div>
  }

  if (!library || library.totalCount === 0) {
    return (
      <ComingSoon
        icon={<IconWarning size={32} />}
        title="Advisories coming soon"
        body="MayaTrail advisories will appear here — each tying an active cloud threat to the emulations that reproduce it, the detections that catch it, and the guardrails that block it."
      />
    )
  }

  return (
    <div className="flex flex-col gap-3">
      {library.advisories.map((advisory) => (
        <article
          key={advisory.id}
          className="bg-surface-card border border-border rounded-card p-5
            transition-all duration-[400ms] hover:border-[rgba(0,180,216,0.2)] hover:-translate-y-0.5"
        >
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[0.65rem] tracking-[1.5px] uppercase text-accent-blue font-medium">
              {advisory.severity}
            </span>
            {advisory.publishedAt && (
              <span className="font-mono text-[0.65rem] text-content-dim ml-auto">
                {new Date(advisory.publishedAt).toLocaleDateString()}
              </span>
            )}
          </div>
          <div className="font-display text-[1.05rem] font-bold text-content-primary leading-snug">
            {advisory.title}
          </div>
          <p className="text-[0.85rem] text-content-secondary leading-[1.6] mt-2">{advisory.summary}</p>
        </article>
      ))}
    </div>
  )
}
