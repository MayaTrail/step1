import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useEmulations } from '@/hooks/usePlatformData'
import { listAuthoredDetections } from '@/services/authoredDetection.service'
import type { AuthoredDetectionListItem } from '@/types'
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

  /*
   * Three states, not two. A refused request caught into an empty array would
   * tell a reader they have written no rules when the truth is that the account
   * cannot author them, which is the mistake the playbooks hub already made.
   */
  const [mine, setMine] = useState<AuthoredDetectionListItem[]>([])
  const [mineLoading, setMineLoading] = useState(true)
  const [mineError, setMineError] = useState<'denied' | 'failed' | null>(null)

  useEffect(() => {
    let live = true
    listAuthoredDetections({ mine: true })
      .then((rows) => {
        if (!live) return
        setMine(rows)
        setMineError(null)
        setMineLoading(false)
      })
      .catch((err) => {
        if (!live) return
        setMine([])
        setMineError(err?.response?.status === 403 ? 'denied' : 'failed')
        setMineLoading(false)
      })
    return () => {
      live = false
    }
  }, [])

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

      {/* The reader's own rules, above the shipped catalogue rather than below
          it. The catalogue runs to fifty emulations; a shelf underneath it is
          invisible without scrolling past the whole thing, which is what
          happened to the authored playbooks. */}
      <div className="mb-8 pb-8 border-b border-border-subtle">
        <div className="flex items-center gap-3 mb-3">
          <h2 className="font-display text-lg font-semibold text-content-primary">Your rules</h2>
          {!mineLoading && !mineError && mine.length > 0 && (
            <span className="font-mono text-2xs text-content-muted border border-border rounded-pill px-2">
              {mine.length}
            </span>
          )}
          <span className="flex-1" />
          <Link
            to="/detections/studio/new"
            className="font-mono text-2xs uppercase tracking-label px-3 py-1.5 rounded-btn
              border border-border-active text-content-primary no-underline
              transition-opacity hover:opacity-60"
          >
            New rule
          </Link>
        </div>

        {mineLoading ? (
          <div className="grid gap-2.5 grid-cols-[repeat(auto-fill,minmax(268px,1fr))]">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                aria-hidden="true"
                className="border border-border rounded-card bg-surface-card px-3.5 py-3 animate-pulse"
              >
                <div className="h-2 w-2/5 rounded bg-surface-elevated mb-2.5" />
                <div className="h-3 w-4/5 rounded bg-surface-elevated mb-2.5" />
                <div className="h-2 w-3/5 rounded bg-surface-elevated" />
              </div>
            ))}
          </div>
        ) : mineError ? (
          <div className="border border-border-subtle rounded-card bg-surface-card px-5 py-6 text-center">
            <p className="text-sm text-content-secondary">
              {mineError === 'denied'
                ? 'Connect an AWS account to write detection rules.'
                : 'Could not load your rules.'}
            </p>
            <p className="text-xs text-content-dim mt-1.5 leading-relaxed max-w-[52ch] mx-auto">
              {mineError === 'denied'
                ? 'Authoring is limited to connected accounts. The catalogue below stays fully readable.'
                : 'The request failed. Refresh to try again.'}
            </p>
          </div>
        ) : mine.length === 0 ? (
          <div className="border border-dashed border-border-active rounded-card px-5 py-6 text-center">
            <p className="text-sm text-content-secondary">You have not written a detection rule yet.</p>
            <p className="text-xs text-content-dim mt-1.5 leading-relaxed max-w-[56ch] mx-auto">
              Write Sigma, or let AI draft it, then score whether it actually fires against
              synthetic CloudTrail events before you ship it to your SIEM.
            </p>
          </div>
        ) : (
          <div className="grid gap-2.5 grid-cols-[repeat(auto-fill,minmax(268px,1fr))]">
            {mine.map((rule) => (
              <AuthoredRuleCard key={rule.id} rule={rule} />
            ))}
          </div>
        )}
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


/**
 * One authored rule, as a compact card.
 *
 * Fidelity is shown as a bar rather than a bare number because the figure only
 * means something relative to the scale: 0.64 reads as a fraction, a two-thirds
 * bar reads as "most of the way there". A rule that has never been validated
 * says so, rather than showing zero, since never-measured and measured-badly
 * are different facts.
 */
function AuthoredRuleCard({ rule }: { rule: AuthoredDetectionListItem }) {
  const pct = rule.last_fidelity === null ? null : Math.round(rule.last_fidelity * 100)
  const tone =
    pct === null ? '' : pct >= 75 ? 'bg-safe' : pct >= 50 ? 'bg-warning' : 'bg-danger'

  return (
    <Link
      to={`/detections/studio/${rule.id}`}
      className="block border border-border rounded-card bg-surface-card px-3.5 py-3
        no-underline transition-opacity hover:opacity-75"
    >
      <div className="flex items-center gap-1.5 mb-1.5">
        {rule.technique_id && (
          <span className="font-mono text-2xs uppercase tracking-caps text-content-muted">
            {rule.technique_id}
          </span>
        )}
        {rule.is_generated && (
          <span className="font-mono text-2xs uppercase tracking-caps px-1.5 rounded border
            border-border text-content-muted shrink-0">
            ai drafted
          </span>
        )}
        <span
          className={`font-mono text-2xs uppercase tracking-caps px-1.5 rounded border shrink-0
            ${rule.status === 'published'
              ? 'text-accent-blue border-accent-blue/30 bg-accent-blue/[0.08]'
              : 'text-content-dim border-border'}`}
        >
          {rule.status}
        </span>
      </div>

      <div className="text-[0.85rem] font-semibold text-content-primary leading-snug mb-2">
        {rule.title}
      </div>

      {pct === null ? (
        <div className="font-mono text-2xs text-content-muted">never validated</div>
      ) : (
        <div className="flex items-center gap-2">
          <div className="flex-1 h-1 rounded-pill bg-surface-elevated overflow-hidden">
            <span className={`block h-full ${tone}`} style={{ width: `${pct}%` }} />
          </div>
          <span className="font-mono text-2xs text-content-secondary">{pct}</span>
        </div>
      )}
    </Link>
  )
}
