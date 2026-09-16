import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { useEmulations } from '@/hooks/usePlatformData'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryToolbar } from '@/components/common/LibraryToolbar'
import { useLibraryFilter, emulationTactics } from '@/components/common/useLibraryFilter'
import { LibraryEmpty } from '@/components/emulations/EmulationsHub'
import { IconClipboard } from '@/components/ui/Icons'
import { PlaybookGuide } from './PlaybookGuide'
import { listPlaybooks } from '@/services/playbook.service'
import type { UserPlaybookListItem } from '@/types'

/**
 * Playbooks content hub — incident-response discovery library.
 *
 * Two shelves. The shipped playbooks come from the emulation packages and are
 * read-only; each card can be forked into an editable copy. Below them sit the
 * playbooks this user has authored, from scratch or by forking.
 */

/** A user-authored playbook, as a card. */
function MyPlaybookCard({ pb }: { pb: UserPlaybookListItem }) {
  return (
    <Link
      to={`/playbooks/${pb.id}`}
      className="block border border-border-subtle rounded-card bg-surface-card p-4 hover:border-border-active transition-colors"
    >
      <div className="flex items-center gap-2 mb-2">
        <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
          {pb.is_fork ? `Fork · ${pb.source_emulation}` : 'Authored'}
        </span>
        {pb.is_example && (
          <span
            title="A starter example. Edit it or delete it - nothing depends on it."
            className="font-mono text-[0.6rem] uppercase tracking-[1px] px-1.5 py-0.5 rounded-btn border border-border-active text-content-dim"
          >
            example
          </span>
        )}
        <span
          className={[
            'font-mono text-[0.6rem] uppercase tracking-[1px] px-1.5 py-0.5 rounded-btn',
            pb.status === 'published'
              ? 'bg-accent-blue/15 text-accent-blue'
              : 'bg-surface-elevated text-content-dim',
          ].join(' ')}
        >
          {pb.status}
        </span>
        {pb.visibility === 'organization' && (
          <span className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim">
            shared
          </span>
        )}
      </div>
      <div className="text-[1rem] font-medium text-content-primary leading-snug">
        {pb.title}
      </div>
      {pb.summary && (
        <div className="text-[0.85rem] text-content-secondary mt-1.5 line-clamp-2">
          {pb.summary}
        </div>
      )}
      <div className="font-mono text-[0.65rem] text-content-dim mt-3">
        edited {new Date(pb.updated_at).toLocaleDateString()} · {pb.owner_username}
      </div>
    </Link>
  )
}

export function PlaybooksHub() {
  const { data: emulations, loading } = useEmulations('aws')
  const { filtered, toolbar } = useLibraryFilter(emulations ?? [])

  const [mine, setMine] = useState<UserPlaybookListItem[] | null>(null)
  const [mineError, setMineError] = useState(false)
  const [showGuide, setShowGuide] = useState(false)

  useEffect(() => {
    let cancelled = false
    listPlaybooks()
      .then((rows) => {
        if (!cancelled) setMine(rows)
      })
      .catch(() => {
        // The shipped shelf is still useful if this call fails, so degrade
        // rather than failing the whole page.
        if (!cancelled) setMineError(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
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
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowGuide(true)}
            className="border border-border-subtle text-content-secondary hover:text-content-primary rounded-btn px-3 py-2 text-[0.85rem] transition-colors"
          >
            Guide
          </button>
          <Link
            to="/playbooks/new"
            className="bg-accent-blue text-button-fg rounded-btn px-4 py-2 text-[0.85rem] font-medium"
          >
            New playbook
          </Link>
        </div>
      </div>

      {/* ── Authored by this user ─────────────────────────────────────── */}
      {mine !== null && mine.length > 0 && (
        <section className="mb-10">
          <h2 className="font-mono text-[0.7rem] uppercase tracking-[2px] text-content-dim mb-3">
            Your playbooks
          </h2>
          <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
            {mine.map((pb) => (
              <MyPlaybookCard key={pb.id} pb={pb} />
            ))}
          </div>
        </section>
      )}

      {mineError && (
        <div className="mb-8 font-mono text-[0.75rem] text-content-dim">
          Your own playbooks could not be loaded. The shipped library is below.
        </div>
      )}

      {/* ── Shipped with the emulation packages ───────────────────────── */}
      <h2 className="font-mono text-[0.7rem] uppercase tracking-[2px] text-content-dim mb-3">
        Shipped playbooks
      </h2>

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
                {
                  label: 'Fork & edit',
                  to: `/playbooks/new?fork=${encodeURIComponent(em.id)}`,
                  variant: 'secondary',
                },
              ]}
            />
          ))}
        </div>
      )}

      {showGuide && <PlaybookGuide onClose={() => setShowGuide(false)} />}
    </div>
  )
}
