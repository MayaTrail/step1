import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useEmulations, useLibraryPlaybooks } from '@/hooks/usePlatformData'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryToolbar } from '@/components/common/LibraryToolbar'
import { SearchInput } from '@/components/ui/SearchInput'
import { useLibraryFilter, emulationTactics } from '@/components/common/useLibraryFilter'
import { LibraryEmpty } from '@/components/emulations/EmulationsHub'
import { IconClipboard, IconSearch } from '@/components/ui/Icons'
import { PlaybookGuide } from './PlaybookGuide'
import { listPlaybooks } from '@/services/playbook.service'
import type { Severity, UserPlaybookListItem } from '@/types'

/**
 * The two kinds of IR playbook MayaTrail carries.
 *
 * They are indexed differently and that difference is the reason for the split:
 * an emulation playbook answers "we ran this attack, how do I respond", while a
 * reference playbook answers "this alert fired, how do I respond" regardless of
 * whether MayaTrail can simulate the attack behind it. Merging them into one
 * list would imply every entry is runnable, which most are not.
 */
type Tab = 'emulation' | 'reference'

/** Library severities are title case; LibraryCard expects the upper-case union. */
function toSeverity(value: string): Severity | undefined {
  const upper = (value ?? '').toUpperCase()
  if (upper === 'CRITICAL' || upper === 'HIGH' || upper === 'MEDIUM') return upper as Severity
  if (upper === 'INFORMATIONAL' || upper === 'LOW') return 'LOW'
  return undefined
}

/**
 * Strip the "IR Playbook: " prefix every library title carries, so the card
 * reads as a name rather than repeating the section it already sits under.
 */
function shortTitle(title: string): string {
  return title.replace(/^IR Playbook:\s*/i, '')
}

/**
 * Playbooks content hub.
 *
 * Two tabs. "From emulations" lists emulations, each of which ships a
 * PLAYBOOK.md, and links into the existing scoped playbook page. "Reference
 * library" lists the standalone playbooks under playbooks/, which are
 * documentation for SOC teams and carry no runnable attack.
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
  const [tab, setTab] = useState<Tab>('emulation')

  const { data: emulations, loading } = useEmulations('aws')
  const { filtered, toolbar } = useLibraryFilter(emulations ?? [])

  const { data: library, loading: libLoading } = useLibraryPlaybooks()
  const [libSearch, setLibSearch] = useState('')

  const libFiltered = useMemo(() => {
    const term = libSearch.trim().toLowerCase()
    if (!term) return library ?? []
    return (library ?? []).filter((p) =>
      `${p.id} ${p.title} ${p.service} ${p.tactic} ${p.techniques.join(' ')}`
        .toLowerCase()
        .includes(term),
    )
  }, [library, libSearch])

  const emulationCount = emulations?.length ?? 0
  const libraryCount = library?.length ?? 0

  // The user's own playbooks. Loaded separately from the two shipped
  // shelves above: those are catalogue content, these are the user's work,
  // and a failure to load one must not blank the other.
  const [mine, setMine] = useState<UserPlaybookListItem[]>([])
  const [showGuide, setShowGuide] = useState(true)
  useEffect(() => {
    let live = true
    listPlaybooks()
      .then((rows) => live && setMine(rows))
      .catch(() => live && setMine([]))
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
          Playbooks
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          Incident-response and remediation guidance
        </div>
      </div>

      <div className="flex gap-2 mb-5" role="tablist" aria-label="Playbook source">
        {([
          ['emulation', 'From emulations', emulationCount],
          ['reference', 'Reference library', libraryCount],
        ] as const).map(([id, label, count]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={
              tab === id
                ? 'rounded-md border border-transparent bg-white/[0.815] px-4 py-2 text-[13px] font-semibold tracking-[0.3px] text-[#18191a] transition-opacity'
                : 'rounded-md border border-white/10 px-4 py-2 text-[13px] font-semibold tracking-[0.3px] text-content-secondary transition-opacity hover:opacity-60'
            }
          >
            {label}
            <span className="ml-2 font-mono text-[11px] opacity-70">{count}</span>
          </button>
        ))}
      </div>

      {tab === 'emulation' ? (
        <>
          <LibraryToolbar {...toolbar} searchPlaceholder="Search playbooks..." />
          {loading ? (
            <div className="py-16 text-center font-mono text-sm text-content-dim">
              Loading playbooks...
            </div>
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
        </>
      ) : (
        <>
          <div className="mb-4 rounded-[10px] border border-border bg-surface-card px-4 py-3 text-[13px] leading-[1.6] text-content-secondary">
            Response procedures for AWS detection use cases, written for SOC analysts and detection
            engineers. These are documentation: they are not tied to a runnable emulation, and the
            detection rules they reference have not been proven to fire.
          </div>

          <div className="flex flex-wrap items-center gap-3 mb-5">
            <SearchInput
              value={libSearch}
              onChange={setLibSearch}
              placeholder="Search the reference library..."
            />
          </div>

          {libLoading ? (
            <div className="py-16 text-center font-mono text-sm text-content-dim">
              Loading reference library...
            </div>
          ) : libFiltered.length === 0 ? (
            <LibraryEmpty noun="playbooks" />
          ) : (
            <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
              {libFiltered.map((p) => (
                <LibraryCard
                  key={p.id}
                  name={shortTitle(p.title)}
                  eyebrow={`Reference · ${p.service.toUpperCase()}`}
                  severity={toSeverity(p.severity)}
                  description={p.incidentType}
                  tactics={p.techniques}
                  actions={[
                    {
                      label: 'View Playbook',
                      icon: <IconSearch size={14} />,
                      to: `/playbooks/library/${p.id}`,
                      variant: 'secondary',
                    },
                  ]}
                />
              ))}
            </div>
          )}
        </>
      )}

      {/* The user's own playbooks. A third shelf rather than a third tab: the
          tabs above split the shipped catalogue by how it is indexed, while
          this is the user's own work and is always worth showing. */}
      <div className="mt-10 pt-8 border-t border-border-subtle">
        <div className="flex items-center justify-between gap-4 mb-4">
          <h2 className="font-display text-lg font-semibold text-content-primary">
            Your playbooks
          </h2>
          <Link
            to="/playbooks/new"
            className="font-mono text-2xs uppercase tracking-label px-3 py-1.5 rounded-btn border border-border-active text-content-primary hover:border-accent-blue transition-colors no-underline"
          >
            New playbook
          </Link>
        </div>
        {mine.length === 0 ? (
          showGuide && <PlaybookGuide onClose={() => setShowGuide(false)} />
        ) : (
          <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
            {mine.map((pb) => (
              <MyPlaybookCard key={pb.id} pb={pb} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
