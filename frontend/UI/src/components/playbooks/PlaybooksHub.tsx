import { useMemo, useState } from 'react'
import { useEmulations, useLibraryPlaybooks } from '@/hooks/usePlatformData'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryToolbar } from '@/components/common/LibraryToolbar'
import { useLibraryFilter, emulationTactics } from '@/components/common/useLibraryFilter'
import { LibraryEmpty } from '@/components/emulations/EmulationsHub'
import { IconClipboard, IconSearch } from '@/components/ui/Icons'
import type { Severity } from '@/types'

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
          <div className="mb-4 rounded-[10px] border border-white/[0.06] bg-surface-100 px-4 py-3 text-[13px] leading-[1.6] text-content-secondary">
            Response procedures for AWS detection use cases, written for SOC analysts and detection
            engineers. These are documentation: they are not tied to a runnable emulation, and the
            detection rules they reference have not been proven to fire.
          </div>

          <input
            type="search"
            value={libSearch}
            onChange={(e) => setLibSearch(e.target.value)}
            placeholder="Search the reference library..."
            aria-label="Search reference playbooks"
            className="mb-5 w-full rounded-lg border border-white/[0.08] bg-bg-deep px-3.5 py-2.5 text-[15px] font-medium tracking-[0.2px] text-content-primary placeholder:text-content-dim focus:border-accent-blue/50 focus:outline-none"
          />

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
    </div>
  )
}
