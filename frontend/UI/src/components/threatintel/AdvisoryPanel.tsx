import { useMemo, useState } from 'react'
import { useAdvisories } from '@/hooks/useThreatIntel'
import type { Advisory } from '@/types'
import { LibraryCard } from '@/components/common/LibraryCard'
import { SearchInput } from '@/components/ui/SearchInput'
import { FilterDropdown, type DropdownOption } from '@/components/ui/FilterDropdown'
import { ComingSoon } from '@/components/common/ComingSoon'
import { IconWarning, IconClipboard } from '@/components/ui/Icons'

/**
 * The Advisory panel — the APT dossier library.
 *
 * Laid out as a discovery library like Playbooks and Detections, reusing
 * LibraryCard so a dossier card sits at the same visual weight as an emulation
 * card. Each card links into its own dossier page rather than expanding here.
 *
 * Dossiers carry no severity, so the card's severity slot stays empty rather
 * than being filled with a number derived from technique or CVE counts — the
 * card would present that as an assessment, and it would not be one. The band
 * carries the catalogue reference instead.
 *
 * Origin and motivation are the filter axes because they are the two fields
 * every dossier populates; the emulation-shaped LibraryToolbar (platform,
 * severity, atomic/composite) has nothing to say about a threat actor.
 */
export function AdvisoryPanel() {
  const { data: library, loading } = useAdvisories()
  const [search, setSearch] = useState('')
  const [origin, setOrigin] = useState('all')
  const [motivation, setMotivation] = useState('all')

  const advisories = library?.advisories ?? []

  // Both axes are built from the data rather than a fixed list: the dossier set
  // grows, and a hardcoded country list would silently drop a new actor's
  // origin from the filter while still showing its card.
  const originOptions = useMemo(
    () => toOptions('All origins', advisories.map((a) => a.origin)),
    [advisories],
  )
  const motivationOptions = useMemo(
    () => toOptions('All motivations', advisories.flatMap((a) => a.motivations)),
    [advisories],
  )

  const filtered = useMemo(() => {
    let list = advisories
    if (origin !== 'all') list = list.filter((a) => a.origin === origin)
    if (motivation !== 'all') list = list.filter((a) => a.motivations.includes(motivation))

    const q = search.trim().toLowerCase()
    if (q) list = list.filter((a) => matches(a, q))
    return list
  }, [advisories, search, origin, motivation])

  if (loading && !library) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading advisories...</div>
  }

  // No dossiers published yet: either the sync has not run or the bucket is
  // unset. Both are the same thing to a reader, so say the honest version.
  if (advisories.length === 0) {
    return (
      <ComingSoon
        icon={<IconWarning size={32} />}
        title="No advisories yet"
        body="APT threat-actor dossiers appear here once the advisory library has been published — each one covering an actor's TTPs, targeted sectors, known exploited CVEs and tooling."
      />
    )
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3 mb-5">
        <SearchInput value={search} onChange={setSearch} placeholder="Search advisories..." />
        <FilterDropdown label="Origin" value={origin} options={originOptions} onChange={setOrigin} />
        <FilterDropdown
          label="Motivation"
          value={motivation}
          options={motivationOptions}
          onChange={setMotivation}
        />
        <span className="font-mono text-[11px] text-content-dim ml-auto">
          {filtered.length} of {advisories.length}
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-12 text-content-dim font-mono text-sm">
          No advisories match that filter.
        </div>
      ) : (
        <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
          {filtered.map((advisory) => (
            <LibraryCard
              key={advisory.id}
              name={advisory.name}
              eyebrow={eyebrowFor(advisory)}
              badge={badgeFor(advisory)}
              description={advisory.summary || undefined}
              tactics={advisory.tactics}
              actions={[
                {
                  label: 'View Advisory',
                  icon: <IconClipboard size={14} />,
                  to: `/threat-intel/advisory/${advisory.id}`,
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
 * Build a dropdown option list from the values present in the library.
 *
 * @param allLabel - Label for the leading "no filter" option.
 * @param values - Every occurrence of the field; blanks and duplicates are
 *   dropped, and the rest sorted so the list reads predictably.
 */
function toOptions(allLabel: string, values: string[]): DropdownOption<string>[] {
  const unique = [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b))
  return [{ value: 'all', label: allLabel }, ...unique.map((v) => ({ value: v, label: v }))]
}

/**
 * Test one advisory against a lowercased search term.
 *
 * Aliases and the catalogue reference are searched alongside the name, so a
 * dossier titled "menuPass" is still found by "apt10" — and one titled "APT38"
 * by "lazarus".
 */
function matches(advisory: Advisory, q: string): boolean {
  return (
    advisory.name.toLowerCase().includes(q) ||
    advisory.reference.toLowerCase().includes(q) ||
    advisory.id.includes(q) ||
    advisory.groupId.toLowerCase().includes(q) ||
    advisory.summary.toLowerCase().includes(q) ||
    advisory.aliases.some((alias) => alias.toLowerCase().includes(q)) ||
    advisory.tactics.some((tactic) => tactic.toLowerCase().includes(q))
  )
}

/** Card eyebrow: what the document is, plus the actor's origin when known. */
function eyebrowFor(advisory: Advisory): string {
  return advisory.origin ? `APT Dossier · ${advisory.origin}` : 'APT Dossier'
}

/**
 * Band label: the catalogue reference, shown only when it tells the reader
 * something the name does not.
 *
 * Suppressed when either name contains the other, which covers both the exact
 * case ("APT29" / "APT29") and the near case ("Sandworm Team" / "SANDWORM").
 * What survives is the handful of dossiers filed under a genuinely different
 * name — "menuPass" under APT10, "Indrik Spider" under APT40.
 */
function badgeFor(advisory: Advisory): string | undefined {
  const normalise = (v: string) => v.toLowerCase().replace(/[^a-z0-9]/g, '')
  const reference = normalise(advisory.reference)
  const name = normalise(advisory.name)
  return reference.includes(name) || name.includes(reference) ? undefined : advisory.reference
}
