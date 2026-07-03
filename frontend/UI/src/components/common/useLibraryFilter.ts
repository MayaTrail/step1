import { useState, useMemo } from 'react'
import type { Emulation, PlatformId, Severity } from '@/types'

/**
 * Unique MITRE tactics an emulation exercises, in first-seen order.
 * Drives the tactic chips on the Option-C library card.
 */
export function emulationTactics(em: Emulation): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const m of em.mitreMappings ?? []) {
    if (m.tactic && !seen.has(m.tactic)) {
      seen.add(m.tactic)
      out.push(m.tactic)
    }
  }
  return out
}

/** Emulation kind: atomic single-technique vs composite APT emulation. */
export type LibraryType = 'all' | 'atomic' | 'composite'

/** True when an emulation is an atomic single-technique (vs a composite APT). */
function isAtomic(em: Emulation): boolean {
  return (em.originLabel ?? '').toUpperCase().includes('ATOMIC')
}

export interface LibraryToolbarState {
  search: string
  onSearch: (v: string) => void
  platform: 'all' | PlatformId
  onPlatform: (v: 'all' | PlatformId) => void
  severity: 'all' | Severity
  onSeverity: (v: 'all' | Severity) => void
  type: LibraryType
  onType: (v: LibraryType) => void
}

/**
 * Shared search + platform + severity filtering for the content-library hubs
 * (Emulations, Detections, Playbooks). All three filter the same emulation
 * catalogue, so the logic lives here once and each hub wires the returned
 * toolbar state into <LibraryToolbar/>.
 */
export function useLibraryFilter(emulations: Emulation[]) {
  const [search, setSearch] = useState('')
  const [platform, setPlatform] = useState<'all' | PlatformId>('all')
  const [severity, setSeverity] = useState<'all' | Severity>('all')
  const [type, setType] = useState<LibraryType>('all')

  const filtered = useMemo(() => {
    let list = emulations
    if (platform !== 'all') list = list.filter((e) => e.platform === platform)
    if (severity !== 'all') list = list.filter((e) => e.severity === severity)
    if (type !== 'all') {
      list = list.filter((e) => (type === 'atomic' ? isAtomic(e) : !isAtomic(e)))
    }
    const q = search.trim().toLowerCase()
    if (q) {
      list = list.filter(
        (e) =>
          e.name.toLowerCase().includes(q) ||
          (e.description ?? '').toLowerCase().includes(q),
      )
    }
    return list
  }, [emulations, search, platform, severity, type])

  const toolbar: LibraryToolbarState = {
    search, onSearch: setSearch,
    platform, onPlatform: setPlatform,
    severity, onSeverity: setSeverity,
    type, onType: setType,
  }

  return { filtered, toolbar }
}
