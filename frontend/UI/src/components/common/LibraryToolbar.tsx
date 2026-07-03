import type { ReactNode } from 'react'
import { platformRegistry, platformShortLabel } from '@/data'
import type { PlatformId, Severity } from '@/types'
import { SearchInput } from '@/components/ui/SearchInput'
import { FilterDropdown, type DropdownOption } from '@/components/ui/FilterDropdown'
import { PlatformIcon } from '@/components/ui/PlatformIcons'
import type { LibraryToolbarState, LibraryType } from './useLibraryFilter'

/** Platform options — "All" plus every registered platform with its icon. */
const PLATFORM_OPTIONS: DropdownOption<'all' | PlatformId>[] = [
  { value: 'all', label: 'All platforms' },
  ...platformRegistry.map((p) => ({
    value: p.id,
    label: platformShortLabel(p.id),
    icon: <PlatformIcon platformId={p.id} size={14} />,
  })),
]

const SEVERITY_OPTIONS: DropdownOption<'all' | Severity>[] = [
  { value: 'all', label: 'All severities' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
]

const TYPE_OPTIONS: DropdownOption<LibraryType>[] = [
  { value: 'all', label: 'All types' },
  { value: 'composite', label: 'APT Emulation' },
  { value: 'atomic', label: 'Atomic Technique' },
]

interface LibraryToolbarProps extends LibraryToolbarState {
  searchPlaceholder?: string
  /** Show the Atomic/Composite type filter (Emulations hub only). */
  showType?: boolean
  /** Extra controls appended to the toolbar row (e.g. a hub-specific toggle). */
  extra?: ReactNode
}

/**
 * Search + Platform + Severity toolbar shared by the content-library hubs.
 * Mirrors the Operations (Results) toolbar: a search box followed by
 * constant-width filter dropdowns. The Type filter is opt-in (Emulations only).
 */
export function LibraryToolbar({
  search, onSearch, platform, onPlatform, severity, onSeverity,
  type, onType, searchPlaceholder, showType = false, extra,
}: LibraryToolbarProps) {
  return (
    <div className="flex flex-wrap items-center gap-3 mb-5">
      <SearchInput value={search} onChange={onSearch} placeholder={searchPlaceholder} />
      <FilterDropdown label="Platform" value={platform} options={PLATFORM_OPTIONS} onChange={onPlatform} />
      <FilterDropdown label="Severity" value={severity} options={SEVERITY_OPTIONS} onChange={onSeverity} />
      {showType && (
        <FilterDropdown label="Type" value={type} options={TYPE_OPTIONS} onChange={onType} />
      )}
      {extra}
    </div>
  )
}
