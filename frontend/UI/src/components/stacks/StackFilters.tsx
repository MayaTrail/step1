/**
 * StackFilters — search + filter controls for the Stacks page.
 *
 * All filtering is client-side: a single user's stack list is small, and the
 * list endpoint is already owner-scoped, so there is no value in round-tripping
 * filter state to the backend for Milestone 1.
 *
 * Filters provided (per PRD Feature 4):
 *   - Search   — by stack name (resource-name search lands in Phase 2, once a
 *                per-stack resource inventory is persisted)
 *   - Status   — by derived health label (Active / Deploying / Failed / …)
 *   - Region   — populated from the regions actually present in the list
 *   - Created  — Today / Last 7 Days / Last 30 Days
 *
 * The "Owner" filter from the wireframe is intentionally omitted: the API only
 * ever returns the current user's stacks, so an owner filter would be a no-op.
 */

import type { Stack } from '@/types'
import { deriveHealth, STACK_HEALTH, type StackHealth } from '@/components/dashboard/stackHelpers'

/* ── Filter state ── */

export type CreatedWindow = 'all' | 'today' | '7d' | '30d'

export interface StackFilterState {
    search: string
    health: StackHealth | 'all'
    region: string | 'all'
    created: CreatedWindow
}

export const EMPTY_FILTERS: StackFilterState = {
    search: '',
    health: 'all',
    region: 'all',
    created: 'all',
}

/** True when no filter is narrowing the list. */
export function filtersAreEmpty(f: StackFilterState): boolean {
    return f.search.trim() === '' && f.health === 'all' && f.region === 'all' && f.created === 'all'
}

/* ── Filtering logic ── */

const DAY_MS = 24 * 60 * 60 * 1000

function withinCreatedWindow(createdAt: string, window: CreatedWindow): boolean {
    if (window === 'all') return true
    const age = Date.now() - new Date(createdAt).getTime()
    if (window === 'today') return age <= DAY_MS
    if (window === '7d') return age <= 7 * DAY_MS
    return age <= 30 * DAY_MS
}

/** Apply the active filters to a stack list. Pure — returns a new array. */
export function filterStacks(stacks: Stack[], f: StackFilterState): Stack[] {
    const q = f.search.trim().toLowerCase()
    return stacks.filter((s) => {
        if (q) {
            // Match the stack name OR any deployed resource name (from the
            // actual inventory persisted on the stack).
            const matchesName = s.name.toLowerCase().includes(q)
            const matchesResource = s.resource_summary?.resources?.some(
                (r) => r.name.toLowerCase().includes(q),
            )
            if (!matchesName && !matchesResource) return false
        }
        if (f.health !== 'all' && deriveHealth(s) !== f.health) return false
        if (f.region !== 'all' && s.region !== f.region) return false
        if (!withinCreatedWindow(s.created_at, f.created)) return false
        return true
    })
}

/* ── Component ── */

interface StackFiltersProps {
    value: StackFilterState
    onChange: (next: StackFilterState) => void
    /** Full unfiltered list — used to populate the Region dropdown. */
    stacks: Stack[]
    /** Count after filtering, for the result summary. */
    resultCount: number
}

const HEALTH_OPTIONS: Array<{ value: StackHealth; label: string }> = (
    Object.keys(STACK_HEALTH) as StackHealth[]
).map((h) => ({ value: h, label: STACK_HEALTH[h].label }))

const CREATED_OPTIONS: Array<{ value: CreatedWindow; label: string }> = [
    { value: 'all', label: 'Any time' },
    { value: 'today', label: 'Today' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
]

export function StackFilters({ value, onChange, stacks, resultCount }: StackFiltersProps) {
    const regions = Array.from(new Set(stacks.map((s) => s.region))).sort()
    const dirty = !filtersAreEmpty(value)

    return (
        <div className="bg-surface-card border border-border rounded-card p-4 mb-6">
            {/* Search */}
            <div className="relative mb-3">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-content-dim pointer-events-none">
                    <SearchIcon />
                </span>
                <input
                    type="text"
                    value={value.search}
                    onChange={(e) => onChange({ ...value, search: e.target.value })}
                    placeholder="Search stacks or resources…"
                    className="w-full font-body text-[0.9rem] text-content-primary bg-surface-base border border-border rounded-btn
                        pl-9 pr-3 py-2.5 tracking-body placeholder:text-content-dim
                        focus:outline-none focus:border-accent-blue focus:shadow-[0_0_0_3px_var(--accent-blue-glow,hsla(202,100%,67%,0.15))] transition-all"
                />
            </div>

            {/* Filter row */}
            <div className="flex flex-wrap items-center gap-3">
                <FilterSelect
                    label="Status"
                    value={value.health}
                    onChange={(v) => onChange({ ...value, health: v as StackHealth | 'all' })}
                    options={[{ value: 'all', label: 'All statuses' }, ...HEALTH_OPTIONS]}
                />
                <FilterSelect
                    label="Region"
                    value={value.region}
                    onChange={(v) => onChange({ ...value, region: v })}
                    options={[{ value: 'all', label: 'All regions' }, ...regions.map((r) => ({ value: r, label: r }))]}
                />
                <FilterSelect
                    label="Created"
                    value={value.created}
                    onChange={(v) => onChange({ ...value, created: v as CreatedWindow })}
                    options={CREATED_OPTIONS}
                />

                <div className="flex-1" />

                <span className="font-mono text-[11px] text-content-dim">
                    {resultCount} result{resultCount !== 1 ? 's' : ''}
                </span>
                {dirty && (
                    <button
                        onClick={() => onChange(EMPTY_FILTERS)}
                        className="font-mono text-[11px] text-accent-blue bg-transparent border-none cursor-pointer
                            transition-opacity hover:opacity-60"
                    >
                        Clear filters
                    </button>
                )}
            </div>
        </div>
    )
}

/* ── Sub-components ── */

function FilterSelect({
    label,
    value,
    onChange,
    options,
}: {
    label: string
    value: string
    onChange: (v: string) => void
    options: Array<{ value: string; label: string }>
}) {
    return (
        <label className="flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-[1px] text-content-dim">{label}</span>
            <select
                value={value}
                onChange={(e) => onChange(e.target.value)}
                className="font-mono text-[11px] text-content-primary bg-surface-base border border-border rounded-btn
                    pl-2.5 pr-7 py-1.5 cursor-pointer appearance-none
                    focus:outline-none focus:border-accent-blue transition-colors
                    bg-[url('data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%2210%22 height=%2210%22 viewBox=%220 0 10 10%22><path d=%22M2 3.5L5 6.5L8 3.5%22 stroke=%22%236a6b6c%22 stroke-width=%221.2%22 fill=%22none%22/></svg>')] bg-no-repeat bg-[right_0.5rem_center]"
            >
                {options.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                ))}
            </select>
        </label>
    )
}

function SearchIcon() {
    return (
        <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <circle cx="7" cy="7" r="4.5" stroke="currentColor" strokeWidth="1.4" />
            <path d="M10.5 10.5L14 14" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        </svg>
    )
}
