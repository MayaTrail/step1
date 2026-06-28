import { useMemo, useState } from 'react'
import { Card } from '@/components/ui/Card'
import { IconLaunch, IconLayers } from '@/components/ui/Icons'
import {
    getMitreCoverage,
    getNavigatorLayer,
    getTacticDetail,
} from '@/services/metrics.service'
import { useCachedResource } from '@/hooks/useCachedResource'
import type {
    CoverageDistribution,
    CoverageFilterOptions,
    CoverageFilters,
    FilterOption,
    TacticHighlight,
} from '@/types/metrics'
import { CoverageGauge } from './CoverageGauge'
import { TacticCard } from './TacticCard'
import { TacticDrillDown } from './TacticDrillDown'
import { InsightsPanel } from './InsightsPanel'
import { STATUS_TEXT, statusOf } from './status'

/**
 * MITRE ATT&CK Coverage — redesigned (Option C, hybrid).
 *
 * Replaces the unreadable tactic-column / tiny-cell matrix with an executive
 * summary band (gauge + stats + distribution), a scannable grid of status-
 * colored tactic cards, a click-to-drill-down panel, filters, and actionable
 * insights.  Coverage re-scopes live by platform / threat actor / emulation.
 */

const NAVIGATOR_URL = 'https://mitre-attack.github.io/attack-navigator/'

type SortMode = 'gaps' | 'matrix'

/** Fetch the Navigator layer, download it, then open the Navigator. */
async function exportNavigatorLayer(): Promise<void> {
    const layer = await getNavigatorLayer()
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'mayatrail-attack-navigator.json'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
    window.open(NAVIGATOR_URL, '_blank', 'noopener')
}

function FilterSelect({
    placeholder,
    value,
    options,
    onChange,
    disabled = false,
}: {
    placeholder: string
    value: string
    options: FilterOption[]
    onChange: (value: string) => void
    disabled?: boolean
}) {
    return (
        <select
            value={value}
            onChange={(e) => onChange(e.target.value)}
            disabled={disabled}
            className="bg-surface-elevated border border-border rounded-btn text-xs text-content-secondary px-2.5 py-1 outline-none focus:border-border-active disabled:opacity-40"
        >
            <option value="">{placeholder}</option>
            {options.map((o) => (
                <option key={o.id} value={o.id}>
                    {o.label}
                </option>
            ))}
        </select>
    )
}

function HighlightStat({ label, highlight }: { label: string; highlight: TacticHighlight | null }) {
    return (
        <div className="flex flex-col min-w-0">
            <span
                className={`font-display text-base font-bold leading-tight truncate ${
                    highlight ? STATUS_TEXT[statusOf(highlight.pct)] : 'text-content-muted'
                }`}
            >
                {highlight ? highlight.name : '—'}
            </span>
            <span className="font-mono text-2xs uppercase tracking-label text-content-muted mt-1">
                {label}
                {highlight ? ` · ${highlight.pct}%` : ''}
            </span>
        </div>
    )
}

function DistributionBar({ dist, total }: { dist: CoverageDistribution; total: number }) {
    const segments = [
        { key: 'covered', n: dist.covered, cls: 'bg-safe' },
        { key: 'partial', n: dist.partial, cls: 'bg-warning' },
        { key: 'none', n: dist.none, cls: 'bg-danger' },
    ]
    return (
        <div className="flex flex-col gap-2">
            <div className="flex h-2 w-full rounded-full overflow-hidden bg-surface-elevated">
                {segments.map((s) =>
                    s.n > 0 ? (
                        <span key={s.key} className={s.cls} style={{ width: `${(100 * s.n) / total}%` }} />
                    ) : null,
                )}
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                {segments.map((s) => (
                    <span key={s.key} className="flex items-center gap-1.5 font-mono text-2xs text-content-muted">
                        <span className={`w-2 h-2 rounded-sm ${s.cls}`} />
                        {s.n} {s.key === 'none' ? 'uncovered' : s.key}
                    </span>
                ))}
            </div>
        </div>
    )
}

const EMPTY_FILTERS: CoverageFilterOptions = { platforms: [], actors: [], emulations: [], tactics: [] }

export function MitreCoverageSection() {
    const [filters, setFilters] = useState<CoverageFilters>({})
    // Stale-while-revalidate: keeps the current coverage on screen during a
    // filter-driven refetch (no blank/flicker) and seeds from cache across
    // navigation. Root-cause fix for the dashboard flicker.
    const { data, loading, failed } = useCachedResource(
        `mitre-coverage:${JSON.stringify(filters)}`,
        () => getMitreCoverage(filters),
    )

    const [selected, setSelected] = useState<string | null>(null)
    const [sortMode, setSortMode] = useState<SortMode>('gaps')
    const [exporting, setExporting] = useState(false)

    // Drill-down: same stale-while-revalidate — switching tactic cards keeps the
    // current detail on screen until the new one loads (no flicker below). A null
    // key (nothing selected) skips the fetch.
    const { data: detailData, loading: detailLoading } = useCachedResource(
        selected ? `tactic:${selected}:${JSON.stringify(filters)}` : null,
        () => getTacticDetail(selected as string, filters),
    )
    const detail = detailData ?? null

    const sortedTactics = useMemo(() => {
        if (!data) return []
        const tactics = [...data.tactics]
        if (sortMode === 'gaps') {
            tactics.sort(
                (a, b) =>
                    a.pct - b.pct ||
                    b.techniqueCount - b.coveredCount - (a.techniqueCount - a.coveredCount),
            )
        }
        return tactics
    }, [data, sortMode])

    function patchFilters(patch: Partial<CoverageFilters>) {
        setFilters((prev) => ({ ...prev, ...patch }))
    }

    async function handleExport() {
        setExporting(true)
        try {
            await exportNavigatorLayer()
        } finally {
            setExporting(false)
        }
    }

    const options = data?.filters ?? EMPTY_FILTERS
    const summary = data?.summary

    return (
        <Card className="flex flex-col">
            {/* Header */}
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-border">
                <span className="flex items-center gap-2 font-mono text-2xs uppercase tracking-label text-content-dim">
                    <IconLayers size={14} />
                    MITRE ATT&amp;CK Coverage
                </span>
                <div className="flex items-center gap-2">
                    {summary && (
                        <span className="font-mono text-2xs text-content-muted">ATT&amp;CK v{summary.attackVersion}</span>
                    )}
                    <button
                        type="button"
                        onClick={handleExport}
                        disabled={exporting || loading || failed}
                        title="Export a MITRE ATT&CK Navigator layer of this coverage"
                        className="inline-flex items-center gap-1.5 rounded-btn border border-border px-2.5 py-1 font-mono text-2xs uppercase tracking-label text-content-secondary transition-opacity hover:opacity-70 disabled:opacity-40"
                    >
                        <IconLaunch size={12} />
                        {exporting ? 'Exporting…' : 'Open in Navigator'}
                    </button>
                </div>
            </div>

            {/* Filter bar */}
            <div className="flex flex-wrap items-center gap-2 px-5 py-3 border-b border-border">
                <FilterSelect
                    placeholder="All Platforms"
                    value={filters.platform ?? ''}
                    options={options.platforms}
                    onChange={(v) => patchFilters({ platform: v || undefined })}
                />
                <FilterSelect
                    placeholder="All Threat Actors"
                    value={filters.actor ?? ''}
                    options={options.actors}
                    onChange={(v) => patchFilters({ actor: v || undefined })}
                />
                <FilterSelect
                    placeholder="All Emulations"
                    value={filters.emulation ?? ''}
                    options={options.emulations}
                    onChange={(v) => patchFilters({ emulation: v || undefined })}
                />
                <FilterSelect
                    placeholder="Jump to Tactic"
                    value={selected ?? ''}
                    options={options.tactics}
                    onChange={(v) => setSelected(v || null)}
                />
                <FilterSelect placeholder="Detection (soon)" value="" options={[]} onChange={() => {}} disabled />
                <button
                    type="button"
                    onClick={() => setSortMode((m) => (m === 'gaps' ? 'matrix' : 'gaps'))}
                    className="ml-auto rounded-btn border border-border px-2.5 py-1 font-mono text-2xs uppercase tracking-label text-content-secondary transition-opacity hover:opacity-70"
                >
                    Sort: {sortMode === 'gaps' ? 'Gaps first' : 'Matrix order'}
                </button>
            </div>

            {loading ? (
                <div className="px-5 py-16 text-center text-sm text-content-dim">Loading…</div>
            ) : failed || !summary ? (
                <div className="px-5 py-16 text-center text-sm text-content-dim">
                    Coverage data is unavailable right now.
                </div>
            ) : (
                <>
                    {/* Summary band */}
                    <div className="flex flex-col lg:flex-row gap-6 px-5 py-5 border-b border-border">
                        <CoverageGauge pct={summary.pct} />
                        <div className="flex-1 flex flex-col justify-center gap-5">
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                                <div className="flex flex-col">
                                    <span className="font-display text-base font-bold tabular-nums leading-none text-content-primary">
                                        {summary.coveredTechniques}/{summary.totalTechniques}
                                    </span>
                                    <span className="font-mono text-2xs uppercase tracking-label text-content-muted mt-1">
                                        Techniques Covered
                                    </span>
                                </div>
                                <HighlightStat label="Most Covered" highlight={summary.mostCovered} />
                                <HighlightStat label="Least Covered" highlight={summary.leastCovered} />
                                <div className="flex flex-col">
                                    <span className="font-display text-base font-bold leading-none text-content-muted">
                                        Soon
                                    </span>
                                    <span className="font-mono text-2xs uppercase tracking-label text-content-muted mt-1">
                                        Coverage Trend
                                    </span>
                                </div>
                            </div>
                            <DistributionBar dist={summary.distribution} total={data.tactics.length} />
                        </div>
                    </div>

                    {/* Tactic grid */}
                    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3 px-5 py-5">
                        {sortedTactics.map((tactic) => (
                            <TacticCard
                                key={tactic.id}
                                tactic={tactic}
                                selected={selected === tactic.shortname}
                                onSelect={(s) => setSelected((cur) => (cur === s ? null : s))}
                            />
                        ))}
                    </div>

                    {/* Drill-down */}
                    <div className="border-t border-border">
                        <div className="px-5 pt-4">
                            <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
                                Tactic Drill-down
                            </span>
                        </div>
                        <TacticDrillDown detail={detail} loading={detailLoading} hasSelection={selected !== null} />
                    </div>

                    {/* Insights */}
                    <InsightsPanel insights={data.insights} />
                </>
            )}
        </Card>
    )
}
