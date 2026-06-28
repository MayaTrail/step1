import { useMemo, useState } from 'react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { Card } from '@/components/ui/Card'
import { IconInfo } from '@/components/ui/Icons'
import { PlatformIcon } from '@/components/ui/PlatformIcons'
import { getPlatformCoverage, getThreatCoverage } from '@/services/metrics.service'
import { useCachedResource } from '@/hooks/useCachedResource'
import type { PlatformId } from '@/types'
import type { ContentType, PlatformCoverageRow, ThreatActor } from '@/types/metrics'

/**
 * Platform & Threat Coverage — a single section merging what used to be the
 * Platform Coverage donut and the Threat Coverage bars.
 *
 * A content-type dropdown (Emulations / Playbooks / Detections) drives both:
 *   - Left: a donut of the selected content distributed across platforms.
 *   - Right: per-actor bars showing how much of each actor's techniques the
 *     selected content backs (e.g. Detections = 6/8 of SCARLETEEL's techniques).
 * A footer line summarises the overall picture.
 *
 * Donut/platform colours use the design-system dashboard accent palette
 * (globals.css) as literal hex because Recharts cannot consume Tailwind classes.
 */

interface ContentOption {
    id: ContentType
    label: string
    singular: string
}

/** Lookup keyed by the ContentType union, so access is always defined. */
const CONTENT_META: Record<ContentType, ContentOption> = {
    emulations: { id: 'emulations', label: 'Emulations', singular: 'emulation' },
    playbooks: { id: 'playbooks', label: 'Playbooks', singular: 'playbook' },
    detections: { id: 'detections', label: 'Detections', singular: 'detection' },
}

/** Dropdown order. */
const CONTENT_OPTIONS: ContentOption[] = [
    CONTENT_META.emulations,
    CONTENT_META.playbooks,
    CONTENT_META.detections,
]

/** Display order and per-platform colours (design-system dashboard accents). */
const PLATFORM_ORDER: PlatformId[] = ['aws', 'azure', 'gcp', 'k8s', 'ai']
const PLATFORM_COLORS: Record<PlatformId, string> = {
    aws: '#55b3ff', // blue
    azure: '#a78bfa', // purple
    gcp: '#5fc992', // green
    k8s: '#ffbc33', // yellow
    ai: '#FF6363', // red
}

const TOOLTIP_STYLE = {
    backgroundColor: '#101111',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: 8,
    fontSize: 12,
    color: '#f9f9f9',
} as const

function SectionLabel({ children, hint }: { children: string; hint: string }) {
    return (
        <span className="flex items-center gap-1.5 font-mono text-2xs uppercase tracking-label text-content-dim">
            {children}
            <IconInfo size={12} aria-label={hint} />
        </span>
    )
}

export function PlatformThreatCoverage() {
    const [content, setContent] = useState<ContentType>('detections')

    // Stale-while-revalidate: seeds from cache across navigation (no flash) and
    // never blanks the card on a background refresh. The content dropdown filters
    // already-loaded data client-side, so it never refetches.
    const { data, loading, failed } = useCachedResource(
        'platform-threat-coverage',
        () => Promise.all([getPlatformCoverage(), getThreatCoverage()]),
    )
    const platforms: PlatformCoverageRow[] = data?.[0].platforms ?? []
    const actors: ThreatActor[] = data?.[1].actors ?? []

    const byId = useMemo(
        () => new Map(platforms.map((p) => [p.platform, p])),
        [platforms],
    )

    // Platform segments for the selected content type, in display order.
    const segments = useMemo(
        () =>
            PLATFORM_ORDER.map((id) => {
                const row = byId.get(id)
                return {
                    platform: id,
                    label: row?.label ?? id.toUpperCase(),
                    value: row ? row[content] : 0,
                    color: PLATFORM_COLORS[id],
                }
            }),
        [byId, content],
    )

    const total = segments.reduce((sum, s) => sum + s.value, 0)
    const platformsWithContent = segments.filter((s) => s.value > 0).length

    const sortedActors = useMemo(
        () => [...actors].sort((a, b) => b.coverageByContent[content].pct - a.coverageByContent[content].pct),
        [actors, content],
    )

    // Overall threat coverage for the selected content, aggregated across actors.
    const overallPct = useMemo(() => {
        const covered = actors.reduce((sum, a) => sum + a.coverageByContent[content].covered, 0)
        const techniques = actors.reduce((sum, a) => sum + a.coverageByContent[content].total, 0)
        return techniques > 0 ? Math.round((100 * covered) / techniques) : 0
    }, [actors, content])

    const option = CONTENT_META[content]
    const contentNoun = total === 1 ? option.singular : option.label.toLowerCase()

    return (
        <Card className="flex flex-col">
            {/* Header */}
            <div className="flex flex-wrap items-start justify-between gap-3 px-5 py-4 border-b border-border">
                <div>
                    <h2 className="text-sm font-semibold uppercase tracking-wide text-content-primary">
                        Platform &amp; Threat Coverage
                    </h2>
                    <p className="text-xs text-content-dim mt-1">
                        Overview of content coverage across platforms and the threat landscape.
                    </p>
                </div>
                <select
                    value={content}
                    onChange={(e) => setContent(e.target.value as ContentType)}
                    disabled={loading || failed}
                    className="bg-surface-elevated border border-border rounded-btn text-xs text-content-secondary px-3 py-1.5 outline-none focus:border-border-active disabled:opacity-50"
                >
                    {CONTENT_OPTIONS.map((o) => (
                        <option key={o.id} value={o.id}>
                            {o.label}
                        </option>
                    ))}
                </select>
            </div>

            {loading ? (
                <div className="px-5 py-16 text-center text-sm text-content-dim">Loading…</div>
            ) : failed ? (
                <div className="px-5 py-16 text-center text-sm text-content-dim">
                    Coverage data is unavailable right now.
                </div>
            ) : (
                <>
                    <div className="grid grid-cols-1 lg:grid-cols-2">
                        {/* Left — content coverage by platform */}
                        <div className="flex flex-col gap-5 px-5 py-5">
                            <SectionLabel hint="Distribution of the selected content type across supported platforms.">
                                Content Coverage by Platform
                            </SectionLabel>
                            {total === 0 ? (
                                <div className="py-10 text-center text-sm text-content-dim">
                                    No {option.label.toLowerCase()} yet.
                                </div>
                            ) : (
                                <div className="flex items-center gap-5">
                                    <div className="relative shrink-0" style={{ width: 160, height: 160 }}>
                                        <ResponsiveContainer width="100%" height="100%">
                                            <PieChart>
                                                <Pie
                                                    data={segments.filter((s) => s.value > 0)}
                                                    dataKey="value"
                                                    nameKey="label"
                                                    innerRadius={52}
                                                    outerRadius={78}
                                                    paddingAngle={2}
                                                    stroke="none"
                                                    startAngle={90}
                                                    endAngle={-270}
                                                >
                                                    {segments
                                                        .filter((s) => s.value > 0)
                                                        .map((s) => (
                                                            <Cell key={s.platform} fill={s.color} />
                                                        ))}
                                                </Pie>
                                                <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={{ color: '#f9f9f9' }} />
                                            </PieChart>
                                        </ResponsiveContainer>
                                        <span className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                                            <span className="font-display text-2xl font-bold tabular-nums leading-none text-content-primary">
                                                {total}
                                            </span>
                                            <span className="font-mono text-2xs uppercase tracking-label text-content-muted mt-1 text-center">
                                                Total
                                                <br />
                                                {option.label}
                                            </span>
                                        </span>
                                    </div>

                                    <div className="flex flex-col gap-3 flex-1 min-w-0">
                                        {segments.map((s) => {
                                            const pct = total > 0 ? Math.round((100 * s.value) / total) : 0
                                            return (
                                                <div key={s.platform} className="flex items-center gap-2.5">
                                                    <span className="shrink-0">
                                                        <PlatformIcon platformId={s.platform} size={18} />
                                                    </span>
                                                    <span className="flex-1 min-w-0">
                                                        <span className="block text-sm font-medium text-content-primary truncate">
                                                            {s.label}
                                                        </span>
                                                        <span className="block font-mono text-2xs text-content-muted">
                                                            {s.value} {option.label.toLowerCase()}
                                                        </span>
                                                    </span>
                                                    <span className="flex items-center gap-2 shrink-0">
                                                        <span
                                                            className="w-2 h-2 rounded-sm"
                                                            style={{ backgroundColor: s.color }}
                                                        />
                                                        <span className="font-mono text-xs text-content-secondary tabular-nums w-9 text-right">
                                                            {pct}%
                                                        </span>
                                                    </span>
                                                </div>
                                            )
                                        })}
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Right — threat coverage by selected content */}
                        <div className="flex flex-col gap-5 px-5 py-5 border-t border-border lg:border-t-0 lg:border-l">
                            <SectionLabel hint="Share of each actor's emulated techniques backed by the selected content.">
                                Threat Coverage (by selected content)
                            </SectionLabel>
                            {sortedActors.length === 0 ? (
                                <div className="py-10 text-center text-sm text-content-dim">
                                    No emulations available yet.
                                </div>
                            ) : (
                                <div className="flex flex-col gap-4 max-h-[300px] overflow-y-auto pr-1">
                                    {sortedActors.map((actor) => {
                                        const c = actor.coverageByContent[content]
                                        return (
                                            <div key={actor.id} className="flex flex-col gap-2">
                                                <div className="flex items-center justify-between gap-3">
                                                    <span className="text-sm font-medium text-content-primary truncate">
                                                        {actor.name}
                                                    </span>
                                                    <span className="shrink-0 font-mono text-xs text-content-secondary tabular-nums">
                                                        {c.covered} / {c.total} ({c.pct}%)
                                                    </span>
                                                </div>
                                                <div className="h-1.5 w-full rounded-full bg-surface-elevated overflow-hidden">
                                                    <span
                                                        className="block h-full rounded-full bg-safe"
                                                        style={{ width: `${Math.max(c.pct, 1.5)}%` }}
                                                    />
                                                </div>
                                            </div>
                                        )
                                    })}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Footer — coverage insight */}
                    <div className="flex items-center gap-2 px-5 py-3.5 border-t border-border">
                        <span className="shrink-0 text-safe">
                            <IconInfo size={14} />
                        </span>
                        <p className="text-xs text-content-secondary">
                            <span className="text-safe font-medium">Coverage Insight:</span> You have {total}{' '}
                            {contentNoun} across {platformsWithContent}{' '}
                            {platformsWithContent === 1 ? 'platform' : 'platforms'} covering {overallPct}% of the
                            targeted threat landscape.
                        </p>
                    </div>
                </>
            )}
        </Card>
    )
}
