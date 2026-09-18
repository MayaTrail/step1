import { Link } from 'react-router-dom'

import { IconChevron } from '@/components/ui/Icons'
import type { CoverageRule, StandingState } from '@/types/coverageHistory'

/**
 * One detection as a bullet graph.
 *
 * Stephen Few's design, with all four encodings carrying meaning: shaded
 * qualitative ranges behind the bar, the measure itself, the target as a
 * comparative tick, and a diamond at the value before the most recent judged
 * run so direction is visible without a second chart.
 *
 * A rule at 0% draws no bar at all rather than a stub. Few's design shows
 * nothing at zero, and a two-pixel sliver reads as a small positive value.
 */

interface BulletRowProps {
    rule: CoverageRule
    /** Reliability percentage a detection is expected to meet. */
    target: number
    /** Emulation this rule belongs to, for the link to its detection page. */
    emulationType: string
    /** Platform the emulation belongs to, so the link is not assumed to be AWS. */
    platform: string
}

const TRACK_WIDTH = 300
const TRACK_HEIGHT = 26
const BAR_HEIGHT = 9
const BAND_HEIGHT = 16

/** Label and colour for the whole-history verdict. */
const STANDING: Record<StandingState, { label: string; className: string }> = {
    never_fired: { label: 'NEVER FIRED', className: 'text-danger' },
    silent_now: { label: 'SILENT NOW', className: 'text-danger' },
    flaky: { label: 'FLAKY', className: 'text-warning' },
    firing: { label: 'FIRING', className: 'text-safe' },
    no_data: { label: 'NO DATA', className: 'text-content-muted' },
}

/** Severity badges tint only for the levels that change what a reader does. */
const SEVERITY: Record<string, string> = {
    critical: 'text-danger bg-danger-dim',
    high: 'text-warning bg-warning-dim',
}

/** Bar colour: the measure against the target. */
function barColor(reliability: number, target: number): string {
    if (reliability >= target) return '#5fc992'
    if (reliability >= 50) return '#ffbc33'
    return '#FF6363'
}

export function BulletRow({ rule, target, emulationType, platform }: BulletRowProps) {
    const x = (pct: number) => (pct / 100) * TRACK_WIDTH
    const bandTop = (TRACK_HEIGHT - BAND_HEIGHT) / 2
    const standing = STANDING[rule.state]
    const measured = rule.reliability !== null

    const streakSuffix =
        rule.state === 'firing' && rule.streak
            ? ` · ${rule.streak}`
            : rule.state === 'flaky' && rule.dips
              ? ` · ${rule.dips}`
              : ''

    return (
        <div className="group grid grid-cols-[minmax(200px,1fr)_minmax(260px,2.2fr)_120px] items-center gap-x-4 py-2">
            <div className="min-w-0">
                <Link
                    to={`/${platform}/emulations/${emulationType}/detections/${rule.ruleId}`}
                    title={`Open ${rule.ruleId} detection`}
                    className="flex items-center gap-1.5 no-underline transition-opacity hover:opacity-75"
                >
                    <span className="truncate text-[13px] text-content-secondary transition-colors group-hover:text-accent-blue">
                        {rule.title}
                    </span>
                    <span className="flex-none -translate-x-1 text-accent-blue opacity-0 transition-all group-hover:translate-x-0 group-hover:opacity-100">
                        <IconChevron size={12} />
                    </span>
                </Link>
                <div className="mt-0.5 flex items-center gap-2 text-[10.5px] text-content-muted">
                    <span className="font-mono">{rule.ruleId}</span>
                    {rule.severity && (
                        <span
                            className={`rounded px-1.5 py-px text-[9px] font-semibold uppercase tracking-wide ${
                                SEVERITY[rule.severity] ?? 'bg-white/5 text-content-dim'
                            }`}
                        >
                            {rule.severity}
                        </span>
                    )}
                </div>
            </div>

            <svg
                viewBox={`0 0 ${TRACK_WIDTH} ${TRACK_HEIGHT}`}
                className="w-full"
                style={{ height: TRACK_HEIGHT }}
                role="img"
                aria-label={
                    measured
                        ? `${rule.reliability}% reliability against a ${target}% target`
                        : 'Never judged'
                }
            >
                <rect x={0} y={bandTop} width={x(50)} height={BAND_HEIGHT} rx={2} fill="rgba(255,255,255,0.028)" />
                <rect x={x(50)} y={bandTop} width={x(target) - x(50)} height={BAND_HEIGHT} fill="rgba(255,255,255,0.045)" />
                <rect x={x(target)} y={bandTop} width={TRACK_WIDTH - x(target)} height={BAND_HEIGHT} rx={2} fill="rgba(255,255,255,0.07)" />

                {measured && rule.reliability! > 0 && (
                    <rect
                        x={0}
                        y={(TRACK_HEIGHT - BAR_HEIGHT) / 2}
                        width={x(rule.reliability!)}
                        height={BAR_HEIGHT}
                        rx={2}
                        fill={barColor(rule.reliability!, target)}
                    />
                )}

                {measured
                    && rule.previousReliability !== null
                    && rule.previousReliability !== rule.reliability && (
                    <path
                        d={`M ${x(rule.previousReliability)} ${TRACK_HEIGHT / 2 - 5}
                            L ${x(rule.previousReliability) + 4.5} ${TRACK_HEIGHT / 2}
                            L ${x(rule.previousReliability)} ${TRACK_HEIGHT / 2 + 5}
                            L ${x(rule.previousReliability) - 4.5} ${TRACK_HEIGHT / 2} Z`}
                        fill="var(--surface-deep)"
                        stroke="rgba(255,255,255,0.45)"
                        strokeWidth={1.2}
                    />
                )}

                <line
                    x1={x(target)}
                    y1={2}
                    x2={x(target)}
                    y2={TRACK_HEIGHT - 2}
                    stroke="var(--content-primary)"
                    strokeWidth={2}
                />
            </svg>

            <div className="flex items-center justify-end gap-2">
                <span
                    className="min-w-[38px] text-right text-sm font-semibold tabular-nums"
                    style={{ color: measured ? barColor(rule.reliability!, target) : 'var(--content-muted)' }}
                >
                    {measured ? `${rule.reliability}%` : '—'}
                </span>
                <span className={`whitespace-nowrap text-[10px] font-semibold tracking-wide ${standing.className}`}>
                    {standing.label}
                    {streakSuffix}
                </span>
            </div>
        </div>
    )
}
