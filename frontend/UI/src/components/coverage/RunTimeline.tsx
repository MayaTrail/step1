import type { CoverageRun } from '@/types/coverageHistory'

import { latencyMinutes, windowMinutes, windowMismatch } from './compare'

/**
 * Both runs on one axis, measured from the moment the attack finished.
 *
 * The normalisation is the analysis. Two runs eleven hours apart share nothing
 * on a wall-clock axis, but measured as latency from attack end their alert
 * timings become directly comparable, and the run that stopped listening
 * earliest can be seen cutting across the other run's slowest alert.
 *
 * That is how a detection can look regressed without being broken, and the
 * warning under the chart names it when the geometry says it happened.
 */

interface RunTimelineProps {
    a: CoverageRun
    b: CoverageRun
    labelA: string
    labelB: string
}

/** Minutes of attack shown to the left of zero, and how far right to plot. */
const AXIS_MIN = -3
const AXIS_HEADROOM = 2

interface Marker {
    at: number
    rules: string[]
}

/** Group a run's alerts by arrival latency, so simultaneous ones share a dot. */
function markers(run: CoverageRun): Marker[] {
    const byLatency = new Map<string, Marker>()
    Object.entries(run.outcomes ?? {}).forEach(([ruleId, outcome]) => {
        const at = latencyMinutes(run.windowEnd, outcome.evidence?.firedAt)
        if (at === null) return
        const key = at.toFixed(2)
        const existing = byLatency.get(key)
        if (existing) existing.rules.push(ruleId)
        else byLatency.set(key, { at, rules: [ruleId] })
    })
    return [...byLatency.values()].sort((p, q) => p.at - q.at)
}

/** Attack duration in minutes, clamped so a long deploy cannot swamp the axis. */
function attackMinutes(run: CoverageRun): number {
    if (!run.windowStart || !run.windowEnd) return 1
    const minutes =
        (new Date(run.windowEnd).getTime() - new Date(run.windowStart).getTime()) / 60000
    return Math.min(Math.max(minutes, 0.3), -AXIS_MIN)
}

export function RunTimeline({ a, b, labelA, labelB }: RunTimelineProps) {
    const rows = [
        { run: a, label: labelA },
        { run: b, label: labelB },
    ]

    // The axis covers every alert plus the SHORTER of the two windows, so the
    // collision between a deadline and a slow alert stays on screen. Including
    // a long window here instead compressed the first few minutes, where all
    // the alerts are, into a sliver.
    const windows = rows
        .map(({ run }) => windowMinutes(run))
        .filter((value): value is number => value !== null)
    const latencies = rows.flatMap(({ run }) => markers(run).map((marker) => marker.at))
    const axisMax =
        Math.max(...latencies, windows.length ? Math.min(...windows) : 1, 1) + AXIS_HEADROOM
    const toPct = (minutes: number) =>
        ((minutes - AXIS_MIN) / (axisMax - AXIS_MIN)) * 100

    const mismatch = windowMismatch(a, b)
    const ticks = Array.from({ length: Math.min(Math.ceil(axisMax), 8) }, (_, i) => i + 1)

    return (
        <div className="mt-3 rounded-btn bg-surface-elevated p-4">
            <div className="mb-1 text-[13px] text-content-primary">
                When everything actually happened
            </div>
            <p className="mb-4 text-[12px] leading-relaxed text-content-muted">
                Both runs on one axis, measured from the moment the attack finished. The bar is the
                attack, each dot is alerts arriving, and the shaded band is how long we kept
                listening.
            </p>

            {rows.map(({ run, label }) => {
                const window = windowMinutes(run)
                const offScale = window !== null && window > axisMax
                const deadlinePct = offScale ? 100 : toPct(window ?? 0)
                return (
                    <div
                        key={run.runId}
                        className="mb-1.5 grid grid-cols-[120px_1fr] items-center gap-3.5"
                    >
                        <div className="text-right text-[11.5px] text-content-dim">
                            {label}
                            <div className="mt-0.5 text-[10px] text-content-muted">
                                {window === null ? 'no window' : `${Math.round(window)} min window`}
                            </div>
                        </div>
                        <div className="relative h-9">
                            <div className="absolute inset-x-0 top-4 h-px bg-white/[0.07]" />
                            <div
                                className="absolute top-2.5 h-4 rounded-sm bg-accent-blue/25 ring-1 ring-inset ring-accent-blue/40"
                                style={{
                                    left: `${toPct(-attackMinutes(run))}%`,
                                    width: `${toPct(0) - toPct(-attackMinutes(run))}%`,
                                }}
                                title="attack running"
                            />
                            <div
                                className="absolute top-3 h-2.5 rounded-sm bg-white/[0.035]"
                                style={{ left: `${toPct(0)}%`, width: `${deadlinePct - toPct(0)}%` }}
                            />
                            {offScale ? (
                                <span className="absolute right-0.5 top-1.5 text-[10px] text-content-muted">
                                    &rarr; +{Math.round(window ?? 0)}m
                                </span>
                            ) : (
                                <>
                                    <div
                                        className="absolute top-1 h-6 w-0.5 bg-danger"
                                        style={{ left: `${deadlinePct}%` }}
                                    />
                                    <span
                                        className="absolute -top-2 -translate-x-1/2 whitespace-nowrap text-[9.5px] text-danger"
                                        style={{ left: `${deadlinePct}%` }}
                                    >
                                        window closes
                                    </span>
                                </>
                            )}
                            {markers(run).map((marker) => (
                                <div key={marker.at} title={marker.rules.join(', ')}>
                                    <div
                                        className="absolute top-2.5 h-3 w-3 -translate-x-1/2 rounded-pill border-2 border-surface-deep bg-safe"
                                        style={{ left: `${toPct(marker.at)}%` }}
                                    />
                                    <span
                                        className="absolute top-6 -translate-x-1/2 text-[9px] text-content-muted"
                                        style={{ left: `${toPct(marker.at)}%` }}
                                    >
                                        {marker.rules.length}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                )
            })}

            <div className="mt-1 grid grid-cols-[120px_1fr] gap-3.5">
                <span />
                <div className="relative h-4 text-[9.5px] text-content-muted">
                    <span className="absolute -translate-x-1/2" style={{ left: `${toPct(0)}%` }}>
                        attack ends
                    </span>
                    {ticks.map((minute) => (
                        <span
                            key={minute}
                            className="absolute -translate-x-1/2"
                            style={{ left: `${toPct(minute)}%` }}
                        >
                            +{minute}m
                        </span>
                    ))}
                </div>
            </div>

            {mismatch && (
                <div className="mt-4 flex gap-3 rounded-btn border-l-2 border-warning bg-surface-card px-4 py-3">
                    <span className="flex-none text-warning">⚠</span>
                    <p className="text-[12.5px] leading-relaxed text-content-secondary">
                        <b className="font-semibold text-content-primary">
                            These runs did not listen for the same length of time.
                        </b>{' '}
                        One waited {Math.round(mismatch.longer)} minutes, the other{' '}
                        {Math.round(mismatch.shorter)}. The longer run was still receiving alerts at{' '}
                        <b className="font-semibold text-content-primary">
                            +{mismatch.slowestAlert.toFixed(1)} min
                        </b>
                        , past the point the shorter run stopped listening, so a detection that
                        reports slowly would look silent here with nothing wrong with it. Treat the
                        changes below as a lead rather than a verdict.
                    </p>
                </div>
            )}
        </div>
    )
}
