import { useState } from 'react'

import type { CoverageRun } from '@/types/coverageHistory'

import { RunIntegrity } from './RunIntegrity'
import { RunTimeline } from './RunTimeline'
import { latencyMinutes, windowMinutes } from './compare'
import type { ChangeKind, ChangeRow, RunComparison } from './compare'

/**
 * Two runs, side by side, grouped by what changed.
 *
 * Regressions lead, because a detection that used to fire and no longer does
 * is the only row here with an action attached. Unchanged rules are collapsed
 * rather than dropped: a panel that showed only what moved would leave a reader
 * unable to tell "nothing regressed" apart from "nothing was evaluated".
 */

interface ComparePanelProps {
    comparison: RunComparison
    /** Labels for the two runs, already disambiguated by the caller. */
    labelA: string
    labelB: string
}

const GROUPS: { kind: ChangeKind; title: string; accent: string; note: string }[] = [
    {
        kind: 'regressed',
        title: 'Regressed',
        accent: 'border-danger',
        note: 'Fired before, did not fire in the later run.',
    },
    {
        kind: 'improved',
        title: 'Improved',
        accent: 'border-safe',
        note: 'Now catching a technique it previously missed.',
    },
    {
        kind: 'changed',
        title: 'Changed',
        accent: 'border-warning',
        note: 'Moved between two states that both mean uncaught.',
    },
    {
        kind: 'unjudged',
        title: 'Not comparable',
        accent: 'border-border-active',
        note: 'Judged in only one of the two runs, so nothing can be concluded.',
    },
]

const VERDICT_CLASS: Record<string, string> = {
    fired: 'bg-safe/15 text-safe',
    silent: 'bg-warning/15 text-warning',
    not_integrated: 'bg-white/5 text-content-muted',
}

const SEVERITY_CLASS: Record<string, string> = {
    critical: 'text-danger bg-danger-dim',
    high: 'text-warning bg-warning-dim',
}

/** One verdict as a pill, or a dash when the run never carried the rule. */
function Verdict({ value }: { value?: string }) {
    if (!value) return <span className="text-content-muted">&ndash;</span>
    return (
        <span
            className={`rounded px-1.5 py-0.5 text-[10px] font-semibold tracking-wide ${
                VERDICT_CLASS[value] ?? 'bg-white/5 text-content-muted'
            }`}
        >
            {value.replace('_', ' ')}
        </span>
    )
}

/**
 * One side of a change: the alert that fired, or a statement that none arrived.
 *
 * The absence is written out rather than left blank. "No matching alert before
 * the window closed at +5.0 min" is a measurement; an empty cell reads as
 * missing data.
 */
function EvidenceSide({
    run,
    label,
    verdict,
    ruleId,
}: {
    run: CoverageRun
    label: string
    verdict?: string
    ruleId: string
}) {
    const outcome = run.outcomes?.[ruleId]
    const latency = latencyMinutes(run.windowEnd, outcome?.evidence?.firedAt)
    const window = windowMinutes(run)

    return (
        <>
            <span className="whitespace-nowrap text-[11px] text-content-muted">{label}</span>
            <span
                className={`rounded px-1.5 py-0.5 text-center text-[9.5px] font-semibold tracking-wide ${
                    verdict === 'fired'
                        ? 'bg-safe/15 text-safe'
                        : verdict === 'silent'
                          ? 'bg-warning/15 text-warning'
                          : 'bg-white/5 text-content-muted'
                }`}
            >
                {(verdict ?? 'absent').replace('_', ' ')}
            </span>
            {outcome?.evidence ? (
                <span className="text-[12px] leading-snug text-content-secondary">
                    <span className="text-content-primary">
                        &ldquo;{outcome.evidence.ruleName}&rdquo;
                    </span>
                    <span className="mt-0.5 block text-[11px] text-content-muted">
                        arrived {latency === null ? 'in window' : `+${latency.toFixed(1)} min`}
                        {outcome.matchTier && ` · matched by ${outcome.matchTier}`}
                        {outcome.evidence.severity && ` · severity ${outcome.evidence.severity}`}
                    </span>
                </span>
            ) : (
                <span className="text-[12px] leading-snug text-content-muted">
                    No matching alert before the window closed
                    {window !== null && ` at +${Math.round(window)} min`}
                </span>
            )}
        </>
    )
}

/** The sentence that says which explanations the run data has already ruled out. */
function meaning(row: ChangeRow, a: CoverageRun, b: CoverageRun): string {
    const exercised = a.attackCompleted && b.attackCompleted
    const routed = a.integrationHealth && b.integrationHealth
    if (row.kind === 'regressed') {
        if (!exercised) return 'One of these runs never finished its attack, so this is not yet a detection finding.'
        if (!routed) return 'A run received no alerts at all, so this is a connection gap rather than a lost detection.'
        return 'The technique ran and the alert route was healthy both times, so this is either a rule that stopped matching or one slower than the later window allowed.'
    }
    if (row.kind === 'improved') {
        return 'A technique that went uncaught in the earlier run is now being reported.'
    }
    return 'Both states mean the technique went uncaught, so this moved without being caught either way.'
}

export function ComparePanel({ comparison, labelA, labelB }: ComparePanelProps) {
    const [showUnchanged, setShowUnchanged] = useState(false)
    const { a, b, rows, counts, delta } = comparison

    const deltaLabel =
        delta === null
            ? 'not comparable'
            : delta === 0
              ? 'no change'
              : `${delta > 0 ? '+' : ''}${delta} pts`
    const deltaClass =
        delta === null || delta === 0
            ? 'text-content-muted'
            : delta > 0
              ? 'text-safe'
              : 'text-danger'

    const unchanged = rows.filter((row) => row.kind === 'unchanged')
    const moved = GROUPS.map((group) => ({
        ...group,
        items: rows.filter((row) => row.kind === group.kind),
    })).filter((group) => group.items.length > 0)

    return (
        <div className="mt-3 rounded-btn bg-surface-elevated p-4">
            <div className="mb-4 flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b border-border-subtle pb-3">
                <span className="font-mono text-[10px] uppercase tracking-label text-content-muted">
                    Comparing
                </span>
                <span className="text-[13px] text-content-secondary">
                    {labelA}
                    <span className="mx-2 text-content-muted">&rarr;</span>
                    {labelB}
                </span>
                <span className="ml-auto flex items-baseline gap-2 text-[13px] tabular-nums">
                    <span className="text-content-muted">
                        {a.coverage === null ? '--' : `${a.coverage}%`}
                        <span className="mx-1.5">&rarr;</span>
                        {b.coverage === null ? '--' : `${b.coverage}%`}
                    </span>
                    <span className={`text-xs font-semibold ${deltaClass}`}>{deltaLabel}</span>
                </span>
            </div>

            <RunIntegrity a={a} b={b} />
            <RunTimeline a={a} b={b} labelA={labelA} labelB={labelB} />

            <div className="mt-3 rounded-btn bg-surface-elevated p-4">
                <div className="mb-1 text-[13px] text-content-primary">
                    What changed, and the alert behind it
                </div>
                <p className="mb-3.5 text-[12px] leading-relaxed text-content-muted">
                    {counts.regressed === 0 && counts.improved === 0 && counts.changed === 0
                        ? 'No detection changed verdict between these two runs.'
                        : 'Every change, with the alert that fired on each side of it.'}
                </p>

                {moved.map((group) => (
                    <div key={group.kind} className="mb-4 last:mb-0">
                        <div className="mb-2 flex items-baseline gap-2">
                            <span className="text-[11px] font-semibold uppercase tracking-wide text-content-secondary">
                                {group.title}
                            </span>
                            <span className="text-[11px] text-content-muted">
                                {group.items.length}
                            </span>
                            <span className="text-[11px] text-content-muted">
                                &middot; {group.note}
                            </span>
                        </div>
                        {group.items.map((row) => (
                            <div
                                key={row.ruleId}
                                className={`mb-2 rounded-r-btn border-l-2 bg-surface-card px-4 py-3.5 ${group.accent}`}
                            >
                                <div className="mb-2.5 flex flex-wrap items-baseline gap-2.5">
                                    <span className="font-mono text-[11px] text-content-muted">
                                        {row.ruleId}
                                    </span>
                                    <span className="text-[13.5px] text-content-primary">
                                        {row.title}
                                    </span>
                                    {row.severity && (
                                        <span
                                            className={`rounded px-1.5 py-px text-[9px] font-semibold uppercase tracking-wide ${
                                                SEVERITY_CLASS[row.severity]
                                                ?? 'bg-white/5 text-content-dim'
                                            }`}
                                        >
                                            {row.severity}
                                        </span>
                                    )}
                                </div>
                                <div className="grid grid-cols-[112px_72px_1fr] items-baseline gap-x-3 gap-y-2.5">
                                    <EvidenceSide
                                        run={a}
                                        label={labelA}
                                        verdict={row.before}
                                        ruleId={row.ruleId}
                                    />
                                    <EvidenceSide
                                        run={b}
                                        label={labelB}
                                        verdict={row.after}
                                        ruleId={row.ruleId}
                                    />
                                </div>
                                <p className="mt-3 border-t border-white/[0.05] pt-2.5 text-[12px] leading-relaxed text-content-dim">
                                    <b className="font-semibold text-content-secondary">
                                        What this means:
                                    </b>{' '}
                                    {meaning(row, a, b)}
                                </p>
                            </div>
                        ))}
                    </div>
                ))}

                {unchanged.length > 0 && (
                <div className="mt-3 border-t border-border-subtle pt-2.5">
                    <button
                        type="button"
                        onClick={() => setShowUnchanged((open) => !open)}
                        aria-expanded={showUnchanged}
                        className="text-[11.5px] text-content-muted transition-opacity hover:opacity-60"
                    >
                        {showUnchanged ? 'Hide' : 'Show'} {unchanged.length} unchanged
                    </button>
                    {showUnchanged
                        && unchanged.map((row) => (
                            <div
                                key={row.ruleId}
                                className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5"
                            >
                                <span className="font-mono text-[11px] text-content-muted">
                                    {row.ruleId}
                                </span>
                                <span className="min-w-0 flex-1 truncate text-[12.5px] text-content-muted">
                                    {row.title}
                                </span>
                                <Verdict value={row.after} />
                            </div>
                        ))}
                </div>
                )}
            </div>
        </div>
    )
}
