import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { Card } from '@/components/ui/Card'
import { getCoverageHistory, setRunArchived } from '@/services/coverageHistory.service'
import { listWorkflowRuns } from '@/services/workflow.service'
import type { CoverageHistory, CoverageRule, StandingState } from '@/types/coverageHistory'
import type { WorkflowRun } from '@/types/workflow'

import { BulletRow } from './BulletRow'
import { ComparePanel } from './ComparePanel'
import { RunGauge } from './RunGauge'
import { compareRuns } from './compare'

/**
 * Detection reliability across every run of one emulation.
 *
 * Two views of the same runs. The filmstrip slices by run, one gauge each, and
 * the bullets slice by detection. Selecting a gauge scrubs the bullets to
 * measure reliability as of that point in history, which is computed locally
 * from the per-run verdicts the payload carries rather than by refetching.
 *
 * Reliability counts only the runs that actually judged a rule. A run where no
 * alerts arrived never exercised it, so counting that as a miss would report a
 * detection failure where the real problem was a missing connection.
 */

const FIRED = 'fired'
const SILENT = 'silent'

interface ArchiveState {
    busy: boolean
    error: string | null
}

/**
 * Recompute one rule's standing over a window of runs.
 *
 * Mirrors the server's logic so a scrub does not need a round trip. The server
 * remains the source of truth for the unscrubbed view; this only narrows the
 * window.
 */
function recompute(
    rule: CoverageRule,
    verdictsPerRun: Record<string, string>[],
    target: number,
): CoverageRule {
    const seq = verdictsPerRun
        .map((verdicts) => verdicts[rule.ruleId])
        .filter((verdict) => verdict === FIRED || verdict === SILENT)

    if (seq.length === 0) {
        return {
            ...rule,
            reliability: null,
            firedRuns: 0,
            judgedRuns: 0,
            previousReliability: null,
            meetsTarget: false,
            state: 'no_data',
            streak: 0,
            dips: 0,
        }
    }

    const fired = seq.filter((verdict) => verdict === FIRED).length
    const reliability = Math.round((fired / seq.length) * 100)

    const earlier = seq.slice(0, -1)
    const previousReliability = earlier.length
        ? Math.round((earlier.filter((v) => v === FIRED).length / earlier.length) * 100)
        : null

    let dips = 0
    for (let i = 1; i < seq.length; i += 1) {
        if (seq[i - 1] === FIRED && seq[i] !== FIRED) dips += 1
    }

    let state: StandingState
    let streak = 0
    if (!seq.includes(FIRED)) {
        state = 'never_fired'
    } else if (seq[seq.length - 1] !== FIRED) {
        state = 'silent_now'
    } else {
        for (let i = seq.length - 1; i >= 0 && seq[i] === FIRED; i -= 1) streak += 1
        state = dips > 0 ? 'flaky' : 'firing'
    }

    return {
        ...rule,
        reliability,
        firedRuns: fired,
        judgedRuns: seq.length,
        previousReliability,
        meetsTarget: reliability >= target,
        state,
        streak,
        dips,
    }
}

/** Short date for a gauge label. */
function gaugeDate(iso: string | null): string {
    if (!iso) return 'Pending'
    return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

/**
 * Label a run, adding the time only when its date alone would be ambiguous.
 *
 * Two runs on the same local day are common, and a strip of identical "18 Sept"
 * labels gives the reader no way to tell which gauge is which, or which run an
 * Archive button is about to act on.
 */
function runLabel(iso: string | null, all: (string | null)[]): string {
    if (!iso) return 'Pending'
    const date = gaugeDate(iso)
    const sameDay = all.filter((other) => other && gaugeDate(other) === date).length
    if (sameDay < 2) return date
    const time = new Date(iso).toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
    })
    return `${date} ${time}`
}

export function CoverageHistoryPage() {
    const [emulations, setEmulations] = useState<string[]>([])
    const [selected, setSelected] = useState<string>('')
    const [history, setHistory] = useState<CoverageHistory | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    // Index of the run the bullets are measured through. Null means all runs.
    const [through, setThrough] = useState<number | null>(null)
    const [archive, setArchive] = useState<ArchiveState>({ busy: false, error: null })
    // Archived runs for the selected emulation. Nothing deletes them on a
    // schedule, so this list is the way back to one.
    const [archived, setArchived] = useState<WorkflowRun[]>([])
    const [showArchived, setShowArchived] = useState(false)
    // Compare mode turns the gauge strip into a two-pick selector. Null means
    // the strip is in its normal scrub role.
    const [comparing, setComparing] = useState(false)
    const [picked, setPicked] = useState<number[]>([])

    const stripRef = useRef<HTMLDivElement>(null)

    // Which emulations the user has actually completed a run of. Derived from
    // their runs rather than the catalogue, so the page never offers an
    // emulation whose history would be empty.
    //
    // Archived runs are included here deliberately: archiving every run of an
    // emulation would otherwise drop it out of this list, and with it the only
    // route back to the runs that were archived.
    useEffect(() => {
        let cancelled = false
        listWorkflowRuns(true)
            .then((runs) => {
                if (cancelled) return
                const types = Array.from(
                    new Set(
                        runs
                            .filter((run) => run.status === 'completed')
                            .map((run) => run.emulationType),
                    ),
                ).sort()
                setEmulations(types)
                setSelected((current) => current || types[0] || '')
                if (types.length === 0) setLoading(false)
            })
            .catch(() => {
                if (cancelled) return
                setError('Could not load your runs.')
                setLoading(false)
            })
        return () => {
            cancelled = true
        }
    }, [])

    const load = useCallback(
        (emulationType: string) => {
            let cancelled = false
            setLoading(true)
            setError(null)
            getCoverageHistory(emulationType)
                .then((data) => {
                    if (cancelled) return
                    setHistory(data)
                    setThrough(null)
                    setComparing(false)
                    setPicked([])
                })
                .catch(() => {
                    if (!cancelled) setError('Could not load coverage history.')
                })
                .finally(() => {
                    if (!cancelled) setLoading(false)
                })

            // Archived runs are a separate read: coverage history deliberately
            // excludes them, and this is the only route back to one.
            listWorkflowRuns(true)
                .then((all) => {
                    if (cancelled) return
                    setArchived(
                        all.filter(
                            (run) => run.emulationType === emulationType && run.archivedAt,
                        ),
                    )
                })
                .catch(() => {
                    if (!cancelled) setArchived([])
                })

            return () => {
                cancelled = true
            }
        },
        [],
    )

    useEffect(() => {
        if (!selected) return undefined
        return load(selected)
    }, [selected, load])

    const runs = history?.runs ?? []
    const target = history?.target ?? 90

    // Past about a dozen runs the strip overflows, and the newest run is the
    // one that matters, so keep the selected gauge in view.
    useEffect(() => {
        const strip = stripRef.current
        const active = strip?.querySelector('[data-selected="true"]')
        active?.scrollIntoView({ block: 'nearest', inline: 'center' })
    }, [runs.length, through])

    const windowRuns = useMemo(
        () => (through === null ? runs : runs.slice(0, through + 1)),
        [runs, through],
    )

    const rules = useMemo(() => {
        if (!history) return []
        if (through === null) return history.rules
        const verdicts = windowRuns.map((run) => run.verdicts ?? {})
        return history.rules.map((rule) => recompute(rule, verdicts, target))
    }, [history, through, windowRuns, target])

    const judged = windowRuns.filter((run) => run.judged)
    const latest = judged[judged.length - 1]
    const belowTarget = rules.filter(
        (rule) => rule.reliability !== null && !rule.meetsTarget,
    ).length

    const selectedRun = through === null ? runs[runs.length - 1] : runs[through]
    // Every completion timestamp on the page, so a label can tell whether its
    // own date is unique.
    const runDates = runs.map((run) => run.completedAt)

    // Two picks make a comparison. Defaults to the latest two the moment
    // compare mode opens, because that is the question people ask first.
    const comparison = useMemo(() => {
        if (!comparing || !history) return null
        // Indexed access is checked, so pull the two runs out before using
        // them rather than trusting picked.length to narrow the tuple.
        const first = picked.length === 2 ? runs[picked[0] ?? -1] : undefined
        const second = picked.length === 2 ? runs[picked[1] ?? -1] : undefined
        if (!first || !second) return null
        return compareRuns(first, second, history.rules)
    }, [comparing, picked, runs, history])

    /** Enter or leave compare mode, seeding the latest two runs on entry. */
    const toggleCompare = () => {
        if (comparing) {
            setComparing(false)
            setPicked([])
            return
        }
        setComparing(true)
        setThrough(null)
        setPicked(runs.length >= 2 ? [runs.length - 2, runs.length - 1] : [])
    }

    /**
     * Clicking a gauge scrubs in normal mode and picks in compare mode.
     *
     * Picking keeps the two most recent choices, so a third click replaces the
     * older of the pair rather than doing nothing.
     */
    const onGaugeClick = (index: number) => {
        if (!comparing) {
            setThrough(through === index && index === runs.length - 1 ? null : index)
            return
        }
        setPicked((current) => {
            if (current.includes(index)) return current.filter((i) => i !== index)
            return [...current, index].slice(-2)
        })
    }

    const toggleArchive = async () => {
        if (!selectedRun) return
        setArchive({ busy: true, error: null })
        try {
            await setRunArchived(selectedRun.runId, true)
            setArchive({ busy: false, error: null })
            load(selected)
        } catch {
            setArchive({
                busy: false,
                error: 'Could not archive that run. It may still be in progress.',
            })
        }
    }

    /** Put an archived run back into coverage history. */
    const restore = async (runId: string) => {
        setArchive({ busy: true, error: null })
        try {
            await setRunArchived(runId, false)
            setArchive({ busy: false, error: null })
            load(selected)
        } catch {
            setArchive({ busy: false, error: 'Could not restore that run.' })
        }
    }

    if (!loading && emulations.length === 0) {
        return (
            <div className="animate-fadeIn">
                <Header />
                <Card className="p-12 text-center">
                    <div className="text-lg text-content-primary mb-2">No completed runs yet</div>
                    <p className="mx-auto max-w-[46ch] text-sm leading-relaxed text-content-muted">
                        Coverage history is built from runs that have settled. Attach an alert
                        endpoint, run an emulation through a workflow, and the first gauge appears
                        when the alert window closes.
                    </p>
                </Card>
            </div>
        )
    }

    return (
        <div className="animate-fadeIn">
            <Header />

            {emulations.length > 1 && (
                <div className="mb-5 inline-flex gap-0.5 rounded-btn bg-surface-elevated p-0.5">
                    {emulations.map((type) => (
                        <button
                            key={type}
                            type="button"
                            onClick={() => setSelected(type)}
                            aria-pressed={type === selected}
                            className={`rounded-md px-3.5 py-1.5 text-[13px] transition-opacity hover:opacity-60 ${
                                type === selected
                                    ? 'bg-white/[0.08] text-content-primary'
                                    : 'text-content-dim'
                            }`}
                        >
                            {type}
                        </button>
                    ))}
                </div>
            )}

            {error && (
                <Card accent="red" className="mb-3 p-4 text-sm text-content-secondary">
                    {error}
                </Card>
            )}

            {loading && !history && (
                <Card className="p-10 text-center text-sm text-content-muted">
                    Loading coverage history...
                </Card>
            )}

            {history && runs.length === 0 && archived.length > 0 && (
                <Card className="p-6">
                    <div className="mb-1.5 text-[15px] text-content-primary">
                        Every run of {selected} is archived
                    </div>
                    <p className="mb-1 max-w-[60ch] text-[12.5px] leading-relaxed text-content-muted">
                        Nothing has been deleted, and nothing will be. Restore a run to bring it
                        back into coverage history.
                    </p>
                    {archive.error && (
                        <p className="text-[12.5px] text-danger">{archive.error}</p>
                    )}
                    <ArchivedRuns runs={archived} busy={archive.busy} onRestore={restore} />
                </Card>
            )}

            {history && runs.length > 0 && (
                <>
                    <div className="mb-4">
                        <div className="text-2xl font-medium leading-tight text-content-primary">
                            {latest ? (
                                <>
                                    <span
                                        className={
                                            latest.coverage !== null && latest.coverage >= target
                                                ? 'text-safe'
                                                : latest.coverage !== null && latest.coverage >= 50
                                                  ? 'text-warning'
                                                  : 'text-danger'
                                        }
                                    >
                                        {latest.fired} of {latest.ruleCount}
                                    </span>{' '}
                                    detections firing
                                </>
                            ) : (
                                <>
                                    Coverage is{' '}
                                    <span className="text-content-muted">unmeasured</span>
                                </>
                            )}
                        </div>
                        <div className="mt-1.5 text-[13px] text-content-dim">
                            {judged.length} of {windowRuns.length} runs judged
                            {belowTarget > 0 && ` · ${belowTarget} below the ${target}% target`}
                            {!latest && ' · no alerts reached the endpoint'}
                        </div>
                    </div>

                    <Card className="mb-3 p-5">
                        <div className="mb-3 flex flex-wrap items-center justify-between gap-4">
                            <h2 className="text-[15px] font-medium text-content-primary">
                                Every run
                            </h2>
                            <div className="flex items-center gap-3 text-[11.5px] text-content-muted">
                                {runs.length >= 2 && (
                                    <button
                                        type="button"
                                        onClick={toggleCompare}
                                        aria-pressed={comparing}
                                        className={`rounded-btn border px-3 py-1 transition-opacity hover:opacity-60 ${
                                            comparing
                                                ? 'border-accent-blue/40 bg-accent-blue-glow text-accent-blue'
                                                : 'border-white/10 text-content-dim'
                                        }`}
                                    >
                                        {comparing ? 'Exit compare' : 'Compare'}
                                    </button>
                                )}
                                {comparing ? (
                                    <span>
                                        {picked.length < 2
                                            ? `Pick ${2 - picked.length} more`
                                            : 'comparing 2 runs'}
                                    </span>
                                ) : through === null ? (
                                    <span>{runs.length} runs · showing all</span>
                                ) : (
                                    <>
                                        <span>
                                            measuring through{' '}
                                            {runLabel(selectedRun?.completedAt ?? null, runDates)}
                                        </span>
                                        <button
                                            type="button"
                                            onClick={() => setThrough(null)}
                                            className="text-accent-blue transition-opacity hover:opacity-60"
                                        >
                                            show all
                                        </button>
                                    </>
                                )}
                            </div>
                        </div>
                        <p className="mb-4 text-[12.5px] leading-relaxed text-content-muted">
                            One gauge per run: the green arc is the share of expected detections
                            that fired, amber is what stayed silent. Select a run to measure
                            reliability as of that point.
                        </p>

                        <div
                            ref={stripRef}
                            className="flex gap-2.5 overflow-x-auto px-0.5 pb-3 pt-1"
                        >
                            {runs.map((run, index) => {
                                const pickOrder = picked.indexOf(index)
                                const isSelected = comparing
                                    ? pickOrder !== -1
                                    : through === null
                                      ? index === runs.length - 1
                                      : index === through
                                return (
                                    <button
                                        key={run.runId}
                                        type="button"
                                        data-selected={isSelected}
                                        onClick={() => onGaugeClick(index)}
                                        className={`flex w-[86px] flex-none flex-col items-center gap-1.5 rounded-xl border px-1 py-2 transition-all hover:opacity-60 ${
                                            isSelected
                                                ? 'border-accent-blue/40 bg-accent-blue-glow'
                                                : 'border-transparent'
                                        }`}
                                    >
                                        <RunGauge run={run} target={target} emphasis={isSelected} />
                                        <span className="whitespace-nowrap text-[10.5px] text-content-dim">
                                            {runLabel(run.completedAt, runDates)}
                                        </span>
                                        <span className="text-[9px] font-semibold uppercase tracking-wide text-accent-blue">
                                            {comparing && pickOrder !== -1
                                                ? pickOrder === 0
                                                    ? 'first'
                                                    : 'second'
                                                : index === runs.length - 1
                                                  ? 'latest'
                                                  : ' '}
                                        </span>
                                    </button>
                                )
                            })}
                        </div>

                        {comparison && (
                            <ComparePanel
                                comparison={comparison}
                                labelA={runLabel(comparison.a.completedAt, runDates)}
                                labelB={runLabel(comparison.b.completedAt, runDates)}
                            />
                        )}

                        {comparing && !comparison && (
                            <p className="mt-3 border-t border-border-subtle pt-3 text-[12.5px] text-content-muted">
                                Select two runs above to see every detection that changed verdict
                                between them.
                            </p>
                        )}

                        {!comparing && selectedRun && (
                            <div className="mt-2 flex flex-wrap items-center justify-between gap-3 border-t border-border-subtle pt-3">
                                <span className="text-[11.5px] text-content-muted">
                                    {archive.error
                                        ?? 'Archiving hides a run from this page. Its report is kept and nothing deletes it.'}
                                </span>
                                <div className="flex items-center gap-2">
                                    {archived.length > 0 && (
                                        <button
                                            type="button"
                                            onClick={() => setShowArchived((open) => !open)}
                                            aria-expanded={showArchived}
                                            className="rounded-btn px-3 py-1.5 text-xs text-accent-blue transition-opacity hover:opacity-60"
                                        >
                                            {showArchived ? 'Hide' : 'Show'} {archived.length}{' '}
                                            archived
                                        </button>
                                    )}
                                    <button
                                        type="button"
                                        onClick={toggleArchive}
                                        disabled={archive.busy}
                                        className="rounded-btn border border-white/10 px-3.5 py-1.5 text-xs text-content-dim transition-opacity hover:opacity-60 disabled:opacity-40"
                                    >
                                        {archive.busy
                                            ? 'Working...'
                                            : `Archive ${runLabel(selectedRun.completedAt, runDates)} run`}
                                    </button>
                                </div>
                            </div>
                        )}

                        {showArchived && archived.length > 0 && (
                            <ArchivedRuns
                                runs={archived}
                                busy={archive.busy}
                                onRestore={restore}
                            />
                        )}
                    </Card>

                    <Card className={`p-5 ${comparing ? 'hidden' : ''}`}>
                        <div className="mb-3 flex flex-wrap items-center justify-between gap-4">
                            <h2 className="text-[15px] font-medium text-content-primary">
                                Detection reliability
                            </h2>
                            <span className="text-[11.5px] text-content-muted">
                                {through === null ? 'all runs' : `runs 1 to ${through + 1}`}
                            </span>
                        </div>
                        <p className="mb-4 text-[12.5px] leading-relaxed text-content-muted">
                            How often each detection has fired in the runs that actually reached it.
                            A run nothing reached is left out of the denominator rather than counted
                            as a miss.
                        </p>

                        <div className="mb-1.5 grid grid-cols-[minmax(200px,1fr)_minmax(260px,2.2fr)_120px] gap-x-4 border-b border-border-subtle pb-2 text-[10px] font-semibold uppercase tracking-wide text-content-muted">
                            <span>Detection</span>
                            <span>Reliability against {target}% target</span>
                            <span className="text-right">Fired share</span>
                        </div>

                        {rules.map((rule) => (
                            <BulletRow
                                key={rule.ruleId}
                                rule={rule}
                                target={target}
                                emulationType={history.emulationType}
                                platform={history.platform}
                            />
                        ))}

                        <div className="mt-3 flex flex-wrap items-center gap-5 border-t border-border-subtle pt-3 text-[11px] text-content-muted">
                            <span className="inline-flex items-center gap-2">
                                <i className="h-2 w-5 rounded-sm bg-safe" />
                                Fired share over {judged.length} judged run
                                {judged.length === 1 ? '' : 's'}
                            </span>
                            <span className="inline-flex items-center gap-2">
                                <i className="h-3 w-0.5 bg-content-primary" />
                                {target}% target
                            </span>
                            <span className="inline-flex items-center gap-2">
                                <i className="h-2 w-2 rotate-45 border border-white/45 bg-surface-deep" />
                                Value before the last run
                            </span>
                        </div>
                    </Card>
                </>
            )}
        </div>
    )
}

interface ArchivedRunsProps {
    runs: WorkflowRun[]
    busy: boolean
    onRestore: (runId: string) => void
}

/**
 * Archived runs, with the way back.
 *
 * Rendered both under a populated filmstrip and on its own when every run of
 * an emulation has been archived. Archiving is reversible and nothing purges
 * these on a schedule, so this list is never a dead end.
 */
function ArchivedRuns({ runs, busy, onRestore }: ArchivedRunsProps) {
    return (
        <div className="mt-3 rounded-btn bg-surface-elevated p-3">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-content-muted">
                Archived runs · excluded from every figure above
            </div>
            {runs.map((run) => (
                <div
                    key={run.id}
                    className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle py-2 last:border-0"
                >
                    <div className="min-w-0">
                        <div className="text-[12.5px] text-content-secondary">
                            {gaugeDate(run.completedAt)}
                            {run.summary && (
                                <span className="text-content-muted"> · {run.summary}</span>
                            )}
                        </div>
                        <div className="mt-0.5 text-[10.5px] text-content-muted">
                            archived {gaugeDate(run.archivedAt)}
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={() => onRestore(run.id)}
                        disabled={busy}
                        className="rounded-btn border border-white/10 px-3 py-1 text-xs text-content-dim transition-opacity hover:opacity-60 disabled:opacity-40"
                    >
                        Restore
                    </button>
                </div>
            ))}
        </div>
    )
}

/** Page heading, shared by the empty and populated states. */
function Header() {
    return (
        <div className="mb-6">
            <div className="mb-2 font-mono text-2xs uppercase tracking-label text-accent-blue">
                Detection engineering
            </div>
            <h1 className="font-display text-2xl font-semibold leading-tight text-content-primary">
                Coverage History
            </h1>
            <p className="mt-1.5 text-sm text-content-dim">
                Which of your detections actually fire, measured across every run of an emulation
            </p>
        </div>
    )
}
