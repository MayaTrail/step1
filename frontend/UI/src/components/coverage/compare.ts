import type { CoverageRule, CoverageRun } from '@/types/coverageHistory'

/**
 * Diffing two runs of the same emulation.
 *
 * Comparing two single runs is a verdict diff, not a reliability diff. Within
 * one run a rule either fired or it did not, so its "reliability" is only ever
 * 100 or 0, and drawing that on the bullet chart would imply a measurement that
 * was never taken. What changed between two runs is a set of transitions.
 *
 * Pure functions over the per-run verdicts the coverage payload already
 * carries, so this needs no request of its own.
 */

const FIRED = 'fired'
const NOT_INTEGRATED = 'not_integrated'

/** What happened to one detection between two runs. */
export type ChangeKind =
    /** Fired before, does not fire now. The finding. */
    | 'regressed'
    /** Was not firing, fires now. */
    | 'improved'
    /** Moved between two states that both mean uncaught. */
    | 'changed'
    /** Same verdict in both runs. */
    | 'unchanged'
    /** Judged in only one of the two runs, so nothing can be concluded. */
    | 'unjudged'

export interface ChangeRow {
    ruleId: string
    title: string
    severity: string
    kind: ChangeKind
    /** Verdict in the earlier run, or undefined when it carried no such rule. */
    before?: string
    /** Verdict in the later run, or undefined when it carries no such rule. */
    after?: string
}

export interface RunComparison {
    /** The earlier run, whichever order the caller picked them in. */
    a: CoverageRun
    /** The later run. */
    b: CoverageRun
    rows: ChangeRow[]
    counts: Record<ChangeKind, number>
    /** Coverage points gained or lost, or null when either run was unjudged. */
    delta: number | null
}

/** Rank for ordering: the rows somebody opened this panel to find come first. */
const ORDER: Record<ChangeKind, number> = {
    regressed: 0,
    improved: 1,
    changed: 2,
    unjudged: 3,
    unchanged: 4,
}

/**
 * Classify one rule's move between two runs.
 *
 * A rule judged in only one of the two runs is `unjudged` rather than a
 * regression. Nothing reached it in the other run, so there is no before and
 * after to compare, and calling that a lost detection would blame a rule for a
 * missing alert route.
 */
function classify(before: string | undefined, after: string | undefined): ChangeKind {
    const judgedBefore = before && before !== NOT_INTEGRATED
    const judgedAfter = after && after !== NOT_INTEGRATED
    if (!judgedBefore || !judgedAfter) return 'unjudged'
    if (before === after) return 'unchanged'
    if (before === FIRED) return 'regressed'
    if (after === FIRED) return 'improved'
    return 'changed'
}

/**
 * Compare two runs, oldest first regardless of selection order.
 *
 * @param runA - One selected run.
 * @param runB - The other selected run.
 * @param rules - Rule metadata from the coverage payload, for titles.
 */
export function compareRuns(
    runA: CoverageRun,
    runB: CoverageRun,
    rules: CoverageRule[],
): RunComparison {
    // Order by completion, so "before" and "after" mean what they say even
    // when the reader clicked the newer gauge first.
    const [a, b] =
        (runA.completedAt ?? '') <= (runB.completedAt ?? '') ? [runA, runB] : [runB, runA]

    const counts: Record<ChangeKind, number> = {
        regressed: 0,
        improved: 0,
        changed: 0,
        unchanged: 0,
        unjudged: 0,
    }

    const rows: ChangeRow[] = rules.map((rule) => {
        const before = a.verdicts?.[rule.ruleId]
        const after = b.verdicts?.[rule.ruleId]
        const kind = classify(before, after)
        counts[kind] += 1
        return {
            ruleId: rule.ruleId,
            title: rule.title,
            severity: rule.severity,
            kind,
            before,
            after,
        }
    })

    const severityRank: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
    }
    rows.sort(
        (p, q) =>
            ORDER[p.kind] - ORDER[q.kind]
            || (severityRank[p.severity] ?? 9) - (severityRank[q.severity] ?? 9)
            || p.ruleId.localeCompare(q.ruleId),
    )

    const delta =
        a.coverage !== null && b.coverage !== null ? b.coverage - a.coverage : null

    return { a, b, rows, counts, delta }
}

/** Minutes between the attack ending and an alert arriving, or null. */
export function latencyMinutes(windowEnd: string | null, firedAt?: string | null): number | null {
    if (!windowEnd || !firedAt) return null
    return (new Date(firedAt).getTime() - new Date(windowEnd).getTime()) / 60000
}

/** How long a run kept listening after its attack finished, in minutes. */
export function windowMinutes(run: CoverageRun): number | null {
    if (!run.windowEnd || !run.alertDeadline) return null
    return (
        (new Date(run.alertDeadline).getTime() - new Date(run.windowEnd).getTime()) / 60000
    )
}

/**
 * Whether the shorter run stopped listening before the other run's slowest
 * alert arrived.
 *
 * This is the caveat that keeps the panel honest. Two runs with different
 * alert windows are not a fair comparison: a detection that reports on a slow
 * schedule looks silent in the shorter run with nothing wrong with it, and
 * without saying so the panel would invite a bug report against a working rule.
 *
 * @returns The facts behind the warning, or null when the runs are comparable.
 */
export function windowMismatch(
    a: CoverageRun,
    b: CoverageRun,
): { shorter: number; longer: number; slowestAlert: number } | null {
    const wa = windowMinutes(a)
    const wb = windowMinutes(b)
    if (wa === null || wb === null || Math.abs(wa - wb) < 0.5) return null

    // The latest any alert arrived in the run that listened longer. An alert
    // at that latency would have been missed by the shorter run.
    const longerRun = wa > wb ? a : b
    const latencies = Object.values(longerRun.outcomes ?? {})
        .map((outcome) => latencyMinutes(longerRun.windowEnd, outcome.evidence?.firedAt))
        .filter((value): value is number => value !== null)
    const slowest = latencies.length ? Math.max(...latencies) : null

    const shorter = Math.min(wa, wb)
    if (slowest === null || slowest < shorter) return null
    return { shorter, longer: Math.max(wa, wb), slowestAlert: slowest }
}
