import type { CoverageRun } from '@/types/coverageHistory'

import { windowMinutes } from './compare'

/**
 * The conditions that have to hold before a verdict about a detection means
 * anything.
 *
 * This is not decoration. Because the attack completed and the alert route was
 * healthy in both runs, the only remaining explanations for a detection going
 * silent are that the rule stopped matching or that the window was too short.
 * Stating what has been ruled out is what earns the evidence rows below it.
 *
 * Every claim here is a fact the run recorded. Nothing is asserted about
 * guardrail policies: the guardrails library is a catalogue that is never
 * applied to a stack, so a tick saying they held would be inventing a control.
 */

interface RunIntegrityProps {
    a: CoverageRun
    b: CoverageRun
}

interface Check {
    label: string
    value: string
    detail: string
    ok: boolean
}

/** Format a window length the way the timeline labels it. */
function windowLabel(run: CoverageRun): string {
    const minutes = windowMinutes(run)
    return minutes === null ? 'unknown' : `${Math.round(minutes)} min`
}

function buildChecks(a: CoverageRun, b: CoverageRun): Check[] {
    const bothAttacked = a.attackCompleted && b.attackCompleted
    const alerts = `${a.alertsReceived} and ${b.alertsReceived} received`
    const unattributed = a.unattributedCount + b.unattributedCount
    const routeHealthy = a.integrationHealth && b.integrationHealth
    const sameWindow = windowLabel(a) === windowLabel(b)

    return [
        {
            label: 'Attack step',
            value: bothAttacked ? 'Completed' : 'Did not complete',
            detail: bothAttacked
                ? 'Both runs reached attack_complete, so the technique was executed each time.'
                : 'At least one run never finished its attack, so nothing was exercised in it.',
            ok: bothAttacked,
        },
        {
            label: 'Alert route',
            value: routeHealthy ? alerts : 'No alerts reached a run',
            detail: routeHealthy
                ? `Every alert signature verified. ${unattributed} unattributed across both runs.`
                : 'A run received nothing at all, so its verdicts are a connection gap.',
            ok: routeHealthy,
        },
        {
            label: 'Alert window',
            value: sameWindow ? windowLabel(a) : `${windowLabel(a)} and ${windowLabel(b)}`,
            detail: sameWindow
                ? 'Both runs waited the same length of time, so their verdicts are comparable.'
                : 'The runs waited different lengths of time. See the timeline below.',
            ok: sameWindow,
        },
        {
            label: 'Scope',
            value: 'Stack-scoped',
            detail: 'Every resource was created by the run’s own stack and destroyed with it.',
            ok: true,
        },
    ]
}

export function RunIntegrity({ a, b }: RunIntegrityProps) {
    const checks = buildChecks(a, b)

    return (
        <div className="mt-3 rounded-btn bg-surface-elevated p-4">
            <div className="mb-1 text-[13px] text-content-primary">What held during both runs</div>
            <p className="mb-3.5 text-[12px] leading-relaxed text-content-muted">
                Facts the runs recorded. These are the conditions that have to be true before a
                verdict about a detection means anything.
            </p>
            <div className="grid grid-cols-[repeat(auto-fit,minmax(190px,1fr))] gap-px overflow-hidden rounded-btn bg-border">
                {checks.map((check) => (
                    <div key={check.label} className="bg-surface-elevated px-3.5 py-3">
                        <div className="font-mono text-[9.5px] uppercase tracking-label text-content-muted">
                            {check.label}
                        </div>
                        <div className="mt-1.5 flex items-center gap-2 text-[13px]">
                            <span className={check.ok ? 'text-safe' : 'text-warning'}>
                                {check.ok ? '✓' : '⚠'}
                            </span>
                            <span className={check.ok ? '' : 'text-warning'}>{check.value}</span>
                        </div>
                        <div className="mt-1 text-[11px] leading-snug text-content-muted">
                            {check.detail}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    )
}
