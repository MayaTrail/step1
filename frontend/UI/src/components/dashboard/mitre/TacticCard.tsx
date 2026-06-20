import type { TacticCoverage } from '@/types/metrics'
import { STATUS_BAR, STATUS_TEXT } from './status'

/**
 * A single tactic coverage card: name, percentage, status dot, a colored
 * progress bar, the covered/total count, and a one-line insight.  Clicking
 * selects the tactic for drill-down.  Replaces the unreadable column of tiny
 * technique cells with a scannable, status-colored summary.
 */

interface TacticCardProps {
    tactic: TacticCoverage
    selected: boolean
    onSelect: (shortname: string) => void
}

export function TacticCard({ tactic, selected, onSelect }: TacticCardProps) {
    return (
        <button
            type="button"
            onClick={() => onSelect(tactic.shortname)}
            className={`flex flex-col gap-2.5 rounded-btn border bg-surface-base px-3.5 py-3 text-left transition-all hover:-translate-y-px ${
                selected ? 'border-accent-blue' : 'border-border hover:border-border-active'
            }`}
        >
            <div className="flex items-start justify-between gap-2">
                <span className="text-sm font-medium text-content-primary leading-tight line-clamp-2">
                    {tactic.name}
                </span>
                <span className={`mt-0.5 shrink-0 ${STATUS_TEXT[tactic.status]}`}>
                    <span className="block w-2 h-2 rounded-full bg-current" />
                </span>
            </div>

            <div className="flex items-end justify-between gap-2">
                <span className={`font-display text-xl font-bold tabular-nums leading-none ${STATUS_TEXT[tactic.status]}`}>
                    {tactic.pct}%
                </span>
                <span className="font-mono text-2xs text-content-muted">
                    {tactic.coveredCount}/{tactic.techniqueCount}
                </span>
            </div>

            <div className="h-1.5 w-full rounded-full bg-surface-elevated overflow-hidden">
                <span
                    className={`block h-full rounded-full ${STATUS_BAR[tactic.status]}`}
                    style={{ width: `${Math.max(tactic.pct, tactic.pct > 0 ? 2 : 0)}%` }}
                />
            </div>

            <span className="font-mono text-2xs text-content-muted">{tactic.insight}</span>
        </button>
    )
}
