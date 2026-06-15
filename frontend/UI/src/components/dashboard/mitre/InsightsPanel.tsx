import type { CoverageInsight } from '@/types/metrics'

/**
 * Actionable insights strip — turns the coverage data into plain-language
 * guidance ("X coverage is only Y%", "N uncovered techniques under Z").
 */

const SEVERITY_DOT: Record<CoverageInsight['severity'], string> = {
    high: 'text-danger',
    medium: 'text-warning',
    info: 'text-accent-blue',
}

export function InsightsPanel({ insights }: { insights: CoverageInsight[] }) {
    if (insights.length === 0) return null

    return (
        <div className="flex flex-col gap-2.5 px-5 py-4 border-t border-border">
            <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
                Actionable Insights
            </span>
            {insights.map((insight, i) => (
                <div key={i} className="flex items-start gap-2.5">
                    <span className={`mt-1 shrink-0 ${SEVERITY_DOT[insight.severity]}`}>
                        <span className="block w-1.5 h-1.5 rounded-full bg-current" />
                    </span>
                    <p className="text-xs text-content-secondary">{insight.text}</p>
                </div>
            ))}
        </div>
    )
}
