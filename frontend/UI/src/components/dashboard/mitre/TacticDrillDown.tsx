import { useNavigate } from 'react-router-dom'
import type { TacticDetail, TechniqueRef } from '@/types/metrics'

/**
 * Tactic drill-down panel.
 *
 * Shows the covered and missing techniques for the selected tactic, the related
 * emulations / playbooks / detections, and a recommendation.  This is the
 * analyst-facing layer the old matrix lacked entirely.
 */

interface TacticDrillDownProps {
    detail: TacticDetail | null
    loading: boolean
    /** True once a tactic has been selected (controls the empty hint vs loading). */
    hasSelection: boolean
}

function TechniqueChip({ technique, covered }: { technique: TechniqueRef; covered: boolean }) {
    return (
        <span
            title={`${technique.id} · ${technique.name}`}
            className={`inline-flex items-center gap-1.5 rounded-btn border px-2 py-0.5 font-mono text-2xs ${
                covered
                    ? 'bg-safe-dim border-safe/25 text-safe'
                    : 'bg-surface-elevated border-border text-content-muted'
            }`}
        >
            {technique.id}
        </span>
    )
}

function RelatedStat({ label, value }: { label: string; value: string | number }) {
    return (
        <div className="flex flex-col">
            <span className="font-display text-base font-bold tabular-nums leading-none text-content-primary">
                {value}
            </span>
            <span className="font-mono text-2xs uppercase tracking-label text-content-muted mt-1">{label}</span>
        </div>
    )
}

export function TacticDrillDown({ detail, loading, hasSelection }: TacticDrillDownProps) {
    const navigate = useNavigate()

    if (!hasSelection) {
        return (
            <div className="px-5 py-8 text-center text-sm text-content-dim">
                Select a tactic above to drill into its covered and missing techniques.
            </div>
        )
    }
    if (loading || !detail) {
        return <div className="px-5 py-8 text-center text-sm text-content-dim">Loading…</div>
    }

    return (
        <div className="flex flex-col gap-5 px-5 py-5">
            <div className="flex items-center justify-between gap-3">
                <span className="text-sm font-semibold text-content-primary">{detail.tactic.name}</span>
                <span className="font-mono text-xs text-content-secondary tabular-nums">
                    {detail.tactic.coveredCount}/{detail.tactic.techniqueCount} · {detail.tactic.pct}%
                </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="flex flex-col gap-2">
                    <span className="font-mono text-2xs uppercase tracking-label text-safe">
                        Covered ({detail.covered.length})
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                        {detail.covered.length === 0 ? (
                            <span className="text-xs text-content-dim">None yet.</span>
                        ) : (
                            detail.covered.map((t) => <TechniqueChip key={t.id} technique={t} covered />)
                        )}
                    </div>
                </div>
                <div className="flex flex-col gap-2">
                    <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
                        Missing ({detail.missing.length})
                    </span>
                    <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                        {detail.missing.length === 0 ? (
                            <span className="text-xs text-content-dim">Fully covered.</span>
                        ) : (
                            detail.missing.map((t) => <TechniqueChip key={t.id} technique={t} covered={false} />)
                        )}
                    </div>
                </div>
            </div>

            <div className="flex flex-wrap items-center gap-6 pt-1">
                <RelatedStat label="Emulations" value={detail.relatedEmulations.length} />
                <RelatedStat label="Playbooks" value={detail.relatedPlaybooks} />
                <RelatedStat label="Detections" value={detail.relatedDetections} />
                {detail.relatedEmulations.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                        {detail.relatedEmulations.map((e) => (
                            <button
                                key={e.id}
                                type="button"
                                onClick={() => navigate(`/aws/emulations/${e.id}`)}
                                className="rounded-btn border border-border bg-surface-elevated px-2 py-0.5 text-2xs text-content-secondary transition-opacity hover:opacity-70"
                            >
                                {e.name}
                            </button>
                        ))}
                    </div>
                )}
            </div>

            <div className="flex items-start gap-2 rounded-btn border border-accent-blue/25 bg-accent-blue/10 px-3 py-2.5">
                <span className="mt-0.5 shrink-0 text-accent-blue">▸</span>
                <p className="text-xs text-content-secondary">{detail.recommendation}</p>
            </div>
        </div>
    )
}
