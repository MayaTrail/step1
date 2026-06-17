/**
 * SecurityContextTab — the security meaning of a deployed stack (Milestone 3).
 *
 * A deployed enterprise stack is always tied to exactly one emulation
 * (`stack.emulation_type`). This tab surfaces that emulation's security context
 * — the ATT&CK kill chain it exercises, its severity-derived risk, and how many
 * detections cover it — directly in the stack view, so an operator understands
 * "what attack does this environment represent, and is it detected?" without
 * leaving for the emulation catalogue.
 *
 * Frontend-only and stack-level: it reuses the existing emulation endpoints
 * (listEmulations / getEmulationDetections) keyed by emulation_type and adds no
 * new data. Per-resource (per-node) associations require authored
 * resource→technique mappings and are a later phase.
 */

import { useEffect, useState } from 'react'
import type { Emulation, DetectionData, Severity } from '@/types'
import { listEmulations, getEmulationDetections } from '@/services/emulation.service'
import { Badge } from '@/components/ui/Badge'
import { emulationLabel } from '@/components/dashboard/stackHelpers'

type RiskTone = 'red' | 'yellow' | 'neutral'

function riskTone(severity: Severity): RiskTone {
    if (severity === 'CRITICAL' || severity === 'HIGH') return 'red'
    if (severity === 'MEDIUM') return 'yellow'
    return 'neutral'
}

export function SecurityContextTab({ emulationType }: { emulationType?: string }) {
    const [emulation, setEmulation] = useState<Emulation | null>(null)
    const [detections, setDetections] = useState<DetectionData | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        if (!emulationType) {
            setLoading(false)
            return
        }
        let cancelled = false
        setLoading(true)
        setError(null)

        Promise.all([
            listEmulations(),
            getEmulationDetections(emulationType).catch(() => null),
        ])
            .then(([emus, dets]) => {
                if (cancelled) return
                setEmulation(emus.find((e) => e.id === emulationType) ?? null)
                setDetections(dets)
            })
            .catch(() => { if (!cancelled) setError('Failed to load security context.') })
            .finally(() => { if (!cancelled) setLoading(false) })

        return () => { cancelled = true }
    }, [emulationType])

    // ── States ──
    if (!emulationType) {
        return (
            <Notice
                title="No security context"
                body="This stack isn't associated with an emulation, so there's no ATT&CK or detection context to show."
            />
        )
    }
    if (loading) {
        return (
            <div className="flex items-center gap-2 text-content-dim font-mono text-xs py-8 justify-center">
                <span className="inline-block w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
                Loading security context…
            </div>
        )
    }
    if (error || !emulation) {
        return (
            <Notice
                title="Security context unavailable"
                body={error ?? `No emulation metadata found for "${emulationLabel(emulationType)}".`}
            />
        )
    }

    const techniqueCount = emulation.mitreMappings?.length || emulation.techniqueCount || 0
    const phaseCount = emulation.attackPath?.length ?? 0
    const detectionCount = detections?.totalCount ?? 0

    return (
        <div className="flex flex-col gap-5">
            {/* Header */}
            <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                    <div className="font-display text-[1rem] font-bold text-content-primary leading-tight">
                        {emulation.name || emulationLabel(emulationType)}
                    </div>
                    {emulation.attribution && (
                        <div className="font-mono text-[11px] text-content-dim mt-0.5 truncate">
                            {emulation.attribution}
                        </div>
                    )}
                </div>
                <Badge tone={riskTone(emulation.severity)} mono>
                    {emulation.severity} RISK
                </Badge>
            </div>

            {/* Stat tiles */}
            <div className="grid grid-cols-3 gap-3">
                <Stat label="ATT&CK Techniques" value={techniqueCount} />
                <Stat label="Kill-Chain Phases" value={phaseCount} />
                <Stat label="Detections" value={detectionCount} />
            </div>

            {/* Kill chain */}
            {emulation.attackPath && emulation.attackPath.length > 0 && (
                <div>
                    <div className="font-mono text-[10px] uppercase tracking-[1px] text-content-dim mb-2">
                        ATT&CK Kill Chain
                    </div>
                    <div className="flex flex-col gap-2">
                        {emulation.attackPath.map((phase) => (
                            <div
                                key={phase.phase}
                                className="bg-surface-base border border-border rounded-btn px-3 py-2.5"
                            >
                                <div className="flex items-center gap-2 mb-1.5">
                                    <span className="font-mono text-[9px] font-bold text-accent-blue bg-accent-blue/10 border border-accent-blue/25 rounded-[4px] px-1.5 py-0.5">
                                        {String(phase.phase).padStart(2, '0')}
                                    </span>
                                    <span className="font-body text-[12px] font-semibold text-content-primary">
                                        {phase.name}
                                    </span>
                                </div>
                                <div className="flex flex-wrap gap-1.5">
                                    {phase.techniques.map((t) => (
                                        <span
                                            key={t.id}
                                            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-btn bg-surface-card border border-border
                                                font-mono text-[10px] text-content-secondary"
                                            title={t.name}
                                        >
                                            <span className="text-accent-blue font-semibold">{t.id}</span>
                                            <span className="truncate max-w-[180px]">{t.name}</span>
                                        </span>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Detection coverage */}
            <div>
                <div className="font-mono text-[10px] uppercase tracking-[1px] text-content-dim mb-2">
                    Detection Coverage
                </div>
                {detectionCount > 0 ? (
                    <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-content-secondary">
                        <Badge tone="green" mono>{detectionCount} RULES</Badge>
                        {detections && (
                            <span className="text-content-dim">
                                {detections.sigma.length} Sigma &middot; {detections.kql.length} KQL
                            </span>
                        )}
                    </div>
                ) : (
                    <div className="font-mono text-[11px] text-content-dim">
                        No detection rules published for this emulation.
                    </div>
                )}
            </div>
        </div>
    )
}

/* ── Sub-components ── */

function Stat({ label, value }: { label: string; value: number }) {
    return (
        <div className="bg-surface-base border border-border rounded-btn px-3 py-2.5">
            <div className="font-display text-[1.3rem] font-bold text-content-primary leading-none tabular-nums">
                {value}
            </div>
            <div className="font-mono text-[9px] uppercase tracking-[1px] text-content-dim mt-1.5">
                {label}
            </div>
        </div>
    )
}

function Notice({ title, body }: { title: string; body: string }) {
    return (
        <div className="rounded-card border border-border bg-surface-deep px-6 py-10 text-center">
            <div className="font-body text-[0.95rem] text-content-secondary mb-1">{title}</div>
            <div className="font-mono text-[11px] text-content-dim leading-[1.6] max-w-[380px] mx-auto">{body}</div>
        </div>
    )
}
