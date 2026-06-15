import { lazy, Suspense, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { getCoverageSummary } from '@/services/metrics.service'
import type { CoverageSummary } from '@/types/metrics'
import { Button } from '@/components/ui/Button'
import { Card } from '@/components/ui/Card'
import { MetricCard } from '@/components/ui/MetricCard'
import { IconLaunch } from '@/components/ui/Icons'
import { ActivityFeed } from './ActivityFeed'
import { PlatformHealth } from './PlatformHealth'

// Lazy-loaded: these pull in Recharts, which we keep out of the initial/login
// bundle since the charts only appear on the dashboard.
const MitreCoverageSection = lazy(() =>
    import('./mitre/MitreCoverageSection').then((m) => ({ default: m.MitreCoverageSection })),
)
const PlatformThreatCoverage = lazy(() =>
    import('./PlatformThreatCoverage').then((m) => ({ default: m.PlatformThreatCoverage })),
)

/**
 * DashboardPage — security validation overview.
 *
 * Answers "how much of the threat landscape can Mayatrail emulate and validate?"
 * rather than "how many infrastructure resources exist?".  Laid out in bands:
 *   A. KPI cards (coverage score, runs, detections, last run)   — /metrics/summary
 *   B. Threat Coverage + MITRE heatmap + Platform Coverage      — /metrics/*
 *   C. Recent Activity
 * Each Band-B widget fetches its own endpoint and owns its loading state; this
 * page only fetches the lightweight KPI summary.
 */

/** Format an ISO timestamp as a coarse relative age, e.g. "2 hours ago". */
function formatRelative(iso: string | null): string {
    if (!iso) return 'No runs yet'
    const then = new Date(iso).getTime()
    if (Number.isNaN(then)) return '—'
    const seconds = Math.round((Date.now() - then) / 1000)
    if (seconds < 60) return 'Just now'
    const minutes = Math.round(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.round(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.round(hours / 24)
    return `${days}d ago`
}

export function DashboardPage() {
    const navigate = useNavigate()
    const { user } = useAuth()

    const [summary, setSummary] = useState<CoverageSummary | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        let active = true
        getCoverageSummary()
            .then((d) => active && setSummary(d))
            .catch(() => active && setSummary(null))
            .finally(() => active && setLoading(false))
        return () => {
            active = false
        }
    }, [])

    const hour = new Date().getHours()
    const greeting = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'
    const firstName = user?.name?.trim().split(' ')[0] || user?.username || 'there'

    return (
        <div className="animate-fadeIn flex flex-col gap-8">
            {/* ── Header ── */}
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div>
                    <span className="inline-flex items-center gap-1.5 font-mono text-2xs uppercase tracking-label mb-3 rounded-btn border px-2 py-0.5 text-safe bg-safe-dim border-safe/25">
                        <span className="w-1.5 h-1.5 rounded-full bg-current" />
                        Security validation
                    </span>
                    <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
                        {greeting}, {firstName}
                    </h1>
                    <p className="text-sm text-content-dim mt-1">
                        How much of the threat landscape Mayatrail can emulate and validate.
                    </p>
                </div>
                <Button variant="cta" size="lg" onClick={() => navigate('/aws/emulations')} icon={<IconLaunch size={16} />}>
                    Deploy emulation
                </Button>
            </div>

            {/* ── Band A — KPI cards ── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard
                    accent="red"
                    value={summary ? `${summary.aptCoverageScore}%` : '—'}
                    label="APT Coverage Score"
                    loading={loading}
                    caption={
                        summary
                            ? `${summary.coveredTechniques}/${summary.totalTechniques} techniques · ATT&CK v${summary.attackVersion}`
                            : undefined
                    }
                />
                <MetricCard
                    accent="blue"
                    value={summary ? summary.emulationsExecuted.toLocaleString() : '—'}
                    label="Emulations Executed"
                    loading={loading}
                    caption="Total emulation runs"
                    onClick={() => navigate('/stacks')}
                />
                <MetricCard
                    accent="green"
                    value={summary ? summary.detectionCoverage.toLocaleString() : '—'}
                    label="Detection Coverage"
                    loading={loading}
                    caption="Detection rules available"
                />
                <MetricCard
                    accent="amber"
                    value={summary ? formatRelative(summary.lastSuccessfulRun) : '—'}
                    label="Last Successful Run"
                    loading={loading}
                    caption="Most recent completed emulation"
                />
            </div>

            {/* ── Band B — Coverage (the hero zone) ── */}
            <Suspense
                fallback={
                    <Card className="px-5 py-16 text-center text-sm text-content-dim">Loading…</Card>
                }
            >
                <MitreCoverageSection />
                <PlatformThreatCoverage />
            </Suspense>

            {/* ── Band C — Recent Activity ── */}
            <ActivityFeed />

            {/* ── Band D — Platform Health (compact operational strip) ── */}
            <PlatformHealth />
        </div>
    )
}
