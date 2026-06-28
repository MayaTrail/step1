import { useNavigate } from 'react-router-dom'
import { Card } from '@/components/ui/Card'
import { listStacks } from '@/services/stack.service'
import { useCachedResource } from '@/hooks/useCachedResource'
import type { Stack } from '@/types'
import { deriveTelemetry, formatAge } from './stackHelpers'

/**
 * Platform Health — Band D operational strip.
 *
 * A deliberately compact, muted footer of engineering metrics (active / healthy
 * stacks, failed deployments, last deployment) so operators retain awareness
 * without infrastructure stats dominating the security-focused dashboard.
 * Clicking through goes to the dedicated Stacks section.
 */

/** Stack statuses considered "healthy" — successfully operating, not in-flight or failed. */
const HEALTHY_STATUSES = new Set<Stack['status']>(['ready', 'ready_for_attack', 'attack_complete'])

interface HealthStat {
    label: string
    value: string | number
    /** Tailwind text-colour class for the value (defaults to primary). */
    valueClass?: string
}

function StatCell({ stat }: { stat: HealthStat }) {
    return (
        <div className="flex flex-col px-4 py-3">
            <span className={`font-display text-lg font-bold tabular-nums leading-none ${stat.valueClass ?? 'text-content-primary'}`}>
                {stat.value}
            </span>
            <span className="font-mono text-2xs uppercase tracking-label text-content-muted mt-1.5">
                {stat.label}
            </span>
        </div>
    )
}

export function PlatformHealth() {
    const navigate = useNavigate()
    // Stale-while-revalidate: seeds from cache on revisit (no flash), never blanks.
    const { data, loading } = useCachedResource('platform-health-stacks', listStacks)
    const stacks = data ?? []

    const telemetry = deriveTelemetry(stacks)
    const healthy = stacks.filter((s) => HEALTHY_STATUSES.has(s.status)).length
    const lastDeployedAt = stacks
        .map((s) => s.created_at)
        .filter(Boolean)
        .sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0]

    const stats: HealthStat[] = [
        { label: 'Active Stacks', value: loading ? '—' : telemetry.active, valueClass: 'text-accent-blue' },
        { label: 'Healthy Stacks', value: loading ? '—' : healthy, valueClass: 'text-safe' },
        {
            label: 'Failed Deployments',
            value: loading ? '—' : telemetry.failed,
            valueClass: telemetry.failed > 0 ? 'text-danger' : 'text-content-primary',
        },
        {
            label: 'Last Deployment',
            value: loading ? '—' : lastDeployedAt ? `${formatAge(lastDeployedAt)} ago` : 'None',
        },
    ]

    return (
        <Card interactive onClick={() => navigate('/stacks')} className="flex flex-col">
            <div className="px-4 pt-3 pb-1.5">
                <span className="font-mono text-2xs uppercase tracking-label text-content-dim">Platform Health</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-y sm:divide-y-0 divide-border border-t border-border">
                {stats.map((stat) => (
                    <StatCell key={stat.label} stat={stat} />
                ))}
            </div>
        </Card>
    )
}
