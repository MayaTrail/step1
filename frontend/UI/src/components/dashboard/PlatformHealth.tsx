import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { IconShield } from '@/components/ui/Icons'
import { listStacks } from '@/services/stack.service'
import { useCachedResource } from '@/hooks/useCachedResource'
import type { Stack } from '@/types'
import { activeStacks, deriveTelemetry, formatAge } from './stackHelpers'

/**
 * Platform Health — vertical stat list for the side-by-side dashboard layout.
 *
 * Shows operational + emulation metrics derived from the stack list: active,
 * healthy, failed, last deployment, expiring soon, AWS regions, success rate,
 * and live emulation status (running / completed).
 */

const HEALTHY_STATUSES = new Set<Stack['status']>(['ready', 'ready_for_attack', 'attack_complete'])

interface HealthStat {
    label: string
    value: string | number
    valueClass?: string
    caption?: string
}

function StatRow({ stat }: { stat: HealthStat }) {
    return (
        <div className="flex items-center justify-between px-4 py-3 border-b border-border last:border-b-0">
            <div className="min-w-0">
                <span className="block font-mono text-2xs uppercase tracking-label text-content-dim">
                    {stat.label}
                </span>
                {stat.caption && (
                    <span className="block font-mono text-2xs text-content-muted mt-0.5">
                        {stat.caption}
                    </span>
                )}
            </div>
            <span className={`font-display text-sm font-bold tabular-nums leading-none shrink-0 ${stat.valueClass ?? 'text-content-primary'}`}>
                {stat.value}
            </span>
        </div>
    )
}

export function PlatformHealth() {
    const { data, loading } = useCachedResource('platform-health-stacks', listStacks)
    const stacks = data ?? []

    const telemetry = deriveTelemetry(stacks)
    const healthy = stacks.filter((s) => HEALTHY_STATUSES.has(s.status)).length
    const lastDeployedAt = stacks
        .map((s) => s.created_at)
        .filter(Boolean)
        .sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0]

    const regions = new Set(activeStacks(stacks).map((s) => s.region).filter(Boolean))
    const total = stacks.length
    const successRate = total > 0 ? Math.round(((total - telemetry.failed) / total) * 100) : 0
    const completed = stacks.filter((s) => s.status === 'attack_complete').length

    const stats: HealthStat[] = [
        { label: 'Active Stacks', value: loading ? '—' : telemetry.active, valueClass: 'text-accent-blue' },
        { label: 'Healthy', value: loading ? '—' : healthy, valueClass: 'text-safe' },
        {
            label: 'Failed Deployments',
            value: loading ? '—' : telemetry.failed,
            valueClass: telemetry.failed > 0 ? 'text-danger' : 'text-content-primary',
        },
        {
            label: 'Last Deployment',
            value: loading ? '—' : lastDeployedAt ? `${formatAge(lastDeployedAt)} ago` : 'None',
        },
        {
            label: 'Expiring Soon',
            value: loading ? '—' : telemetry.expiringSoon,
            valueClass: telemetry.expiringSoon > 0 ? 'text-warning' : 'text-content-primary',
            caption: 'Within 1 hour',
        },
        {
            label: 'AWS Regions',
            value: loading ? '—' : regions.size,
            caption: loading ? undefined : regions.size > 0 ? [...regions].join(', ') : 'No active regions',
        },
        {
            label: 'Success Rate',
            value: loading ? '—' : `${successRate}%`,
            valueClass: successRate >= 90 ? 'text-safe' : successRate >= 70 ? 'text-warning' : 'text-danger',
            caption: loading ? undefined : `${total - telemetry.failed}/${total} deployments`,
        },
        {
            label: 'Emulations Running',
            value: loading ? '—' : telemetry.attacking,
            valueClass: telemetry.attacking > 0 ? 'text-warning' : 'text-content-primary',
        },
        {
            label: 'Emulations Completed',
            value: loading ? '—' : completed,
            valueClass: 'text-safe',
        },
    ]

    return (
        <Card className="flex flex-col">
            <div className="flex items-center justify-between px-4 py-3.5 border-b border-border">
                <span className="flex items-center gap-2 font-mono text-2xs uppercase tracking-label text-content-dim">
                    <IconShield size={14} />
                    Platform Health
                </span>
                {!loading && telemetry.expiringSoon > 0 && (
                    <Badge tone="yellow" mono dot pulse>
                        {telemetry.expiringSoon} expiring
                    </Badge>
                )}
            </div>
            <div className="flex flex-col flex-1">
                {stats.map((stat) => (
                    <StatRow key={stat.label} stat={stat} />
                ))}
            </div>
        </Card>
    )
}
