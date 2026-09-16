import type { ReactNode } from 'react'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { IconShield } from '@/components/ui/Icons'
import { listStacks } from '@/services/stack.service'
import { useUiMode } from '@/context/UiModeContext'
import { useCachedResource } from '@/hooks/useCachedResource'
import type { Stack } from '@/types'
import { activeStacks, deriveTelemetry, formatAge } from './stackHelpers'

/**
 * Platform Health — vertical stat list for the side-by-side dashboard layout.
 *
 * Shows operational + emulation metrics derived from the stack list: active,
 * healthy, failed, last deployment, expiring soon, AWS regions, success rate,
 * and live emulation status (running / completed).
 *
 * Classic renders all nine as one flat list. Simple mode de-densifies it (the
 * critique's "nine identical rows, no way in" finding): three headline numbers
 * as a scannable strip, then the rest under two small group labels -
 * Deployments and Simulations - so the eye has somewhere to land.
 */

const HEALTHY_STATUSES = new Set<Stack['status']>(['ready', 'ready_for_attack', 'attack_complete'])

interface HealthStat {
    label: string
    value: string | number
    valueClass?: string
    caption?: string
    /** Simple-mode placement: a headline tile, or which labelled group it sits in. */
    band?: 'headline' | 'deployments' | 'emulations'
    /** Shorter, plainer label used in Simple mode. */
    plainLabel?: string
}

function GroupLabel({ children }: { children: ReactNode }) {
    return (
        <div className="px-4 pt-3 pb-1.5 font-mono text-2xs uppercase tracking-label text-content-muted bg-surface-deep border-b border-border">
            {children}
        </div>
    )
}

function StatRow({ stat, plain = false }: { stat: HealthStat; plain?: boolean }) {
    return (
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-border last:border-b-0">
            <div className="min-w-0">
                <span
                    className={
                        plain
                            ? 'block text-xs text-content-secondary'
                            : 'block font-mono text-2xs uppercase tracking-label text-content-dim'
                    }
                >
                    {plain ? (stat.plainLabel ?? stat.label) : stat.label}
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
    const { plain } = useUiMode()
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
        {
            label: 'Active Stacks',
            plainLabel: 'Active',
            value: loading ? '—' : telemetry.active,
            valueClass: 'text-accent-blue',
            band: 'headline',
        },
        {
            label: 'Healthy',
            plainLabel: 'Healthy',
            value: loading ? '—' : healthy,
            valueClass: 'text-safe',
            band: 'headline',
        },
        {
            label: 'Failed Deployments',
            plainLabel: 'Failed',
            value: loading ? '—' : telemetry.failed,
            valueClass: telemetry.failed > 0 ? 'text-danger' : 'text-content-primary',
            band: 'headline',
        },
        {
            label: 'Last Deployment',
            plainLabel: 'Last deployment',
            value: loading ? '—' : lastDeployedAt ? `${formatAge(lastDeployedAt)} ago` : 'None',
            band: 'deployments',
        },
        {
            label: 'Expiring Soon',
            plainLabel: 'Expiring soon',
            value: loading ? '—' : telemetry.expiringSoon,
            valueClass: telemetry.expiringSoon > 0 ? 'text-warning' : 'text-content-primary',
            caption: 'Within 1 hour',
            band: 'deployments',
        },
        {
            label: 'AWS Regions',
            plainLabel: 'Regions in use',
            value: loading ? '—' : regions.size,
            caption: loading ? undefined : regions.size > 0 ? [...regions].join(', ') : 'No active regions',
            band: 'deployments',
        },
        {
            label: 'Success Rate',
            plainLabel: 'Deployments that worked',
            value: loading ? '—' : `${successRate}%`,
            valueClass: successRate >= 90 ? 'text-safe' : successRate >= 70 ? 'text-warning' : 'text-danger',
            caption: loading ? undefined : `${total - telemetry.failed}/${total} deployments`,
            band: 'deployments',
        },
        {
            label: 'Emulations Running',
            plainLabel: 'Running now',
            value: loading ? '—' : telemetry.attacking,
            valueClass: telemetry.attacking > 0 ? 'text-warning' : 'text-content-primary',
            band: 'emulations',
        },
        {
            label: 'Emulations Completed',
            plainLabel: 'Finished',
            value: loading ? '—' : completed,
            valueClass: 'text-safe',
            band: 'emulations',
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
            {plain ? (
                <div className="flex flex-col flex-1">
                    <div className="grid grid-cols-3 divide-x divide-border border-b border-border">
                        {stats
                            .filter((stat) => stat.band === 'headline')
                            .map((stat) => (
                                <div key={stat.label} className="px-4 py-4 text-center">
                                    <div
                                        className={`font-display text-2xl font-bold tabular-nums leading-none ${stat.valueClass ?? 'text-content-primary'}`}
                                    >
                                        {stat.value}
                                    </div>
                                    <div className="font-mono text-2xs uppercase tracking-label text-content-dim mt-1.5">
                                        {stat.plainLabel ?? stat.label}
                                    </div>
                                </div>
                            ))}
                    </div>
                    <GroupLabel>Deployments</GroupLabel>
                    {stats
                        .filter((stat) => stat.band === 'deployments')
                        .map((stat) => (
                            <StatRow key={stat.label} stat={stat} plain />
                        ))}
                    <GroupLabel>Simulations</GroupLabel>
                    {stats
                        .filter((stat) => stat.band === 'emulations')
                        .map((stat) => (
                            <StatRow key={stat.label} stat={stat} plain />
                        ))}
                </div>
            ) : (
                <div className="flex flex-col flex-1">
                    {stats.map((stat) => (
                        <StatRow key={stat.label} stat={stat} />
                    ))}
                </div>
            )}
        </Card>
    )
}
