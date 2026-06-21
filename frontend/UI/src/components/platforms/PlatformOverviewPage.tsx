import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { usePlatformOverview } from '@/hooks/usePlatformOverview'
import { useEmulations } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import { attackSurfaceFor } from '@/data/attackSurface'
import type { PlatformId, Emulation } from '@/types'
import { MetricCard } from '@/components/ui/MetricCard'
import { severityColorClass } from '@/components/ui/SeverityBadge'
import {
  IconFlask, IconSearch, IconClipboard, IconLayers, IconShield,
} from '@/components/ui/Icons'

/** Row caps so each box stays a consistent height with internal scroll. */
const TOP_TECHNIQUES = 6
const RECENT_LIMIT = 5

export function PlatformOverviewPage() {
  const { platformId } = useParams<{ platformId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const navigate = useNavigate()

  const { coverage, mitre, loading } = usePlatformOverview(pid)
  const { data: allEmulations } = useEmulations(pid)

  // The catalogue endpoint returns every emulation regardless of platform, so
  // filter to this platform for the per-platform boxes.
  const emulations = useMemo(
    () => (allEmulations ?? []).filter((e) => e.platform === pid),
    [allEmulations, pid],
  )

  const label = meta?.label ?? pid?.toUpperCase() ?? ''
  const shortLabel = pid?.toUpperCase() ?? ''

  return (
    <div className="lg:h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Platform
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          {label}
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          What Mayatrail can currently do on {shortLabel}
        </div>
      </div>

      {/* Summary tiles */}
      <SectionLabel>Summary</SectionLabel>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 mb-2">
        <MetricCard
          accent="red" loading={loading} icon={<IconFlask size={16} />}
          value={coverage?.emulations ?? 0} label="Emulations" caption="available"
          onClick={() => navigate('/emulations')}
        />
        <MetricCard
          accent="blue" loading={loading} icon={<IconSearch size={16} />}
          value={coverage?.detections ?? 0} label="Detections" caption="SIGMA + KQL"
          onClick={() => navigate('/detections')}
        />
        <MetricCard
          accent="green" loading={loading} icon={<IconClipboard size={16} />}
          value={coverage?.playbooks ?? 0} label="Playbooks" caption="IR guides"
          onClick={() => navigate('/playbooks')}
        />
        <MetricCard
          accent="amber" loading={loading} icon={<IconLayers size={16} />}
          value={
            <>
              {mitre?.coveredTechniques ?? 0}
              <span className="text-[18px] text-content-dim">/{mitre?.totalTechniques ?? 0}</span>
            </>
          }
          label="MITRE Techniques" caption="covered / total"
        />
        <MetricCard
          accent="neutral" icon={<IconShield size={16} />}
          value="—" label="Guardrails" caption="coming soon"
        />
      </div>

      {/* Detail boxes — always rendered (empty platforms show per-box empty states).
          On lg the row absorbs leftover viewport height (lg:flex-1) so the boxes
          stretch and Quick Actions pins to the bottom; each box body scrolls
          internally when its content overflows. */}
      <SectionLabel>Coverage &amp; Activity</SectionLabel>
      <div className="flex flex-col lg:flex-row gap-4 mb-2 items-stretch lg:flex-1 lg:min-h-0">
        <AttackSurfaceBox platform={pid} emulations={emulations} />
        <TopTechniquesBox emulations={emulations} mitreTotal={mitre?.totalTechniques ?? 0} mitreCovered={mitre?.coveredTechniques ?? 0} />
        <RecentlyAddedBox platform={pid} emulations={emulations} />
      </div>

      {/* Quick Actions — always at the bottom */}
      <SectionLabel>Quick Actions</SectionLabel>
      <div className="flex flex-wrap gap-3">
        <QuickAction to="/emulations" icon={<IconFlask size={16} />} label="Browse Emulations" />
        <QuickAction to="/detections" icon={<IconSearch size={16} />} label="Browse Detections" />
        <QuickAction to="/playbooks" icon={<IconClipboard size={16} />} label="Browse Playbooks" />
        <QuickAction to="/guardrails" icon={<IconShield size={16} />} label="Browse Guardrails" />
      </div>
    </div>
  )
}

/* ── Uniform box shell ────────────────────────────────────────────────────── */

interface OverviewBoxProps {
  title: string
  /** Right-aligned headline metric, e.g. "5/12" or "2 added". */
  headline: ReactNode
  /** Optional 0–100 bar; omit for boxes with no honest denominator. */
  pct?: number
  children: ReactNode
}

/**
 * Equal-height card used for the three detail boxes. Header (title + headline)
 * over an optional progress bar, then a fixed-height body that scrolls so all
 * three boxes line up regardless of content length.
 */
function OverviewBox({ title, headline, pct, children }: OverviewBoxProps) {
  return (
    <div className="flex-1 min-w-0 lg:min-h-0 bg-surface-card border border-border rounded-card shadow-ring p-5 flex flex-col
      transition-colors hover:border-border-active">
      <div className="flex items-baseline justify-between gap-2 mb-3">
        <span className="font-display text-base font-bold text-content-primary">{title}</span>
        <span className="font-mono text-[13px] text-content-secondary whitespace-nowrap">{headline}</span>
      </div>
      {pct != null && (
        <div className="h-2 rounded-full bg-surface-elevated overflow-hidden mb-4">
          <div className="h-full bg-accent-blue rounded-full transition-all duration-300" style={{ width: `${pct}%` }} />
        </div>
      )}
      <div className="flex-1 min-h-[160px] lg:min-h-0 overflow-y-auto pr-1">{children}</div>
    </div>
  )
}

/** Centered empty-state used inside a box body when there's no data. */
function BoxEmpty({ text }: { text: string }) {
  return (
    <div className="h-full min-h-[150px] flex items-center justify-center text-center">
      <span className="text-sm text-content-dim">{text}</span>
    </div>
  )
}

/* ── Attack Surface Coverage ──────────────────────────────────────────────── */

function AttackSurfaceBox({ platform, emulations }: { platform: PlatformId; emulations: Emulation[] }) {
  const categories = attackSurfaceFor(platform)
  const covered = useMemo(
    () => new Set(emulations.flatMap((e) => e.services ?? [])),
    [emulations],
  )

  const totalServices = categories.reduce((n, c) => n + c.services.length, 0)
  const coveredServices = categories.reduce(
    (n, c) => n + c.services.filter((s) => covered.has(s)).length,
    0,
  )
  const pct = totalServices ? Math.round((coveredServices / totalServices) * 100) : 0

  return (
    <OverviewBox
      title="Attack Surface Coverage"
      headline={categories.length ? `${coveredServices}/${totalServices} services` : '—'}
      pct={categories.length ? pct : undefined}
    >
      {categories.length === 0 ? (
        <BoxEmpty text="No attack-surface data yet" />
      ) : (
        <div className="flex flex-col gap-3">
          {categories.map((cat) => {
            const c = cat.services.filter((s) => covered.has(s)).length
            const cpct = cat.services.length ? Math.round((c / cat.services.length) * 100) : 0
            return (
              <div key={cat.name} className="flex items-center gap-3">
                <span className="text-sm text-content-secondary w-[92px] shrink-0 truncate">{cat.name}</span>
                <div className="flex-1 h-2 rounded-full bg-surface-elevated overflow-hidden">
                  <div className={`h-full rounded-full ${c ? 'bg-accent-blue' : 'bg-transparent'}`} style={{ width: `${cpct}%` }} />
                </div>
                <span className="font-mono text-[12px] text-content-dim w-8 text-right">{c}/{cat.services.length}</span>
              </div>
            )
          })}
        </div>
      )}
    </OverviewBox>
  )
}

/* ── Top Techniques ───────────────────────────────────────────────────────── */

function TopTechniquesBox({ emulations, mitreCovered, mitreTotal }: { emulations: Emulation[]; mitreCovered: number; mitreTotal: number }) {
  const ranked = useMemo(() => {
    const byId = new Map<string, { id: string; name: string; count: number }>()
    for (const em of emulations) {
      for (const m of em.mitreMappings ?? []) {
        const existing = byId.get(m.id)
        if (existing) existing.count += 1
        else byId.set(m.id, { id: m.id, name: m.name, count: 1 })
      }
    }
    return Array.from(byId.values())
      .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
      .slice(0, TOP_TECHNIQUES)
  }, [emulations])

  const pct = mitreTotal ? Math.round((mitreCovered / mitreTotal) * 100) : 0

  return (
    <OverviewBox
      title="Top Techniques"
      headline={`${mitreCovered}/${mitreTotal} covered`}
      pct={pct}
    >
      {ranked.length === 0 ? (
        <BoxEmpty text="No technique data yet" />
      ) : (
        <div className="flex flex-col gap-2.5">
          {ranked.map((t) => (
            <div key={t.id} className="flex items-center gap-3">
              <span className="font-mono text-[13px] text-accent-blue font-semibold w-[84px] shrink-0">{t.id}</span>
              <span className="text-sm text-content-secondary truncate flex-1">{t.name}</span>
              <span className="font-mono text-[12px] text-content-dim whitespace-nowrap">×{t.count}</span>
            </div>
          ))}
        </div>
      )}
    </OverviewBox>
  )
}

/* ── Recently Added (count headline, no bar — no honest denominator) ───────── */

function RecentlyAddedBox({ platform, emulations }: { platform: PlatformId; emulations: Emulation[] }) {
  const recent = useMemo(
    () =>
      [...emulations]
        .sort((a, b) => (b.added ?? '').localeCompare(a.added ?? ''))
        .slice(0, RECENT_LIMIT),
    [emulations],
  )

  return (
    <OverviewBox
      title="Recently Added"
      headline={`${emulations.length} emulation${emulations.length === 1 ? '' : 's'}`}
    >
      {recent.length === 0 ? (
        <BoxEmpty text="No emulations yet" />
      ) : (
        <div className="flex flex-col gap-2">
          {recent.map((em) => (
            <Link
              key={em.id}
              to={`/${platform}/emulations/${em.id}`}
              className="flex items-center gap-3 px-3 py-2.5 -mx-1 rounded-lg no-underline transition-colors hover:bg-white/[0.03]"
            >
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-content-primary truncate">{em.name}</div>
                {em.added && <div className="font-mono text-[11px] text-content-dim mt-0.5">Added {em.added}</div>}
              </div>
              <span className={`font-mono text-[11px] font-bold shrink-0 ${severityColorClass(em.severity)}`}>{em.severity}</span>
            </Link>
          ))}
        </div>
      )}
    </OverviewBox>
  )
}

/* ── Shared bits ──────────────────────────────────────────────────────────── */

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="font-mono text-[10px] uppercase tracking-[2px] text-content-dim font-bold mt-7 mb-3.5">
      {children}
    </div>
  )
}

function QuickAction({ to, icon, label }: { to: string; icon: ReactNode; label: string }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-2.5 px-4 py-2.5 rounded-lg border border-[rgba(255,255,255,0.12)]
        text-content-primary text-sm font-semibold no-underline transition-opacity hover:opacity-60"
    >
      <span className="text-accent-blue">{icon}</span>
      {label}
    </Link>
  )
}
