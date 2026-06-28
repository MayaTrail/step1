import { Fragment, useState } from 'react'
import type { Emulation } from '@/types'
import { useDetections } from '@/hooks/usePlatformData'
import { Card } from '@/components/ui/Card'
import { MetricCard } from '@/components/ui/MetricCard'
import { TacticBadge } from '@/components/ui/TacticBadge'

/**
 * MITRE Mapping tab. Connects the emulation's ATT&CK techniques to the rest of
 * the platform: summary metrics, a filterable technique table, and an
 * expandable row that links out to MITRE and shows which kill-chain phase the
 * technique runs in.
 *
 * Every column is backed by data that already exists. Per-technique detection
 * coverage (Available / Partial / Unavailable) is intentionally absent: the
 * detection files are not tagged to individual techniques, so a coverage column
 * would be guesswork. Detection volume is shown once, at the summary level,
 * where it is accurate.
 */

/** Phase accent colors, shared with the Attack Path timeline. */
const PHASE_COLORS = ['#f87171', '#ff6b35', '#fbbf24', '#00d4ff', '#a78bfa', '#10b981']

interface MitreMappingTabProps {
  emulation: Emulation
  platformLabel: string
}

interface PhaseRef {
  phase: number
  name: string
  color: string
}

/** Build the canonical MITRE ATT&CK URL for a technique or sub-technique id. */
function mitreUrl(id: string): string {
  const [main, sub] = id.split('.')
  return sub
    ? `https://attack.mitre.org/techniques/${main}/${sub}/`
    : `https://attack.mitre.org/techniques/${main}/`
}

export function MitreMappingTab({ emulation: em, platformLabel }: MitreMappingTabProps) {
  const { data: detections } = useDetections(em.id)
  const [openId, setOpenId] = useState<string | null>(null)
  const [tacticFilter, setTacticFilter] = useState<string>('all')

  // technique id -> the kill-chain phase it runs in (with the phase's color).
  const phaseByTech = new Map<string, PhaseRef>()
  em.attackPath.forEach((p, i) => {
    const color = PHASE_COLORS[i % PHASE_COLORS.length] ?? PHASE_COLORS[0]
    p.techniques.forEach((t) => phaseByTech.set(t.id, { phase: p.phase, name: p.name, color: color! }))
  })

  const tactics = Array.from(new Set(em.mitreMappings.map((m) => m.tactic)))
  const rows =
    tacticFilter === 'all'
      ? em.mitreMappings
      : em.mitreMappings.filter((m) => m.tactic === tacticFilter)

  return (
    <div className="flex flex-col gap-4 animate-fadeIn">
      {/* ── Summary metrics ─────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <MetricCard accent="neutral" label="Techniques" value={em.techniqueCount || em.mitreMappings.length} />
        <MetricCard accent="neutral" label="Tactics" value={tactics.length} />
        <MetricCard accent="neutral" label="AWS Services" value={em.services?.length ?? 0} />
        <MetricCard
          accent="neutral"
          label="Detection Rules"
          value={detections?.totalCount ?? '—'}
          caption={detections?.formats}
        />
      </div>

      {/* ── Tactic filter ───────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-2xs uppercase tracking-label text-content-dim mr-1">Tactic</span>
        <FilterChip label="All" active={tacticFilter === 'all'} onClick={() => setTacticFilter('all')} />
        {tactics.map((t) => (
          <FilterChip key={t} label={t} active={tacticFilter === t} onClick={() => setTacticFilter(t)} />
        ))}
      </div>

      {/* ── Technique table ─────────────────────────────────────────── */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                {['Technique', 'Tactic', 'Phase', 'Platform', 'Description', ''].map((h, i) => (
                  <th
                    key={h || `c${i}`}
                    className="text-left px-4 py-3 font-mono text-2xs tracking-label text-content-dim uppercase border-b border-border bg-white/[0.01]"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((mt) => {
                const ph = phaseByTech.get(mt.id)
                const open = openId === mt.id
                return (
                  <Fragment key={mt.id}>
                    <tr
                      onClick={() => setOpenId(open ? null : mt.id)}
                      className="cursor-pointer transition-colors hover:bg-white/[0.02] align-top"
                    >
                      <td className="px-4 py-3.5 border-b border-border">
                        <div className="flex flex-col gap-1.5">
                          <span className="font-mono text-[11px] text-danger bg-danger/[0.06] border border-danger/15 rounded-[4px] px-2 py-0.5 w-fit">
                            {mt.id}
                          </span>
                          <span className="text-[13px] font-medium text-content-primary">{mt.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 border-b border-border">
                        <TacticBadge tactic={mt.tactic} />
                      </td>
                      <td className="px-4 py-3.5 border-b border-border whitespace-nowrap">
                        {ph ? (
                          <span
                            className="font-mono text-[10px] px-2 py-0.5 rounded-[5px]"
                            style={{ color: ph.color, backgroundColor: `${ph.color}1a`, border: `1px solid ${ph.color}33` }}
                          >
                            P{ph.phase}
                          </span>
                        ) : (
                          <span className="text-content-dim">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5 border-b border-border font-mono text-[11px] text-content-secondary whitespace-nowrap">
                        {mt.platform}
                      </td>
                      <td className="px-4 py-3.5 border-b border-border max-w-[360px]">
                        <span className={`text-[12px] text-content-dim leading-relaxed ${open ? '' : 'line-clamp-2'}`}>
                          {mt.description}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 border-b border-border text-content-dim">
                        <span className={`inline-block transition-transform ${open ? 'rotate-90' : ''}`}>{'›'}</span>
                      </td>
                    </tr>
                    {open && (
                      <tr>
                        <td colSpan={6} className="border-b border-border bg-surface-base px-4 py-4">
                          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
                            {ph && (
                              <DetailItem label="Runs In">
                                <span style={{ color: ph.color }}>Phase {ph.phase}</span>
                                <span className="text-content-secondary"> · {ph.name}</span>
                              </DetailItem>
                            )}
                            <DetailItem label="Platform">
                              <span className="text-content-secondary">{mt.platform}</span>
                            </DetailItem>
                            <DetailItem label="Reference">
                              <a
                                href={mitreUrl(mt.id)}
                                target="_blank"
                                rel="noreferrer noopener"
                                onClick={(e) => e.stopPropagation()}
                                className="text-accent-blue no-underline hover:underline"
                              >
                                attack.mitre.org/{mt.id} {'↗'}
                              </a>
                            </DetailItem>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <p className="font-mono text-2xs text-content-dim">
        ATT&amp;CK mapping for {platformLabel}. Select a row for the phase context and MITRE reference.
      </p>
    </div>
  )
}

/* ── Local presentational helpers ──────────────────────────────────── */

function FilterChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`font-mono text-[10px] tracking-caps uppercase rounded-[7px] px-3 py-1.5 border transition-all
        ${active
          ? 'text-content-primary border-border-active bg-surface-card'
          : 'text-content-dim border-border bg-surface-base hover:border-border-active'}`}
    >
      {label}
    </button>
  )
}

function DetailItem({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-2xs uppercase tracking-label text-content-dim">{label}</span>
      <span className="font-mono text-[11px]">{children}</span>
    </div>
  )
}
