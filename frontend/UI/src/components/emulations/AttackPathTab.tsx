import { useState } from 'react'
import type { Emulation, MitreMapping } from '@/types'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { TacticBadge } from '@/components/ui/TacticBadge'

/**
 * Attack Path tab. Turns the kill chain into an interactive workspace: a
 * horizontal timeline selects a phase, and the detail panel narrates that
 * phase using the technique data the MANIFEST already provides.
 *
 * Each phase technique is joined to its full MITRE mapping (by technique id)
 * so the panel can show the tactic, platform, and a real description rather
 * than just a name. Per-phase metadata the PRD envisions (duration, risk,
 * telemetry, artifacts) has no authored source yet, so it is left out instead
 * of being faked; it can land later as a MANIFEST enrichment.
 */

/** Phase accent colors, shared with the Overview attack-summary timeline. */
const PHASE_COLORS = ['#f87171', '#ff6b35', '#fbbf24', '#00d4ff', '#a78bfa', '#10b981']

interface AttackPathTabProps {
  emulation: Emulation
}

export function AttackPathTab({ emulation: em }: AttackPathTabProps) {
  const phases = em.attackPath
  const [active, setActive] = useState(0)

  if (phases.length === 0) {
    return (
      <Card className="p-6">
        <p className="text-content-secondary text-sm">No attack phases are defined for this emulation.</p>
      </Card>
    )
  }

  // technique id -> full MITRE mapping, so a phase can show rich detail.
  const mitreById = new Map<string, MitreMapping>(em.mitreMappings.map((m) => [m.id, m]))
  const phase = phases[active]
  if (!phase) return null
  const color = PHASE_COLORS[active % PHASE_COLORS.length] ?? PHASE_COLORS[0]

  return (
    <div className="flex flex-col gap-4 animate-fadeIn">
      {/* ── Horizontal timeline selector ────────────────────────────── */}
      <Card className="p-6">
        <div className="font-mono text-2xs tracking-label uppercase text-content-dim mb-4">
          Attack Timeline
        </div>
        <div className="flex items-stretch overflow-x-auto pb-1">
          {phases.map((p, i) => {
            const c = PHASE_COLORS[i % PHASE_COLORS.length]
            const selected = i === active
            const isLast = i === phases.length - 1
            return (
              <div key={p.phase} className="flex items-center">
                <button
                  onClick={() => setActive(i)}
                  className={`flex-1 min-w-[150px] text-left rounded-[10px] px-4 py-3 cursor-pointer transition-all
                    border bg-surface-base hover:border-border-active hover:-translate-y-0.5
                    ${selected ? 'border-border-active' : 'border-border'}`}
                  style={selected ? { borderTopColor: c, borderTopWidth: '2px' } : undefined}
                >
                  <div className="font-mono text-[9px] tracking-label uppercase" style={{ color: c }}>
                    Phase {p.phase}
                  </div>
                  <div className="text-[0.8rem] font-semibold text-content-primary mt-1.5">{p.name}</div>
                  <div className="font-mono text-[10px] text-content-dim mt-1">
                    {p.techniques.map((t) => t.id).join(' · ')}
                  </div>
                </button>
                {!isLast && <span className="text-content-dim px-1.5 shrink-0">{'→'}</span>}
              </div>
            )
          })}
        </div>
      </Card>

      {/* ── Phase detail panel ──────────────────────────────────────── */}
      <Card className="p-6">
        <div className="flex items-center gap-3 mb-5">
          <span
            className="font-mono text-2xs tracking-label uppercase px-2.5 py-1 rounded-btn"
            style={{ color, backgroundColor: `${color}1a`, border: `1px solid ${color}40` }}
          >
            Phase {phase.phase} of {phases.length}
          </span>
          <span className="text-xl font-semibold text-content-primary">{phase.name}</span>
        </div>

        {/* one block per technique, enriched from the MITRE mapping */}
        <div className="flex flex-col gap-3">
          {phase.techniques.map((tech) => {
            const m = mitreById.get(tech.id)
            return (
              <div key={tech.id} className="bg-surface-base border border-border rounded-[10px] p-4">
                <div className="flex flex-wrap items-center gap-2.5 mb-2">
                  <span className="font-mono text-[11px] text-danger bg-danger/[0.06] border border-danger/15 rounded-[4px] px-2 py-0.5">
                    {tech.id}
                  </span>
                  <span className="text-[0.9rem] font-semibold text-content-primary">{tech.name}</span>
                  {m && <TacticBadge tactic={m.tactic} />}
                  {m?.platform && (
                    <span className="font-mono text-[10px] text-content-dim ml-auto">{m.platform}</span>
                  )}
                </div>
                {m?.description && (
                  <p className="text-[0.85rem] leading-relaxed text-content-secondary font-medium">
                    {m.description}
                  </p>
                )}
              </div>
            )
          })}
        </div>

        {/* phase navigation */}
        <div className="flex justify-between mt-6 pt-5 border-t border-border">
          <Button
            variant="secondary"
            disabled={active === 0}
            onClick={() => setActive((i) => Math.max(0, i - 1))}
          >
            {'←'} Previous Phase
          </Button>
          <Button
            variant="secondary"
            disabled={active === phases.length - 1}
            onClick={() => setActive((i) => Math.min(phases.length - 1, i + 1))}
          >
            Next Phase {'→'}
          </Button>
        </div>
      </Card>
    </div>
  )
}
