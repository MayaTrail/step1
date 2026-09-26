import { useEffect, useRef, useState } from 'react'
import type { Emulation, MitreMapping } from '@/types'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { TacticBadge } from '@/components/ui/TacticBadge'
import { getPrevention } from '@/services/prevention.service'
import type { PreventionAnalysis, PreventionPolicy } from '@/types/prevention'
import { GuardrailDrawer } from './GuardrailDrawer'
import { Shield, perimeterPolicies, policiesFor, shieldFor } from './preventionMeta'

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
 *
 * Prevention is an annotation here rather than a tab of its own. It was one
 * briefly, and it redrew these same phases as a static list with three
 * paragraphs of preamble: a second kill chain, less interactive than this one,
 * saying the same thing backwards. A shield on each timeline card and a block
 * in the panel carry it without a duplicate view, and the policy documents
 * live in a drawer because they are reference a reader dips into and leaves.
 */

/** Phase accent colors, shared with the Overview attack-summary timeline. */
const PHASE_COLORS = ['#f87171', '#ff6b35', '#fbbf24', '#00d4ff', '#a78bfa', '#10b981']

interface AttackPathTabProps {
  emulation: Emulation
  /** Platform segment for links into the guardrail library. */
  platformId: string
}

export function AttackPathTab({ emulation: em, platformId }: AttackPathTabProps) {
  const phases = em.attackPath
  const [active, setActive] = useState(0)
  const [prevention, setPrevention] = useState<PreventionAnalysis | null>(null)
  const [openPolicy, setOpenPolicy] = useState<PreventionPolicy | null>(null)
  const [openPerimeter, setOpenPerimeter] = useState(false)

  // Prevention is supplementary: a failure leaves the attack path intact and
  // simply shows no shields, rather than taking the tab down with it.
  useEffect(() => {
    let cancelled = false
    setPrevention(null)
    getPrevention(em.id)
      .then((result) => !cancelled && setPrevention(result))
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [em.id])

  // Keep the selected phase visible when the timeline overflows horizontally
  // (long kill chains scroll rather than grow). Skip the initial mount so the
  // page does not jump on first render.
  const activeBtnRef = useRef<HTMLButtonElement | null>(null)
  const firstRender = useRef(true)
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false
      return
    }
    activeBtnRef.current?.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' })
  }, [active])

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
                  ref={selected ? activeBtnRef : undefined}
                  onClick={() => setActive(i)}
                  className={`relative flex-1 min-w-[150px] text-left rounded-[10px] px-4 py-3 cursor-pointer
                    border bg-surface-base transition-[border-color,transform]
                    hover:border-border-active hover:-translate-y-0.5
                    ${selected ? 'border-border-active' : 'border-border'}`}
                >
                  {/* The phase accent, on its own element so it neither fights
                      the hover border nor changes the box size. */}
                  <span
                    aria-hidden="true"
                    className={`absolute inset-x-3.5 top-0 h-0.5 rounded-b-sm transition-opacity
                      ${selected ? 'opacity-100' : 'opacity-0'}`}
                    style={{ backgroundColor: c }}
                  />
                  {shieldFor(p.phase, prevention) && (
                    <span className="absolute right-3 top-2.5">
                      <Shield state={shieldFor(p.phase, prevention)!} />
                    </span>
                  )}
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
        {prevention?.analysed && (
          <p className="mt-3.5 text-[11.5px] leading-relaxed text-content-dim">
            The shield on each phase is what a <b className="font-semibold text-content-secondary">
            catalogue policy would do</b> if you deployed it. Solid blocks outright, amber depends on
            a condition in your organisation, dashed means nothing in the library denies it.
          </p>
        )}
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

        {/* ── Prevention for this phase ─────────────────────────────── */}
        {prevention?.analysed && (
          <div className="mt-5 border-t border-border pt-5">
            {(() => {
              const forPhase = policiesFor(phase.phase, prevention)
              const perimeter = perimeterPolicies(prevention)
              const named = forPhase.filter((item) => item.scope === 'targeted')
              // Declared actions live on the prevention payload: the emulation
              // type predates the manifest field and does not carry them.
              const declared = prevention.phases.find((row) => row.phase === phase.phase)?.actions
              return (
                <>
                  <div className="mb-2.5 font-mono text-2xs uppercase tracking-label text-content-dim">
                    Prevention
                    {named.length > 0
                      && ` — ${named.length} ${named.length === 1 ? 'policy' : 'policies'} would refuse this phase`}
                  </div>

                  {named.length === 0 ? (
                    <div className="rounded-btn border-l-2 border-border-active bg-surface-elevated px-3.5 py-3 text-[12.5px] leading-relaxed text-content-dim">
                      No library policy denies{' '}
                      <span className="font-mono text-content-secondary">
                        {declared?.join(', ') || 'these actions'}
                      </span>{' '}
                      outright. That is expected for ordinary read calls: a policy blocking them
                      would break normal use of the resource.
                    </div>
                  ) : (
                    named.map((item) => {
                      const blocks = item.verdict === 'blocks'
                      return (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => setOpenPolicy(item)}
                          className={`group mb-1.5 flex w-full items-start gap-3 rounded-btn border-l-2 bg-surface-elevated px-3.5 py-3 text-left transition-opacity hover:opacity-70 ${
                            blocks ? 'border-safe' : 'border-warning'
                          }`}
                        >
                          <span className="mt-0.5 flex-none">
                            <Shield state={blocks ? 'blocks' : 'conditional'} size={16} />
                          </span>
                          <span className="min-w-0 flex-1">
                            <span className="flex items-center gap-2 text-[13px] text-content-primary">
                              {item.purpose}
                              <span className="font-mono text-[10px] text-content-dim">
                                {item.type}
                              </span>
                            </span>
                            <span className="mt-1.5 flex flex-wrap gap-1">
                              {item.actions.map((action) => (
                                <span
                                  key={action}
                                  className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                                    blocks ? 'bg-safe/10 text-safe' : 'bg-warning/10 text-warning'
                                  }`}
                                >
                                  {action}
                                </span>
                              ))}
                            </span>
                            <span className="mt-1.5 block text-[11px] leading-relaxed text-content-dim">
                              {blocks
                                ? 'Unconditional deny. If deployed, these actions fail for every principal.'
                                : `Denies this unless ${item.conditionKeys[0]} is satisfied, a value only your organisation knows.`}
                            </span>
                          </span>
                          <span className="flex-none text-accent-blue opacity-0 transition-opacity group-hover:opacity-100">
                            &rsaquo;
                          </span>
                        </button>
                      )
                    })
                  )}

                  {perimeter.length > 0 && (
                    <p className="mt-2.5 text-[11.5px] text-content-dim">
                      {perimeter.length} data-perimeter policies also apply to every phase
                      {' — '}
                      <button
                        type="button"
                        onClick={() => setOpenPerimeter(true)}
                        className="text-accent-blue transition-opacity hover:opacity-60"
                      >
                        see them
                      </button>
                    </p>
                  )}
                </>
              )
            })()}
          </div>
        )}

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

      <GuardrailDrawer
        policy={openPolicy}
        perimeter={perimeterPolicies(prevention)}
        showPerimeter={openPerimeter}
        platformId={platformId}
        onClose={() => {
          setOpenPolicy(null)
          setOpenPerimeter(false)
        }}
      />
    </div>
  )
}
