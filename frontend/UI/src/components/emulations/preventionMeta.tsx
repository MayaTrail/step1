import type { PreventionAnalysis, PreventionPolicy } from '@/types/prevention'

/**
 * Reading a prevention analysis into what the attack timeline draws.
 *
 * The API is deliberately strict about what it asserts: `blockedBy` carries
 * only unconditional blockers, because whether a conditional policy protects
 * anyone depends on values inside their organisation. A phase covered only by
 * conditional policies is still not the same as one covered by nothing, so the
 * middle state is derived here rather than claimed there.
 */

/** What a phase's shield says. */
export type ShieldState = 'blocks' | 'conditional' | 'open'

/**
 * How a phase fares against the catalogue.
 *
 * @param phaseNumber - The phase to judge.
 * @param analysis - The prevention analysis, or null before it loads.
 */
export function shieldFor(
  phaseNumber: number,
  analysis: PreventionAnalysis | null,
): ShieldState | null {
  if (!analysis?.analysed) return null
  const phase = analysis.phases.find((row) => row.phase === phaseNumber)
  if (phase && phase.blockedBy.length > 0) return 'blocks'
  const conditional = analysis.policies.some(
    (policy) => policy.verdict === 'blocks_conditional' && policy.phases.includes(phaseNumber),
  )
  return conditional ? 'conditional' : 'open'
}

/** Policies bearing on one phase, unconditional first. */
export function policiesFor(
  phaseNumber: number,
  analysis: PreventionAnalysis | null,
): PreventionPolicy[] {
  if (!analysis?.analysed) return []
  return analysis.policies.filter((policy) => policy.phases.includes(phaseNumber))
}

/**
 * The broad perimeter family.
 *
 * Separated because they apply to every phase equally: showing them per phase
 * would repeat the same seven rows five times and crowd out the policies that
 * name the phase's own actions.
 */
export function perimeterPolicies(analysis: PreventionAnalysis | null): PreventionPolicy[] {
  return (analysis?.policies ?? []).filter((policy) => policy.scope === 'broad')
}

const SHIELD_COLOR: Record<ShieldState, string> = {
  blocks: '#5fc992',
  conditional: '#ffbc33',
  open: '#434345',
}

const SHIELD_TITLE: Record<ShieldState, string> = {
  blocks: 'A catalogue policy would refuse this phase outright',
  conditional: 'A catalogue policy would refuse this phase if a condition in your org holds',
  open: 'No catalogue policy denies this phase outright',
}

/**
 * The phase shield.
 *
 * An outline shield rather than a filled badge: it sits on a timeline card
 * that already carries a phase colour, and a second solid block there competes
 * with it.
 */
export function Shield({ state, size = 17 }: { state: ShieldState; size?: number }) {
  const color = SHIELD_COLOR[state]
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      role="img"
      aria-label={SHIELD_TITLE[state]}
    >
      <title>{SHIELD_TITLE[state]}</title>
      <path
        d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"
        strokeDasharray={state === 'open' ? '3 3' : undefined}
      />
      {state === 'blocks' && <path d="M9 12l2 2 4-4" />}
      {state === 'conditional' && (
        <>
          <path d="M12 8v4" />
          <circle cx="12" cy="15.5" r="0.9" fill={color} stroke="none" />
        </>
      )}
    </svg>
  )
}
