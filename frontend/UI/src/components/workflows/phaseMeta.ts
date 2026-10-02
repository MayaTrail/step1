import type { AttackPhase } from '@/types/platform'
import type { PreventionAnalysis } from '@/types/prevention'
import type { RuleOutcome } from '@/types/workflow'
import { shieldFor } from '@/components/emulations/preventionMeta'

/**
 * Joining a run's detection verdicts onto the emulation's attack phases.
 *
 * The run stores one verdict per rule, each carrying the ATT&CK technique it
 * detects; the MANIFEST lists the techniques each phase uses. The join is on
 * the technique id, so everything here is about making two spellings of the
 * same id agree.
 */

/**
 * Spell a technique id the ATT&CK way.
 *
 * Reports stored before the backend learned to read "T1685_002" still carry
 * that spelling, and a report is never rewritten, so the join has to accept it.
 *
 * @param value - A technique id as the run recorded it.
 */
export function canonicalTechnique(value: string): string {
  return value.toUpperCase().replace(/^(T\d{4})_(\d{3})$/, '$1.$2')
}

/**
 * Whether a rule detects one of a phase's techniques.
 *
 * A rule for a sub-technique (T1098.001) belongs to a phase that lists only
 * the parent (T1098). The reverse is not assumed: a rule for the parent does
 * not prove coverage of one specific sub-technique.
 */
function belongsTo(rule: RuleOutcome, phase: AttackPhase): boolean {
  const technique = canonicalTechnique(rule.technique || '')
  if (!technique) return false
  const ids = new Set(phase.techniques.map((t) => t.id.toUpperCase()))
  return ids.has(technique) || ids.has(technique.split('.')[0] ?? '')
}

/**
 * The rules whose technique belongs to a phase.
 *
 * @param phase - One attack phase.
 * @param rules - Every rule verdict from the run.
 */
export function rulesForPhase(phase: AttackPhase, rules: RuleOutcome[]): RuleOutcome[] {
  return rules.filter((rule) => belongsTo(rule, phase))
}

/**
 * The rules that belong to no phase.
 *
 * Listed separately rather than dropped: a per-phase layout would otherwise
 * hide them, while the detection score still counts them.
 *
 * @param phases - The emulation's attack phases.
 * @param rules - Every rule verdict from the run.
 */
export function unplacedRules(phases: AttackPhase[], rules: RuleOutcome[]): RuleOutcome[] {
  return rules.filter((rule) => !phases.some((phase) => belongsTo(rule, phase)))
}

/** How many phases the catalogue would block outright, and how many only conditionally. */
export interface PreventionCounts {
  outright: number
  conditional: number
  total: number
}

/**
 * Count the phases by what the catalogue would do to them.
 *
 * @param phases - The emulation's attack phases.
 * @param analysis - The prevention analysis.
 */
export function preventionCounts(
  phases: AttackPhase[],
  analysis: PreventionAnalysis,
): PreventionCounts {
  const states = phases.map((phase) => shieldFor(phase.phase, analysis))
  return {
    outright: states.filter((state) => state === 'blocks').length,
    conditional: states.filter((state) => state === 'conditional').length,
    total: phases.length,
  }
}
