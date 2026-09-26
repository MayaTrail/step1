/**
 * Types for guardrail prevention analysis (/api/guardrails/emulation/<type>/).
 *
 * Which library policies would refuse the actions an emulation performs. Every
 * verdict here means "if you deployed this": the library is a catalogue of
 * published AWS samples, and MayaTrail does not read the caller's own
 * Organization policies. `basis` carries that so a client cannot render the
 * result as protection already in place.
 */

/** How certainly a policy would refuse the action. */
export type PreventionVerdict =
  /** Denies the action with no condition attached. */
  | 'blocks'
  /** Denies it, but a Condition decides, and its values are the reader's. */
  | 'blocks_conditional'

/**
 * How precisely a policy addresses this attack.
 *
 * `targeted` names the actions or a narrow prefix of them; `broad` matched
 * through a service-wide wildcard such as `s3:*`. Targeted policies rank
 * first, because a policy naming the action is a more useful answer than one
 * that happened to include it.
 */
export type PreventionScope = 'targeted' | 'broad'

/** One catalogue policy, judged against the attack. */
export interface PreventionPolicy {
  id: string
  purpose: string
  /** Service or resource control policy. */
  type: string
  source: { label?: string; url?: string }
  verdict: PreventionVerdict
  scope: PreventionScope
  /** Attack actions this policy would refuse. */
  actions: string[]
  /**
   * Condition keys a reader has to check against their own organisation.
   * Empty on a `blocks` verdict.
   */
  conditionKeys: string[]
  /**
   * Phases this policy would interrupt. Deliberately empty for a broad match:
   * a policy denying `s3:*` touches every phase of an S3 attack, which
   * restates the wildcard rather than saying anything about the emulation.
   */
  phases: number[]
}

/** One attack phase, with what would refuse it. */
export interface PreventionPhase {
  phase: number
  name: string
  /** AWS actions this phase performs, declared in the emulation manifest. */
  actions: string[]
  /** Ids of policies that would refuse it outright. Conditional ones excluded. */
  blockedBy: string[]
}

/** Everything the Prevention section renders. */
export interface PreventionAnalysis {
  emulationType: string
  displayName: string
  /** Platform the emulation belongs to, for links into the guardrail library. */
  platform?: string
  /**
   * False when no phase declares its AWS actions. The section then says the
   * emulation has not been analysed, which is not the same as "no policy
   * applies" and must not be rendered as it.
   */
  analysed: boolean
  /** Always "catalogue": published samples, not the caller's deployed policies. */
  basis: string
  actions: string[]
  phases: PreventionPhase[]
  policies: PreventionPolicy[]
  counts: {
    blocks: number
    blocks_conditional: number
    targeted: number
    broad: number
  }
}
