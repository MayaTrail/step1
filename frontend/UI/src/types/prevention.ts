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
  /**
   * True when the manifest declares this phase's actions, including declaring
   * none. An empty `actions` with `annotated` true is a verified finding: the
   * phase performs nothing IAM authorises. With it false the phase has simply
   * not been mapped, and no prevention verdict can be given.
   */
  annotated: boolean
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

/**
 * What the caller's own policies would do, as AWS evaluates them.
 *
 * The middle of three confidence levels. `catalogue` above says a published
 * sample policy would refuse an action if it were deployed; this says the
 * caller's real policies refuse it now. Neither is `observed`, which only an
 * actual refusal during a run can establish, so neither may change a
 * detection score.
 */

/** Per-action outcome of the account check. */
export type CheckVerdict = 'allowed' | 'denied' | 'undecided'

/**
 * Who refused the action.
 *
 * `organization_scp` and `permissions_boundary` are guardrails working.
 * `identity_policy` means the connected role simply lacks the permission,
 * which stops the attack for an unrelated reason and is never prevention.
 */
export type DeniedBy = 'organization_scp' | 'permissions_boundary' | 'identity_policy'

/** One action, as AWS judged it. */
export interface CheckedAction {
  action: string
  verdict: CheckVerdict
  deniedBy: DeniedBy | null
  /** Condition keys AWS needed and we could not supply, so the answer is not final. */
  missingContext: string[]
}

/** A phase's verdict, folded up from its actions. */
export interface CheckedPhase {
  phase: number
  name: string
  verdict: CheckVerdict | 'no_iam_call' | 'role_cannot_perform'
  preventedActions: string[]
  undecidedActions: string[]
  roleCannotPerform: string[]
}

/** The account check's result. */
export interface AccountCheck {
  emulationType: string
  displayName: string
  /** Always "simulated". */
  basis: string
  region: string
  /** The connected role's name, never its ARN. */
  identity: string
  summary: {
    actionsChecked: number
    prevented: string[]
    undecided: string[]
    roleCannotPerform: string[]
    allowed: string[]
  }
  actions: CheckedAction[]
  phases: CheckedPhase[]
}

/** Why a check could not run, with the fix when there is one. */
export interface AccountCheckError {
  detail: string
  /** Set when the connected role is missing iam:SimulatePrincipalPolicy. */
  missingPermission: string | null
}
