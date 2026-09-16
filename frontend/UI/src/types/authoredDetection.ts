/**
 * Types for authored (user-written / AI-generated) detection rules.
 * Endpoint family: /api/detections/authored/
 *
 * The writable counterpart to the read-only rules that ship in the emulation
 * packages. `sigma` is Sigma YAML - the same format the shipped rules and the
 * SIEM converter speak - so an authored rule validates, exports and renders
 * through the same paths.
 */

export type AuthoredStatus = 'draft' | 'published'
export type AuthoredVisibility = 'private' | 'organization'
export type AuthoredOrigin = 'manual' | 'generated'

/** A rule without its Sigma body, for list responses. */
export interface AuthoredDetectionListItem {
  id: string
  title: string
  slug: string
  summary: string
  technique_id: string
  origin: AuthoredOrigin
  is_generated: boolean
  status: AuthoredStatus
  visibility: AuthoredVisibility
  /** Last validation fidelity (0..1), or null if never validated. */
  last_fidelity: number | null
  owner_username: string
  created_at: string
  updated_at: string
}

/** A full rule, including the Sigma body. */
export interface AuthoredDetection extends AuthoredDetectionListItem {
  sigma: string
}

/** Writable fields for create/update. */
export interface AuthoredDetectionDraft {
  title: string
  summary?: string
  technique_id?: string
  sigma?: string
  status?: AuthoredStatus
  visibility?: AuthoredVisibility
  /** Set to 'generated' when the rule was first drafted by AI. */
  origin?: AuthoredOrigin
}

/** Request for POST /generate/. reference_urls are cited, never fetched. */
export interface DetectionGenerateRequest {
  brief: string
  technique_id?: string
  reference_urls?: string[]
  reference_text?: string
}

/** One synthetic-event outcome from a validation pass. */
export interface SigmaValidationScenario {
  label: 'positive' | 'benign' | 'evasion'
  matched: boolean
  expected: boolean
  note?: string
}

/** The fidelity report, or a not-evaluable verdict. */
export interface DetectionValidationResult {
  evaluable?: boolean
  reason?: string
  fidelity?: number
  summary?: string
  scenarios?: SigmaValidationScenario[]
  suggestions?: string
}
