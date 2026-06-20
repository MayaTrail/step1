/**
 * Types for the dashboard metrics endpoints (/api/metrics/*).
 *
 * These mirror the camelCase payloads produced by apps/metrics on the backend.
 * Every figure is a platform-wide, live aggregation over the emulation registry
 * (plus EmulationRun for execution counts) — see apps/metrics/aggregations.py.
 */

/** GET /api/metrics/summary — the four KPI-card figures. */
export interface CoverageSummary {
  /** Percent of catalogue techniques covered, e.g. 3.6. */
  aptCoverageScore: number
  coveredTechniques: number
  totalTechniques: number
  /** ATT&CK release the bundled catalogue was built from, e.g. "19.1". */
  attackVersion: string
  emulationsExecuted: number
  /** Total detection rule files across all emulations. */
  detectionCoverage: number
  /** ISO timestamp of the latest completed run, or null if none. */
  lastSuccessfulRun: string | null
}

/** Coverage status for a tactic (or technique): green / amber / red. */
export type TacticStatus = 'covered' | 'partial' | 'none'

/** A per-tactic coverage row for the tactic grid. */
export interface TacticCoverage {
  id: string
  shortname: string
  name: string
  techniqueCount: number
  coveredCount: number
  pct: number
  status: TacticStatus
  insight: string
}

/** A compact tactic reference used for the most/least-covered highlights. */
export interface TacticHighlight {
  shortname: string
  name: string
  pct: number
}

/** Counts of tactics in each coverage status. */
export interface CoverageDistribution {
  covered: number
  partial: number
  none: number
}

/** The executive summary band of the coverage section. */
export interface MitreSummary {
  coveredTechniques: number
  totalTechniques: number
  pct: number
  attackVersion: string
  distribution: CoverageDistribution
  mostCovered: TacticHighlight | null
  leastCovered: TacticHighlight | null
  /** Whether a coverage trend series is available yet (deferred — false today). */
  trendAvailable: boolean
}

/** An actionable insight line. */
export interface CoverageInsight {
  severity: 'high' | 'medium' | 'info'
  text: string
}

/** A single selectable filter option. */
export interface FilterOption {
  id: string
  label: string
}

/** The filter options the toolbar dropdowns offer. */
export interface CoverageFilterOptions {
  platforms: FilterOption[]
  actors: FilterOption[]
  emulations: FilterOption[]
  tactics: FilterOption[]
}

/** GET /api/metrics/mitre-coverage — summary + per-tactic coverage + insights. */
export interface MitreCoverage {
  summary: MitreSummary
  tactics: TacticCoverage[]
  insights: CoverageInsight[]
  filters: CoverageFilterOptions
}

/** A technique id + name pair (drill-down chips). */
export interface TechniqueRef {
  id: string
  name: string
}

/** GET /api/metrics/mitre-coverage/<shortname>/ — tactic drill-down. */
export interface TacticDetail {
  tactic: {
    shortname: string
    name: string
    pct: number
    coveredCount: number
    techniqueCount: number
  }
  covered: TechniqueRef[]
  missing: TechniqueRef[]
  relatedEmulations: { id: string; name: string }[]
  relatedPlaybooks: number
  relatedDetections: number
  recommendation: string
}

/** Active coverage filters sent as query params. */
export interface CoverageFilters {
  platform?: string
  actor?: string
  emulation?: string
}

/** Content types that can drive the merged Platform & Threat Coverage section. */
export type ContentType = 'emulations' | 'playbooks' | 'detections'

/** How much of an actor's techniques a single content type backs. */
export interface ContentCoverage {
  covered: number
  total: number
  pct: number
}

/** A per-emulation (per threat-actor campaign) coverage row. */
export interface ThreatActor {
  id: string
  name: string
  origin: string
  originLabel: string
  attribution: string
  severity: string
  techniqueCount: number
  coveragePct: number
  /** Per content type: how many of this actor's techniques that content backs. */
  coverageByContent: Record<ContentType, ContentCoverage>
}

/** GET /api/metrics/threat-coverage — progress-bar rows. */
export interface ThreatCoverage {
  totalTechniques: number
  actors: ThreatActor[]
}

/** Content-depth counts for one platform. */
export interface PlatformCoverageRow {
  platform: string
  label: string
  emulations: number
  playbooks: number
  detections: number
}

/** GET /api/metrics/platform-coverage — per-platform content depth. */
export interface PlatformCoverage {
  platforms: PlatformCoverageRow[]
}
