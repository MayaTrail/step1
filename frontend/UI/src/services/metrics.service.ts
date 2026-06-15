/**
 * Metrics Service — API calls for the redesigned security dashboard.
 *
 * Endpoints (all read-only, require an authenticated user):
 *   GET /api/metrics/summary/           → KPI-card figures
 *   GET /api/metrics/mitre-coverage/    → global ATT&CK matrix for the heatmap
 *   GET /api/metrics/threat-coverage/   → per-actor coverage rows
 *   GET /api/metrics/platform-coverage/ → per-platform content depth
 *
 * Figures are platform-wide and computed live from the emulation registry, so
 * a newly added emulation surfaces here without any frontend change.
 */

import api from './api'
import type {
  CoverageFilters,
  CoverageSummary,
  MitreCoverage,
  PlatformCoverage,
  TacticDetail,
  ThreatCoverage,
} from '@/types/metrics'

/** Drop undefined filter values so axios only sends the active ones. */
function filterParams(filters?: CoverageFilters): Record<string, string> {
  const params: Record<string, string> = {}
  if (filters?.platform) params.platform = filters.platform
  if (filters?.actor) params.actor = filters.actor
  if (filters?.emulation) params.emulation = filters.emulation
  return params
}

/** Fetch the four KPI-card figures. */
export async function getCoverageSummary(): Promise<CoverageSummary> {
  const { data } = await api.get<CoverageSummary>('/metrics/summary/')
  return data
}

/** Fetch the MITRE ATT&CK coverage summary, optionally filtered. */
export async function getMitreCoverage(filters?: CoverageFilters): Promise<MitreCoverage> {
  const { data } = await api.get<MitreCoverage>('/metrics/mitre-coverage/', {
    params: filterParams(filters),
  })
  return data
}

/** Fetch the drill-down detail for one ATT&CK tactic, honouring the filters. */
export async function getTacticDetail(
  shortname: string,
  filters?: CoverageFilters,
): Promise<TacticDetail> {
  const { data } = await api.get<TacticDetail>(`/metrics/mitre-coverage/${shortname}/`, {
    params: filterParams(filters),
  })
  return data
}

/**
 * Fetch the MITRE ATT&CK Navigator layer preloaded with Mayatrail's coverage.
 *
 * Returned as a plain object; callers serialise it to a file for the Navigator's
 * "Open Existing Layer" flow. Typed as unknown because the consumer only
 * round-trips it through JSON.stringify.
 */
export async function getNavigatorLayer(): Promise<unknown> {
  const { data } = await api.get('/metrics/mitre-coverage/navigator-layer/')
  return data
}

/** Fetch per-emulation (per threat-actor campaign) coverage rows. */
export async function getThreatCoverage(): Promise<ThreatCoverage> {
  const { data } = await api.get<ThreatCoverage>('/metrics/threat-coverage/')
  return data
}

/**
 * Fetch per-platform content depth.
 *
 * @param platform - Optional platform id to restrict the result to one platform.
 */
export async function getPlatformCoverage(platform?: string): Promise<PlatformCoverage> {
  const { data } = await api.get<PlatformCoverage>('/metrics/platform-coverage/', {
    params: platform ? { platform } : undefined,
  })
  return data
}
