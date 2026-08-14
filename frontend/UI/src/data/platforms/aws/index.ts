import type { PlatformData } from '@/types'

/** Placeholder shape only — every field is served by the backend API at runtime
 *  (emulations, detections and playbooks per emulation, guardrails from
 *  /api/guardrails/). Kept so getPlatformData() has an AWS entry to return. */
export const awsData: PlatformData = {
  emulations: [],
  detections: { totalCount: 0, formats: '', rules: [] },
  guardrails: { scp: [], rcp: [], totalCount: 0, formats: '' },
  playbooks: [],
}
