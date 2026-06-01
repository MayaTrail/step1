import { awsGuardrails } from './detections'
import type { PlatformData } from '@/types'

export const awsData: PlatformData = {
  emulations: [],
  detections: { sigma: [], kql: [], totalCount: 0, formats: '' },
  guardrails: awsGuardrails,
  playbooks: [],
}
