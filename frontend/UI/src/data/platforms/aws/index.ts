import { awsGuardrails } from './detections'
import type { PlatformData } from '@/types'

export const awsData: PlatformData = {
  emulations: [],
  detections: { totalCount: 0, formats: '', rules: [] },
  guardrails: awsGuardrails,
  playbooks: [],
}
