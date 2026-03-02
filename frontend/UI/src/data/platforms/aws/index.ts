import { awsEmulations } from './emulations'
import { awsDetections, awsGuardrails } from './detections'
import { awsPlaybooks } from './playbooks'
import type { PlatformData } from '@/types'

export const awsData: PlatformData = {
  emulations: awsEmulations,
  detections: awsDetections,
  guardrails: awsGuardrails,
  playbooks: awsPlaybooks,
}
