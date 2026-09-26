/**
 * Guardrail prevention analysis for one emulation.
 *
 * Endpoint: GET /api/guardrails/emulation/<emulation_type>/
 *
 * Answers "could this attack have been refused", which is the question
 * underneath detection coverage. The result describes published AWS sample
 * policies, not the caller's deployed ones, so every figure means "if you
 * deployed this".
 */

import api from './api'
import type { PreventionAnalysis } from '@/types/prevention'

/**
 * Read which library policies bear on one emulation's attack.
 *
 * @param emulationType - Registry name of the emulation.
 */
export async function getPrevention(emulationType: string): Promise<PreventionAnalysis> {
  const { data } = await api.get<PreventionAnalysis>(
    `/guardrails/emulation/${emulationType}/`,
  )
  return data
}
