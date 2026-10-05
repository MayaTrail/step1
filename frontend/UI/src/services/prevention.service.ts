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
import type { AccountCheck, PreventionAnalysis } from '@/types/prevention'

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

/**
 * Ask AWS whether the caller's own policies would refuse this emulation.
 *
 * Endpoint: POST /api/guardrails/emulation/<emulation_type>/check/
 *
 * Performs none of the actions. AWS evaluates the connected role's policies,
 * its permissions boundary and the organization's service control policies,
 * and reports what would happen. Rate-limited server-side, so this belongs
 * behind a deliberate action rather than a page load.
 *
 * @param emulationType - Registry name of the emulation.
 * @param region - Region to judge region-conditional policies against.
 *   Omitted means the region a lab would deploy to.
 */
export async function checkAgainstAccount(
  emulationType: string,
  region?: string,
): Promise<AccountCheck> {
  const { data } = await api.post<AccountCheck>(
    `/guardrails/emulation/${emulationType}/check/`,
    region ? { region } : {},
  )
  return data
}
