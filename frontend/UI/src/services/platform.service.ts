import type { PlatformId, PlatformData, Emulation, DetectionData, Guardrails, Playbook } from '@/types'
import { getPlatformData } from '@/data'

/**
 * Platform service — wraps static data in async helpers so the call-sites
 * are already structured for a future API swap.
 *
 * When the backend API is ready, replace the body of each function with
 * an `api.get(...)` call and remove the static data import.
 */

export async function fetchPlatformData(platformId: PlatformId): Promise<PlatformData | null> {
  // TODO: api.get(`/platforms/${platformId}`)
  const data = getPlatformData(platformId)
  return data ?? null
}

export async function fetchEmulations(platformId: PlatformId): Promise<Emulation[]> {
  const data = await fetchPlatformData(platformId)
  return data?.emulations ?? []
}

export async function fetchEmulationById(
  platformId: PlatformId,
  emulationId: string,
): Promise<Emulation | null> {
  const emulations = await fetchEmulations(platformId)
  return emulations.find((e) => e.id === emulationId) ?? null
}

export async function fetchDetections(platformId: PlatformId): Promise<DetectionData | null> {
  const data = await fetchPlatformData(platformId)
  return data?.detections ?? null
}

export async function fetchGuardrails(platformId: PlatformId): Promise<Guardrails | null> {
  const data = await fetchPlatformData(platformId)
  return data?.guardrails ?? null
}

export async function fetchPlaybooks(platformId: PlatformId): Promise<Playbook[]> {
  const data = await fetchPlatformData(platformId)
  return data?.playbooks ?? []
}

export async function fetchPlaybookById(
  platformId: PlatformId,
  index: number,
): Promise<Playbook | null> {
  const playbooks = await fetchPlaybooks(platformId)
  return playbooks[index] ?? null
}
