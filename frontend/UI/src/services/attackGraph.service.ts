/**
 * Attack Graph API.
 *
 *   POST   /api/attack-graph/scan/                              → start a scan
 *   GET    /api/attack-graph/scan/list/                          → history, newest first
 *   GET    /api/attack-graph/scan/<id>/                          → one scan, for polling
 *   DELETE /api/attack-graph/scan/<id>/                          → delete a finished scan
 *   GET    /api/attack-graph/scan/<id>/graph/entity/?id=          → one entity's full record
 */

import api from './api'
import type { GraphEntity, ScanDetail, ScanSummary } from '@/types/attackGraph'

/** Start a scan. Throws with a 409 when one is already in flight. */
export async function triggerScan(): Promise<{ scanId: string }> {
  const { data } = await api.post<{ scanId: string }>('/attack-graph/scan/')
  return data
}

/** The requesting user's scans, newest first. */
export async function listScans(): Promise<ScanSummary[]> {
  const { data } = await api.get<ScanSummary[]>('/attack-graph/scan/list/')
  return data
}

/** One scan with its result envelope. */
export async function getScan(scanId: string): Promise<ScanDetail> {
  const { data } = await api.get<ScanDetail>(`/attack-graph/scan/${scanId}/`)
  return data
}

/** Delete one finished scan and its stored graph. Throws with a 409 while it runs. */
export async function deleteScan(scanId: string): Promise<void> {
  await api.delete(`/attack-graph/scan/${scanId}/`)
}

/** One entity's full record. 404s for a scan stored before graphs were kept. */
export async function getGraphEntity(scanId: string, id: string): Promise<GraphEntity> {
  const { data } = await api.get<GraphEntity>(
    `/attack-graph/scan/${scanId}/graph/entity/`,
    { params: { id } },
  )
  return data
}
