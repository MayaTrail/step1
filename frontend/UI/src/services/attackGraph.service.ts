/**
 * Attack Graph API.
 *
 *   POST /api/attack-graph/scan/            → start a scan
 *   GET  /api/attack-graph/scan/list/       → history, newest first
 *   GET  /api/attack-graph/scan/<id>/       → one scan, for polling
 */

import api from './api'
import type { ScanDetail, ScanSummary } from '@/types/attackGraph'

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
