/**
 * Attack Graph API.
 *
 *   POST /api/attack-graph/scan/                              → start a scan
 *   GET  /api/attack-graph/scan/list/                          → history, newest first
 *   GET  /api/attack-graph/scan/<id>/                          → one scan, for polling
 *   GET  /api/attack-graph/scan/<id>/graph/nodes/?q=            → search graph entities
 *   GET  /api/attack-graph/scan/<id>/graph/entity/?id=          → one entity's full record
 *   GET  /api/attack-graph/scan/<id>/graph/path/?src=&dst=      → paths between two entities
 */

import api from './api'
import type {
  ChainNode, GraphEntity, PathQueryResult, ScanDetail, ScanSummary,
} from '@/types/attackGraph'

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

/**
 * Search one scan's graph nodes. Backs both query pickers.
 *
 * Node ids go through axios `params`, never a hand-built query string: they
 * contain ":", "/" and sometimes "*", and `params` urlencodes them. Debounce
 * the caller at 200ms — this is an autocomplete, and the endpoint's cost
 * should track searches rather than keystrokes.
 */
export async function searchGraphNodes(scanId: string, q: string): Promise<ChainNode[]> {
  const { data } = await api.get<{ nodes: ChainNode[] }>(
    `/attack-graph/scan/${scanId}/graph/nodes/`,
    { params: { q } },
  )
  return data.nodes
}

/** One entity's full record. 404s for a scan stored before graphs were kept. */
export async function getGraphEntity(scanId: string, id: string): Promise<GraphEntity> {
  const { data } = await api.get<GraphEntity>(
    `/attack-graph/scan/${scanId}/graph/entity/`,
    { params: { id } },
  )
  return data
}

/** Paths between two entities. Both ids must be exact — the pickers supply them. */
export async function findPaths(
  scanId: string, src: string, dst: string,
): Promise<PathQueryResult> {
  const { data } = await api.get<PathQueryResult>(
    `/attack-graph/scan/${scanId}/graph/path/`,
    { params: { src, dst } },
  )
  return data
}
