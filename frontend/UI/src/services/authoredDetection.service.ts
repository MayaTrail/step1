/**
 * Authored Detection Service — user-written and AI-generated Sigma rules.
 *
 * Endpoints (all under /api/detections/authored/):
 *   GET    /                    list rules visible to the caller
 *   POST   /                    create
 *   GET    /<id>/               read
 *   PATCH  /<id>/               edit (author only)
 *   DELETE /<id>/               delete (author only)
 *   POST   /generate/           draft a rule with the LLM (unsaved)
 *   POST   /validate/           score ad-hoc Sigma (before saving)
 *   POST   /<id>/validate/      score a saved rule, storing its fidelity
 *   GET    /<id>/export/        compile to a SIEM (?target=)
 *
 * The generate -> validate loop is the point: draft a rule, score whether it
 * actually fires against synthetic events, tune, then save and export.
 */

import api from './api'
import type {
  AuthoredDetection,
  AuthoredDetectionDraft,
  AuthoredDetectionListItem,
  DetectionGenerateRequest,
  DetectionValidationResult,
} from '@/types'

export async function listAuthoredDetections(
  opts: { mine?: boolean; technique?: string } = {},
): Promise<AuthoredDetectionListItem[]> {
  const params: Record<string, string> = {}
  if (opts.mine) params.mine = '1'
  if (opts.technique) params.technique = opts.technique
  const { data } = await api.get<AuthoredDetectionListItem[]>('/detections/authored/', { params })
  return data
}

export async function getAuthoredDetection(id: string): Promise<AuthoredDetection> {
  const { data } = await api.get<AuthoredDetection>(`/detections/authored/${id}/`)
  return data
}

export async function createAuthoredDetection(
  draft: AuthoredDetectionDraft,
): Promise<AuthoredDetection> {
  const { data } = await api.post<AuthoredDetection>('/detections/authored/', draft)
  return data
}

export async function updateAuthoredDetection(
  id: string,
  patch: Partial<AuthoredDetectionDraft>,
): Promise<AuthoredDetection> {
  const { data } = await api.patch<AuthoredDetection>(`/detections/authored/${id}/`, patch)
  return data
}

export async function deleteAuthoredDetection(id: string): Promise<void> {
  await api.delete(`/detections/authored/${id}/`)
}

/** Draft a Sigma rule. Returns the YAML unsaved. Slow — extends the timeout. */
export async function generateDetection(
  req: DetectionGenerateRequest,
): Promise<{ sigma: string }> {
  const { data } = await api.post<{ sigma: string }>('/detections/authored/generate/', req, {
    timeout: 120_000,
  })
  return data
}

/** Score Sigma that has not been saved yet (the loop, right after generation). */
export async function validateAdhocSigma(sigma: string): Promise<DetectionValidationResult> {
  const { data } = await api.post<DetectionValidationResult>(
    '/detections/authored/validate/',
    { sigma },
    { timeout: 120_000 },
  )
  return data
}

/** Score a saved rule; the backend records its fidelity. */
export async function validateSavedDetection(id: string): Promise<DetectionValidationResult> {
  const { data } = await api.post<DetectionValidationResult>(
    `/detections/authored/${id}/validate/`,
    {},
    { timeout: 120_000 },
  )
  return data
}

/** Download a saved rule compiled for a SIEM target. */
export async function downloadAuthoredDetection(
  id: string,
  target: string,
  slug: string,
): Promise<void> {
  const { data } = await api.get(`/detections/authored/${id}/export/`, {
    params: { target, download: '1' },
    responseType: 'blob',
  })
  const url = URL.createObjectURL(new Blob([data], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `${slug || 'detection'}-${target}.txt`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
