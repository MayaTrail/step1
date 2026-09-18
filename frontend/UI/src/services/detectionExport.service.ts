/**
 * Detection Export Service — compile shipped Sigma rules into a SIEM dialect.
 *
 * Endpoints:
 *   GET /api/emulations/detection-targets/                    what this server can compile to
 *   GET /api/emulations/<type>/detections/export/             a whole emulation, or a subset
 *   GET /api/emulations/<run_id>/detections/export/           only the rules a run judged
 *   GET /api/workflows/runs/<id>/export/                      the rules a SIEM missed
 *
 * The run-scoped export is the one that matters: a run reports which rules
 * stayed silent, and this hands back exactly those in the customer's own query
 * language, which turns a finding into something they can deploy.
 */

import api from './api'
import type { DetectionExportBundle, DetectionTarget } from '@/types'

/** Verdicts a run export can be filtered by. */
export type ExportVerdict = 'fired' | 'silent' | 'no_logs'

/**
 * List the conversion targets, including ones whose backend is missing.
 *
 * Unavailable targets come back with `installed: false` rather than being
 * omitted, so the UI can say "your server is missing a package" instead of
 * implying the product cannot do it at all.
 */
export async function listDetectionTargets(): Promise<DetectionTarget[]> {
  const { data } = await api.get<{ targets: DetectionTarget[] }>(
    '/emulations/detection-targets/',
  )
  return data.targets
}

/** Compile an emulation's rules, or a named subset of them. */
export async function exportEmulationDetections(
  emulationType: string,
  target: string,
  ruleIds?: string[],
): Promise<DetectionExportBundle> {
  const { data } = await api.get<DetectionExportBundle>(
    `/emulations/${emulationType}/detections/export/`,
    { params: { target, ...(ruleIds?.length ? { rule_ids: ruleIds.join(',') } : {}) } },
  )
  return data
}

/** Compile the rules a run judged with the given verdicts. */
export async function exportRunDetections(
  runId: string,
  target: string,
  verdicts: ExportVerdict[] = ['silent'],
): Promise<DetectionExportBundle> {
  const { data } = await api.get<DetectionExportBundle>(
    `/emulations/${runId}/detections/export/`,
    { params: { target, verdict: verdicts.join(',') } },
  )
  return data
}

/**
 * Download a bundle as a file.
 *
 * Fetched through the configured axios instance rather than by pointing an <a>
 * at the URL, because the endpoint needs the Authorization header.
 */
async function download(path: string, params: Record<string, string>, filename: string) {
  const { data } = await api.get(path, {
    params: { ...params, download: '1' },
    responseType: 'blob',
  })
  const url = URL.createObjectURL(new Blob([data], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/** Download a whole emulation's rules for one target. */
export async function downloadEmulationDetections(
  emulationType: string,
  target: string,
  ruleIds?: string[],
): Promise<void> {
  await download(
    `/emulations/${emulationType}/detections/export/`,
    { target, ...(ruleIds?.length ? { rule_ids: ruleIds.join(',') } : {}) },
    `${emulationType}-${target}.txt`,
  )
}

/** Download the rules a run judged with the given verdicts. */
export async function downloadRunDetections(
  runId: string,
  target: string,
  verdicts: ExportVerdict[] = ['silent'],
): Promise<void> {
  await download(
    `/emulations/${runId}/detections/export/`,
    { target, verdict: verdicts.join(',') },
    `run-${verdicts.join('-')}-${target}.txt`,
  )
}

/**
 * Compile the detections a workflow found silent.
 *
 * This is the run-scoped export that works on this deployment. The emulation
 * app's equivalent reads a run's `detection_check`, which comes from the
 * CloudTrail-in-S3 path retired in September; a workflow's score comes from the
 * customer's own SIEM, which is where the verdicts now live.
 *
 * Only silent rules are returned, and the server enforces that: a rule that
 * fired needs nothing, and `not_integrated` means no alert route existed, so
 * the rule was never exercised and a query for it would assert an unmeasured
 * gap.
 *
 * @param workflowId - UUID of the workflow run.
 * @param target - Conversion target, for example "splunk".
 * @param outputFormat - Target-specific format, for example "savedsearches".
 * @returns The compiled bundle, or null when nothing was silent.
 */
export async function exportWorkflowGap(
  workflowId: string,
  target: string,
  outputFormat: string,
): Promise<DetectionExportBundle | null> {
  try {
    const { data } = await api.get<DetectionExportBundle>(
      `/workflows/runs/${workflowId}/export/`,
      { params: { target, output_format: outputFormat } },
    )
    return data
  } catch (caught) {
    // A run with nothing silent answers 404 by design, which is an outcome
    // rather than a failure: every expected detection fired.
    if ((caught as { response?: { status?: number } }).response?.status === 404) return null
    throw caught
  }
}
