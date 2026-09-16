/**
 * Workflow Service, API calls for detection validation runs.
 *
 * Endpoints (all require an authenticated user):
 *   GET  POST /api/workflows/runs/          list workflows, or start one
 *   GET  /api/workflows/runs/<id>/          one run with its per-rule verdicts
 *   GET  POST /api/workflows/endpoints/     list webhooks, or create one
 *
 * The alert webhook itself is not called from here. A client's SIEM posts to it
 * directly, signed with the endpoint's secret.
 */

import api from './api'
import type {
  AlertEndpoint,
  AlertEndpointCreated,
  WorkflowRun,
  WorkflowRunDetail,
} from '@/types/workflow'

/** List the caller's workflows, newest first. */
export async function listWorkflowRuns(): Promise<WorkflowRun[]> {
  const { data } = await api.get<{ runs: WorkflowRun[] }>('/workflows/runs/')
  return data.runs
}

/**
 * Read one workflow with its full report.
 *
 * @param workflowId - UUID of the run.
 */
export async function getWorkflowRun(workflowId: string): Promise<WorkflowRunDetail> {
  const { data } = await api.get<WorkflowRunDetail>(`/workflows/runs/${workflowId}/`)
  return data
}

/**
 * Queue a workflow for one emulation.
 *
 * Returns as soon as the run is recorded. The pipeline is advanced by a
 * scheduled job, so the caller is free to navigate away.
 *
 * @param emulationType - Registry name of the emulation to validate.
 */
export async function startWorkflowRun(emulationType: string): Promise<WorkflowRun> {
  const { data } = await api.post<WorkflowRun>('/workflows/runs/', { emulationType })
  return data
}

/** List the caller's alert endpoints. Secrets are never returned. */
export async function listAlertEndpoints(): Promise<AlertEndpoint[]> {
  const { data } = await api.get<{ endpoints: AlertEndpoint[] }>('/workflows/endpoints/')
  return data.endpoints
}

/**
 * Create an alert endpoint.
 *
 * The response carries the plaintext secret, and is the only time it exists
 * outside the client's SIEM: it is stored encrypted and cannot be read back.
 *
 * @param name - Client-chosen label, for example "Splunk production".
 */
export async function createAlertEndpoint(name: string): Promise<AlertEndpointCreated> {
  const { data } = await api.post<AlertEndpointCreated>('/workflows/endpoints/', { name })
  return data
}
