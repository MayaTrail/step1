/**
 * Workflow Service, API calls for detection validation runs.
 *
 * Endpoints (all require an authenticated user):
 *   GET  POST /api/workflows/runs/          list workflows, or start one
 *   GET  DELETE /api/workflows/runs/<id>/   one run with its verdicts, or remove it
 *   GET  POST /api/workflows/endpoints/     list webhooks, or create one
 *   GET  DELETE /api/workflows/endpoints/<id>/        read one, or delete it
 *   GET  POST /api/workflows/endpoints/<id>/secret/   reveal, or rotate
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
 * @param scheduledFor - ISO timestamp to start at, or undefined to start now.
 */
export async function startWorkflowRun(
  emulationType: string,
  scheduledFor?: string,
): Promise<WorkflowRun> {
  const { data } = await api.post<WorkflowRun>('/workflows/runs/', {
    emulationType,
    ...(scheduledFor ? { scheduledFor } : {}),
  })
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
 * The response carries the plaintext secret. It is stored encrypted rather than
 * hashed, because the server reproduces an HMAC with it on every inbound alert,
 * so it can also be read back later through revealEndpointSecret.
 *
 * @param name - Client-chosen label, for example "Splunk production".
 */
export async function createAlertEndpoint(name: string): Promise<AlertEndpointCreated> {
  const { data } = await api.post<AlertEndpointCreated>('/workflows/endpoints/', { name })
  return data
}

/**
 * Read an endpoint's current signing secret.
 *
 * Throttled and logged server-side. Used when a client's SIEM operator has lost
 * their copy and would otherwise have to re-point the whole integration.
 *
 * @param endpointId - UUID of the endpoint.
 */
export async function revealEndpointSecret(endpointId: string): Promise<string> {
  const { data } = await api.get<{ secret: string }>(
    `/workflows/endpoints/${endpointId}/secret/`,
  )
  return data.secret
}

/**
 * Replace an endpoint's secret with a newly generated one.
 *
 * Alerts signed with the old secret stop verifying immediately, so the client
 * has to update their SIEM before their next run.
 *
 * @param endpointId - UUID of the endpoint.
 */
export async function rotateEndpointSecret(endpointId: string): Promise<AlertEndpointCreated> {
  const { data } = await api.post<AlertEndpointCreated>(
    `/workflows/endpoints/${endpointId}/secret/`,
  )
  return data
}

/**
 * Delete an endpoint that has never received an alert.
 *
 * The server refuses with 409 when the endpoint has alerts behind it, because
 * those alerts are the evidence behind completed workflow reports.
 *
 * @param endpointId - UUID of the endpoint.
 */
export async function deleteAlertEndpoint(endpointId: string): Promise<void> {
  await api.delete(`/workflows/endpoints/${endpointId}/`)
}

/**
 * Remove a failed run, or cancel a scheduled one.
 *
 * The server refuses with 409 for a completed run, whose report is the record,
 * and for one still in progress. Any stack the run created is left in place: a
 * workflow does not own the infrastructure it asked for, and destroying it is a
 * separate decision made on the Stacks page.
 *
 * @param workflowId - UUID of the run.
 */
export async function deleteWorkflowRun(workflowId: string): Promise<void> {
  await api.delete(`/workflows/runs/${workflowId}/`)
}
