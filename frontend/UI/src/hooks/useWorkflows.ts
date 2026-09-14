import { useCachedResource } from './useCachedResource'
import * as workflowService from '@/services/workflow.service'
import type { AlertEndpoint, WorkflowRun, WorkflowRunDetail } from '@/types/workflow'

/**
 * Data hooks for workflows.
 *
 * The list and an open run poll, because a workflow advances on a scheduled
 * job rather than in response to anything the browser does. Polling never
 * toggles `loading`, so the page updates in place instead of flashing.
 */

/** How often to re-read a run that is still moving. */
const OPEN_RUN_POLL_MS = 15_000

/**
 * Fetch the caller's workflows.
 *
 * @param pollMs - Poll interval while runs are still moving.
 * @param version - Bump to force a fresh read after a mutation. The version is
 *   part of the cache key, which refetches without remounting anything. An
 *   earlier version remounted the page instead, which discarded component state
 *   that had just been set.
 */
export function useWorkflowRuns(pollMs?: number, version = 0) {
  return useCachedResource<WorkflowRun[]>(
    `workflow-runs:${version}`,
    workflowService.listWorkflowRuns,
    pollMs ? { pollMs } : undefined,
  )
}

/**
 * Fetch one workflow.
 *
 * @param workflowId - UUID of the run, or null to skip fetching.
 * @param open - Whether the run is still advancing, which decides polling.
 */
export function useWorkflowRun(workflowId: string | null, open: boolean) {
  return useCachedResource<WorkflowRunDetail>(
    workflowId ? `workflow-run:${workflowId}` : null,
    () => workflowService.getWorkflowRun(workflowId as string),
    open ? { pollMs: OPEN_RUN_POLL_MS } : undefined,
  )
}

/**
 * Fetch the caller's alert endpoints.
 *
 * @param version - Bump after creating one to refetch without a remount.
 */
export function useAlertEndpoints(version = 0) {
  return useCachedResource<AlertEndpoint[]>(
    `workflow-endpoints:${version}`,
    workflowService.listAlertEndpoints,
  )
}
