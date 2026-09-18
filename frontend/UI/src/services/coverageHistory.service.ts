/**
 * Coverage history, and archiving the runs behind it.
 *
 * Endpoints:
 *   GET   /api/workflows/coverage/?emulation=<type>   reliability across runs
 *   PATCH /api/workflows/runs/<id>/                   archive or restore one run
 *
 * Archiving is how old runs are cleared out of the way. Deleting a completed
 * run is refused by the API on purpose: reliability is a share of judged runs,
 * so removing the runs where a rule stayed silent would raise that rule's
 * figure, and a detection would appear to improve because its failures were
 * destroyed.
 */

import api from './api'
import type { CoverageHistory } from '@/types/coverageHistory'
import type { WorkflowRunDetail } from '@/types/workflow'

/**
 * Read detection reliability across every completed run of one emulation.
 *
 * Archived runs are excluded by the server, which is the whole point of
 * archiving them.
 *
 * @param emulationType - Registry name of the emulation.
 * @param days - Optional window; omit to read the full history.
 */
export async function getCoverageHistory(
  emulationType: string,
  days?: number,
): Promise<CoverageHistory> {
  const { data } = await api.get<CoverageHistory>('/workflows/coverage/', {
    params: { emulation: emulationType, ...(days ? { days } : {}) },
  })
  return data
}

/**
 * Archive a run, or restore an archived one.
 *
 * Reversible, and the report is kept either way. Only a settled run can be
 * archived; the API answers 409 for one that is still in flight.
 *
 * @param workflowId - UUID of the run.
 * @param archived - True to hide it, false to bring it back.
 */
export async function setRunArchived(
  workflowId: string,
  archived: boolean,
): Promise<WorkflowRunDetail> {
  const { data } = await api.patch<WorkflowRunDetail>(
    `/workflows/runs/${workflowId}/`,
    { archived },
  )
  return data
}
