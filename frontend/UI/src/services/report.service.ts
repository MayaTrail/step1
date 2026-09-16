/**
 * The evidence packet, and two runs side by side.
 *
 * Both read data the run already produced — verdicts, the change against the
 * previous run, the emulation's coverage history — so a report can never
 * disagree with the run page it came from.
 */

import api from './api'
import type { RunComparison, RunReport } from '@/types'

/** Everything one run proved, in a single payload. */
export async function getRunReport(runId: string): Promise<RunReport> {
  const { data } = await api.get<RunReport>(`/emulations/${runId}/report/`)
  return data
}

/**
 * Compare two runs.
 *
 * `baselineRunId` is the "before" and `runId` the "after", but the server
 * orders them by completion time regardless, so passing them the wrong way
 * round still reads correctly.
 */
export async function compareRuns(
  baselineRunId: string,
  runId: string,
): Promise<RunComparison> {
  const { data } = await api.get<RunComparison>('/emulations/compare/', {
    params: { a: baselineRunId, b: runId },
  })
  return data
}
