/**
 * Emulation Service — API calls for triggering and polling simulation runs.
 *
 * Endpoints:
 *   GET  /api/simulations/modules/  → list available modules
 *   POST /api/simulations/run/      → trigger a new run
 *   GET  /api/simulations/{id}/     → poll run status
 *   GET  /api/simulations/          → list all runs
 */

import api from './api'
import type {
  SimulationModule,
  SimulationRun,
  TriggerSimulationRequest,
  TriggerSimulationResponse,
} from '@/types'

/**
 * List all available simulation modules.
 */
export async function listSimulationModules(): Promise<SimulationModule[]> {
  const { data } = await api.get<SimulationModule[]>('/simulations/modules/')
  return data
}

/**
 * Trigger a new simulation run.
 *
 * @param payload - stack_id and module_id
 * @returns The created SimulationRun + Celery task_id
 */
export async function triggerSimulation(
  payload: TriggerSimulationRequest,
): Promise<TriggerSimulationResponse> {
  const { data } = await api.post<TriggerSimulationResponse>(
    '/simulations/run/',
    payload,
  )
  return data
}

/**
 * Poll a single simulation run by its UUID.
 *
 * @param runId - UUID of the SimulationRun record
 * @returns Latest state of the run (status, stdout, stderr, etc.)
 */
export async function getSimulationRun(
  runId: string,
): Promise<SimulationRun> {
  const { data } = await api.get<SimulationRun>(`/simulations/${runId}/`)
  return data
}

/**
 * List all simulation runs for the authenticated user.
 */
export async function listSimulationRuns(): Promise<SimulationRun[]> {
  const { data } = await api.get<SimulationRun[]>('/simulations/')
  return data
}

/**
 * Poll a run until it reaches a terminal state (completed or failed).
 * Returns the final run state.
 *
 * @param runId - UUID of the SimulationRun record
 * @param intervalMs - Polling interval in milliseconds (default 2000)
 * @param onUpdate - Optional callback invoked with each poll result
 * @param signal - Optional AbortSignal to cancel polling
 */
export async function pollSimulationUntilDone(
  runId: string,
  intervalMs = 2000,
  onUpdate?: (run: SimulationRun) => void,
  signal?: AbortSignal,
): Promise<SimulationRun> {
  const TERMINAL = new Set(['completed', 'failed'])

  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (signal?.aborted) {
      throw new DOMException('Polling aborted', 'AbortError')
    }

    const run = await getSimulationRun(runId)
    onUpdate?.(run)

    if (TERMINAL.has(run.status)) {
      return run
    }

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, intervalMs)
      signal?.addEventListener('abort', () => {
        clearTimeout(timer)
        reject(new DOMException('Polling aborted', 'AbortError'))
      }, { once: true })
    })
  }
}
