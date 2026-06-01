/**
 * Emulation Service — API calls for the enterprise emulation lifecycle.
 *
 * Endpoints:
 *   GET  /api/emulations/                          List available emulation packages
 *   GET  /api/emulations/<type>/estimate/          Cost breakdown before deploy
 *   GET  /api/emulations/<type>/techniques/        MITRE ATT&CK data
 *   GET  /api/emulations/<type>/detections/        SIGMA + KQL detection rules
 *   GET  /api/emulations/<type>/playbook/          IR playbook markdown
 *   POST /api/emulations/deploy/                   Deploy emulation stack
 *   GET  /api/emulations/<run_id>/                 Poll EmulationRun status
 *   POST /api/emulations/<stack_id>/attack/        Trigger attack phase
 *   POST /api/emulations/<stack_id>/destroy/       Destroy emulation stack
 */

import api from './api'
import type {
  Emulation,
  EmulationEstimate,
  EmulationRunRecord,
  EmulationRunStatus,
  DeployEmulationResponse,
  TriggerAttackResponse,
  DetectionData,
} from '@/types'

/** List all available emulation packages. */
export async function listEmulations(): Promise<Emulation[]> {
  const { data } = await api.get<Emulation[]>('/emulations/')
  return data
}

/**
 * Fetch the cost estimate for an emulation type before deploying.
 *
 * @param emulationType - Emulation package name, e.g. "scarleteel".
 */
export async function getEmulationEstimate(
  emulationType: string,
): Promise<EmulationEstimate> {
  const { data } = await api.get<EmulationEstimate>(
    `/emulations/${emulationType}/estimate/`,
  )
  return data
}

/**
 * Fetch MITRE ATT&CK technique data for an emulation type.
 *
 * @param emulationType - Emulation package name.
 */
export async function getEmulationTechniques(
  emulationType: string,
): Promise<{ attackPath: Emulation['attackPath']; mitreMappings: Emulation['mitreMappings'] }> {
  const { data } = await api.get(`/emulations/${emulationType}/techniques/`)
  return data
}

/**
 * Fetch SIGMA and KQL detection rules for an emulation type.
 *
 * @param emulationType - Emulation package name.
 */
export async function getEmulationDetections(
  emulationType: string,
): Promise<DetectionData> {
  const { data } = await api.get<DetectionData>(
    `/emulations/${emulationType}/detections/`,
  )
  return data
}

/**
 * Deploy an enterprise emulation stack.
 *
 * @param emulationType - Emulation package name, e.g. "scarleteel".
 * @param stackName     - Pulumi stack name for this deployment.
 */
export async function deployEmulationStack(
  emulationType: string,
  stackName: string,
): Promise<DeployEmulationResponse> {
  const { data } = await api.post<DeployEmulationResponse>('/emulations/deploy/', {
    emulation_type: emulationType,
    stack_name: stackName,
  })
  return data
}

/**
 * Poll a single EmulationRun by its UUID.
 *
 * @param runId - UUID of the EmulationRun record.
 */
export async function getEmulationRun(runId: string): Promise<EmulationRunRecord> {
  const { data } = await api.get<EmulationRunRecord>(`/emulations/${runId}/`)
  return data
}

/**
 * Trigger the attack phase against a ready emulation stack.
 *
 * The stack must be in ready_for_attack status.
 *
 * @param stackId - UUID of the Stack to attack.
 */
export async function triggerEmulationAttack(
  stackId: string,
): Promise<TriggerAttackResponse> {
  const { data } = await api.post<TriggerAttackResponse>(
    `/emulations/${stackId}/attack/`,
  )
  return data
}

/**
 * Manually destroy an enterprise emulation stack before TTL expiry.
 *
 * @param stackId - UUID of the Stack to destroy.
 */
export async function destroyEmulationStack(stackId: string): Promise<void> {
  await api.post(`/emulations/${stackId}/destroy/`)
}

/**
 * Poll an EmulationRun until it reaches a terminal state.
 *
 * @param runId      - UUID of the EmulationRun to poll.
 * @param intervalMs - Polling interval in milliseconds (default 3000).
 * @param onUpdate   - Optional callback invoked with each poll result.
 * @param signal     - Optional AbortSignal to cancel polling.
 */
export async function pollEmulationRunUntilDone(
  runId: string,
  intervalMs = 3000,
  onUpdate?: (run: EmulationRunRecord) => void,
  signal?: AbortSignal,
): Promise<EmulationRunRecord> {
  const TERMINAL = new Set<EmulationRunStatus>(['completed', 'failed'])

  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (signal?.aborted) {
      throw new DOMException('Polling aborted', 'AbortError')
    }

    const run = await getEmulationRun(runId)
    onUpdate?.(run)

    if (TERMINAL.has(run.status)) {
      return run
    }

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, intervalMs)
      signal?.addEventListener(
        'abort',
        () => {
          clearTimeout(timer)
          reject(new DOMException('Polling aborted', 'AbortError'))
        },
        { once: true },
      )
    })
  }
}
