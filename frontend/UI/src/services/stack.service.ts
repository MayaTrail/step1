/**
 * Stack Service: reads the user's Pulumi infrastructure stacks.
 *
 * Endpoints (read-only; stacks are deployed and destroyed through the
 * emulation service):
 *   GET /api/stacks/                → list user's stacks
 *   GET /api/stacks/{id}/           → get a single stack
 *   GET /api/stacks/{id}/progress/  → live deploy progress
 */

import api from './api'
import type { Stack, StackProgress } from '@/types'

/** List all stacks owned by the authenticated user. */
export async function listStacks(): Promise<Stack[]> {
  const { data } = await api.get<Stack[]>('/stacks/')
  // Guard: if nginx SPA fallback returns HTML instead of JSON, return empty
  if (!Array.isArray(data)) return []
  return data
}

/** Get a single stack by UUID. */
export async function getStack(stackId: string): Promise<Stack> {
  const { data } = await api.get<Stack>(`/stacks/${stackId}/`)
  return data
}

/**
 * Fetch live deployment progress for a stack.
 *
 * Reads the deploy task's PROGRESS state (resource counts, percentage, recent
 * Pulumi log lines) from the backend. Safe to poll while a deploy is in flight;
 * returns percentage 100 / 0 for terminal stacks.
 *
 * @param stackId - UUID of the stack to query.
 */
export async function getStackProgress(stackId: string): Promise<StackProgress> {
  const { data } = await api.get<StackProgress>(`/stacks/${stackId}/progress/`)
  return data
}

/**
 * Poll a stack until it reaches a target status or a terminal state.
 *
 * @param stackId    UUID of the stack
 * @param intervalMs Polling interval in ms (default 3000)
 * @param onUpdate   Callback on each poll
 * @param signal     AbortSignal to cancel
 */
export async function pollStackUntilReady(
  stackId: string,
  intervalMs = 3000,
  onUpdate?: (stack: Stack) => void,
  signal?: AbortSignal,
): Promise<Stack> {
  const TERMINAL = new Set(['ready', 'failed', 'pending', 'destroyed'])

  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (signal?.aborted) {
      throw new DOMException('Polling aborted', 'AbortError')
    }

    let stack: Stack
    try {
      stack = await getStack(stackId)
    } catch (err: unknown) {
      // 404 means the stack record was deleted (successful destroy removes the DB row).
      // Treat this as a clean terminal state — resolve with a synthetic destroyed record.
      const httpStatus = (err as { response?: { status?: number } })?.response?.status
      if (httpStatus === 404) {
        const synthetic: Stack = {
          id: stackId, name: '', region: '', status: 'destroyed',
          outputs: {}, owner: '', created_at: '', updated_at: '',
          // The row is gone, so its recorded phases went with it. Empty is the
          // honest value and renders as "no phase history", not as a timeline.
          lifecycle: [],
        }
        onUpdate?.(synthetic)
        return synthetic
      }
      throw err
    }

    onUpdate?.(stack)

    if (TERMINAL.has(stack.status)) {
      return stack
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
