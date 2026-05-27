/**
 * Stack Service — API calls for managing Pulumi infrastructure stacks.
 *
 * Endpoints:
 *   GET    /api/stacks/              → list user's stacks
 *   POST   /api/stacks/              → create a new stack record
 *   GET    /api/stacks/{id}/         → get a single stack
 *   DELETE /api/stacks/{id}/         → delete a stack record
 *   POST   /api/stacks/{id}/deploy/  → deploy (pulumi up)
 *   POST   /api/stacks/{id}/destroy/ → destroy (pulumi destroy)
 */

import api from './api'
import type { Stack, CreateStackRequest, StackActionResponse } from '@/types'

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

/** Create a new stack record (starts as "pending"). */
export async function createStack(payload: CreateStackRequest): Promise<Stack> {
  const { data } = await api.post<Stack>('/stacks/', payload)
  return data
}

/** Trigger a deploy (pulumi up) for a stack. */
export async function deployStack(stackId: string): Promise<StackActionResponse> {
  const { data } = await api.post<StackActionResponse>(`/stacks/${stackId}/deploy/`)
  return data
}

/** Trigger a destroy (pulumi destroy) for a stack. */
export async function destroyStack(stackId: string): Promise<StackActionResponse> {
  const { data } = await api.post<StackActionResponse>(`/stacks/${stackId}/destroy/`)
  return data
}

/** Trigger a refresh (pulumi refresh) for a stack. */
export async function refreshStack(stackId: string): Promise<StackActionResponse> {
  const { data } = await api.post<StackActionResponse>(`/stacks/${stackId}/refresh/`)
  return data
}

/** Trigger a preview (pulumi preview) for a stack. */
export async function previewStack(stackId: string): Promise<StackActionResponse> {
  const { data } = await api.post<StackActionResponse>(`/stacks/${stackId}/preview/`)
  return data
}

/** Delete a stack record. */
export async function deleteStack(stackId: string): Promise<void> {
  await api.delete(`/stacks/${stackId}/`)
}

/**
 * Force-destroy a stack regardless of its current status.
 *
 * Use this for stacks stuck in deploying, refreshing, or other busy states
 * where the standard destroy endpoint returns 409 Conflict.
 *
 * @param stackId - UUID of the stack to force-destroy.
 */
export async function forceDestroyStack(stackId: string): Promise<StackActionResponse> {
  const { data } = await api.post<StackActionResponse>(`/stacks/${stackId}/force-destroy/`)
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
