/**
 * AI Service — the bring-your-own-key LLM connector (apps.ai).
 *
 * Endpoints:
 *   GET    /api/ai/connector/        Current connector (masked; never the key)
 *   PUT    /api/ai/connector/        Create or update (upsert)
 *   DELETE /api/ai/connector/        Remove it
 *   POST   /api/ai/connector/test/   Validate a key without billing
 */

import api from './api'
import type {
  Conversation,
  LLMConnector,
  LLMConnectorTestResult,
  LLMProvider,
} from '@/types'

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api'
const TOKEN_KEY = 'mayatrail_token'

/** Fetch the current user's connector (masked). */
export async function getLLMConnector(): Promise<LLMConnector> {
  const { data } = await api.get<LLMConnector>('/ai/connector/')
  return data
}

export interface SaveLLMConnectorPayload {
  provider: LLMProvider
  model: string
  enabled?: boolean
  /** Plaintext key; required on first create, optional on update. */
  api_key?: string
}

/** Create or update the connector. */
export async function saveLLMConnector(
  payload: SaveLLMConnectorPayload,
): Promise<LLMConnector> {
  const { data } = await api.put<LLMConnector>('/ai/connector/', payload)
  return data
}

/** Remove the connector and its stored key. */
export async function deleteLLMConnector(): Promise<void> {
  await api.delete('/ai/connector/')
}

/**
 * Test a connection. Pass a provider+key to validate before saving; omit the
 * argument to test the stored connector.
 */
export async function testLLMConnector(
  payload?: { provider: LLMProvider; api_key: string },
): Promise<LLMConnectorTestResult> {
  const { data } = await api.post<LLMConnectorTestResult>('/ai/connector/test/', payload ?? {})
  return data
}

/** Suggested models per provider (mirrors backend providers.MODELS; custom ids allowed). */
export const SUGGESTED_MODELS: Record<LLMProvider, string[]> = {
  openai: ['gpt-4o', 'gpt-4o-mini', 'o4-mini'],
  anthropic: ['claude-opus-4-8', 'claude-sonnet-4-6', 'claude-haiku-4-5-20251001'],
}

/* ── Multi-turn chat (M3) ── */

/** List the user's conversations for one emulation, newest first. */
export async function listConversations(emulationType: string): Promise<Conversation[]> {
  const { data } = await api.get<Conversation[]>('/ai/conversations/', {
    params: { emulation_type: emulationType },
  })
  return data
}

/** Create a new (empty) conversation for an emulation. */
export async function createConversation(emulationType: string): Promise<Conversation> {
  const { data } = await api.post<Conversation>('/ai/conversations/', {
    emulation_type: emulationType,
  })
  return data
}

/** Fetch a conversation with its full message history. */
export async function getConversation(id: string): Promise<Conversation> {
  const { data } = await api.get<Conversation>(`/ai/conversations/${id}/`)
  return data
}

/** Delete a conversation and its messages. */
export async function deleteConversation(id: string): Promise<void> {
  await api.delete(`/ai/conversations/${id}/`)
}

/**
 * Send a user turn and stream the assistant reply.
 *
 * Uses fetch + ReadableStream (not EventSource) so the JWT can be sent in the
 * Authorization header. `onDelta` is called with each text chunk as it arrives.
 * Pre-stream errors (no connector, bad request) reject with the server detail.
 */
export async function streamMessage(
  conversationId: string,
  content: string,
  onDelta: (chunk: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  const token = localStorage.getItem(TOKEN_KEY)
  const res = await fetch(`${API_BASE}/ai/conversations/${conversationId}/messages/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ content }),
    signal,
  })

  if (!res.ok || !res.body) {
    let detail = `Request failed (${res.status})`
    try {
      const body = await res.json()
      if (body?.detail) detail = body.detail
    } catch {
      /* non-JSON error body; keep the default */
    }
    throw new Error(detail)
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (value) onDelta(decoder.decode(value, { stream: true }))
  }
}
