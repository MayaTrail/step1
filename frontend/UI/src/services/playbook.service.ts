/**
 * Playbook Service — API calls for user-authored IR playbooks.
 *
 * Endpoints:
 *   GET    /api/playbooks/              List playbooks visible to the caller
 *   POST   /api/playbooks/              Author a new playbook
 *   POST   /api/playbooks/fork/         Fork an emulation's shipped PLAYBOOK.md
 *   POST   /api/playbooks/generate/     Draft one with the user's LLM connector
 *   GET    /api/playbooks/<id>/         Read one
 *   PATCH  /api/playbooks/<id>/         Edit one (author only)
 *   DELETE /api/playbooks/<id>/         Delete one (author only)
 *   GET    /api/playbooks/<id>/export/  Download as PLAYBOOK.md
 *
 * The `body` field is Markdown. The editor is a rich-text surface and never
 * shows it, but Markdown is what the shipped playbooks use, so a fork in and a
 * download out are both lossless.
 */

import api from './api'
import type {
  PlaybookDraft,
  PlaybookGenerateRequest,
  UserPlaybook,
  UserPlaybookListItem,
  UserPlaybookDraft,
} from '@/types'

/** List playbooks the current user can see, most recently edited first. */
export async function listPlaybooks(
  opts: { mine?: boolean; source?: string } = {},
): Promise<UserPlaybookListItem[]> {
  const params: Record<string, string> = {}
  if (opts.mine) params.mine = '1'
  if (opts.source) params.source = opts.source
  const { data } = await api.get<UserPlaybookListItem[]>('/playbooks/', { params })
  return data
}

/** Fetch one playbook, including its Markdown body. */
export async function getPlaybook(id: string): Promise<UserPlaybook> {
  const { data } = await api.get<UserPlaybook>(`/playbooks/${id}/`)
  return data
}

/** Create a playbook from scratch. */
export async function createPlaybook(draft: UserPlaybookDraft): Promise<UserPlaybook> {
  const { data } = await api.post<UserPlaybook>('/playbooks/', draft)
  return data
}

/**
 * Fork the PLAYBOOK.md that ships with an emulation into an editable copy.
 *
 * @param emulationType - Emulation package name, e.g. "ambersquid".
 * @param title - Optional title; the server derives one when omitted.
 */
export async function forkPlaybook(
  emulationType: string,
  title?: string,
): Promise<UserPlaybook> {
  const { data } = await api.post<UserPlaybook>('/playbooks/fork/', {
    emulation_type: emulationType,
    ...(title ? { title } : {}),
  })
  return data
}

/** Apply a partial update. Author only; others get 403. */
export async function updatePlaybook(
  id: string,
  patch: Partial<UserPlaybookDraft>,
): Promise<UserPlaybook> {
  const { data } = await api.patch<UserPlaybook>(`/playbooks/${id}/`, patch)
  return data
}

/** Delete a playbook. Author only. */
export async function deletePlaybook(id: string): Promise<void> {
  await api.delete(`/playbooks/${id}/`)
}

/**
 * Download a playbook as a PLAYBOOK.md file.
 *
 * Fetches through the configured axios instance rather than pointing an <a> at
 * the URL, because the endpoint needs the Authorization header.
 */
export async function downloadPlaybook(
  id: string,
  filename: string,
): Promise<void> {
  const { data } = await api.get(`/playbooks/${id}/export/`, {
    responseType: 'blob',
  })
  const url = URL.createObjectURL(new Blob([data], { type: 'text/markdown' }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename.endsWith('.md') ? filename : `${filename}.md`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/**
 * Draft a playbook with the user's configured AI connector.
 *
 * Returns the document unsaved: the editor loads it as blocks and the author
 * decides whether it is worth keeping. Requires an AI connector configured in
 * Settings; without one the endpoint answers 409.
 *
 * Generation is slower than a normal call, so this overrides the client's
 * default timeout.
 */
export async function generatePlaybook(
  req: PlaybookGenerateRequest,
): Promise<PlaybookDraft> {
  const { data } = await api.post<PlaybookDraft>('/playbooks/generate/', req, {
    timeout: 120_000,
  })
  return data
}
