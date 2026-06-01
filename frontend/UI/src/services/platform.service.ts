/**
 * Platform service — API calls for emulation catalogue data.
 *
 * All data previously served from static TypeScript files in data/platforms/
 * is now driven by the backend emulations API.  The function signatures are
 * preserved so usePlatformData.ts hooks require no changes.
 *
 * Endpoints consumed:
 *   GET /api/emulations/                        → list of Emulation objects
 *   GET /api/emulations/<type>/detections/      → DetectionData
 *   GET /api/emulations/<type>/playbook/        → PlaybookRaw (markdown)
 */

import api from './api'
import type {
  PlatformId,
  PlatformData,
  Emulation,
  DetectionData,
  Guardrails,
  Playbook,
  PlaybookRaw,
} from '@/types'

/**
 * Parse a raw PLAYBOOK.md string into the Playbook steps structure expected
 * by PlaybookPage.  Each H2 section ("## Title") becomes one step; the
 * content below becomes the body; the first fenced code block becomes the
 * optional code field.
 */
function parsePlaybookMarkdown(content: string): Playbook {
  const steps: Playbook['steps'] = []
  const sections = content.split(/^## /m).filter(Boolean)

  for (const section of sections) {
    const lines = section.split('\n')
    const title = (lines[0] ?? '').trim()
    const rest = lines.slice(1).join('\n').trim()

    // Extract first fenced code block if present.
    const codeMatch = rest.match(/```[\w]*\n([\s\S]*?)```/)
    const code = codeMatch ? (codeMatch[1] ?? '').trimEnd() : undefined
    const body = rest.replace(/```[\w]*\n[\s\S]*?```/g, '').trim()

    if (title) {
      steps.push({ title, body, code })
    }
  }

  return { steps }
}

/**
 * Fetch all emulations from the backend.
 *
 * All emulations are currently AWS-platform.  As other platforms are added,
 * the backend will need a platform filter.  For now the list is filtered
 * client-side on the (single) supported platform.
 */
export async function fetchEmulations(_platformId: PlatformId): Promise<Emulation[]> {
  try {
    const { data } = await api.get<Emulation[]>('/emulations/')
    return data
  } catch {
    return []
  }
}

/**
 * Fetch a single emulation by its ID (MANIFEST name field).
 */
export async function fetchEmulationById(
  platformId: PlatformId,
  emulationId: string,
): Promise<Emulation | null> {
  const emulations = await fetchEmulations(platformId)
  return emulations.find((e) => e.id === emulationId) ?? null
}

/**
 * Fetch detection rules for a specific emulation type.
 *
 * @param emulationType - The emulation package name, e.g. "scarleteel".
 */
export async function fetchDetections(emulationType: string): Promise<DetectionData | null> {
  if (!emulationType) return null
  try {
    const { data } = await api.get<DetectionData>(`/emulations/${emulationType}/detections/`)
    return data
  } catch {
    return null
  }
}

/**
 * Fetch the IR playbook for a specific emulation type and parse it into steps.
 *
 * @param emulationType - The emulation package name, e.g. "scarleteel".
 */
export async function fetchPlaybook(emulationType: string): Promise<Playbook | null> {
  if (!emulationType) return null
  try {
    const { data } = await api.get<PlaybookRaw>(`/emulations/${emulationType}/playbook/`)
    return parsePlaybookMarkdown(data.content)
  } catch {
    return null
  }
}

/* The following stubs are retained so that any call-sites that haven't yet
   been updated compile without errors.  They will be removed once all
   call-sites are migrated to the per-emulation signatures above. */

export async function fetchPlatformData(_platformId: PlatformId): Promise<PlatformData | null> {
  return null
}

export async function fetchGuardrails(_platformId: PlatformId): Promise<Guardrails | null> {
  return null
}

export async function fetchPlaybooks(_platformId: PlatformId): Promise<Playbook[]> {
  return []
}

export async function fetchPlaybookById(
  _platformId: PlatformId,
  _index: number,
): Promise<Playbook | null> {
  return null
}
