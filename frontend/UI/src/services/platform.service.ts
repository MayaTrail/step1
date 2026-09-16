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
  DetectionDetail,
  GuardrailLibrary,
  GuardrailDetail,
  Playbook,
  PlaybookRaw,
  CommandResult,
} from '@/types'

/** Build a tab/URL-safe slug from a section title. */
function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

/**
 * Parse a raw PLAYBOOK.md into navigable sections.
 *
 * Each H2 heading ("## Title") becomes one section, and the markdown beneath it
 * is preserved verbatim (sub-headings, lists, tables, and every fenced code
 * block).  Keeping the raw markdown, rather than flattening it to a single
 * body + first-code-block, lets the page render each section faithfully via the
 * shared Markdown component and lets the tab set mirror whatever sections the
 * playbook actually declares (graceful degradation across thin and rich
 * playbooks).
 */
export function parsePlaybookMarkdown(content: string): Playbook {
  // The leading H1 (if any) is the playbook's own title.
  const titleMatch = content.match(/^#\s+(.+)$/m)
  const title = titleMatch ? titleMatch[1]?.trim() : undefined

  // split() on the H2 boundary drops the preamble before the first H2 as the
  // initial element, so slice(1) discards it and leaves one entry per section.
  const parts = content.split(/^##\s+/m).slice(1)
  const sections: Playbook['sections'] = []

  for (const part of parts) {
    const nl = part.indexOf('\n')
    const rawTitle = (nl === -1 ? part : part.slice(0, nl)).trim()
    if (!rawTitle) continue
    const markdown = (nl === -1 ? '' : part.slice(nl + 1)).trim()
    // Strip a leading ordinal ("2. ") so the tab label reads "Identification".
    const cleanTitle = rawTitle.replace(/^\d+\.\s*/, '')
    sections.push({ id: slugify(cleanTitle), title: cleanTitle, markdown })
  }

  return { title, sections }
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
 * Fetch the full detail for a single detection rule.
 *
 * @param emulationType - The emulation package name, e.g. "ambersquid".
 * @param ruleId - The technique grouping key, e.g. "t1098.001".
 */
export async function fetchDetectionDetail(
  emulationType: string,
  ruleId: string,
): Promise<DetectionDetail | null> {
  if (!emulationType || !ruleId) return null
  try {
    const { data } = await api.get<DetectionDetail>(
      `/emulations/${emulationType}/detections/${ruleId}/`,
    )
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

/**
 * Run a single read-only playbook command against the user's AWS account.
 *
 * The backend parses, resolves, allowlist-validates, and (only if safe) executes
 * the command with the user's assumed role. A non-runnable command comes back
 * with `runnable: false` and a reason rather than an error.
 */
export async function runPlaybookCommand(emulationType: string, command: string): Promise<CommandResult> {
  const { data } = await api.post<CommandResult>(`/emulations/${emulationType}/command/`, { command })
  return data
}

/* The following stubs are retained so that any call-sites that haven't yet
   been updated compile without errors.  They will be removed once all
   call-sites are migrated to the per-emulation signatures above. */

export async function fetchPlatformData(_platformId: PlatformId): Promise<PlatformData | null> {
  return null
}

/**
 * Fetch the SCP/RCP guardrail library index.
 *
 * The library is AWS-only, so other platforms resolve to null and the
 * Guardrails pages render their empty state rather than an AWS policy list.
 * Policy documents are not included; use fetchGuardrail for one policy's text.
 */
export async function fetchGuardrails(platformId: PlatformId): Promise<GuardrailLibrary | null> {
  if (platformId !== 'aws') return null
  try {
    const { data } = await api.get<GuardrailLibrary>('/guardrails/')
    return data
  } catch {
    return null
  }
}

/**
 * Fetch one guardrail with its policy document.
 *
 * @param guardrailId - The catalogue slug, e.g. "deny-kms-key-deletion".
 */
export async function fetchGuardrail(guardrailId: string): Promise<GuardrailDetail | null> {
  try {
    const { data } = await api.get<GuardrailDetail>(`/guardrails/${guardrailId}/`)
    return data
  } catch {
    return null
  }
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

/**
 * A playbook from the standalone IR library (playbooks/), which is indexed by
 * detection use case rather than by technique. Most have no emulation behind
 * them, so they are documentation: useful to a SOC analyst on its own, but the
 * detection rules they carry are unvalidated reference material.
 */
export interface LibraryPlaybook {
  id: string
  title: string
  service: string
  tactic: string
  severity: string
  incidentType: string
  platform: string
  techniques: string[]
  tactics: string[]
  services: string[]
  detectionFiles: string[]
  lineCount: number
  markdown?: string
}

/** Fetch the standalone playbook library index. Empty when none is mounted. */
export async function fetchLibraryPlaybooks(): Promise<LibraryPlaybook[]> {
  try {
    const { data } = await api.get<{ count: number; playbooks: LibraryPlaybook[] }>(
      '/emulations/library/',
    )
    return data.playbooks ?? []
  } catch {
    return []
  }
}

/** Fetch one standalone playbook, including its markdown body. */
export async function fetchLibraryPlaybook(id: string): Promise<LibraryPlaybook | null> {
  if (!id) return null
  try {
    const { data } = await api.get<LibraryPlaybook>(`/emulations/library/${id}/`)
    return data
  } catch {
    return null
  }
}
