/**
 * Global search index for the command palette.
 *
 * Builds one flat, client-side index from existing data sources, with no new
 * backend endpoint. Emulations come from the backend list; each emulation also
 * yields a Playbook and Detections entry pointing at its per-emulation routes
 * (so the whole index costs three API calls, not N+1). Stacks come from the
 * stacks list. Guardrails come from the library index, which carries no policy
 * text, so indexing all of them stays cheap.
 */

import type { PlatformId } from '@/types'
import { fetchEmulations, fetchGuardrails } from './platform.service'
import { listStacks } from './stack.service'

export type SearchItemType = 'emulation' | 'playbook' | 'detection' | 'stack' | 'guardrail'

export interface SearchItem {
    /** Stable unique id within the index (also used as the React key). */
    id: string
    type: SearchItemType
    /** The text shown and matched against (name-only search). */
    name: string
    /** Owning platform, when applicable (for the badge). */
    platform?: PlatformId
    /** Short trailing metadata: severity, "Playbook", stack status, etc. */
    meta?: string
    /** Absolute route to navigate to on select. */
    route: string
}

/**
 * Build the full search index. Resolves emulations and stacks in parallel and
 * flattens them into SearchItems. Failures degrade to an empty list per source
 * so one failing call never blanks the whole palette.
 */
export async function buildSearchIndex(): Promise<SearchItem[]> {
    const [emulations, stacks, guardrails] = await Promise.all([
        // platformId is ignored by the service today; it returns all emulations.
        fetchEmulations('aws' as PlatformId).catch(() => []),
        listStacks().catch(() => []),
        fetchGuardrails('aws' as PlatformId).catch(() => null),
    ])

    const items: SearchItem[] = []

    for (const e of emulations) {
        const base = `/${e.platform}/emulations/${e.id}`
        items.push({
            id: `emulation:${e.id}`,
            type: 'emulation',
            name: e.name,
            platform: e.platform,
            meta: e.severity,
            route: base,
        })
        items.push({
            id: `playbook:${e.id}`,
            type: 'playbook',
            name: e.name,
            platform: e.platform,
            meta: 'Playbook',
            route: `${base}/playbook`,
        })
        items.push({
            id: `detection:${e.id}`,
            type: 'detection',
            name: e.name,
            platform: e.platform,
            meta: 'Detections',
            route: `${base}/detections`,
        })
    }

    for (const s of stacks) {
        items.push({
            id: `stack:${s.id}`,
            type: 'stack',
            name: s.name,
            meta: s.status,
            route: '/stacks',
        })
    }

    // The purpose is the only name a policy has, so it is what the palette
    // matches against; the SCP/RCP split rides along as the trailing meta.
    for (const g of guardrails?.guardrails ?? []) {
        items.push({
            id: `guardrail:${g.id}`,
            type: 'guardrail',
            name: g.purpose,
            platform: 'aws' as PlatformId,
            meta: g.type,
            route: `/aws/guardrails/${g.id}`,
        })
    }

    return items
}
