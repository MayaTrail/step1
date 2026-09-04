import { useEffect, useRef, useState } from 'react'
import type { PlatformId, PlatformData, Emulation, DetectionData, DetectionDetail, GuardrailLibrary, GuardrailDetail, Playbook } from '@/types'
import type { LibraryPlaybook } from '@/services/platform.service'
import * as platformService from '@/services/platform.service'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
}

/**
 * Stale-while-revalidate fetch with a process-lifetime cache, in the AsyncState
 * shape these hooks return. Fixes the navigation flicker whose cause was: every
 * page mount refetched and showed a loading state with nothing cached between
 * visits.
 *
 *   - `key === null` means "skip" (a required param is undefined): no fetch.
 *   - Seeds synchronously from cache, so revisiting a page renders instantly.
 *   - Only reports `loading` when there is nothing to show, so a revalidation
 *     never blanks already-rendered content.
 *
 * @param key         Stable cache key, or null to skip fetching.
 * @param fetcher     Returns the resource (or null when not found).
 * @param notFoundMsg Error string when the fetch resolves to a falsy value.
 */
const _cache = new Map<string, unknown>()

function useCachedAsync<T>(
  key: string | null,
  fetcher: () => Promise<T | null>,
  notFoundMsg: string | null,
): AsyncState<T> {
  const has = key !== null && _cache.has(key)
  const [data, setData] = useState<T | null>(() => (has ? (_cache.get(key as string) as T) : null))
  const [loading, setLoading] = useState<boolean>(() => key !== null && !has)
  const [error, setError] = useState<string | null>(null)

  const dataRef = useRef(data)
  dataRef.current = data

  useEffect(() => {
    if (key === null) {
      setData(null)
      setLoading(false)
      setError(null)
      return
    }
    let cancelled = false
    if (dataRef.current === null) setLoading(true)
    setError(null)
    fetcher()
      .then((d) => {
        if (cancelled) return
        _cache.set(key, d)
        setData(d)
        setError(d ? null : notFoundMsg)
      })
      .catch(() => !cancelled && setError(notFoundMsg))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
    // key encodes all inputs; fetcher is recreated each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  return { data, loading, error }
}

export function usePlatformData(platformId: PlatformId | undefined): AsyncState<PlatformData> {
  return useCachedAsync(
    platformId ? `platform:${platformId}` : null,
    () => platformService.fetchPlatformData(platformId as PlatformId),
    'Platform not found',
  )
}

export function useEmulations(platformId: PlatformId | undefined): AsyncState<Emulation[]> {
  return useCachedAsync(
    platformId ? `emulations:${platformId}` : null,
    () => platformService.fetchEmulations(platformId as PlatformId),
    null,
  )
}

export function useEmulation(
  platformId: PlatformId | undefined,
  emulationId: string | undefined,
): AsyncState<Emulation> {
  return useCachedAsync(
    platformId && emulationId ? `emulation:${platformId}:${emulationId}` : null,
    () => platformService.fetchEmulationById(platformId as PlatformId, emulationId as string),
    'Emulation not found',
  )
}

/**
 * Fetch detection rules for a specific emulation type.
 * Detections are per-emulation, not per-platform.
 *
 * @param emulationType - The emulation package name, e.g. "scarleteel".
 */
export function useDetections(emulationType: string | undefined): AsyncState<DetectionData> {
  return useCachedAsync(
    emulationType ? `detections:${emulationType}` : null,
    () => platformService.fetchDetections(emulationType as string),
    'Detections not found',
  )
}

/**
 * Fetch the full detail for a single detection rule.
 *
 * @param emulationType - The emulation package name, e.g. "ambersquid".
 * @param ruleId - The technique grouping key, e.g. "t1098.001".
 */
export function useDetectionDetail(
  emulationType: string | undefined,
  ruleId: string | undefined,
): AsyncState<DetectionDetail> {
  return useCachedAsync(
    emulationType && ruleId ? `detection:${emulationType}:${ruleId}` : null,
    () => platformService.fetchDetectionDetail(emulationType as string, ruleId as string),
    'Detection not found',
  )
}

/**
 * Fetch the SCP/RCP guardrail library index for a platform.
 * The library is AWS-only today; other platforms resolve to null.
 */
export function useGuardrails(platformId: PlatformId | undefined): AsyncState<GuardrailLibrary> {
  return useCachedAsync(
    platformId ? `guardrails:${platformId}` : null,
    () => platformService.fetchGuardrails(platformId as PlatformId),
    'Guardrails not found',
  )
}

/**
 * Fetch one guardrail with its policy document.
 *
 * The index omits policy text, so the preview pane resolves it per selection.
 * Each document is cached for the session, making re-selection instant.
 *
 * @param guardrailId - The catalogue slug, e.g. "deny-kms-key-deletion".
 */
export function useGuardrail(guardrailId: string | undefined): AsyncState<GuardrailDetail> {
  return useCachedAsync(
    guardrailId ? `guardrail:${guardrailId}` : null,
    () => platformService.fetchGuardrail(guardrailId as string),
    'Guardrail not found',
  )
}

/**
 * Fetch the IR playbook for a specific emulation type.
 * Playbooks are per-emulation, not per-platform.
 *
 * @param emulationType - The emulation package name, e.g. "scarleteel".
 */
export function usePlaybook(emulationType: string | undefined): AsyncState<Playbook> {
  return useCachedAsync(
    emulationType ? `playbook:${emulationType}` : null,
    () => platformService.fetchPlaybook(emulationType as string),
    'Playbook not found',
  )
}

/** @deprecated Use usePlaybook(emulationType) instead. */
export function usePlaybooks(_platformId: PlatformId | undefined): AsyncState<Playbook[]> {
  return { data: null, loading: false, error: null }
}

/** @deprecated Use usePlaybook(emulationType) instead. */
export function usePlaybookById(_platformId: PlatformId | undefined, _index: number): AsyncState<Playbook> {
  return { data: null, loading: false, error: null }
}

/** Index of the standalone IR playbook library (documentation, not emulations). */
export function useLibraryPlaybooks(): AsyncState<LibraryPlaybook[]> {
  return useCachedAsync('library:playbooks', () => platformService.fetchLibraryPlaybooks(), null)
}

/** One standalone playbook, with its markdown body. */
export function useLibraryPlaybook(id: string | undefined): AsyncState<LibraryPlaybook> {
  return useCachedAsync(
    id ? `library:playbook:${id}` : null,
    () => platformService.fetchLibraryPlaybook(id as string),
    'Playbook not found',
  )
}
