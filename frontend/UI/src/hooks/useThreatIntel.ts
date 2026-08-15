import { useEffect, useRef, useState } from 'react'
import type { ThreatIntelFeed, ThreatIntelSources } from '@/types'
import * as threatIntelService from '@/services/threatintel.service'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
}

/**
 * Stale-while-revalidate fetch with a process-lifetime cache.
 *
 * Same contract as the helper in usePlatformData.ts, kept local to this file
 * rather than exported from there: threat intel is not platform-scoped, and
 * lifting the helper into a shared module is a refactor of that file's
 * concern, not this feature's.
 *
 *   - Seeds synchronously from cache, so switching panels renders instantly.
 *   - Only reports `loading` when there is nothing to show, so a revalidation
 *     never blanks already-rendered content.
 */
const _cache = new Map<string, unknown>()

function useCachedAsync<T>(key: string, fetcher: () => Promise<T | null>): AsyncState<T> {
  const has = _cache.has(key)
  const [data, setData] = useState<T | null>(() => (has ? (_cache.get(key) as T) : null))
  const [loading, setLoading] = useState<boolean>(() => !has)
  const [error, setError] = useState<string | null>(null)

  const dataRef = useRef(data)
  dataRef.current = data

  useEffect(() => {
    let cancelled = false
    if (dataRef.current === null) setLoading(true)
    setError(null)
    fetcher()
      .then((d) => {
        if (cancelled) return
        _cache.set(key, d)
        setData(d)
      })
      .catch(() => !cancelled && setError('Could not load threat intel'))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
    // key encodes all inputs; fetcher is recreated each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  return { data, loading, error }
}

/**
 * Fetch the aggregated RSS feed from the latest ingest run.
 *
 * @param limit - Maximum items to request.
 */
export function useThreatIntelFeed(limit = 100): AsyncState<ThreatIntelFeed> {
  return useCachedAsync(`threatintel:feed:${limit}`, () =>
    threatIntelService.fetchThreatIntelFeed(limit),
  )
}

/** Fetch the subscription list with each feed's latest ingest outcome. */
export function useThreatIntelSources(): AsyncState<ThreatIntelSources> {
  return useCachedAsync('threatintel:sources', threatIntelService.fetchThreatIntelSources)
}
