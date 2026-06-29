import { useEffect, useRef, useState } from 'react'

/**
 * Stale-while-revalidate data hook backed by a process-lifetime in-memory cache.
 *
 * Fixes the dashboard "flicker on every filter / navigation" issue, whose root
 * cause was: each section fetched on mount/refetch and replaced its whole body
 * with a "Loading…" placeholder during the round-trip (and nothing was cached
 * between visits).
 *
 * This hook:
 *   - Seeds initial state synchronously from the module cache, so revisiting a
 *     page shows the last data immediately (no navigation flash).
 *   - Only reports `loading` when there is genuinely nothing to show
 *     (`data === undefined`), so a refetch — e.g. after a filter change — keeps
 *     the existing content on screen and swaps it silently when new data lands.
 *   - Always revalidates in the background, so what you see is at most one render
 *     stale and self-corrects on the next tick.
 *
 * @param key     Stable cache key encoding all request params (e.g. the filters),
 *                or `null` to skip fetching (e.g. nothing selected).
 * @param fetcher Returns the resource for the current key.
 * @param options Optional `{ pollMs }` to silently revalidate on an interval
 *                (used by live views like Active Runs). Polling never toggles
 *                `loading`, so the visible content never flashes.
 */
const _cache = new Map<string, unknown>()

export function useCachedResource<T>(
    key: string | null,
    fetcher: () => Promise<T>,
    options?: { pollMs?: number },
) {
    const pollMs = options?.pollMs
    const seeded = key !== null && _cache.has(key)
    const [data, setData] = useState<T | undefined>(() => (seeded ? (_cache.get(key as string) as T) : undefined))
    const [loading, setLoading] = useState<boolean>(() => key !== null && !seeded)
    const [failed, setFailed] = useState(false)

    // Keep a live view of the current data so the effect can decide whether to
    // blank (only when there is nothing on screen at all).
    const dataRef = useRef(data)
    dataRef.current = data

    useEffect(() => {
        if (key === null) {
            setLoading(false)
            setFailed(false)
            return
        }
        const k = key  // narrowed to string (null handled above)
        let active = true

        // Revalidate without blanking the screen; loading is cleared on settle.
        const revalidate = () => {
            fetcher()
                .then((d) => {
                    if (!active) return
                    _cache.set(k, d)
                    setData(d)
                })
                .catch(() => active && setFailed(true))
                .finally(() => active && setLoading(false))
        }

        if (dataRef.current === undefined) setLoading(true)
        setFailed(false)
        revalidate()

        if (!pollMs) {
            return () => {
                active = false
            }
        }
        const id = setInterval(revalidate, pollMs)
        return () => {
            active = false
            clearInterval(id)
        }
        // fetcher is recreated each render; the key encodes its inputs.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [key, pollMs])

    return { data, loading, failed }
}
