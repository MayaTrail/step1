import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import type { PlatformId, PlatformData } from '@/types'
import { fetchPlatformData } from '@/services/platform.service'

interface PlatformContextValue {
  /** Currently-selected platform ID (null = dashboard overview) */
  activePlatform: PlatformId | null
  setActivePlatform: (id: PlatformId | null) => void
  /** Cached platform data keyed by ID */
  cache: Partial<Record<PlatformId, PlatformData>>
  /** Load platform data into cache (no-op if already cached) */
  loadPlatform: (id: PlatformId) => Promise<PlatformData | null>
}

const PlatformContext = createContext<PlatformContextValue | null>(null)

export function PlatformProvider({ children }: { children: ReactNode }) {
  const [activePlatform, setActivePlatform] = useState<PlatformId | null>(null)
  const [cache, setCache] = useState<Partial<Record<PlatformId, PlatformData>>>({})

  const loadPlatform = useCallback(
    async (id: PlatformId): Promise<PlatformData | null> => {
      if (cache[id]) return cache[id]!
      const data = await fetchPlatformData(id)
      if (data) {
        setCache((prev) => ({ ...prev, [id]: data }))
      }
      return data
    },
    [cache],
  )

  return (
    <PlatformContext.Provider value={{ activePlatform, setActivePlatform, cache, loadPlatform }}>
      {children}
    </PlatformContext.Provider>
  )
}

export function usePlatform(): PlatformContextValue {
  const ctx = useContext(PlatformContext)
  if (!ctx) throw new Error('usePlatform must be used within <PlatformProvider>')
  return ctx
}
