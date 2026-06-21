import { useState, useEffect } from 'react'
import type { PlatformId } from '@/types'
import type { PlatformCoverageRow, MitreSummary } from '@/types/metrics'
import { getPlatformCoverage, getMitreCoverage } from '@/services/metrics.service'

interface OverviewState {
  /** Content-depth counts for this platform (emulations/playbooks/detections). */
  coverage: PlatformCoverageRow | null
  /** MITRE technique coverage for this platform (covered/total). */
  mitre: MitreSummary | null
  loading: boolean
}

/**
 * Fetch the metric figures for one platform's overview page.
 *
 * Combines two existing, platform-aware dashboard endpoints — platform-coverage
 * (content depth) and mitre-coverage (technique coverage) — into a single state.
 * Both already return zero-filled data for platforms without content, so empty
 * platforms render naturally.
 */
export function usePlatformOverview(platformId: PlatformId): OverviewState {
  const [state, setState] = useState<OverviewState>({ coverage: null, mitre: null, loading: true })

  useEffect(() => {
    let cancelled = false
    setState((s) => ({ ...s, loading: true }))

    Promise.all([
      getPlatformCoverage(platformId),
      getMitreCoverage({ platform: platformId }),
    ])
      .then(([coverage, mitre]) => {
        if (cancelled) return
        const row = coverage.platforms.find((p) => p.platform === platformId) ?? null
        setState({ coverage: row, mitre: mitre.summary, loading: false })
      })
      .catch(() => {
        if (!cancelled) setState({ coverage: null, mitre: null, loading: false })
      })

    return () => { cancelled = true }
  }, [platformId])

  return state
}
