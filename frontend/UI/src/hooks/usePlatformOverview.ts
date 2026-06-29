import type { PlatformId } from '@/types'
import type { PlatformCoverageRow, MitreSummary } from '@/types/metrics'
import { getPlatformCoverage, getMitreCoverage } from '@/services/metrics.service'
import { useCachedResource } from './useCachedResource'

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
 * Backed by useCachedResource, so switching between platforms shows the last
 * figures immediately and revalidates in the background instead of flashing a
 * loading state on every change. Both endpoints already return zero-filled data
 * for platforms without content, so empty platforms render naturally.
 */
export function usePlatformOverview(platformId: PlatformId): OverviewState {
  const { data, loading } = useCachedResource<Omit<OverviewState, 'loading'>>(
    `platform-overview:${platformId}`,
    async () => {
      const [coverage, mitre] = await Promise.all([
        getPlatformCoverage(platformId),
        getMitreCoverage({ platform: platformId }),
      ])
      const row = coverage.platforms.find((p) => p.platform === platformId) ?? null
      return { coverage: row, mitre: mitre.summary }
    },
  )

  return { coverage: data?.coverage ?? null, mitre: data?.mitre ?? null, loading }
}
