import { awsData } from './aws'
import type { PlatformData, PlatformId, PlatformMeta } from '@/types'

/** Short, recognizable label per platform — used by the sidebar, hub filter
 *  chips, and the Operations run tables. Single source of truth so the same
 *  abbreviation appears everywhere. */
export const PLATFORM_SHORT_LABEL: Record<PlatformId, string> = {
  aws: 'AWS',
  gcp: 'GCP',
  azure: 'Azure',
  k8s: 'Kubernetes',
  ai: 'AI',
}

/** Return the short label for a platform id, falling back to upper-case. */
export function platformShortLabel(id: PlatformId): string {
  return PLATFORM_SHORT_LABEL[id] ?? id.toUpperCase()
}

/** Platform metadata for sidebar, navigation, and badges */
export const platformRegistry: PlatformMeta[] = [
  { id: 'aws', label: 'Amazon Web Services', icon: '\u{f0379}', route: 'aws', badgeCount: 5 },
  { id: 'ai', label: 'AI / ML Security', icon: '\u{f01a7}', route: 'ai', badgeCount: 4 },
  { id: 'gcp', label: 'Google Cloud Platform', icon: '\u{f03ea}', route: 'gcp', badgeCount: 5 },
  { id: 'azure', label: 'Microsoft Azure', icon: '\u{f0805}', route: 'azure', badgeCount: 5 },
  { id: 'k8s', label: 'Kubernetes', icon: '\u{f10fe}', route: 'k8s', badgeCount: 5 },
]

/** Map of platform data keyed by platform ID. Only AWS is populated for now;
 *  other platforms will be fetched from the API once the backend is ready. */
const platformDataMap: Partial<Record<PlatformId, PlatformData>> = {
  aws: awsData,
}

export function getPlatformData(id: PlatformId): PlatformData | undefined {
  return platformDataMap[id]
}

export function getPlatformMeta(id: PlatformId): PlatformMeta | undefined {
  return platformRegistry.find((p) => p.id === id)
}

export { awsData }
