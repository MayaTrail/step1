import { useCachedResource } from './useCachedResource'
import { buildSearchIndex, type SearchItem } from '@/services/search.service'

/**
 * Load the global search index, cached for the process lifetime.
 *
 * Backed by useCachedResource: the first open builds the index (two API calls)
 * and every subsequent open is instant from cache, revalidating in the
 * background. Pass `enabled = false` to skip building entirely (key = null), so
 * nothing is fetched until the palette is actually opened.
 */
export function useSearchIndex(enabled: boolean): { items: SearchItem[]; loading: boolean } {
    const { data, loading } = useCachedResource<SearchItem[]>(
        enabled ? 'search-index' : null,
        buildSearchIndex,
    )
    return { items: data ?? [], loading }
}
