import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSearchIndex } from '@/hooks/useSearchIndex'
import type { SearchItem, SearchItemType } from '@/services/search.service'
import { platformShortLabel } from '@/data/platforms'

/**
 * Global command palette.
 *
 * Name-only, client-side search over the cached index (emulations, playbooks,
 * detections, stacks). Results are grouped by type; the keyboard drives a single
 * flat selection across all groups (up/down to move, Enter to open, Esc to
 * close). Selecting a result navigates to its route and closes the palette.
 */

const GROUPS: { type: SearchItemType; label: string }[] = [
    { type: 'emulation', label: 'Emulations' },
    { type: 'playbook', label: 'Playbooks' },
    { type: 'detection', label: 'Detections' },
    { type: 'stack', label: 'Stacks' },
]

// Cap per group so a broad query stays scannable.
const PER_GROUP = 6

export function SearchPalette({ onClose }: { onClose: () => void }) {
    const navigate = useNavigate()
    const { items, loading } = useSearchIndex(true)
    const [query, setQuery] = useState('')
    const [activeIndex, setActiveIndex] = useState(0)
    const activeRef = useRef<HTMLButtonElement>(null)

    // Name-only match; prefix matches rank above substring matches.
    const matched = useMemo(() => {
        const q = query.trim().toLowerCase()
        if (!q) return [] as SearchItem[]
        const hits = items.filter((i) => i.name.toLowerCase().includes(q))
        return hits.sort((a, b) => {
            const ap = a.name.toLowerCase().startsWith(q) ? 0 : 1
            const bp = b.name.toLowerCase().startsWith(q) ? 0 : 1
            return ap - bp
        })
    }, [items, query])

    // Group (in fixed order), cap each group, and flatten for keyboard nav.
    const { groups, flat } = useMemo(() => {
        const g = GROUPS
            .map((grp) => ({ ...grp, items: matched.filter((m) => m.type === grp.type).slice(0, PER_GROUP) }))
            .filter((grp) => grp.items.length > 0)
        return { groups: g, flat: g.flatMap((grp) => grp.items) }
    }, [matched])

    const indexById = useMemo(() => new Map(flat.map((it, i) => [it.id, i])), [flat])

    // Reset the cursor whenever the result set changes.
    useEffect(() => {
        setActiveIndex(0)
    }, [query])

    // Keep the active row in view as the cursor moves.
    useEffect(() => {
        activeRef.current?.scrollIntoView({ block: 'nearest' })
    }, [activeIndex])

    function select(item: SearchItem) {
        navigate(item.route)
        onClose()
    }

    function handleKeyDown(e: React.KeyboardEvent) {
        if (e.key === 'ArrowDown') {
            e.preventDefault()
            setActiveIndex((i) => Math.min(i + 1, flat.length - 1))
        } else if (e.key === 'ArrowUp') {
            e.preventDefault()
            setActiveIndex((i) => Math.max(i - 1, 0))
        } else if (e.key === 'Enter') {
            e.preventDefault()
            const item = flat[activeIndex]
            if (item) select(item)
        }
    }

    return (
        <div
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[200] flex items-start justify-center pt-20"
            onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
        >
            <div className="bg-surface-card border border-border rounded-card w-[600px] max-w-[92vw] overflow-hidden animate-modalIn shadow-[0_12px_40px_rgba(0,0,0,0.6)]">
                {/* Input */}
                <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
                    <span className="text-content-dim" aria-hidden>&#128269;</span>
                    <input
                        type="text"
                        autoFocus
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Search emulations, playbooks, detections, stacks..."
                        className="flex-1 bg-transparent border-none outline-none font-mono text-sm text-content-primary placeholder:text-content-dim"
                    />
                    <span
                        onClick={onClose}
                        className="font-mono text-[10px] text-content-dim cursor-pointer hover:text-content-secondary"
                    >
                        ESC
                    </span>
                </div>

                {/* Results */}
                <div className="p-2 max-h-[400px] overflow-y-auto">
                    {!query.trim() ? (
                        <div className="text-center py-8 text-content-dim font-mono text-xs">
                            {loading ? 'Building search index...' : 'Start typing to search across the platform...'}
                        </div>
                    ) : flat.length === 0 ? (
                        <div className="text-center py-8 text-content-dim font-mono text-xs">
                            No matches for &ldquo;{query.trim()}&rdquo;.
                        </div>
                    ) : (
                        groups.map((grp) => (
                            <div key={grp.type} className="mb-1">
                                <div className="px-3 pt-3 pb-1 text-[11px] font-mono uppercase tracking-label text-content-dim">
                                    {grp.label}
                                </div>
                                {grp.items.map((item) => {
                                    const idx = indexById.get(item.id) ?? -1
                                    const active = idx === activeIndex
                                    return (
                                        <button
                                            key={item.id}
                                            ref={active ? activeRef : undefined}
                                            type="button"
                                            onMouseMove={() => setActiveIndex(idx)}
                                            onClick={() => select(item)}
                                            className={`flex w-full items-center justify-between gap-3 px-3 py-2 rounded-btn text-left cursor-pointer border-none
                                                ${active ? 'bg-white/10' : 'bg-transparent hover:bg-white/[0.04]'}`}
                                        >
                                            <span className="text-sm text-content-primary truncate">{item.name}</span>
                                            <span className="flex items-center gap-2 font-mono text-[11px] text-content-dim shrink-0">
                                                {item.platform && <span>{platformShortLabel(item.platform)}</span>}
                                                {item.meta && <span className="text-content-secondary">{item.meta}</span>}
                                            </span>
                                        </button>
                                    )
                                })}
                            </div>
                        ))
                    )}
                </div>

                {/* Footer hint */}
                <div className="flex items-center gap-4 px-4 py-2.5 border-t border-border text-[11px] font-mono text-content-dim">
                    <span>&#8593;&#8595; navigate</span>
                    <span>&#8629; open</span>
                    <span>esc close</span>
                </div>
            </div>
        </div>
    )
}
