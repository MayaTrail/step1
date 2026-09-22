/**
 * Ask the stored graph for the paths between two entities.
 *
 * Not the ranked-chains list: that is the top 25 Scout pre-scored at depth 5,
 * and this searches the whole graph to depth 10 for one specific pair. A path
 * found here that is not in the list is the point, not a discrepancy — hence
 * the depth note below.
 *
 * Four result states, and the distinctions matter more than the happy path:
 *
 *   paths found   — drawn through the same layout the chain view uses.
 *   none found    — named with the edge types actually traversed, because
 *                   "no path" is only true of those.
 *   search capped — the budget ran out. "No path found" would be unsafe to
 *                   say, so it is not said.
 *   truncated     — more paths exist; the shown ones are the shortest.
 *
 * One combination this view produces that the chain view almost never did: a
 * resource_access/resource_control hop carrying certainty: 'conditional'. The
 * spec flagged it as worth confirming the step renderer survives. It does, and
 * by construction rather than by luck — `mechanism` is read in exactly two
 * places (AttackChainGraph.tsx:246 and :445), both as the fallback half of
 * `step.action || step.mechanism`. Nothing in this frontend branches on its
 * value, so certainty and mechanism cannot interact. Keep it that way: a
 * `switch (step.mechanism)` is what would make this a real case to handle.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import * as attackGraph from '@/services/attackGraph.service'
import type { ChainNode, PathQueryResult } from '@/types/attackGraph'

import { GraphCanvas } from './AttackChainGraph'
import { stepsToGraph } from './chainGraph'
import { NodeIcon } from './nodeIcons'

// The endpoint's cost should track searches, not keystrokes. 200ms is the
// contract the backend's no-rehydrate search path was sized against.
const SEARCH_DEBOUNCE_MS = 200

function EntityPicker({
  scanId, label, value, onChange,
}: {
  scanId: string
  label: string
  value: ChainNode | null
  onChange: (node: ChainNode | null) => void
}) {
  const [term, setTerm] = useState('')
  const [options, setOptions] = useState<ChainNode[]>([])
  const [open, setOpen] = useState(false)
  // A failed search is not the same as an empty result — a scan with no
  // stored graph (GRAPH_UNAVAILABLE/GRAPH_PENDING/GRAPH_FAILED) 404s on
  // every search, and swallowing that left the picker looking permanently
  // empty with no explanation. The backend's own message names which of the
  // three it is; surface it verbatim, the same way QueryPanel.run()'s own
  // catch already does for the path query itself.
  const [error, setError] = useState('')
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => {
    if (!open) return
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => {
      attackGraph.searchGraphNodes(scanId, term)
        .then((nodes) => { setOptions(nodes); setError('') })
        .catch((err: unknown) => {
          setOptions([])
          const detail = (err as { response?: { data?: { detail?: string } } })
            ?.response?.data?.detail
          setError(detail || 'Search failed. Try again.')
        })
    }, SEARCH_DEBOUNCE_MS)
    return () => window.clearTimeout(timer.current)
  }, [scanId, term, open])

  return (
    <div className="relative">
      <label className="block text-[0.7rem] text-content-secondary mb-1">{label}</label>
      <input
        type="text"
        value={value ? value.label : term}
        onChange={(e) => { onChange(null); setTerm(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
        placeholder="Search identities and resources"
        className="w-full px-2 py-1.5 text-[0.75rem] rounded border border-border bg-surface-elevated text-content-primary"
      />
      {open && options.length > 0 && !value && (
        <ul className="absolute z-10 mt-1 w-full max-h-56 overflow-y-auto rounded border border-border bg-surface-card shadow-ring">
          {options.map((node) => (
            <li key={node.id}>
              <button
                type="button"
                onClick={() => { onChange(node); setOpen(false) }}
                className="w-full flex items-center gap-2 px-2 py-1.5 text-left text-[0.72rem] hover:bg-surface-elevated"
              >
                <NodeIcon nodeType={node.node_type} label={node.label} size={16} />
                <span className="truncate" title={node.id}>{node.label}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {open && error && !value && (
        <div className="absolute z-10 mt-1 w-full text-[0.7rem] text-danger">{error}</div>
      )}
    </div>
  )
}

export default function QueryPanel({
  scanId, initialSource, onClose,
}: { scanId: string; initialSource: ChainNode | null; onClose: () => void }) {
  const [src, setSrc] = useState<ChainNode | null>(initialSource)
  const [dst, setDst] = useState<ChainNode | null>(null)
  const [result, setResult] = useState<PathQueryResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => { setSrc(initialSource); setResult(null) }, [initialSource])

  const run = useCallback(async () => {
    if (!src || !dst) return
    setBusy(true)
    setError('')
    setResult(null)
    try {
      setResult(await attackGraph.findPaths(scanId, src.id, dst.id))
    } catch (err: unknown) {
      // The backend's message names the id it could not find, or says the scan
      // has no stored graph — both are worth showing verbatim.
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail
      setError(detail || 'The path query failed. Try again.')
    } finally {
      setBusy(false)
    }
  }, [scanId, src, dst])

  // Each path gets its own node/edge set so one long path does not distort
  // another's layout. `result.nodes` is passed as the type LOOKUP, not as a
  // seed — stepsToGraph only emits the ids this path's steps reference, so
  // path 1's layout does not contain path 3's nodes. (No `seed` argument:
  // that exists for zero-hop ranked chains, and a query never returns one.)
  // Without the lookup every node here would be a grey ARN-labelled box.
  const graphs = useMemo(
    () => (result?.paths ?? []).map((path, i) =>
      stepsToGraph(path.steps, `q${i}`, result?.nodes ?? [])),
    [result],
  )

  const edgeTypes = (result?.edge_types ?? []).join(' / ')
  const longPath = (result?.paths ?? []).some((p) => p.hop_count > 5)

  return (
    <div className="w-[360px] shrink-0 bg-surface-card border border-border rounded-card p-4 animate-slideUp shadow-ring overflow-y-auto" style={{ maxHeight: '74vh' }}>
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="font-display text-[0.9rem] font-bold text-content-primary">
          Find paths
        </div>
        <button type="button" onClick={onClose}
                className="text-content-secondary hover:text-content-primary text-[0.8rem]">
          Close
        </button>
      </div>

      <div className="space-y-2 mb-3">
        <EntityPicker scanId={scanId} label="From" value={src} onChange={setSrc} />
        <EntityPicker scanId={scanId} label="To" value={dst} onChange={setDst} />
      </div>

      <button
        type="button"
        onClick={run}
        disabled={!src || !dst || busy}
        className="w-full mb-3 px-3 py-1.5 text-[0.75rem] rounded border border-border text-content-primary hover:bg-surface-elevated disabled:opacity-40"
      >
        {busy ? 'Searching…' : 'Find paths'}
      </button>

      {error && <div className="text-[0.72rem] text-danger mb-3">{error}</div>}

      {result && result.search_capped && (
        <div className="text-[0.72rem] text-warning mb-3">
          Search budget reached before the graph was fully explored — there may
          be paths this query did not find.
        </div>
      )}

      {result && !result.search_capped && result.paths.length === 0 && (
        <div className="text-[0.72rem] text-content-secondary mb-3">
          No escalation path found from {src?.label} to {dst?.label} within{' '}
          {result.max_depth} hops, following {edgeTypes} edges.
        </div>
      )}

      {result && result.truncated && (
        <div className="text-[0.72rem] text-content-secondary mb-2">
          Showing the {result.paths.length} shortest paths; more exist.
        </div>
      )}

      {longPath && (
        <div className="text-[0.72rem] text-content-secondary mb-2">
          The ranked chain list only covers paths up to 5 hops, so a longer path
          here is differently scoped — not missing from the list by mistake.
        </div>
      )}

      {graphs.map((graph, i) => {
        // graphs and result.paths are built from the same array in the same
        // order (see the useMemo above), so this is always defined here —
        // noUncheckedIndexedAccess just can't see that across the two maps.
        const path = result?.paths[i]
        return (
        <div key={i} className="mb-3">
          <div className="text-[0.7rem] text-content-secondary mb-1">
            Path {i + 1} — {path?.hop_count} hops
          </div>
          <ol className="space-y-1 mb-2">
            {path?.steps.map((step, s) => (
              <li key={s} className="text-[0.7rem] text-content-primary">
                <span className="text-content-secondary">{s + 1}.</span>{' '}
                {step.detail}
                {step.certainty === 'conditional' && (
                  <span className="text-warning"> — {step.conditional_reason}</span>
                )}
              </li>
            ))}
          </ol>
          {/* GraphCanvas's <svg> renders at its native layout width/height
              (viewBox scales coordinates internally, not the element itself),
              so a path with more than a couple of nodes is wider than this
              360px panel. overflow-hidden would silently clip it with no way
              to see the rest; overflow-x-auto makes it scrollable instead. */}
          <div className="rounded border border-border overflow-x-auto bg-surface-deep">
            <GraphCanvas graph={graph} />
          </div>
        </div>
        )
      })}
    </div>
  )
}
