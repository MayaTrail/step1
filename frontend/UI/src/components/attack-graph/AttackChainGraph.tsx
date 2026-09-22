/**
 * The attack chain graph.
 *
 * A sibling of InfraGraphView: same dagre layout, same hand-rolled SVG, same
 * node-card treatment, so a user moving between the Stacks resource map and
 * this page is looking at one product. What differs is what a node means —
 * here it is an identity, and an edge is a privilege-escalation step Scout
 * evaluated as permitted.
 *
 * Default-exported for React.lazy: this pulls in dagre, which is why
 * InfraGraphView is lazy-loaded too (see ResourceMapModal.tsx:10).
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import dagre from 'dagre'

import { chainsThrough, toGraph } from './chainGraph'
import type { GraphEdge } from './chainGraph'
import { NodeIcon } from './nodeIcons'
import { getGraphEntity } from '@/services/attackGraph.service'
import type { AttackChain, ChainNode, GraphEntity, ScanEnvelope } from '@/types/attackGraph'

const NODE_WIDTH = 190
const NODE_HEIGHT = 64
const NODE_RX = 10
const ACCENT = '#55b3ff'
const DIRECT_COLOR = '#ff6b6b'

/** Edge label text, capped so it doesn't sprawl across neighbouring nodes. */
function truncateLabel(text: string, max = 26): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

/** "FULL_ACCOUNT_COMPROMISE" -> "Full Account Compromise". */
function formatImpact(impact: string): string {
  return impact
    .toLowerCase()
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

/**
 * Identity kinds mapped onto the palette InfraGraphView already uses, so a
 * colour means the same thing on both pages. IAM amber carries identities.
 */
type Category = 'iam' | 'other'

const NODE_CATEGORY: Record<string, Category> = {
  user: 'iam',
  role: 'iam',
  group: 'iam',
  policy: 'other',
}

const CAT_COLOR: Record<Category, string> = {
  iam: '#ffbc33',
  other: '#8a8f98',
}

const CAT_LABEL: Record<Category, string> = {
  iam: 'IAM Identity',
  other: 'Other',
}

function categorize(node: ChainNode): Category {
  return NODE_CATEGORY[node.type] ?? 'other'
}

interface LayoutNode extends ChainNode {
  x: number
  y: number
}
interface LayoutEdge extends GraphEdge {
  path: string
  labelX: number
  labelY: number
}
interface Layout {
  nodes: LayoutNode[]
  edges: LayoutEdge[]
  width: number
  height: number
}

function pointsToPath(points: Array<{ x: number; y: number }>): string {
  if (!points.length) return ''
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ')
}

/**
 * Lay the graph out left to right: a chain is a sequence, and reading it
 * along the axis text already runs in costs nothing.
 */
function computeLayout(nodes: ChainNode[], edges: GraphEdge[]): Layout {
  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'LR', nodesep: 40, ranksep: 90, marginx: 20, marginy: 20 })
  g.setDefaultEdgeLabel(() => ({}))

  nodes.forEach((node) => g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT }))
  edges.forEach((edge) => g.setEdge(edge.from, edge.to))

  dagre.layout(g)

  const laidOutNodes: LayoutNode[] = nodes.map((node) => {
    const n = g.node(node.id)
    return { ...node, x: n.x, y: n.y }
  })
  const laidOutEdges: LayoutEdge[] = edges.map((edge) => {
    const ge = g.edge(edge.from, edge.to)
    const points = ge?.points ?? []
    // Midpoint of the routed path, not the straight line between endpoints:
    // dagre curves multi-hop edges around other nodes, and a straight-line
    // midpoint would put the label on top of an unrelated node.
    const mid = points[Math.floor(points.length / 2)] ?? { x: 0, y: 0 }
    return { ...edge, path: pointsToPath(points), labelX: mid.x, labelY: mid.y }
  })

  const graph = g.graph()
  return { nodes: laidOutNodes, edges: laidOutEdges, width: graph.width ?? 100, height: graph.height ?? 100 }
}

// ── SVG node card ─────────────────────────────────────────────────────────────

function SvgNode({
  node, selected, dimmed, direct, onClick,
}: { node: LayoutNode; selected: boolean; dimmed: boolean; direct: boolean; onClick: () => void }) {
  const x = node.x - NODE_WIDTH / 2
  const y = node.y - NODE_HEIGHT / 2
  const cat = categorize(node)
  const color = CAT_COLOR[cat]
  const clipId = `acg-nclip-${Math.round(node.x)}-${Math.round(node.y)}`

  return (
    <g onClick={onClick} style={{ cursor: 'pointer', opacity: dimmed ? 0.35 : 1, transition: 'opacity 0.2s ease' }}>
      {selected && (
        <rect x={x - 3} y={y - 3} width={NODE_WIDTH + 6} height={NODE_HEIGHT + 6} rx={NODE_RX + 3} fill="none" stroke={ACCENT} strokeOpacity={0.3} strokeWidth={2} />
      )}
      <rect x={x} y={y} width={NODE_WIDTH} height={NODE_HEIGHT} rx={NODE_RX} fill="#101314" stroke={selected ? ACCENT : direct ? DIRECT_COLOR : color} strokeOpacity={selected ? 1 : direct ? 0.7 : 0.5} strokeWidth={selected ? 1.5 : 1} />

      {direct && (
        <circle cx={x + NODE_WIDTH - 10} cy={y + 10} r={4} fill={DIRECT_COLOR} />
      )}

      <rect x={x + 11} y={y + 19} width={26} height={26} rx={7} fill={color} fillOpacity={0.14} />
      <text x={x + 24} y={y + 36} textAnchor="middle" fill={color} fontSize={9} fontFamily="Geist Mono, monospace" fontWeight={700}>
        {node.type.slice(0, 3).toUpperCase()}
      </text>

      <defs>
        <clipPath id={clipId}><rect x={x} y={y} width={NODE_WIDTH - 8} height={NODE_HEIGHT} rx={NODE_RX} /></clipPath>
      </defs>
      <g clipPath={`url(#${clipId})`}>
        <text x={x + 46} y={y + 28} fill="#f3f4f6" fontSize={13} fontFamily="Inter, sans-serif" fontWeight={600} letterSpacing={0.1}>
          {node.label.length > 16 ? `${node.label.slice(0, 15)}…` : node.label}
        </text>
        <text x={x + 46} y={y + 44} fill="#9aa1ad" fontSize={9} fontFamily="Geist Mono, monospace">
          {CAT_LABEL[cat]}
        </text>
      </g>
    </g>
  )
}

// ── Detail panel ──────────────────────────────────────────────────────────────

/**
 * Chains through the selected node, with their steps verbatim.
 *
 * `action` is shown as the heading and `mechanism`/`detail` as the body —
 * Scout's own evaluated fields, carried through unparaphrased. Scout attaches
 * no per-step technique or condition (verified in Task 1); a chain's MITRE
 * technique ids are chain-level and shown once, on the chain.
 */
function EntityPanel({
  scanId, node, nodeId, chains, onClose, onFindPaths,
}: {
  scanId: string
  node: ChainNode | undefined
  nodeId: string
  chains: AttackChain[]
  onClose: () => void
  onFindPaths: (id: string) => void
}) {
  const [copied, setCopied] = useState(false)
  const [entity, setEntity] = useState<GraphEntity | null>(null)
  const [rawOpen, setRawOpen] = useState(false)

  // A 404 here is the normal, permanent state for any scan stored before the
  // graph was kept — nothing backfills those. Falling back to the ARN-parsed
  // header is the whole handling; there is no error to show a user who did
  // nothing wrong.
  useEffect(() => {
    let cancelled = false
    setEntity(null)
    setRawOpen(false)
    getGraphEntity(scanId, nodeId)
      .then((data) => { if (!cancelled) setEntity(data) })
      .catch(() => { if (!cancelled) setEntity(null) })
    return () => { cancelled = true }
  }, [scanId, nodeId])

  // Truncated by CSS (`truncate`), not by string length: `title` gives the
  // full ARN on hover, and the click-to-copy is the actual escape hatch —
  // hover alone doesn't work on touch, and the ARN is too long to select by
  // hand reliably at 10px. Clipboard access can be denied (permissions
  // policy, insecure context); fails silently rather than throwing, since
  // the title tooltip already covers "I just need to read it".
  const copyArn = async () => {
    try {
      await navigator.clipboard.writeText(nodeId)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      // no-op — see comment above
    }
  }

  return (
    <div className="w-[320px] shrink-0 bg-surface-card border border-border rounded-card p-4 animate-slideUp shadow-ring overflow-y-auto" style={{ maxHeight: '74vh' }}>
      <div className="flex items-start gap-2 mb-3">
        <NodeIcon nodeType={entity?.type ?? node?.node_type} label={node?.label ?? nodeId} size={24} />
        <div className="min-w-0 flex-1">
          <div className="font-display text-[0.9rem] font-bold text-content-primary leading-tight truncate"
               title={entity?.name || node?.label || nodeId}>
            {entity?.name || node?.label || nodeId}
          </div>
          <div className="text-[0.7rem] text-content-secondary truncate">
            {entity ? `${entity.type}${entity.account_id ? ` · ${entity.account_id}` : ''}` : (node?.type ?? 'entity')}
          </div>
        </div>
        <button onClick={onClose} aria-label="Close" className="text-content-dim hover:text-content-primary transition-opacity hover:opacity-60 bg-transparent border-none cursor-pointer text-[14px] leading-none shrink-0">&#10005;</button>
      </div>

      <button
        type="button"
        onClick={() => onFindPaths(nodeId)}
        className="w-full mb-3 px-3 py-1.5 text-[0.75rem] rounded border border-border text-content-primary hover:bg-surface-elevated"
      >
        Find paths from here
      </button>

      {entity && Object.keys(entity.properties).length > 0 && (
        <div className="mb-3">
          <button
            type="button"
            onClick={() => setRawOpen((open) => !open)}
            className="text-[0.7rem] text-content-secondary hover:text-content-primary"
            aria-expanded={rawOpen}
          >
            {rawOpen ? 'Hide' : 'Show'} raw properties
          </button>
          {rawOpen && (
            <pre className="mt-2 text-[0.65rem] leading-tight text-content-secondary bg-surface-elevated rounded p-2 overflow-x-auto">
              {JSON.stringify(entity.properties, null, 2)}
            </pre>
          )}
        </div>
      )}

      <div className="min-w-0 mb-3">
        <div className="font-display text-[0.9rem] font-bold text-content-primary leading-tight truncate">
          {chains.length} chain{chains.length === 1 ? '' : 's'} through this identity
        </div>
        <button
          type="button"
          onClick={copyArn}
          title={nodeId}
          className="font-mono text-[10px] text-content-dim truncate text-left bg-transparent border-none p-0 cursor-pointer hover:text-content-primary transition-opacity max-w-full block"
        >
          {copied ? 'Copied to clipboard' : nodeId}
        </button>
      </div>

      <div className="h-px bg-border mb-3" />

      <div className="flex flex-col gap-3">
        {chains.map((chain) => (
          <div key={chain.id} className="rounded-btn border border-border bg-surface-base p-2.5">
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-mono text-[10px] text-content-secondary">Rank #{chain.rank}</span>
              {chain.score != null && (
                <span className="font-mono text-[10px] text-content-dim">score {chain.score}</span>
              )}
            </div>
            {chain.mitre_techniques.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2">
                {chain.mitre_techniques.map((t) => (
                  <span key={t} className="font-mono text-[8.5px] uppercase tracking-[0.6px] px-1.5 py-0.5 rounded-[4px]" style={{ color: CAT_COLOR.iam, background: `${CAT_COLOR.iam}1a` }}>{t}</span>
                ))}
              </div>
            )}
            {chain.steps.length === 0 ? (
              <div className="pl-2 border-l" style={{ borderColor: DIRECT_COLOR }}>
                <div className="font-mono text-[10px] font-bold" style={{ color: DIRECT_COLOR }}>
                  Direct access — no escalation step needed
                </div>
                <div className="font-mono text-[9px] text-content-dim leading-[1.5]">
                  {chain.terminal_impact
                    ? `This identity already holds: ${formatImpact(chain.terminal_impact)}`
                    : 'Scout did not report what impact this identity already holds.'}
                </div>
              </div>
            ) : (
              <div className="flex flex-col gap-1.5">
                {chain.steps.map((step, i) => (
                  <div key={`${chain.id}-${i}`} className="pl-2 border-l border-border">
                    <div className="font-mono text-[10px] text-content-secondary">{step.action || step.mechanism || '—'}</div>
                    {step.detail && <div className="font-mono text-[9px] text-content-dim leading-[1.5]">{step.detail}</div>}
                    {step.certainty === 'conditional' && step.conditional_reason && (
                      <div className="font-mono text-[9px] leading-[1.5]" style={{ color: CAT_COLOR.iam }}>
                        Conditional — {step.conditional_reason}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
            {chain.alternate_mechanisms.length > 0 && (
              <div className="font-mono text-[9px] text-content-dim leading-[1.5] mt-1.5">
                +{chain.alternate_mechanisms.length} other route{chain.alternate_mechanisms.length === 1 ? '' : 's'} to the same target: {chain.alternate_mechanisms.join(', ')}
              </div>
            )}
            {chain.narrative && (
              <div className="mt-2 pt-2 border-t border-border">
                <div className="font-mono text-[8.5px] uppercase tracking-[0.6px] text-content-dim mb-1">How it works</div>
                <div className="font-mono text-[9.5px] text-content-secondary leading-[1.5]">{chain.narrative}</div>
                {chain.detection && (
                  <div className="font-mono text-[9px] text-content-dim leading-[1.5] mt-1.5">
                    <span style={{ color: CAT_COLOR.iam }}>Detection —</span> {chain.detection}
                  </div>
                )}
                {chain.remediation && (
                  <div className="font-mono text-[9px] text-content-dim leading-[1.5] mt-1">
                    <span style={{ color: DIRECT_COLOR }}>Remediation —</span> {chain.remediation}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AttackChainGraph({ envelope, scanId }: { envelope: ScanEnvelope; scanId: string }) {
  const [selected, setSelected] = useState<string | null>(null)
  // Task 9 gives this setter a panel to open; for now nothing reads the
  // value it tracks, so it isn't destructured.
  const [, setFindPathsFrom] = useState<string | null>(null)
  const { nodes, edges } = useMemo(() => toGraph(envelope), [envelope])
  const layout = useMemo(() => computeLayout(nodes, edges), [nodes, edges])

  // Pan/zoom state. A plain CSS transform on a wrapper div, not a viewBox
  // change — viewBox math for cursor-centred zoom plus drag-to-pan is a lot
  // more code for the same visible result, and every existing coordinate in
  // computeLayout/SvgNode stays untouched.
  const containerRef = useRef<HTMLDivElement>(null)
  const [view, setView] = useState({ x: 0, y: 0, scale: 1 })
  // Not state: a drag updates on every pointermove, and re-rendering to
  // track "did this gesture move" would fight the render that setView
  // already causes. handleNodeClick reads .moved synchronously from the
  // same gesture, so a ref (read after the fact, never rendered) is correct
  // here, not a bug.
  const dragRef = useRef({ dragging: false, moved: false, lastX: 0, lastY: 0 })

  // New scan data -> fresh view. Without this, switching envelopes (a new
  // scan, or the same page after a re-scan) keeps whatever pan/zoom the
  // previous graph's very different node layout happened to be at.
  useEffect(() => {
    setView({ x: 0, y: 0, scale: 1 })
  }, [layout.width, layout.height])

  // Native, non-passive listener: React's onWheel is passive by default, so
  // e.preventDefault() inside a React handler is a silent no-op (and a dev
  // console warning) — the page would scroll under the graph on every
  // zoom gesture instead of just zooming.
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12
      setView((v) => ({ ...v, scale: Math.min(2.5, Math.max(0.35, v.scale * factor)) }))
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [])

  if (nodes.length === 0) return null

  const selectedChains = selected ? chainsThrough(envelope, selected) : []
  const selectedChainIds = new Set(selectedChains.map((c) => c.id))
  const cats = Array.from(new Set(layout.nodes.map((n) => categorize(n))))
  const hasConditionalEdge = edges.some((e) => e.certainty === 'conditional')

  // A node is "direct" when at least one chain names it (as source or
  // target) with zero steps — Scout found it already holds that chain's
  // impact, not an escalation path leading to it. Those nodes draw no edge,
  // so without this flag they are indistinguishable from a node the scan
  // simply had nothing to say about.
  const directNodeIds = new Set(
    envelope.chains
      .filter((c) => c.steps.length === 0)
      .flatMap((c) => [c.source.id, c.target.id]),
  )
  const directCount = envelope.chains.filter((c) => c.steps.length === 0).length

  const handlePointerDown = (e: React.PointerEvent) => {
    dragRef.current = { dragging: true, moved: false, lastX: e.clientX, lastY: e.clientY }
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  const handlePointerMove = (e: React.PointerEvent) => {
    if (!dragRef.current.dragging) return
    const dx = e.clientX - dragRef.current.lastX
    const dy = e.clientY - dragRef.current.lastY
    // A real drag, not just sub-pixel jitter under an otherwise-still
    // pointer — below this, handleNodeClick below still treats it as a
    // click rather than silently swallowing every node click.
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) dragRef.current.moved = true
    dragRef.current.lastX = e.clientX
    dragRef.current.lastY = e.clientY
    setView((v) => ({ ...v, x: v.x + dx, y: v.y + dy }))
  }
  const handlePointerUp = (e: React.PointerEvent) => {
    dragRef.current.dragging = false
    e.currentTarget.releasePointerCapture?.(e.pointerId)
  }
  // The click a node's own onClick would otherwise fire is not suppressed
  // by the browser just because a drag happened elsewhere in the same
  // gesture — this is the actual guard against "drag ends on top of a
  // node" silently reopening the detail panel on the wrong identity.
  const handleNodeClick = (id: string) => {
    if (dragRef.current.moved) return
    setSelected((p) => (p === id ? null : id))
  }
  const zoomBy = (factor: number) =>
    setView((v) => ({ ...v, scale: Math.min(2.5, Math.max(0.35, v.scale * factor)) }))
  const resetView = () => setView({ x: 0, y: 0, scale: 1 })

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="font-mono text-[10px] text-content-dim uppercase tracking-[1px]">
          {layout.nodes.length} identities &middot; {envelope.chains.length} chains
          {directCount > 0 && (
            <span> &middot; <span style={{ color: DIRECT_COLOR }}>{directCount} already privileged, no hops needed</span></span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {cats.map((c) => (
            <span key={c} className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ background: CAT_COLOR[c] }} />
              <span className="font-mono text-[9px] text-content-dim uppercase tracking-[0.6px]">{CAT_LABEL[c]}</span>
            </span>
          ))}
          {hasConditionalEdge && (
            <span className="flex items-center gap-1.5">
              <svg width="14" height="2" viewBox="0 0 14 2">
                <line x1="0" y1="1" x2="14" y2="1" stroke="rgba(255,255,255,0.5)" strokeWidth={1.4} strokeDasharray="4 2.5" />
              </svg>
              <span className="font-mono text-[9px] text-content-dim uppercase tracking-[0.6px]">Conditional step</span>
            </span>
          )}
        </div>
      </div>

      <div className="flex gap-3 items-start">
        <div
          ref={containerRef}
          className="flex-1 min-w-0 rounded-card border border-border overflow-hidden bg-surface-deep relative"
          style={{ height: '74vh', touchAction: 'none', cursor: dragRef.current.dragging ? 'grabbing' : 'grab' }}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerCancel={handlePointerUp}
        >
          <div style={{
            transform: `translate(${view.x}px, ${view.y}px) scale(${view.scale})`,
            transformOrigin: '0 0', width: layout.width, height: layout.height,
          }}
          >
            <svg viewBox={`0 0 ${layout.width} ${layout.height}`} width={layout.width} height={layout.height} preserveAspectRatio="xMinYMin meet" style={{ display: 'block' }}>
              <defs>
                <marker id="acg-ar" markerWidth={8} markerHeight={8} refX={7} refY={3.5} orient="auto"><path d="M0 1L7 3.5L0 6z" fill="rgba(255,255,255,0.28)" /></marker>
                <marker id="acg-arh" markerWidth={8} markerHeight={8} refX={7} refY={3.5} orient="auto"><path d="M0 1L7 3.5L0 6z" fill={ACCENT} /></marker>
              </defs>

              {layout.edges.map((e) => {
                const hl = selected != null && selectedChainIds.has(e.chainId)
                const dimmed = selected != null && !hl
                return (
                  <g key={e.id}>
                    <path d={e.path} fill="none"
                      stroke={hl ? ACCENT : 'rgba(255,255,255,0.13)'} strokeOpacity={dimmed ? 0.3 : hl ? 0.7 : 1} strokeWidth={hl ? 1.6 : 1}
                      strokeDasharray={e.certainty === 'conditional' ? '5 3' : undefined}
                      markerEnd={`url(#${hl ? 'acg-arh' : 'acg-ar'})`} style={{ transition: 'stroke 0.2s ease, stroke-opacity 0.2s ease' }} />
                    {/* Only on the highlighted chain: every edge labelled at
                        once is illegible clutter the moment a graph has more
                        than a handful of hops — this is the same
                        highlight-on-select gate the edges themselves use. */}
                    {hl && (
                      <text x={e.labelX} y={e.labelY - 5} textAnchor="middle"
                        fontSize={9} fontFamily="Geist Mono, monospace" fill={ACCENT}
                        style={{ paintOrder: 'stroke', stroke: '#101314', strokeWidth: 3, strokeLinejoin: 'round' }}
                      >
                        {truncateLabel(e.action || e.mechanism)}
                      </text>
                    )}
                  </g>
                )
              })}

              {layout.nodes.map((node) => (
                <SvgNode
                  key={node.id}
                  node={node}
                  selected={selected === node.id}
                  dimmed={selected != null && selected !== node.id && !edges.some(
                    (e) => selectedChainIds.has(e.chainId) && (e.from === node.id || e.to === node.id),
                  )}
                  direct={directNodeIds.has(node.id)}
                  onClick={() => handleNodeClick(node.id)}
                />
              ))}
            </svg>
          </div>

          <div className="absolute bottom-2 right-2 flex gap-1">
            <button type="button" onClick={() => zoomBy(1.25)} aria-label="Zoom in"
              className="w-6 h-6 rounded-btn border border-border bg-surface-card text-content-secondary hover:text-content-primary text-[13px] leading-none cursor-pointer">+</button>
            <button type="button" onClick={() => zoomBy(1 / 1.25)} aria-label="Zoom out"
              className="w-6 h-6 rounded-btn border border-border bg-surface-card text-content-secondary hover:text-content-primary text-[13px] leading-none cursor-pointer">&minus;</button>
            <button type="button" onClick={resetView} aria-label="Reset view"
              className="px-2 h-6 rounded-btn border border-border bg-surface-card text-content-dim hover:text-content-primary text-[9px] font-mono uppercase tracking-[0.6px] cursor-pointer">Reset</button>
          </div>
        </div>

        {selected && (
          <EntityPanel
            scanId={scanId}
            node={layout.nodes.find((n) => n.id === selected)}
            nodeId={selected}
            chains={selectedChains}
            onClose={() => setSelected(null)}
            onFindPaths={setFindPathsFrom}
          />
        )}
      </div>

      {envelope.truncated && (
        <div className="font-mono text-[9.5px] text-content-dim">
          Showing the top {envelope.chains.length} chains.
        </div>
      )}
    </div>
  )
}
