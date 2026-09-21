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

import { useMemo, useState } from 'react'
import dagre from 'dagre'

import { chainsThrough, toGraph } from './chainGraph'
import type { GraphEdge } from './chainGraph'
import type { AttackChain, ChainNode, ScanEnvelope } from '@/types/attackGraph'

const NODE_WIDTH = 190
const NODE_HEIGHT = 64
const NODE_RX = 10
const ACCENT = '#55b3ff'

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
    return { ...edge, path: pointsToPath(ge?.points ?? []) }
  })

  const graph = g.graph()
  return { nodes: laidOutNodes, edges: laidOutEdges, width: graph.width ?? 100, height: graph.height ?? 100 }
}

// ── SVG node card ─────────────────────────────────────────────────────────────

function SvgNode({
  node, selected, dimmed, onClick,
}: { node: LayoutNode; selected: boolean; dimmed: boolean; onClick: () => void }) {
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
      <rect x={x} y={y} width={NODE_WIDTH} height={NODE_HEIGHT} rx={NODE_RX} fill="#101314" stroke={selected ? ACCENT : color} strokeOpacity={selected ? 1 : 0.5} strokeWidth={selected ? 1.5 : 1} />

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
function DetailPanel({
  nodeId, chains, onClose,
}: { nodeId: string; chains: AttackChain[]; onClose: () => void }) {
  return (
    <div className="w-[320px] shrink-0 bg-surface-card border border-border rounded-card p-4 animate-slideUp shadow-ring overflow-y-auto" style={{ maxHeight: '74vh' }}>
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="min-w-0">
          <div className="font-display text-[0.9rem] font-bold text-content-primary leading-tight truncate">
            {chains.length} chain{chains.length === 1 ? '' : 's'} through this identity
          </div>
          <div className="font-mono text-[10px] text-content-dim truncate">{nodeId}</div>
        </div>
        <button onClick={onClose} aria-label="Close" className="text-content-dim hover:text-content-primary transition-opacity hover:opacity-60 bg-transparent border-none cursor-pointer text-[14px] leading-none shrink-0">&#10005;</button>
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
            <div className="flex flex-col gap-1.5">
              {chain.steps.map((step, i) => (
                <div key={`${chain.id}-${i}`} className="pl-2 border-l border-border">
                  <div className="font-mono text-[10px] text-content-secondary">{step.action || step.mechanism || '—'}</div>
                  {step.detail && <div className="font-mono text-[9px] text-content-dim leading-[1.5]">{step.detail}</div>}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AttackChainGraph({ envelope }: { envelope: ScanEnvelope }) {
  const [selected, setSelected] = useState<string | null>(null)
  const { nodes, edges } = useMemo(() => toGraph(envelope), [envelope])
  const layout = useMemo(() => computeLayout(nodes, edges), [nodes, edges])

  if (nodes.length === 0) return null

  const selectedChains = selected ? chainsThrough(envelope, selected) : []
  const selectedChainIds = new Set(selectedChains.map((c) => c.id))
  const cats = Array.from(new Set(layout.nodes.map((n) => categorize(n))))

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="font-mono text-[10px] text-content-dim uppercase tracking-[1px]">
          {layout.nodes.length} identities &middot; {envelope.chains.length} chains
        </div>
        <div className="flex items-center gap-3">
          {cats.map((c) => (
            <span key={c} className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ background: CAT_COLOR[c] }} />
              <span className="font-mono text-[9px] text-content-dim uppercase tracking-[0.6px]">{CAT_LABEL[c]}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="flex gap-3 items-start">
        <div className="flex-1 min-w-0 rounded-card border border-border overflow-auto bg-surface-deep" style={{ maxHeight: '74vh' }}>
          <svg viewBox={`0 0 ${layout.width} ${layout.height}`} width={layout.width} height={layout.height} preserveAspectRatio="xMinYMin meet" style={{ display: 'block' }}>
            <defs>
              <marker id="acg-ar" markerWidth={8} markerHeight={8} refX={7} refY={3.5} orient="auto"><path d="M0 1L7 3.5L0 6z" fill="rgba(255,255,255,0.28)" /></marker>
              <marker id="acg-arh" markerWidth={8} markerHeight={8} refX={7} refY={3.5} orient="auto"><path d="M0 1L7 3.5L0 6z" fill={ACCENT} /></marker>
            </defs>

            {layout.edges.map((e) => {
              const hl = selected != null && selectedChainIds.has(e.chainId)
              const dimmed = selected != null && !hl
              return (
                <path key={e.id} d={e.path} fill="none"
                  stroke={hl ? ACCENT : 'rgba(255,255,255,0.13)'} strokeOpacity={dimmed ? 0.3 : hl ? 0.7 : 1} strokeWidth={hl ? 1.6 : 1}
                  markerEnd={`url(#${hl ? 'acg-arh' : 'acg-ar'})`} style={{ transition: 'stroke 0.2s ease, stroke-opacity 0.2s ease' }} />
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
                onClick={() => setSelected((p) => (p === node.id ? null : node.id))}
              />
            ))}
          </svg>
        </div>

        {selected && (
          <DetailPanel nodeId={selected} chains={selectedChains} onClose={() => setSelected(null)} />
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
