/**
 * InfraGraphView — data-driven resource dependency graph (Milestone 2).
 *
 * Renders the stack's ACTUAL deployed resources and their dependency edges from
 * `stack.resource_summary` (persisted from Pulumi state on the last successful
 * deploy/refresh). Layout is computed with dagre (left-to-right layered DAG);
 * nodes are drawn as the same SVG cards used elsewhere on the page, and edges
 * follow dagre's routed points. Selecting a node opens a data-driven detail
 * panel with the resource's type/name and its Depends On / Used By relations.
 *
 * When a stack has no persisted inventory yet (never deployed under the current
 * build, or torn down), an empty state is shown rather than a fabricated graph.
 *
 * Out of scope here: per-resource health (all nodes carry the stack's status —
 * real per-resource state is Milestone 4), and canvas controls like pan/zoom/
 * minimap (Milestone 2 Phase 3).
 */

import { useMemo, useState } from 'react'
import dagre from 'dagre'
import type { Stack, StackStatus, StackResourceSummary } from '@/types'
import { Badge } from '@/components/ui/Badge'
import { deriveHealth, STACK_HEALTH } from '@/components/dashboard/stackHelpers'

// ── Layout constants ─────────────────────────────────────────────────────────

const NW = 178          // node width
const NH = 50           // node height
const NRX = 9           // node corner radius

// ── Status → node colour (legend: Healthy / Deploying / Failed / Destroyed) ───

type NodeState = 'healthy' | 'deploying' | 'failed' | 'destroyed' | 'pending'

const STATE_COLOR: Record<NodeState, string> = {
  healthy:   '#5fc992',
  deploying: '#ffbc33',
  failed:    '#FF6363',
  destroyed: '#6a6b6c',
  pending:   '#6a6b6c',
}

function stackNodeState(status: StackStatus): NodeState {
  if (['ready', 'ready_for_attack', 'attacking', 'attack_complete'].includes(status)) return 'healthy'
  if (status === 'failed') return 'failed'
  if (['destroying', 'destroyed'].includes(status)) return 'destroyed'
  if (status === 'pending') return 'pending'
  return 'deploying'
}

const ACCENT = '#55b3ff'

// ── Pulumi type parsing → label + icon ────────────────────────────────────────

type IconKey = 'user' | 'key' | 'doc' | 'shield' | 'link' | 'bucket' | 'cube' | 'gear'

const SERVICE_LABELS: Record<string, string> = {
  s3: 'S3', iam: 'IAM', lambda: 'Lambda', ec2: 'EC2', dynamodb: 'DynamoDB',
  cloudtrail: 'CloudTrail', secretsmanager: 'Secrets Manager', kms: 'KMS',
  cloudwatch: 'CloudWatch', guardduty: 'GuardDuty', rds: 'RDS', sns: 'SNS', sqs: 'SQS',
}

/** Split "aws:s3/bucket:Bucket" into its service ("s3") and kind ("Bucket"). */
function parseType(ptype: string): { service: string; kind: string } {
  const parts = ptype.split(':')
  const service = parts[1]?.split('/')[0] ?? ''
  const kind = parts[2] ?? parts[0] ?? 'Resource'
  return { service, kind }
}

/** Human label for a node title, e.g. "S3 Bucket", "IAM Role". */
function typeLabel(ptype: string): string {
  const { service, kind } = parseType(ptype)
  const sl = SERVICE_LABELS[service] ?? (service ? service.toUpperCase() : 'AWS')
  return `${sl} ${kind}`
}

function iconForType(ptype: string): IconKey {
  const { service, kind } = parseType(ptype)
  const k = kind.toLowerCase()
  if (service === 's3') return k.includes('object') ? 'cube' : 'bucket'
  if (service === 'iam') {
    if (k.includes('user')) return 'user'
    if (k.includes('role')) return 'shield'
    if (k.includes('accesskey') || k.includes('key')) return 'key'
    if (k.includes('attach')) return 'link'
    if (k.includes('policy')) return 'doc'
    return 'doc'
  }
  if (service === 'lambda') return 'gear'
  return 'cube'
}

// ── Icon glyphs (drawn inside a 16×16 box, stroked in currentColor) ───────────

function IconGlyph({ icon }: { icon: IconKey }) {
  const common = { stroke: 'currentColor', strokeWidth: 1.3, fill: 'none', strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const }
  switch (icon) {
    case 'user':   return <g {...common}><circle cx="8" cy="5.5" r="2.6" /><path d="M3.5 13c0-2.5 2-4 4.5-4s4.5 1.5 4.5 4" /></g>
    case 'key':    return <g {...common}><circle cx="5.5" cy="6" r="2.5" /><path d="M7.5 7.5L13 13M11 11l1.5-1.5M9.5 9.5l1.5-1.5" /></g>
    case 'doc':    return <g {...common}><path d="M4 2.5h5l3 3V13.5H4z" /><path d="M9 2.5v3h3M6 8.5h4M6 10.5h4" /></g>
    case 'shield': return <g {...common}><path d="M8 2.5l4.5 1.8v3.4c0 2.7-1.9 4.6-4.5 5.8-2.6-1.2-4.5-3.1-4.5-5.8V4.3z" /></g>
    case 'link':   return <g {...common}><path d="M6.5 9.5l3-3M6 6.5L4.5 8a2.1 2.1 0 003 3l1-1M10 9.5L11.5 8a2.1 2.1 0 00-3-3l-1 1" /></g>
    case 'bucket': return <g {...common}><path d="M3.5 4.5h9l-1 8.5a.8.8 0 01-.8.7H5.3a.8.8 0 01-.8-.7z" /><ellipse cx="8" cy="4.5" rx="4.5" ry="1.6" /></g>
    case 'cube':   return <g {...common}><path d="M8 2.5l4.5 2.5v6L8 13.5 3.5 11V5z" /><path d="M3.5 5L8 7.5 12.5 5M8 7.5v6" /></g>
    case 'gear':   return <g {...common}><circle cx="8" cy="8" r="2.2" /><path d="M8 2.5v1.6M8 11.9v1.6M2.5 8h1.6M11.9 8h1.6M4 4l1.1 1.1M10.9 10.9L12 12M12 4l-1.1 1.1M5.1 10.9L4 12" /></g>
  }
}

// ── Layout ────────────────────────────────────────────────────────────────────

interface LayoutNode {
  urn: string
  name: string
  type: string
  x: number  // center
  y: number  // center
}

interface LayoutEdge {
  from: string
  to: string
  path: string
}

interface Layout {
  nodes: LayoutNode[]
  edges: LayoutEdge[]
  width: number
  height: number
}

function pointsToPath(points: Array<{ x: number; y: number }>): string {
  if (points.length === 0) return ''
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ')
}

/** Run dagre over the persisted resources + edges. */
function computeLayout(summary: StackResourceSummary): Layout {
  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'LR', nodesep: 26, ranksep: 90, marginx: 24, marginy: 24 })
  g.setDefaultEdgeLabel(() => ({}))

  // Coalesce — stacks deployed before M2 have resources but no `edges` key.
  const srcResources = summary.resources ?? []
  const srcEdges = summary.edges ?? []

  const urns = new Set(srcResources.map((r) => r.urn))
  srcResources.forEach((r) => g.setNode(r.urn, { width: NW, height: NH }))
  srcEdges.forEach((e) => {
    if (urns.has(e.from) && urns.has(e.to)) g.setEdge(e.from, e.to)
  })

  dagre.layout(g)

  const nodes: LayoutNode[] = srcResources.map((r) => {
    const n = g.node(r.urn)
    return { urn: r.urn, name: r.name, type: r.type, x: n.x, y: n.y }
  })
  const edges: LayoutEdge[] = []
  srcEdges.forEach((e) => {
    if (!urns.has(e.from) || !urns.has(e.to)) return
    const ge = g.edge(e.from, e.to)
    edges.push({ from: e.from, to: e.to, path: pointsToPath(ge?.points ?? []) })
  })

  const graph = g.graph()
  return { nodes, edges, width: graph.width ?? 100, height: graph.height ?? 100 }
}

// ── SVG node card ─────────────────────────────────────────────────────────────

function SvgNode({
  node, state, selected, onClick,
}: {
  node: LayoutNode
  state: NodeState
  selected: boolean
  onClick: () => void
}) {
  const x = node.x - NW / 2
  const y = node.y - NH / 2
  const color = STATE_COLOR[state]
  const stroke = selected ? ACCENT : color
  const icon = iconForType(node.type)
  const title = typeLabel(node.type)
  const isAnimated = state === 'deploying'

  return (
    <g onClick={onClick} style={{ cursor: 'pointer' }}>
      {selected && (
        <rect x={x - 3} y={y - 3} width={NW + 6} height={NH + 6} rx={NRX + 3}
          fill="none" stroke={ACCENT} strokeOpacity={0.25} strokeWidth={2} />
      )}
      <rect x={x} y={y} width={NW} height={NH} rx={NRX}
        fill="#101111" stroke={stroke} strokeOpacity={selected ? 1 : 0.55} strokeWidth={selected ? 1.5 : 1} />

      {/* Icon chip */}
      <rect x={x + 10} y={y + NH / 2 - 13} width={26} height={26} rx={7} fill={color} fillOpacity={0.12} />
      <g transform={`translate(${x + 15}, ${y + NH / 2 - 8})`} style={{ color }}>
        <IconGlyph icon={icon} />
      </g>

      {/* Title + subtitle */}
      <text x={x + 46} y={y + NH / 2 - 3} fill="#f9f9f9" fontSize={11} fontFamily="Inter, sans-serif" fontWeight={600} letterSpacing={0.1}>
        {title.length > 20 ? `${title.slice(0, 19)}…` : title}
      </text>
      <text x={x + 46} y={y + NH / 2 + 11} fill="#9c9c9d" fontSize={8.5} fontFamily="Geist Mono, monospace" letterSpacing={0.2}>
        {node.name.length > 22 ? `${node.name.slice(0, 21)}…` : node.name}
      </text>

      {/* Status dot */}
      <circle cx={x + NW - 13} cy={y + 13} r={3.2} fill={color}>
        {isAnimated && <animate attributeName="opacity" values="1;0.3;1" dur="1.6s" repeatCount="indefinite" />}
      </circle>
    </g>
  )
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function DetailPanel({
  node, stack, state, nodeByUrn, edges, onSelect, onClose,
}: {
  node: LayoutNode
  stack: Stack
  state: NodeState
  nodeByUrn: Record<string, LayoutNode>
  edges: Array<{ from: string; to: string }>
  onSelect: (urn: string) => void
  onClose: () => void
}) {
  const color = STATE_COLOR[state]
  const icon = iconForType(node.type)
  const title = typeLabel(node.type)
  const healthMeta = STACK_HEALTH[deriveHealth(stack)]

  const dependsOn = edges.filter((e) => e.to === node.urn).map((e) => nodeByUrn[e.from]).filter(Boolean) as LayoutNode[]
  const usedBy = edges.filter((e) => e.from === node.urn).map((e) => nodeByUrn[e.to]).filter(Boolean) as LayoutNode[]

  return (
    <div className="w-[280px] shrink-0 bg-surface-card border border-border rounded-card p-4 animate-slideUp shadow-ring">
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="w-9 h-9 rounded-btn flex items-center justify-center shrink-0" style={{ background: `${color}1f`, color }}>
            <svg width="18" height="18" viewBox="0 0 16 16"><IconGlyph icon={icon} /></svg>
          </span>
          <div className="min-w-0">
            <div className="font-display text-[0.9rem] font-bold text-content-primary leading-tight truncate">{title}</div>
            <div className="font-mono text-[10px] text-content-dim truncate">{node.name}</div>
          </div>
        </div>
        <button onClick={onClose} aria-label="Close"
          className="text-content-dim hover:text-content-primary transition-opacity hover:opacity-60 bg-transparent border-none cursor-pointer text-[14px] leading-none shrink-0">
          &#10005;
        </button>
      </div>

      <div className="mb-3">
        <Badge tone={healthMeta.tone} mono dot pulse={healthMeta.pulse}>{healthMeta.label}</Badge>
      </div>

      <div className="h-px bg-border mb-3" />

      <PanelRow label="Type" value={node.type} />
      <PanelRow label="Name" value={node.name} />

      <Relationship label="Depends On" nodes={dependsOn} onSelect={onSelect} />
      <Relationship label="Used By" nodes={usedBy} onSelect={onSelect} />
    </div>
  )
}

function PanelRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="mb-2.5">
      <div className="font-mono text-[8.5px] text-content-dim uppercase tracking-[1px] mb-0.5">{label}</div>
      <div className="font-mono text-[10px] text-content-secondary break-all leading-[1.5]" style={{ letterSpacing: '0.2px' }}>{value}</div>
    </div>
  )
}

function Relationship({
  label, nodes, onSelect,
}: {
  label: string
  nodes: LayoutNode[]
  onSelect: (urn: string) => void
}) {
  return (
    <div className="mt-3">
      <div className="font-mono text-[8.5px] text-content-dim uppercase tracking-[1px] mb-1.5">
        {label} {nodes.length > 0 && `(${nodes.length})`}
      </div>
      {nodes.length === 0 ? (
        <div className="font-mono text-[10px] text-content-dim">— None —</div>
      ) : (
        <div className="flex flex-col gap-1">
          {nodes.map((n) => (
            <button key={n.urn} onClick={() => onSelect(n.urn)}
              className="flex items-center justify-between gap-2 px-2 py-1.5 rounded-btn border border-border
                bg-surface-base text-left transition-colors hover:border-accent-blue/40 cursor-pointer group">
              <span className="font-mono text-[10px] text-content-secondary truncate">
                {typeLabel(n.type)} <span className="text-content-dim">{n.name}</span>
              </span>
              <span className="text-content-dim group-hover:text-accent-blue transition-colors shrink-0">&rsaquo;</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Empty state ───────────────────────────────────────────────────────────────

function GraphEmptyState() {
  return (
    <div className="rounded-card border border-border bg-surface-deep px-6 py-12 text-center">
      <div className="font-body text-[0.95rem] text-content-secondary mb-1">No resource graph yet</div>
      <div className="font-mono text-[11px] text-content-dim leading-[1.6] max-w-[360px] mx-auto">
        Deploy or refresh this stack to capture its resources and dependencies from
        Pulumi state. The graph appears here once an inventory has been recorded.
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export function InfraGraphView({ stack }: { stack: Stack }) {
  const [selectedUrn, setSelectedUrn] = useState<string | null>(null)
  const summary = stack.resource_summary
  const state = stackNodeState(stack.status)

  const layout = useMemo<Layout | null>(() => {
    if (!summary || !summary.resources || summary.resources.length === 0) return null
    return computeLayout(summary)
  }, [summary])

  if (!layout) return <GraphEmptyState />

  const nodeByUrn = Object.fromEntries(layout.nodes.map((n) => [n.urn, n])) as Record<string, LayoutNode>
  const selectedNode = selectedUrn ? (nodeByUrn[selectedUrn] ?? null) : null
  const edgeList = summary?.edges ?? []

  return (
    <div className="flex flex-col gap-2.5">
      {/* Header line */}
      <div className="flex items-center justify-between">
        <div className="font-mono text-[10px] text-content-dim uppercase tracking-[1px]">
          {layout.nodes.length} resources &middot; {layout.edges.length} dependencies
        </div>
        <div className="font-mono text-[9px] text-content-dim">click a node for details</div>
      </div>

      {/* Canvas + detail panel */}
      <div className="flex gap-3 items-start">
        <div className="flex-1 min-w-0 rounded-card border border-border overflow-hidden bg-surface-deep">
          <svg viewBox={`0 0 ${layout.width} ${layout.height}`} width="100%" preserveAspectRatio="xMidYMid meet" style={{ display: 'block' }}>
            <defs>
              <marker id={`arrow-${stack.id}`} markerWidth={8} markerHeight={8} refX={7} refY={3.5} orient="auto">
                <path d="M 0 1 L 7 3.5 L 0 6 Z" fill="rgba(255,255,255,0.22)" />
              </marker>
              <marker id={`arrow-hl-${stack.id}`} markerWidth={8} markerHeight={8} refX={7} refY={3.5} orient="auto">
                <path d="M 0 1 L 7 3.5 L 0 6 Z" fill={ACCENT} />
              </marker>
            </defs>

            {/* Edges */}
            {layout.edges.map((e) => {
              const highlighted = e.from === selectedUrn || e.to === selectedUrn
              return (
                <path
                  key={`${e.from}->${e.to}`}
                  d={e.path}
                  fill="none"
                  stroke={highlighted ? ACCENT : 'rgba(255,255,255,0.12)'}
                  strokeOpacity={highlighted ? 0.6 : 1}
                  strokeWidth={highlighted ? 1.6 : 1}
                  markerEnd={`url(#${highlighted ? `arrow-hl-${stack.id}` : `arrow-${stack.id}`})`}
                  style={{ transition: 'stroke 0.2s ease' }}
                />
              )
            })}

            {/* Nodes */}
            {layout.nodes.map((node) => (
              <SvgNode
                key={node.urn}
                node={node}
                state={state}
                selected={selectedUrn === node.urn}
                onClick={() => setSelectedUrn((prev) => (prev === node.urn ? null : node.urn))}
              />
            ))}
          </svg>
        </div>

        {selectedNode && (
          <DetailPanel
            node={selectedNode}
            stack={stack}
            state={state}
            nodeByUrn={nodeByUrn}
            edges={edgeList}
            onSelect={setSelectedUrn}
            onClose={() => setSelectedUrn(null)}
          />
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 pt-0.5">
        <LegendDot color={STATE_COLOR.healthy} label="Healthy" />
        <LegendDot color={STATE_COLOR.deploying} label="Deploying" />
        <LegendDot color={STATE_COLOR.failed} label="Failed" />
        <LegendDot color={STATE_COLOR.destroyed} label="Destroyed" />
      </div>
    </div>
  )
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="w-2 h-2 rounded-full" style={{ background: color }} />
      <span className="font-mono text-[9px] text-content-dim uppercase tracking-[0.8px]">{label}</span>
    </div>
  )
}
