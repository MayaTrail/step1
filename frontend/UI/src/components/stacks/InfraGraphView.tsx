/**
 * InfraGraphView — infrastructure topology graph (Milestone 2, dark adaptation).
 *
 * Renders the stack's actual resources + dependency edges from
 * `stack.resource_summary` as a Wiz/Datadog-style topology map: compact,
 * category-colour-coded typed node cards laid out top-down with dagre, solid
 * dependency edges, and a detail panel (type, region, Depends On / Used By).
 *
 * Robustness: resources persisted before M2 have no `urn` and no `edges`. We
 * synthesize a stable per-node id when `urn` is missing so every resource still
 * renders as a distinct node (edges simply won't be present for that old data —
 * a redeploy under the current backend captures them).
 *
 * Theme: dark, consistent with the rest of the console. Layout/structure mirror
 * the agreed reference. Canvas controls (pan/zoom/minimap), the left meta/filter
 * rail and the bottom attack-path band are the follow-up full-page scope.
 */

import { useMemo, useState } from 'react'
import dagre from 'dagre'
import type { Stack, StackStatus, StackResourceSummary } from '@/types'
import { Badge } from '@/components/ui/Badge'
import { deriveHealth, STACK_HEALTH } from '@/components/dashboard/stackHelpers'

// ── Layout constants ─────────────────────────────────────────────────────────

const NW = 172
const NH = 64
const NRX = 10

// ── Category model (dark palette) ─────────────────────────────────────────────

type Category = 'net' | 'compute' | 'data' | 'iam' | 'other'

const CAT_COLOR: Record<Category, string> = {
  net:     '#5fc992', // green
  compute: '#a78bfa', // purple
  data:    '#55b3ff', // blue
  iam:     '#ffbc33', // amber
  other:   '#8a8f98', // grey
}
const CAT_LABEL: Record<Category, string> = {
  net: 'Network', compute: 'Compute', data: 'Data Store', iam: 'IAM / Security', other: 'Other',
}

// ── Pulumi type parsing → category / label / icon ─────────────────────────────

type IconKey = 'cloud' | 'net' | 'gw' | 'nat' | 'sg' | 'ec2' | 'db' | 'doc' | 'iam' | 'key' | 'link' | 'bucket' | 'gear' | 'cube'

const SERVICE_LABELS: Record<string, string> = {
  s3: 'S3', iam: 'IAM', lambda: 'Lambda', ec2: 'EC2', dynamodb: 'DynamoDB',
  cloudtrail: 'CloudTrail', secretsmanager: 'Secrets Manager', kms: 'KMS',
  cloudwatch: 'CloudWatch', guardduty: 'GuardDuty', rds: 'RDS', sns: 'SNS', sqs: 'SQS',
}

function parseType(ptype: string): { service: string; kind: string } {
  const parts = ptype.split(':')
  const service = parts[1]?.split('/')[0] ?? ''
  const kind = parts[2] ?? parts[0] ?? 'Resource'
  return { service, kind }
}

const NET_KINDS = ['vpc', 'subnet', 'internetgateway', 'natgateway', 'routetable', 'route', 'eip', 'vpcendpoint', 'networkacl', 'networkinterface']

function categorize(ptype: string): Category {
  const { service, kind } = parseType(ptype)
  const k = kind.toLowerCase()
  if (service === 'ec2' && NET_KINDS.some((x) => k.includes(x))) return 'net'
  if (service === 'iam' || service === 'kms' || (service === 'ec2' && k.includes('securitygroup'))) return 'iam'
  if (['s3', 'rds', 'dynamodb', 'secretsmanager', 'efs', 'elasticache'].includes(service)) return 'data'
  if (service === 'lambda' || service === 'ecs' || service === 'eks' || service === 'autoscaling'
      || service.startsWith('elasticloadbalancing')
      || (service === 'ec2' && (k.includes('instance') || k.includes('launchtemplate')))) return 'compute'
  return 'other'
}

// Friendly names for common resource types, keyed by `service/kind` (lowercased).
const FRIENDLY: Record<string, string> = {
  'ec2/vpc': 'VPC', 'ec2/subnet': 'Subnet', 'ec2/internetgateway': 'Internet Gateway',
  'ec2/natgateway': 'NAT Gateway', 'ec2/routetable': 'Route Table',
  'ec2/routetableassociation': 'Route Table Assoc.', 'ec2/securitygroup': 'Security Group',
  'ec2/instance': 'EC2 Instance', 'ec2/eip': 'Elastic IP', 'ec2/launchtemplate': 'Launch Template',
  's3/bucket': 'S3 Bucket', 's3/bucketv2': 'S3 Bucket', 's3/bucketobject': 'S3 Object',
  's3/bucketobjectv2': 'S3 Object', 's3/bucketpolicy': 'S3 Bucket Policy',
  'iam/role': 'IAM Role', 'iam/user': 'IAM User', 'iam/policy': 'IAM Policy',
  'iam/rolepolicy': 'IAM Role Policy', 'iam/rolepolicyattachment': 'Role Policy Attach',
  'iam/instanceprofile': 'Instance Profile', 'iam/accesskey': 'Access Key',
  'secretsmanager/secret': 'Secret', 'secretsmanager/secretversion': 'Secret Version',
  'lambda/function': 'Lambda Function', 'cloudtrail/trail': 'CloudTrail',
  'rds/instance': 'RDS Instance', 'dynamodb/table': 'DynamoDB Table',
}

function typeLabel(ptype: string): string {
  const { service, kind } = parseType(ptype)
  const friendly = FRIENDLY[`${service}/${kind.toLowerCase()}`]
  if (friendly) return friendly
  const sl = SERVICE_LABELS[service] ?? (service ? service.toUpperCase() : 'AWS')
  return `${sl} ${kind}`
}

function iconForType(ptype: string): IconKey {
  const { service, kind } = parseType(ptype)
  const k = kind.toLowerCase()
  if (service === 'ec2') {
    if (k.includes('vpc')) return 'cloud'
    if (k.includes('subnet')) return 'net'
    if (k.includes('internetgateway')) return 'gw'
    if (k.includes('natgateway')) return 'nat'
    if (k.includes('securitygroup')) return 'sg'
    if (k.includes('instance')) return 'ec2'
    return 'net'
  }
  if (service === 's3') return 'bucket'
  if (service === 'iam') {
    if (k.includes('role')) return 'iam'
    if (k.includes('accesskey')) return 'key'
    if (k.includes('attach')) return 'link'
    return 'doc'
  }
  if (['rds', 'dynamodb', 'secretsmanager', 'elasticache'].includes(service)) return 'db'
  if (service === 'lambda') return 'gear'
  if (service === 'cloudtrail' || service === 'cloudwatch') return 'doc'
  return 'cube'
}

// ── Icon glyphs (16×16, stroked in currentColor) ──────────────────────────────

const ICON_PATHS: Record<IconKey, string> = {
  cloud:  'M6 13h7a3 3 0 0 0 .3-6A4 4 0 0 0 6 8a3 3 0 0 0 0 5z',
  net:    'M3 3.5h4v4H3zM13 3.5h4v4h-4zM8 12.5h4v4H8zM5 7.5v3h10v-3M10 10.5v2',
  gw:     'M10 3v6M6 6l4-3 4 3M4 12h12v4H4z',
  nat:    'M4 10a6 6 0 1 1 12 0M7 10h6M10 7l3 3-3 3',
  sg:     'M10 3l5 2v4c0 3-2 5-5 6-3-1-5-3-5-6V5z',
  ec2:    'M4 4h12v12H4zM7 7h6v6H7z',
  db:     'M4.5 5.5c0-1 2.5-2 5.5-2s5.5 1 5.5 2-2.5 2-5.5 2-5.5-1-5.5-2zM4.5 5.5v9c0 1 2.5 2 5.5 2s5.5-1 5.5-2v-9',
  doc:    'M5 3h6l4 4v10H5zM11 3v4h4M7 10h6M7 12.5h6',
  iam:    'M10 7a2.6 2.6 0 1 0 0-.01M5 16c0-3 2.2-4.5 5-4.5s5 1.5 5 4.5',
  key:    'M7.5 7.5L13 13M11 11l1.5-1.5M5.5 8.5a2.5 2.5 0 1 0 0-.01',
  link:   'M6.5 9.5l3-3M6 6.5L4.5 8a2.1 2.1 0 0 0 3 3l1-1M10 9.5L11.5 8a2.1 2.1 0 0 0-3-3l-1 1',
  bucket: 'M4 5h12l-1 11H5zM4 5c0-1 2.7-1.8 6-1.8S16 4 16 5',
  gear:   'M10 7.8a2.2 2.2 0 1 0 0 .01M10 2.5v1.6M10 15.9v1.6M2.5 10h1.6M15.9 10h1.6M4.5 4.5l1.1 1.1M14.4 14.4l1.1 1.1M15.5 4.5l-1.1 1.1M5.6 14.4L4.5 15.5',
  cube:   'M10 2.5l6 3.2v8L10 17l-6-3.3v-8zM4 5.7L10 9l6-3.3M10 9v8',
}
function IconGlyph({ icon }: { icon: IconKey }) {
  return (
    <path d={ICON_PATHS[icon]} fill="none" stroke="currentColor" strokeWidth={1.4} strokeLinecap="round" strokeLinejoin="round" />
  )
}

// ── Node status colour (legend) ───────────────────────────────────────────────

type NodeState = 'healthy' | 'deploying' | 'failed' | 'destroyed' | 'pending'
const STATE_DOT: Record<NodeState, string> = {
  healthy: '#5fc992', deploying: '#ffbc33', failed: '#FF6363', destroyed: '#6a6b6c', pending: '#6a6b6c',
}
function stackNodeState(status: StackStatus): NodeState {
  if (['ready', 'ready_for_attack', 'attacking', 'attack_complete'].includes(status)) return 'healthy'
  if (status === 'failed') return 'failed'
  if (['destroying', 'destroyed'].includes(status)) return 'destroyed'
  if (status === 'pending') return 'pending'
  return 'deploying'
}

const ACCENT = '#55b3ff'

// ── Layout ────────────────────────────────────────────────────────────────────

interface LayoutNode { id: string; urn?: string; name: string; type: string; cat: Category; x: number; y: number }
interface LayoutEdge { from: string; to: string; path: string }
interface Layout { nodes: LayoutNode[]; edges: LayoutEdge[]; width: number; height: number }

function pointsToPath(points: Array<{ x: number; y: number }>): string {
  if (!points.length) return ''
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ')
}

const CAT_ORDER: Category[] = ['net', 'compute', 'data', 'iam', 'other']

interface Item { _id: string; urn?: string; name: string; type: string }

/**
 * Grid layout, grouped by category — used when the stack has no dependency
 * edges (e.g. pre-M2 data). Without edges there is no topology to lay out, so a
 * tidy category-grouped grid reads far better than dagre's single flat row.
 */
function gridLayout(items: Item[]): Layout {
  const sorted = [...items].sort(
    (a, b) => CAT_ORDER.indexOf(categorize(a.type)) - CAT_ORDER.indexOf(categorize(b.type)),
  )
  const cols = Math.min(5, Math.max(3, Math.ceil(Math.sqrt(sorted.length))))
  const gapX = 28, gapY = 30, m = 20
  const nodes: LayoutNode[] = sorted.map((it, i) => {
    const c = i % cols, r = Math.floor(i / cols)
    return {
      id: it._id, urn: it.urn, name: it.name, type: it.type, cat: categorize(it.type),
      x: m + NW / 2 + c * (NW + gapX),
      y: m + NH / 2 + r * (NH + gapY),
    }
  })
  const rows = Math.ceil(sorted.length / cols)
  return {
    nodes,
    edges: [],
    width: m * 2 + cols * NW + (cols - 1) * gapX,
    height: m * 2 + rows * NH + (rows - 1) * gapY,
  }
}

function computeLayout(summary: StackResourceSummary): Layout {
  // Stable id per resource — fall back to a synthesized id for pre-M2 records
  // that have no urn, so every resource still renders as a distinct node.
  const items: Item[] = (summary.resources ?? []).map((r, i) => ({ ...r, _id: r.urn || `${r.type}#${i}` }))
  const ids = new Set(items.map((it) => it._id))
  const validEdges = (summary.edges ?? []).filter((e) => ids.has(e.from) && ids.has(e.to))

  // No dependency data → tidy grid instead of dagre's flat single row.
  if (validEdges.length === 0) return gridLayout(items)

  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'TB', nodesep: 26, ranksep: 58, marginx: 20, marginy: 20 })
  g.setDefaultEdgeLabel(() => ({}))

  items.forEach((it) => g.setNode(it._id, { width: NW, height: NH }))
  validEdges.forEach((e) => g.setEdge(e.from, e.to))

  dagre.layout(g)

  const nodes: LayoutNode[] = items.map((it) => {
    const n = g.node(it._id)
    return { id: it._id, urn: it.urn, name: it.name, type: it.type, cat: categorize(it.type), x: n.x, y: n.y }
  })
  const edges: LayoutEdge[] = validEdges.map((e) => {
    const ge = g.edge(e.from, e.to)
    return { from: e.from, to: e.to, path: pointsToPath(ge?.points ?? []) }
  })

  const graph = g.graph()
  return { nodes, edges, width: graph.width ?? 100, height: graph.height ?? 100 }
}

// ── SVG node card ─────────────────────────────────────────────────────────────

function SvgNode({ node, dot, selected, onClick }: { node: LayoutNode; dot: string; selected: boolean; onClick: () => void }) {
  const x = node.x - NW / 2
  const y = node.y - NH / 2
  const color = CAT_COLOR[node.cat]
  const icon = iconForType(node.type)
  const title = typeLabel(node.type)
  // Clip text to the node box (minus right padding) so long ids can never spill
  // past the card edge; coordinates are unique per node, so the id is too.
  const clipId = `nclip-${Math.round(node.x)}-${Math.round(node.y)}`

  return (
    <g onClick={onClick} style={{ cursor: 'pointer' }}>
      {selected && (
        <rect x={x - 3} y={y - 3} width={NW + 6} height={NH + 6} rx={NRX + 3} fill="none" stroke={ACCENT} strokeOpacity={0.3} strokeWidth={2} />
      )}
      <rect x={x} y={y} width={NW} height={NH} rx={NRX} fill="#101314" stroke={selected ? ACCENT : color} strokeOpacity={selected ? 1 : 0.5} strokeWidth={selected ? 1.5 : 1} />

      {/* Icon chip */}
      <rect x={x + 11} y={y + 19} width={26} height={26} rx={7} fill={color} fillOpacity={0.14} />
      <g transform={`translate(${x + 15}, ${y + 23})`} style={{ color }}><IconGlyph icon={icon} /></g>

      {/* Title + subtitle — clipped to the node so long ids can't overflow */}
      <defs>
        <clipPath id={clipId}><rect x={x} y={y} width={NW - 8} height={NH} rx={NRX} /></clipPath>
      </defs>
      <g clipPath={`url(#${clipId})`}>
        <text x={x + 46} y={y + 28} fill="#f3f4f6" fontSize={13} fontFamily="Inter, sans-serif" fontWeight={600} letterSpacing={0.1}>
          {title.length > 16 ? `${title.slice(0, 15)}…` : title}
        </text>
        <text x={x + 46} y={y + 44} fill="#9aa1ad" fontSize={9.5} fontFamily="Geist Mono, monospace">
          {node.name.length > 19 ? `${node.name.slice(0, 18)}…` : node.name}
        </text>
      </g>

      {/* Status dot */}
      <circle cx={x + NW - 13} cy={y + 14} r={3.2} fill={dot} />
    </g>
  )
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function DetailPanel({
  node, stack, nodeById, edges, onSelect, onClose,
}: {
  node: LayoutNode
  stack: Stack
  nodeById: Record<string, LayoutNode>
  edges: LayoutEdge[]
  onSelect: (id: string) => void
  onClose: () => void
}) {
  const color = CAT_COLOR[node.cat]
  const icon = iconForType(node.type)
  const healthMeta = STACK_HEALTH[deriveHealth(stack)]
  const dependsOn = edges.filter((e) => e.to === node.id).map((e) => nodeById[e.from]).filter(Boolean) as LayoutNode[]
  const usedBy = edges.filter((e) => e.from === node.id).map((e) => nodeById[e.to]).filter(Boolean) as LayoutNode[]

  return (
    <div className="w-[284px] shrink-0 bg-surface-card border border-border rounded-card p-4 animate-slideUp shadow-ring">
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="w-9 h-9 rounded-btn flex items-center justify-center shrink-0" style={{ background: `${color}22`, color }}>
            <svg width="18" height="18" viewBox="0 0 20 20"><IconGlyph icon={icon} /></svg>
          </span>
          <div className="min-w-0">
            <div className="font-display text-[0.9rem] font-bold text-content-primary leading-tight truncate">{typeLabel(node.type)}</div>
            <div className="font-mono text-[10px] text-content-dim truncate">{node.name}</div>
          </div>
        </div>
        <button onClick={onClose} aria-label="Close" className="text-content-dim hover:text-content-primary transition-opacity hover:opacity-60 bg-transparent border-none cursor-pointer text-[14px] leading-none shrink-0">&#10005;</button>
      </div>

      <div className="flex items-center gap-2 mb-3">
        <Badge tone={healthMeta.tone} mono dot pulse={healthMeta.pulse}>{healthMeta.label}</Badge>
        <span className="font-mono text-[9px] uppercase tracking-[0.6px] px-1.5 py-0.5 rounded-[4px]" style={{ color, background: `${color}1a` }}>{CAT_LABEL[node.cat]}</span>
      </div>

      <div className="h-px bg-border mb-3" />

      <PanelRow label="Type" value={node.type} />
      <PanelRow label="Name" value={node.name} />
      <PanelRow label="Region" value={stack.region} />

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

function Relationship({ label, nodes, onSelect }: { label: string; nodes: LayoutNode[]; onSelect: (id: string) => void }) {
  return (
    <div className="mt-3">
      <div className="font-mono text-[8.5px] text-content-dim uppercase tracking-[1px] mb-1.5">{label} {nodes.length > 0 && `(${nodes.length})`}</div>
      {nodes.length === 0 ? (
        <div className="font-mono text-[10px] text-content-dim">— None —</div>
      ) : (
        <div className="flex flex-col gap-1">
          {nodes.map((n) => (
            <button key={n.id} onClick={() => onSelect(n.id)}
              className="flex items-center justify-between gap-2 px-2 py-1.5 rounded-btn border border-border bg-surface-base text-left transition-colors hover:border-accent-blue/40 cursor-pointer group">
              <span className="font-mono text-[10px] text-content-secondary truncate">
                <span style={{ color: CAT_COLOR[n.cat] }}>●</span> {typeLabel(n.type)} <span className="text-content-dim">{n.name}</span>
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
        Deploy or refresh this stack to capture its resources and dependencies from Pulumi state.
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export function InfraGraphView({ stack }: { stack: Stack }) {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const summary = stack.resource_summary
  const dot = STATE_DOT[stackNodeState(stack.status)]

  const layout = useMemo<Layout | null>(() => {
    if (!summary || !summary.resources || summary.resources.length === 0) return null
    return computeLayout(summary)
  }, [summary])

  if (!layout) return <GraphEmptyState />

  const nodeById = Object.fromEntries(layout.nodes.map((n) => [n.id, n])) as Record<string, LayoutNode>
  const selectedNode = selectedId ? (nodeById[selectedId] ?? null) : null
  const cats = Array.from(new Set(layout.nodes.map((n) => n.cat)))

  return (
    <div className="flex flex-col gap-2.5">
      {/* Header: counts + legend */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="font-mono text-[10px] text-content-dim uppercase tracking-[1px]">
          {layout.nodes.length} resources &middot; {layout.edges.length} dependencies
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

      {/* Canvas + panel */}
      <div className="flex gap-3 items-start">
        <div className="flex-1 min-w-0 rounded-card border border-border overflow-auto bg-surface-deep" style={{ maxHeight: '74vh' }}>
          {/* Render the SVG at its natural pixel size so nodes stay readable; the
              container scrolls (left-right and up-down) for large topologies
              instead of shrinking the whole map to fit. */}
          <svg viewBox={`0 0 ${layout.width} ${layout.height}`} width={layout.width} height={layout.height} preserveAspectRatio="xMinYMin meet" style={{ display: 'block' }}>
            <defs>
              <marker id={`ar-${stack.id}`} markerWidth={8} markerHeight={8} refX={7} refY={3.5} orient="auto"><path d="M0 1L7 3.5L0 6z" fill="rgba(255,255,255,0.28)" /></marker>
              <marker id={`arh-${stack.id}`} markerWidth={8} markerHeight={8} refX={7} refY={3.5} orient="auto"><path d="M0 1L7 3.5L0 6z" fill={ACCENT} /></marker>
            </defs>

            {layout.edges.map((e) => {
              const hl = e.from === selectedId || e.to === selectedId
              return (
                <path key={`${e.from}->${e.to}`} d={e.path} fill="none"
                  stroke={hl ? ACCENT : 'rgba(255,255,255,0.13)'} strokeOpacity={hl ? 0.7 : 1} strokeWidth={hl ? 1.6 : 1}
                  markerEnd={`url(#${hl ? `arh-${stack.id}` : `ar-${stack.id}`})`} style={{ transition: 'stroke 0.2s ease' }} />
              )
            })}

            {layout.nodes.map((node) => (
              <SvgNode key={node.id} node={node} dot={dot} selected={selectedId === node.id} onClick={() => setSelectedId((p) => (p === node.id ? null : node.id))} />
            ))}
          </svg>
        </div>

        {selectedNode && (
          <DetailPanel node={selectedNode} stack={stack} nodeById={nodeById} edges={layout.edges} onSelect={setSelectedId} onClose={() => setSelectedId(null)} />
        )}
      </div>
    </div>
  )
}
