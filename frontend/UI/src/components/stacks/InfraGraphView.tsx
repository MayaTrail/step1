/**
 * InfraGraphView — SVG DAG visualization of the AWS resources Pulumi deploys.
 *
 * Renders the 10-resource graph from src/__main__.py as a two-column directed
 * acyclic graph.  Column 0 holds root resources; column 1 holds their
 * dependents.  Clicking a node opens a detail panel showing resource
 * configuration and any known runtime values from stack.outputs.
 *
 * No external graph library is used — layout is computed from fixed constants
 * that match the Pulumi program structure, and the canvas is plain SVG.
 */

import { useState } from 'react'
import type { Stack, StackStatus } from '@/types'

// ── Canvas layout constants ──────────────────────────────────────────────────

const CW = 820          // viewBox width
const CH = 400          // viewBox height
const NW = 158          // node width
const NH = 54           // node height
const NRX = 7           // node border-radius
const COL_X: Record<0 | 1, number> = { 0: 183, 1: 637 }
const ROWS = 5
const ROW_SPACING = 72
const ROW_TOP = (CH - (ROWS * ROW_SPACING - (ROW_SPACING - NH))) / 2

function ry(row: number) { return ROW_TOP + row * ROW_SPACING }

// ── Types ────────────────────────────────────────────────────────────────────

type Service = 'iam' | 's3'

interface GraphNode {
  id: string
  lines: string[]
  resourceType: string
  service: Service
  col: 0 | 1
  row: number
}

interface GraphEdge {
  from: string
  to: string
}

// ── Static graph definition — mirrors src/__main__.py resource graph ──────────

const NODES: GraphNode[] = [
  // Column 0: root resources (no dependencies within this stack)
  { id: 'iam_user',        lines: ['IAM User'],              resourceType: 'AWS::IAM::User',                service: 'iam', col: 0, row: 0 },
  { id: 'user_policy',     lines: ['User Policy'],           resourceType: 'AWS::IAM::ManagedPolicy',       service: 'iam', col: 0, row: 1 },
  { id: 'iam_role',        lines: ['IAM Role'],              resourceType: 'AWS::IAM::Role',                service: 'iam', col: 0, row: 2 },
  { id: 'role_policy',     lines: ['Role Policy'],           resourceType: 'AWS::IAM::ManagedPolicy',       service: 'iam', col: 0, row: 3 },
  { id: 's3_bucket',       lines: ['S3 Bucket'],             resourceType: 'AWS::S3::Bucket',               service: 's3',  col: 0, row: 4 },
  // Column 1: dependent resources (require column-0 resources to exist first)
  { id: 'access_key',      lines: ['Access Key'],            resourceType: 'AWS::IAM::AccessKey',           service: 'iam', col: 1, row: 0 },
  { id: 'login_cleanup',   lines: ['Login Profile', 'Cleanup'], resourceType: 'Custom::LoginCleanup',      service: 'iam', col: 1, row: 1 },
  { id: 'user_attachment', lines: ['Policy Binding', '(User)'], resourceType: 'AWS::IAM::UserPolicyAttach', service: 'iam', col: 1, row: 2 },
  { id: 'role_attachment', lines: ['Policy Binding', '(Role)'], resourceType: 'AWS::IAM::RolePolicyAttach', service: 'iam', col: 1, row: 3 },
  { id: 's3_object',       lines: ['Bucket Object'],         resourceType: 'AWS::S3::BucketObject',         service: 's3',  col: 1, row: 4 },
]

const EDGES: GraphEdge[] = [
  { from: 'iam_user',    to: 'access_key' },
  { from: 'iam_user',    to: 'login_cleanup' },
  { from: 'iam_user',    to: 'user_attachment' },
  { from: 'user_policy', to: 'user_attachment' },
  { from: 'iam_role',    to: 'role_attachment' },
  { from: 'role_policy', to: 'role_attachment' },
  { from: 's3_bucket',   to: 's3_object' },
]

const NODE_BY_ID = Object.fromEntries(NODES.map((n) => [n.id, n]))

// ── Style helpers ────────────────────────────────────────────────────────────

const SVC_LIVE: Record<Service, string>     = { iam: '#fbbf24', s3: '#5fc992' }
const SVC_DEPLOY: Record<Service, string>   = { iam: '#fbbf2455', s3: '#5fc99255' }
const SVC_BADGE: Record<Service, { bg: string; text: string }> = {
  iam: { bg: 'rgba(251,191,36,0.12)',  text: '#fbbf24' },
  s3:  { bg: 'rgba(95,201,146,0.12)', text: '#5fc992' },
}

function nodeStroke(service: Service, status: StackStatus, selected: boolean): string {
  if (selected) return '#48e8c8'
  if (['ready', 'ready_for_attack', 'attacking', 'attack_complete'].includes(status))
    return SVC_LIVE[service]
  if (status === 'deploying') return SVC_DEPLOY[service]
  if (status === 'failed')    return 'rgba(255,99,99,0.45)'
  return 'rgba(255,255,255,0.1)'
}

function nodeFill(service: Service, status: StackStatus, selected: boolean): string {
  if (selected) return 'rgba(72,232,200,0.06)'
  if (['ready', 'ready_for_attack', 'attacking', 'attack_complete'].includes(status))
    return service === 'iam' ? 'rgba(251,191,36,0.05)' : 'rgba(95,201,146,0.05)'
  if (status === 'failed') return 'rgba(255,99,99,0.04)'
  return '#101111'
}

function groupOpacity(col: 0 | 1, status: StackStatus): number {
  if (status === 'pending') return 0.4
  if (status === 'deploying' && col === 1) return 0.7
  if (status === 'failed') return 0.75
  return 1
}

function edgeStroke(srcId: string, tgtId: string, selectedId: string | null): string {
  if (srcId === selectedId || tgtId === selectedId) return 'rgba(72,232,200,0.5)'
  return 'rgba(255,255,255,0.1)'
}

// ── Bezier path between two nodes ────────────────────────────────────────────

function bezierPath(src: GraphNode, tgt: GraphNode): string {
  const sx = COL_X[src.col] + NW / 2
  const sy = ry(src.row) + NH / 2
  const tx = COL_X[tgt.col] - NW / 2
  const ty = ry(tgt.row) + NH / 2
  const cp = 65
  return `M ${sx} ${sy} C ${sx + cp} ${sy}, ${tx - cp} ${ty}, ${tx} ${ty}`
}

// ── Per-node detail data ──────────────────────────────────────────────────────

function nodeDetails(
  node: GraphNode,
  stack: Stack,
): Array<{ key: string; value: string }> {
  const n = stack.name
  const o = stack.outputs

  switch (node.id) {
    case 'iam_user':
      return [
        { key: 'Name',         value: `mayatrail-user-${n}` },
        { key: 'Path',         value: '/' },
        { key: 'Force Destroy', value: 'Enabled' },
        { key: 'Access Key ID', value: String(o.username ?? '—') },
        { key: 'Tags',         value: 'test-key: test-value' },
        { key: 'Managed By',   value: 'Pulumi' },
      ]
    case 'iam_role':
      return [
        { key: 'Name',           value: `mayatrail-role-${n}` },
        { key: 'ARN',            value: String(o.role_arn ?? '(deploying…)') },
        { key: 'Max Session',    value: '3600 s (1 hour)' },
        { key: 'Trust Principal', value: `mayatrail-user-${n}` },
        { key: 'Trust Action',   value: 'sts:AssumeRole' },
        { key: 'Managed By',    value: 'Pulumi' },
      ]
    case 'access_key':
      return [
        { key: 'Access Key ID', value: String(o.username ?? '—') },
        { key: 'Status',        value: 'Active' },
        { key: 'Attached User', value: `mayatrail-user-${n}` },
        { key: 'Secret Key',    value: '(encrypted by Pulumi)' },
      ]
    case 'login_cleanup':
      return [
        { key: 'Type',        value: 'Custom (Dynamic Resource)' },
        { key: 'Purpose',     value: 'Deletes login profile before IAM user on destroy' },
        { key: 'Username',    value: `mayatrail-user-${n}` },
        { key: 'Runs On',     value: 'pulumi destroy' },
        { key: 'Provider',    value: 'pulumi.dynamic.ResourceProvider' },
      ]
    case 'user_policy':
      return [
        { key: 'Policy Name', value: 'mayatrail-user-policy' },
        { key: 'Permission 1', value: 'iam:* on *' },
        { key: 'Permission 2', value: `sts:AssumeRole on mayatrail-role-${n}` },
        { key: 'Attached To', value: `mayatrail-user-${n}` },
      ]
    case 'role_policy':
      return [
        { key: 'Policy Name',  value: 'mayatrail-role-policy' },
        { key: 'Permission',   value: 'iam:AttachRolePolicy on *' },
        { key: 'Attached To',  value: `mayatrail-role-${n}` },
        { key: 'Purpose',      value: 'Allows role to escalate privileges via policy attachment' },
      ]
    case 'user_attachment':
      return [
        { key: 'Type',    value: 'IAM User Policy Attachment' },
        { key: 'User',    value: `mayatrail-user-${n}` },
        { key: 'Policy',  value: 'mayatrail-user-policy' },
        { key: 'Effect',  value: 'Binds policy permissions to user identity' },
      ]
    case 'role_attachment':
      return [
        { key: 'Type',   value: 'IAM Role Policy Attachment' },
        { key: 'Role',   value: `mayatrail-role-${n}` },
        { key: 'Policy', value: 'mayatrail-role-policy' },
        { key: 'Effect', value: 'Binds policy permissions to assumed role' },
      ]
    case 's3_bucket':
      return [
        { key: 'Bucket Name',  value: `mayatrail-step1-bucket-${n}` },
        { key: 'Region',       value: stack.region },
        { key: 'Type',         value: 'General Purpose' },
        { key: 'Public Access', value: 'Blocked (default)' },
        { key: 'Object URL',   value: String(o.object_url ?? '(deploying…)') },
      ]
    case 's3_object':
      return [
        { key: 'Object Key',  value: 'dummy-text-file1' },
        { key: 'Bucket',      value: `mayatrail-step1-bucket-${n}` },
        { key: 'Content',     value: 'Sample text file uploaded by Pulumi' },
        { key: 'Object URL',  value: String(o.object_url ?? '(deploying…)') },
      ]
    default:
      return []
  }
}

// ── Sub-components ───────────────────────────────────────────────────────────

/** Single node rendered as an SVG group. */
function SvgNode({
  node,
  status,
  selected,
  onClick,
}: {
  node: GraphNode
  status: StackStatus
  selected: boolean
  onClick: () => void
}) {
  const x = COL_X[node.col] - NW / 2
  const y = ry(node.row)
  const cx = COL_X[node.col]
  const cy = y + NH / 2
  const svc = SVC_BADGE[node.service]
  const isDeploying = status === 'deploying'
  const isSingleLine = node.lines.length === 1

  return (
    <g
      onClick={onClick}
      style={{
        opacity: groupOpacity(node.col, status),
        cursor: 'pointer',
        animation: isDeploying
          ? `pulse 2s cubic-bezier(0.4,0,0.6,1) infinite ${node.col === 1 ? '0.6s' : '0s'}`
          : 'none',
      }}
    >
      {/* Node body */}
      <rect
        x={x}
        y={y}
        width={NW}
        height={NH}
        rx={NRX}
        fill={nodeFill(node.service, status, selected)}
        stroke={nodeStroke(node.service, status, selected)}
        strokeWidth={selected ? 1.5 : 1}
      />

      {/* Selection glow */}
      {selected && (
        <rect
          x={x - 2}
          y={y - 2}
          width={NW + 4}
          height={NH + 4}
          rx={NRX + 2}
          fill="none"
          stroke="rgba(72,232,200,0.2)"
          strokeWidth={2}
        />
      )}

      {/* Service badge — top-left corner */}
      <rect
        x={x + 7}
        y={y + 6}
        width={node.service === 'iam' ? 24 : 18}
        height={14}
        rx={3}
        fill={svc.bg}
      />
      <text
        x={x + 7 + (node.service === 'iam' ? 12 : 9)}
        y={y + 16}
        textAnchor="middle"
        dominantBaseline="middle"
        fill={svc.text}
        fontSize={8}
        fontFamily="GeistMono, ui-monospace, monospace"
        fontWeight={600}
        letterSpacing={0.3}
      >
        {node.service.toUpperCase()}
      </text>

      {/* Node label */}
      {isSingleLine ? (
        <text
          x={cx}
          y={cy + 5}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#f9f9f9"
          fontSize={11.5}
          fontFamily="Inter, sans-serif"
          fontWeight={500}
          letterSpacing={0.2}
        >
          {node.lines[0]}
        </text>
      ) : (
        <text
          x={cx}
          textAnchor="middle"
          fill="#f9f9f9"
          fontSize={11}
          fontFamily="Inter, sans-serif"
          fontWeight={500}
          letterSpacing={0.2}
        >
          <tspan x={cx} y={cy + 1}>{node.lines[0]}</tspan>
          <tspan x={cx} dy={14} fill="#9c9c9d" fontSize={10}>{node.lines[1]}</tspan>
        </text>
      )}
    </g>
  )
}

/** Detail panel shown to the right of the SVG when a node is selected. */
function DetailPanel({
  node,
  stack,
  onClose,
}: {
  node: GraphNode
  stack: Stack
  onClose: () => void
}) {
  const details = nodeDetails(node, stack)
  const svc = SVC_BADGE[node.service]

  return (
    <div
      className="w-[270px] shrink-0 bg-[#0d0e0f] border border-[rgba(255,255,255,0.08)] rounded-[10px] p-4 animate-slideUp"
      style={{ boxShadow: 'rgb(27,28,30) 0px 0px 0px 1px, rgb(7,8,10) 0px 0px 0px 1px inset' }}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span
              className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded-[3px] uppercase tracking-[0.4px]"
              style={{ background: svc.bg, color: svc.text }}
            >
              {node.service.toUpperCase()}
            </span>
          </div>
          <div className="font-display text-[0.85rem] font-bold text-content-primary leading-tight">
            {node.lines.join(' ')}
          </div>
          <div className="font-mono text-[9px] text-content-dim mt-0.5 truncate">
            {node.resourceType}
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-content-dim hover:text-content-primary transition-opacity hover:opacity-60
            bg-transparent border-none cursor-pointer text-[14px] leading-none shrink-0 mt-0.5"
        >
          &#10005;
        </button>
      </div>

      {/* Divider */}
      <div className="h-px bg-[rgba(255,255,255,0.06)] mb-3" />

      {/* Detail rows */}
      <div className="flex flex-col gap-2.5">
        {details.map(({ key, value }) => (
          <div key={key}>
            <div className="font-mono text-[8.5px] text-content-dim uppercase tracking-[1px] mb-0.5">
              {key}
            </div>
            <div
              className="font-mono text-[10px] text-content-secondary break-all leading-[1.5]"
              style={{ letterSpacing: '0.2px' }}
            >
              {value}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main component ───────────────────────────────────────────────────────────

export function InfraGraphView({ stack }: { stack: Stack }) {
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const selectedNode: GraphNode | null = selectedId ? (NODE_BY_ID[selectedId] ?? null) : null

  function handleNodeClick(id: string) {
    setSelectedId((prev) => (prev === id ? null : id))
  }

  const isLive = ['ready', 'ready_for_attack', 'attacking', 'attack_complete'].includes(stack.status)

  return (
    <div className="flex flex-col gap-2">
      {/* Legend + status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <LegendDot color="#fbbf24" label="IAM" />
          <LegendDot color="#5fc992" label="S3" />
          <LegendDot color="#48e8c8" label="Selected" />
        </div>
        <div className="font-mono text-[9px] text-content-dim uppercase tracking-[1px]">
          {NODES.length} resources · {EDGES.length} dependencies · click a node for details
        </div>
      </div>

      {/* Canvas + detail panel */}
      <div className="flex gap-3 items-start">
        {/* SVG canvas */}
        <div
          className="flex-1 min-w-0 rounded-[8px] border border-[rgba(255,255,255,0.06)] overflow-hidden"
          style={{ background: '#07080a' }}
        >
          <svg
            viewBox={`0 0 ${CW} ${CH}`}
            width="100%"
            preserveAspectRatio="xMidYMid meet"
            style={{ display: 'block' }}
          >
            <defs>
              {/* Arrowhead marker for default edges */}
              <marker
                id={`arrow-${stack.id}`}
                markerWidth={8}
                markerHeight={8}
                refX={7}
                refY={3.5}
                orient="auto"
              >
                <path d="M 0 1 L 7 3.5 L 0 6 Z" fill="rgba(255,255,255,0.18)" />
              </marker>
              {/* Arrowhead marker for highlighted edges */}
              <marker
                id={`arrow-hl-${stack.id}`}
                markerWidth={8}
                markerHeight={8}
                refX={7}
                refY={3.5}
                orient="auto"
              >
                <path d="M 0 1 L 7 3.5 L 0 6 Z" fill="rgba(72,232,200,0.7)" />
              </marker>
            </defs>

            {/* Column labels */}
            <text
              x={COL_X[0]}
              y={14}
              textAnchor="middle"
              fill="rgba(255,255,255,0.2)"
              fontSize={9}
              fontFamily="GeistMono, monospace"
              letterSpacing={1}
            >
              ROOT RESOURCES
            </text>
            <text
              x={COL_X[1]}
              y={14}
              textAnchor="middle"
              fill="rgba(255,255,255,0.2)"
              fontSize={9}
              fontFamily="GeistMono, monospace"
              letterSpacing={1}
            >
              DEPENDENTS
            </text>

            {/* Column separator line */}
            <line
              x1={(COL_X[0] + COL_X[1]) / 2}
              y1={22}
              x2={(COL_X[0] + COL_X[1]) / 2}
              y2={CH - 10}
              stroke="rgba(255,255,255,0.04)"
              strokeWidth={1}
              strokeDasharray="4 4"
            />

            {/* Edges */}
            {EDGES.map(({ from, to }) => {
              // Non-null assertions are safe — EDGES only references IDs that exist in NODES.
              const src = NODE_BY_ID[from]!
              const tgt = NODE_BY_ID[to]!
              const highlighted = from === selectedId || to === selectedId
              const stroke = edgeStroke(from, to, selectedId)
              const markerId = highlighted
                ? `arrow-hl-${stack.id}`
                : `arrow-${stack.id}`
              return (
                <path
                  key={`${from}-${to}`}
                  d={bezierPath(src, tgt)}
                  fill="none"
                  stroke={stroke}
                  strokeWidth={highlighted ? 1.5 : 1}
                  markerEnd={`url(#${markerId})`}
                  style={{ transition: 'stroke 0.2s ease, stroke-width 0.2s ease' }}
                />
              )
            })}

            {/* Nodes */}
            {NODES.map((node) => (
              <SvgNode
                key={node.id}
                node={node}
                status={stack.status}
                selected={selectedId === node.id}
                onClick={() => handleNodeClick(node.id)}
              />
            ))}

            {/* "Live" pulse rings on ready stacks */}
            {isLive && NODES.filter((n) => n.col === 0).map((node) => {
              const cx = COL_X[node.col]
              const cy = ry(node.row) + NH / 2
              const color = SVC_LIVE[node.service]
              return (
                <circle
                  key={`pulse-${node.id}`}
                  cx={cx}
                  cy={cy}
                  r={NW / 2 - 2}
                  fill="none"
                  stroke={color}
                  strokeWidth={1}
                  opacity={0}
                  style={{
                    animation: `pingRing 2.5s ease-out infinite ${node.row * 0.3}s`,
                  }}
                />
              )
            })}
          </svg>

          {/* Keyframe styles — injected inline since Tailwind has no ping-ring utility */}
          <style>{`
            @keyframes pingRing {
              0%   { r: ${NW / 2 - 4}; opacity: 0.4; }
              100% { r: ${NW / 2 + 14}; opacity: 0; }
            }
            @keyframes pulse {
              0%, 100% { opacity: 1; }
              50%       { opacity: 0.45; }
            }
          `}</style>
        </div>

        {/* Node detail panel */}
        {selectedNode && (
          <DetailPanel
            node={selectedNode}
            stack={stack}
            onClose={() => setSelectedId(null)}
          />
        )}
      </div>
    </div>
  )
}

// ── Legend dot ────────────────────────────────────────────────────────────────

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-2 h-2 rounded-full" style={{ background: color }} />
      <span className="font-mono text-[9px] text-content-dim uppercase tracking-[0.8px]">{label}</span>
    </div>
  )
}
