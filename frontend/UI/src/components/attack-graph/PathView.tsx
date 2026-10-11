/**
 * One attack path, drawn as flow cards on a grid canvas.
 *
 * Every identity, then the impact the path ends in, is a compact card. Cards
 * are joined handle to handle by curved edges. Each escalation step carries a
 * numbered badge (dashed and yellow when the step is conditional), so "Step 2"
 * in the panel matches the 2 on the canvas; the last edge, into the impact,
 * is not a step and has none. Selecting a card or a badge spotlights it and
 * opens a panel pointing at it.
 *
 * The reach view draws its paths here too. A path that ends at an identity
 * rather than an impact passes showImpact={false}: every edge is then a step,
 * and endNote says what the last card's panel should.
 */

import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { ReactNode, RefObject } from 'react'

import { IconCrown, IconResource, IconRole, IconUser } from '@/components/ui/Icons'
import { getGraphEntity } from '@/services/attackGraph.service'
import type { AttackChain, GraphEntity } from '@/types/attackGraph'

import { impactLabel, pathNodes, severityOf, stepCalls, stepSentence } from './pathModel'
import type { PathNode } from './pathModel'

type Selection = { kind: 'node'; index: number } | { kind: 'step'; index: number } | { kind: 'impact' } | null

const STILL = 'motion-reduce:animate-none'

// The reach view starts from a user or a role, the identities its list offers.
const REACHABLE_KINDS = ['IAM user', 'IAM role']

// Canvas geometry in px. Cards are w-40 h-12 (160 x 48); the layout below must match.
const CARD_W = 160
const CARD_H = 48
const PAD = 28
const MIN_GAP = 72
const CANVAS_H = 128
const MID_Y = CANVAS_H / 2
// Handles sit 4px outside each card, so edges start and end on them.
const HANDLE = 4
const ARROW = 8

function NodeIcon({ kind }: { kind: string }) {
  if (kind === 'IAM user') return <IconUser size={14} />
  if (kind.startsWith('IAM') || kind === 'Assumed role') return <IconRole size={14} />
  return <IconResource size={14} />
}

/** The container's width, kept current as it resizes. */
function useWidth(ref: RefObject<HTMLDivElement>): number {
  const [width, setWidth] = useState(0)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return undefined
    const observer = new ResizeObserver(() => setWidth(el.clientWidth))
    observer.observe(el)
    setWidth(el.clientWidth)
    return () => observer.disconnect()
  }, [ref])
  return width
}

export function PathView({
  chain, scanId, showImpact = true, endNote, onReach,
}: {
  chain: AttackChain
  scanId: string
  /** End the path in the impact card. */
  showImpact?: boolean
  /** The last identity's panel text when there is no impact card. */
  endNote?: string
  /** Offered on a user's or role's panel: show what that identity can reach. */
  onReach?: (nodeId: string) => void
}) {
  const [selected, setSelected] = useState<Selection>(null)
  const nodes = pathNodes(chain)
  const canvasRef = useRef<HTMLDivElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const [pointer, setPointer] = useState(48)
  const containerWidth = useWidth(canvasRef)

  useEffect(() => setSelected(null), [chain.id])

  // Identities, then the impact, spread across the canvas but never closer
  // than MIN_GAP: a long path makes the canvas wider and it scrolls sideways.
  const count = nodes.length + (showImpact ? 1 : 0)
  const width = Math.max(containerWidth, PAD * 2 + CARD_W * count + MIN_GAP * (count - 1))
  const gap = (width - PAD * 2 - CARD_W * count) / Math.max(count - 1, 1)
  const left = (i: number) => PAD + i * (CARD_W + gap)

  // Aim the panel's pointer at the centre of whatever is selected.
  useLayoutEffect(() => {
    const target = canvasRef.current?.querySelector('[data-selected="true"]')
    const panel = panelRef.current
    if (!target || !panel) return
    const box = target.getBoundingClientRect()
    setPointer(Math.max(16, box.left + box.width / 2 - panel.getBoundingClientRect().left - 6))
  }, [selected, width])

  const focus = selected !== null
  const isNode = (i: number) => selected?.kind === 'node' && selected.index === i
  const isStep = (i: number) => selected?.kind === 'step' && selected.index === i
  const impactPicked = selected?.kind === 'impact'

  const toggle = (next: NonNullable<Selection>) => {
    setSelected((current) => (JSON.stringify(current) === JSON.stringify(next) ? null : next))
  }

  // One edge per gap: the steps between identities, then the plain edge into the impact.
  const edges = Array.from({ length: count - 1 }, (_, i) => {
    const step = chain.steps[i]
    const x1 = left(i) + CARD_W + HANDLE
    const x2 = left(i + 1) - HANDLE
    return { i, step, x1, x2, mid: (x1 + x2) / 2, picked: step ? isStep(i) : impactPicked }
  })

  return (
    <div>
      <div
        ref={canvasRef}
        className="relative mt-4 overflow-x-auto overflow-y-hidden rounded-xl border border-border bg-surface-deep bg-grid-lines bg-grid-cell"
      >
        {containerWidth > 0 && (
          <div className="relative" style={{ width, height: CANVAS_H }}>
            <svg aria-hidden width={width} height={CANVAS_H} className="pointer-events-none absolute inset-0 overflow-visible">
              {edges.map(({ i, step, x1, x2, mid, picked }) => {
                const conditional = step?.certainty === 'conditional'
                return (
                  <g key={i} className={`transition-opacity ${focus && !picked ? 'opacity-35' : ''}`}>
                    <path
                      d={`M${x1} ${MID_Y} C ${mid} ${MID_Y - 18}, ${mid} ${MID_Y + 18}, ${x2 - ARROW + 1} ${MID_Y}`}
                      fill="none"
                      strokeWidth={1.5}
                      strokeDasharray={conditional ? '5 4' : undefined}
                      className={conditional ? 'stroke-content-dim' : 'stroke-content-muted'}
                    />
                    <path d={`M${x2 - ARROW} ${MID_Y - 4.5} L${x2} ${MID_Y} L${x2 - ARROW} ${MID_Y + 4.5}z`} className="fill-content-muted" />
                  </g>
                )
              })}
            </svg>

            {nodes.map((node, i) => (
              <Card
                key={`${node.id}-${i}`}
                x={left(i)}
                hasIn={i > 0}
                hasOut={showImpact || i < nodes.length - 1}
                picked={isNode(i)}
                faded={focus && !isNode(i)}
                onClick={() => toggle({ kind: 'node', index: i })}
                title={`${node.name} (${node.kind})`}
                icon={<NodeIcon kind={node.kind} />}
                name={node.name}
                caption={node.accountTail ? `${node.kind} · …${node.accountTail}` : node.kind}
              />
            ))}
            {showImpact && (
              <Card
                x={left(nodes.length)}
                hasIn
                hasOut={false}
                impact
                picked={impactPicked}
                faded={focus && !impactPicked}
                onClick={() => toggle({ kind: 'impact' })}
                title={impactLabel(chain.terminal_impact)}
                icon={<IconCrown size={14} />}
                name={impactLabel(chain.terminal_impact)}
                caption="Impact"
              />
            )}

            {edges.map(({ i, step, mid }) => step && (
              <StepBadge
                key={i}
                number={i + 1}
                x={mid}
                conditional={step.certainty === 'conditional'}
                picked={isStep(i)}
                faded={focus && !isStep(i)}
                onClick={() => toggle({ kind: 'step', index: i })}
              />
            ))}
          </div>
        )}
      </div>

      {selected === null && (
        <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-content-dim">
          {chain.steps.length > 0 ? (
            <>
              <span className="flex items-center gap-1.5"><Marker />Select a numbered badge to see a step</span>
              {chain.steps.some((s) => s.certainty === 'conditional') && (
                <span className="flex items-center gap-1.5"><Marker warn />conditional step</span>
              )}
              <span>or a card to see an identity</span>
            </>
          ) : (
            <span>No escalation needed: this identity already holds {impactLabel(chain.terminal_impact).toLowerCase()}. Select a card for details.</span>
          )}
        </div>
      )}

      {selected !== null && (
        <div
          ref={panelRef}
          className="relative mt-3 animate-fadeSlideIn rounded-xl border border-border bg-surface-card px-5 py-4 shadow-ring"
        >
          <span
            aria-hidden
            style={{ left: pointer }}
            className="absolute -top-1.5 h-3 w-3 rotate-45 border-l border-t border-border bg-surface-card"
          />
          {selected.kind === 'step' && <StepDetail chain={chain} index={selected.index} />}
          {selected.kind === 'node' && (
            <NodeDetail chain={chain} nodes={nodes} index={selected.index} scanId={scanId} endNote={endNote} onReach={onReach} />
          )}
          {selected.kind === 'impact' && <ImpactDetail chain={chain} />}
        </div>
      )}
    </div>
  )
}

function Card({
  x, hasIn, hasOut, impact = false, picked, faded, onClick, title, icon, name, caption,
}: {
  x: number
  hasIn: boolean
  hasOut: boolean
  impact?: boolean
  picked: boolean
  faded: boolean
  onClick: () => void
  title: string
  icon: ReactNode
  name: string
  caption: string
}) {
  const ring = picked
    ? 'border-accent-blue ring-4 ring-accent-blue-glow'
    : impact ? 'border-danger ring-4 ring-danger-glow' : 'border-border-active'
  return (
    <button
      type="button"
      data-selected={picked}
      onClick={onClick}
      title={title}
      style={{ left: x, top: MID_Y - CARD_H / 2 }}
      className={`absolute flex h-12 w-40 items-center gap-2.5 rounded-lg border bg-surface-elevated px-2.5 text-left transition-opacity
        hover:opacity-60 ${ring} ${faded ? 'opacity-40' : ''}`}
    >
      {hasIn && <Handle side="left" />}
      {hasOut && <Handle side="right" />}
      <span
        className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md
          ${impact ? 'bg-danger-glow text-danger' : 'bg-white/5 text-content-secondary'}`}
      >
        {icon}
      </span>
      <span className="flex min-w-0 flex-col">
        <span className="truncate text-sm font-semibold leading-tight text-content-primary">{name}</span>
        <span className="truncate text-2xs text-content-dim">{caption}</span>
      </span>
    </button>
  )
}

function Handle({ side }: { side: 'left' | 'right' }) {
  return (
    <span
      aria-hidden
      className={`absolute top-1/2 h-2 w-2 -translate-y-1/2 rounded-full border border-content-muted bg-surface-deep
        ${side === 'left' ? '-left-1' : '-right-1'}`}
    />
  )
}

function StepBadge({
  number, x, conditional, picked, faded, onClick,
}: { number: number; x: number; conditional: boolean; picked: boolean; faded: boolean; onClick: () => void }) {
  let tone: string
  if (conditional) {
    tone = picked
      ? 'border-warning bg-warning text-surface-deep ring-4 ring-warning-glow'
      : `border-dashed border-warning bg-surface-card text-warning animate-hopPulseWarn ${STILL}`
  } else {
    tone = picked
      ? 'border-accent-blue bg-accent-blue text-surface-deep ring-4 ring-accent-blue-glow'
      : `border-accent-blue bg-surface-card text-accent-blue animate-hopPulse ${STILL}`
  }
  return (
    <button
      type="button"
      data-selected={picked}
      onClick={onClick}
      aria-label={`Step ${number}`}
      title={`Step ${number}`}
      style={{ left: x, top: MID_Y }}
      className={`absolute flex h-5 w-5 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border
        font-mono text-2xs font-semibold transition-opacity hover:opacity-60 ${tone} ${faded ? 'opacity-35' : ''}`}
    >
      {number}
    </button>
  )
}

function Marker({ warn = false }: { warn?: boolean }) {
  return (
    <span
      aria-hidden
      className={`inline-block h-2.5 w-2.5 rounded-full border ${warn ? 'border-dashed border-warning' : 'border-accent-blue'}`}
    />
  )
}

function Calls({ calls }: { calls: string[] }) {
  if (calls.length === 0) return <span className="text-xs text-content-dim">Scout listed no IAM call for this step.</span>
  return (
    <div className="mt-1.5 flex flex-wrap gap-1.5">
      {calls.map((call) => (
        <span key={call} className="rounded-btn border border-border px-2 py-0.5 font-mono text-2xs text-content-secondary">{call}</span>
      ))}
    </div>
  )
}

function StepDetail({ chain, index }: { chain: AttackChain; index: number }) {
  const step = chain.steps[index]
  const nodes = pathNodes(chain)
  const from = nodes[index]
  const to = nodes[index + 1]
  if (!step || !from || !to) return null
  const calls = stepCalls(step)
  return (
    <>
      <div className="flex flex-wrap items-baseline gap-x-3">
        <h4 className="text-sm font-semibold text-content-primary">Step {index + 1}: {from.name} → {to.name}</h4>
        <span className="font-mono text-2xs text-content-dim">{step.mechanism}</span>
      </div>
      <p className="mt-1.5 text-sm text-content-secondary">{stepSentence(step)}</p>
      <div className="mt-3 text-xs text-content-dim">{calls.length > 1 ? 'IAM calls' : 'IAM call'}</div>
      <Calls calls={calls} />
      {step.certainty === 'conditional' && (
        <p className="mt-3 text-xs text-warning">
          Conditional: {step.conditional_reason || 'a condition applies'}. An attacker needs to meet it first.
        </p>
      )}
    </>
  )
}

function NodeDetail({
  chain, nodes, index, scanId, endNote, onReach,
}: {
  chain: AttackChain
  nodes: PathNode[]
  index: number
  scanId: string
  endNote?: string
  onReach?: (nodeId: string) => void
}) {
  const node = nodes[index]
  const next = chain.steps[index]
  const nodeId = node?.id ?? ''
  const [entity, setEntity] = useState<GraphEntity | null>(null)
  const [rawOpen, setRawOpen] = useState(false)

  // The full record comes from the scan's stored graph. A 404 is normal for a
  // scan stored before graphs were kept; the panel works without it.
  useEffect(() => {
    if (!nodeId) return undefined
    let active = true
    setEntity(null)
    getGraphEntity(scanId, nodeId)
      .then((data) => { if (active) setEntity(data) })
      .catch(() => undefined)
    return () => { active = false }
  }, [scanId, nodeId])

  if (!node) return null

  return (
    <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
      <div>
        <h4 className="truncate text-sm font-semibold text-content-primary" title={node.name}>{node.name}</h4>
        <div className="text-xs text-content-dim">{node.kind}{node.accountTail ? ` · account …${node.accountTail}` : ''}</div>
        <p className="mt-2.5 text-sm text-content-secondary">
          {next ? stepSentence(next) : endNote ?? `Holds ${impactLabel(chain.terminal_impact).toLowerCase()} at the end of this path.`}
        </p>
        {onReach && REACHABLE_KINDS.includes(node.kind) && (
          <button
            type="button"
            onClick={() => onReach(node.id)}
            className="mt-2.5 bg-transparent p-0 text-xs text-accent-blue transition-opacity hover:opacity-60"
          >
            See what it can reach
          </button>
        )}
      </div>
      <div>
        {next && (
          <>
            <div className="text-xs text-content-dim">Can call next</div>
            <Calls calls={stepCalls(next)} />
          </>
        )}
        {entity && Object.keys(entity.properties).length > 0 && (
          <div className="mt-3">
            <button type="button" onClick={() => setRawOpen((open) => !open)} aria-expanded={rawOpen}
              className="bg-transparent p-0 text-xs text-accent-blue transition-opacity hover:opacity-60">
              {rawOpen ? 'Hide raw properties' : 'Show raw properties'}
            </button>
            {rawOpen && (
              <pre className="mt-2 max-h-64 overflow-auto rounded-btn bg-surface-deep p-2.5 font-mono text-2xs leading-snug text-content-secondary">
                {JSON.stringify(entity.properties, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function ImpactDetail({ chain }: { chain: AttackChain }) {
  const severity = severityOf(chain.score)
  return (
    <>
      <h4 className="text-sm font-semibold text-content-primary">{impactLabel(chain.terminal_impact)}</h4>
      <p className="mt-1.5 text-sm text-content-secondary">
        {chain.steps.length === 0
          ? 'This identity already holds it, with no escalation needed.'
          : `Reached in ${chain.steps.length} step${chain.steps.length > 1 ? 's' : ''}.`}
        {/* A reach path is not one of Scout's ranked chains, so it has no score to explain. */}
        {chain.score !== null && (
          <>
            {' '}Rated {severity.toLowerCase()} from Scout&apos;s risk score of {chain.score}, which weighs what the path
            reaches against how few steps it takes.
          </>
        )}
      </p>
      {chain.alternate_mechanisms.length > 0 && (
        <p className="mt-2 text-xs text-content-dim">
          {chain.alternate_mechanisms.length} other route{chain.alternate_mechanisms.length > 1 ? 's' : ''} reach the same
          target: {chain.alternate_mechanisms.join(', ')}.
        </p>
      )}
    </>
  )
}
