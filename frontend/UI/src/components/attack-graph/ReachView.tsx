/**
 * "What can an identity reach?": every user and role in this scan, each with
 * its result shown before it is picked, and beside it what the selected one
 * can become, worst first, with the shortest way to each.
 *
 * Reads the scan's stored graph, so it works on scans already taken. The list
 * loads once per scan with every identity's counts; the reach itself is one
 * request per pick. An opened path is drawn with the same PathView and
 * ActOnPath the ranked paths use.
 */

import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { IconChevron, IconRole, IconUser } from '@/components/ui/Icons'
import { useCachedResource } from '@/hooks/useCachedResource'
import * as attackGraph from '@/services/attackGraph.service'
import type {
  AttackChain, ChainNode, IdentityList, IdentityNode, ReachLevel, ReachResult, ReachTarget, ScanEnvelope,
} from '@/types/attackGraph'

import { ActOnPath } from './ActOnPath'
import { PathView } from './PathView'
import { impactLabel, nodeFromArn } from './pathModel'
import { CARD, FILTER_ROW, FilterChip, PANEL_HEIGHT } from './SplitPanels'

const LEVELS: { level: ReachLevel; label: string; tone: string }[] = [
  { level: 'admin', label: 'Administrator access', tone: 'text-danger' },
  { level: 'self', label: 'Can make itself administrator', tone: 'text-danger' },
  { level: 'other', label: 'Other identities', tone: 'text-content-dim' },
]

// What the last card's panel says when the path ends at an identity, not an impact.
const END_NOTE: Record<ReachLevel, string> = {
  admin: '',
  self: 'Can make itself an administrator, so reaching it is as good as administrator access.',
  other: 'Not an administrator, and cannot make itself one directly.',
}

// Ranked-path impacts that end at a resource rather than an identity.
const RESOURCE_IMPACTS = new Set(['DATA_EXFILTRATION', 'RESOURCE_CONTROL'])

/** An identity's result, which sets its tag, its filter and its place in the list. */
type Outcome = 'admin' | 'others' | 'already' | 'nothing'
type OutcomeFilter = Outcome | 'all'

const OUTCOMES: { outcome: Outcome; label: string }[] = [
  { outcome: 'admin', label: 'Reach admin' },
  { outcome: 'others', label: 'Reach others' },
  { outcome: 'already', label: 'Already admin' },
  { outcome: 'nothing', label: 'Reach nothing' },
]

function outcomeOf(identity: IdentityNode): Outcome {
  if (identity.level !== 'other') return 'already'
  if (identity.reaches_admin > 0) return 'admin'
  return identity.reaches > 0 ? 'others' : 'nothing'
}

/** A reached identity's path, in the shape PathView and ActOnPath draw. */
function toChain(origin: ChainNode, target: ReachTarget): AttackChain {
  return {
    id: `reach:${target.node.id}`,
    rank: 0,
    score: null,
    source: origin,
    target: target.node,
    mitre_techniques: [],
    steps: target.steps,
    terminal_impact: target.level === 'admin' ? 'FULL_ACCOUNT_COMPROMISE' : null,
    alternate_mechanisms: [],
    narrative: '',
    detection: '',
    remediation: '',
  }
}

function steps(count: number): string {
  return `${count} step${count === 1 ? '' : 's'}`
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`
}

function KindIcon({ kind }: { kind: string }) {
  return (
    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-elevated text-content-secondary">
      {kind === 'IAM user' ? <IconUser size={15} /> : <IconRole size={15} />}
    </span>
  )
}

export function ReachView({
  envelope, scanId, origin, onOrigin, onOpenRanked,
}: {
  envelope: ScanEnvelope
  scanId: string
  /** The picked identity's node id, or "" to start on the first in the list. */
  origin: string
  onOrigin: (nodeId: string) => void
  /** Open a ranked path by its index in envelope.chains. */
  onOpenRanked: (index: number) => void
}) {
  const [filter, setFilter] = useState<OutcomeFilter>('all')
  const { data: identities, failed: listFailed } = useCachedResource<IdentityList>(
    `attack-graph:identities:${scanId}`,
    () => attackGraph.listIdentities(scanId),
  )

  // Grouped by result, worst first; within a group the backend's order (by name).
  const ordered = useMemo(() => OUTCOMES.flatMap(({ outcome }) => (
    (identities?.nodes ?? []).filter((n) => outcomeOf(n) === outcome)
  )), [identities])
  const shown = ordered.filter((n) => filter === 'all' || outcomeOf(n) === filter)
  const current = origin || ordered[0]?.id || ''

  // Filtering away the selected identity selects the first one left, so the card matches a visible row.
  const pickFilter = (next: OutcomeFilter) => {
    setFilter(next)
    const selected = ordered.find((n) => n.id === current)
    const first = ordered.find((n) => next === 'all' || outcomeOf(n) === next)
    if (next !== 'all' && first && (!selected || outcomeOf(selected) !== next)) onOrigin(first.id)
  }
  // A path's "See what it can reach" may name an identity the filter hides.
  const reachFrom = (nodeId: string) => {
    setFilter('all')
    onOrigin(nodeId)
  }

  return (
    <div className="mt-4 grid grid-cols-1 items-start gap-4 xl:grid-cols-3">
      <div style={{ maxHeight: PANEL_HEIGHT }} className={`${CARD} overflow-y-auto`}>
        <div className={FILTER_ROW}>
          <FilterChip on={filter === 'all'} count={ordered.length} onClick={() => pickFilter('all')}>All</FilterChip>
          {OUTCOMES.map(({ outcome, label }) => (
            <FilterChip
              key={outcome}
              on={filter === outcome}
              count={ordered.filter((n) => outcomeOf(n) === outcome).length}
              onClick={() => pickFilter(outcome)}
            >
              {label}
            </FilterChip>
          ))}
        </div>
        {!identities && (
          <p className="px-4 py-4 text-xs text-content-dim">
            {listFailed ? 'Could not load the users and roles in this scan. Try again.' : 'Loading users and roles…'}
          </p>
        )}
        <ul className="divide-y divide-border">
          {shown.map((identity) => (
            <li key={identity.id}>
              <IdentityRow identity={identity} on={identity.id === current} onClick={() => onOrigin(identity.id)} />
            </li>
          ))}
        </ul>
        {identities?.truncated && (
          <p className="border-t border-border px-4 py-3 text-xs text-content-dim">
            This account has more users and roles than this list shows; it lists the first {identities.nodes.length} by name.
          </p>
        )}
      </div>

      <div className="min-w-0 xl:col-span-2">
        {current && (
          <ReachCard
            key={current}
            envelope={envelope}
            scanId={scanId}
            origin={current}
            onReach={reachFrom}
            onOpenRanked={onOpenRanked}
          />
        )}
      </div>
    </div>
  )
}

function IdentityRow({ identity, on, onClick }: { identity: IdentityNode; on: boolean; onClick: () => void }) {
  const node = nodeFromArn(identity.id)
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={on}
      className="flex w-full items-center gap-3 bg-transparent px-4 py-3 text-left transition-opacity hover:opacity-60"
    >
      <KindIcon kind={node.kind} />
      <span className="min-w-0 flex-1">
        <span title={node.name} className={`block truncate text-sm font-semibold ${on ? 'text-accent-blue' : 'text-content-primary'}`}>
          {node.name}
        </span>
        <span className="block truncate text-xs text-content-dim">{node.kind}</span>
      </span>
      <OutcomeTag identity={identity} />
      <IconChevron size={14} className="shrink-0 text-content-dim" />
    </button>
  )
}

function OutcomeTag({ identity }: { identity: IdentityNode }) {
  const outcome = outcomeOf(identity)
  if (outcome === 'already') {
    return (
      <span className="whitespace-nowrap text-xs font-semibold text-danger">
        {identity.level === 'self' ? 'can make itself admin' : 'already admin'}
      </span>
    )
  }
  if (outcome === 'nothing') {
    return <span className="whitespace-nowrap text-xs font-semibold text-content-dim">reaches nothing</span>
  }
  return (
    <span className="whitespace-nowrap font-mono text-2xs text-content-dim">
      reaches {identity.reaches}
      {identity.reaches_admin > 0 && <> · <span className="text-danger">{identity.reaches_admin} admin</span></>}
    </span>
  )
}

/** A card holding only a message, as tall as its text. */
function MessageCard({
  eyebrow, tone, title, children,
}: { eyebrow: string; tone: string; title: string; children: ReactNode }) {
  return (
    <section className={`${CARD} px-6 py-5`}>
      <div className={`font-mono text-2xs uppercase tracking-label ${tone}`}>{eyebrow}</div>
      <div className="mt-1 text-base font-semibold text-content-primary">{title}</div>
      <p className="mt-1.5 text-sm text-content-secondary">{children}</p>
    </section>
  )
}

function ReachCard({
  envelope, scanId, origin, onReach, onOpenRanked,
}: {
  envelope: ScanEnvelope
  scanId: string
  origin: string
  onReach: (nodeId: string) => void
  onOpenRanked: (index: number) => void
}) {
  const { data: reach, loading, failed } = useCachedResource<ReachResult>(
    `attack-graph:reach:${scanId}:${origin}`,
    () => attackGraph.getReach(scanId, origin),
  )
  const result = reach && reach.origin.id === origin ? reach : undefined
  const name = nodeFromArn(origin).name

  if (!result) {
    return (
      <MessageCard eyebrow="Searching" tone="text-content-dim" title={name}>
        {failed && !loading ? 'Could not search this scan. Try again.' : 'Finding what it can reach…'}
      </MessageCard>
    )
  }

  if (result.origin_level !== 'admin' && result.origin_level !== 'self' && result.reached.length > 0) {
    return <Reached result={result} scanId={scanId} name={name} onReach={onReach} />
  }

  if (result.origin_level === 'other') {
    const regionsRead = (envelope.regions ?? []).length > 0
    // This tab follows identities only. A ranked path from this identity that
    // ends at a resource (data read, a function it can change) is still a
    // finding, so the card points to it rather than reading as "nothing".
    const resourcePaths = envelope.chains
      .map((chain, index) => ({ chain, index }))
      .filter(({ chain }) => chain.source.arn === origin && chain.steps.length > 0
        && RESOURCE_IMPACTS.has(chain.terminal_impact ?? ''))
    return (
      <MessageCard
        eyebrow={resourcePaths.length > 0 ? 'Reaches resources only' : 'Reaches nothing'}
        tone="text-content-dim"
        title={`${name} cannot become any other identity`}
      >
        {result.search_capped
          ? 'The search stopped early, so this is not a complete answer.'
          : 'Checked every role it may assume and every escalation it can perform in this scan.'}
        {!regionsRead && ' Identities only: this scan read no regions.'}
        {resourcePaths.length > 0 && (
          <>
            {' '}It does reach resources:{' '}
            {resourcePaths.map(({ chain, index }, i) => (
              <span key={chain.id}>
                {i > 0 && ', '}
                <button
                  type="button"
                  onClick={() => onOpenRanked(index)}
                  className="bg-transparent p-0 text-sm text-accent-blue transition-opacity hover:opacity-60"
                >
                  ranked path {chain.rank}
                </button>
                {' '}({impactLabel(chain.terminal_impact).toLowerCase()})
              </span>
            ))}
            .
          </>
        )}
      </MessageCard>
    )
  }

  const self = result.origin_level === 'self'
  // A ranked path that starts at this identity with no steps is the same finding.
  const rankedIndex = envelope.chains.findIndex((c) => c.source.arn === origin && c.steps.length === 0)
  return (
    <MessageCard
      eyebrow={self ? 'Can make itself administrator' : 'Already administrator'}
      tone="text-danger"
      title={self ? `${name} can make itself an administrator` : `${name} already has administrator access`}
    >
      {self ? 'It needs no other identity to get full control' : 'It can already do anything in this account'}, so
      there is nothing further to reach.
      {rankedIndex >= 0 && (
        <>
          {' '}It is ranked path {rankedIndex + 1}.{' '}
          <button
            type="button"
            onClick={() => onOpenRanked(rankedIndex)}
            className="bg-transparent p-0 text-sm text-accent-blue transition-opacity hover:opacity-60"
          >
            Open it
          </button>
        </>
      )}
    </MessageCard>
  )
}

function Reached({
  result, scanId, name, onReach,
}: { result: ReachResult; scanId: string; name: string; onReach: (nodeId: string) => void }) {
  const [openId, setOpenId] = useState(result.reached[0]?.node.id ?? '')
  useEffect(() => setOpenId(result.reached[0]?.node.id ?? ''), [result])

  const count = (level: ReachLevel) => result.reached.filter((r) => r.level === level).length
  const total = result.reached.length + result.truncated
  // Same count as the list's tag: an identity that can make itself an administrator leads to one too.
  const toAdmin = count('admin') + count('self')
  const parts: ReactNode[] = []
  if (toAdmin > 0) {
    parts.push(
      <span key="admin">
        <span className="text-danger">{toAdmin} lead{toAdmin === 1 ? 's' : ''} to administrator access</span>{' '}
        ({count('admin') === 1 ? '1 is an administrator' : `${count('admin')} are administrators`}
        {count('self') > 0 && `, ${count('self')} can make itself one`})
      </span>,
    )
  }
  if (count('other') > 0) parts.push(<span key="other">{plural(count('other'), 'other', 'others')}</span>)
  if (result.truncated > 0) parts.push(<span key="more">{result.truncated} more not listed</span>)
  parts.push(<span key="scope">identities only</span>)

  return (
    <section style={{ height: PANEL_HEIGHT }} className={`${CARD} flex flex-col`}>
      <div className="border-b border-border px-6 pb-3 pt-5">
        <div className="text-base font-semibold text-content-primary">
          {name} can become {plural(total, 'other identity', 'other identities')}
        </div>
        <p className="mt-1.5 text-sm text-content-secondary">
          {parts.map((part, i) => <span key={i}>{i > 0 && ' · '}{part}</span>)}. Select one to see the shortest way there.
        </p>
        {result.search_capped && (
          <p className="mt-1.5 text-xs text-content-secondary">
            <span className="font-semibold text-warning">Search stopped early.</span> This account is too large to
            search completely, so an identity that is not listed may still be reachable.
          </p>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto pb-3">
        {LEVELS.map(({ level, label, tone }) => {
          const rows = result.reached.filter((r) => r.level === level)
          if (rows.length === 0) return null
          return (
            <div key={level}>
              <div className={`flex justify-between px-6 pb-1.5 pt-3.5 font-mono text-2xs uppercase tracking-label ${tone}`}>
                <span>{label}</span>
                <span className="text-content-dim">{rows.length}</span>
              </div>
              <ul className="divide-y divide-border">
                {rows.map((row) => (
                  <ReachedRow
                    key={row.node.id}
                    result={result}
                    target={row}
                    open={row.node.id === openId}
                    onToggle={() => setOpenId((id) => (id === row.node.id ? '' : row.node.id))}
                    scanId={scanId}
                    onReach={onReach}
                  />
                ))}
              </ul>
            </div>
          )
        })}
      </div>
    </section>
  )
}

/** One identity the origin can become; opened, its path and what to do about it. */
function ReachedRow({
  result, target, open, onToggle, scanId, onReach,
}: {
  result: ReachResult
  target: ReachTarget
  open: boolean
  onToggle: () => void
  scanId: string
  onReach: (nodeId: string) => void
}) {
  const node = nodeFromArn(target.node.id)
  const chain = toChain(result.origin, target)
  return (
    <li>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center gap-3.5 bg-transparent px-6 py-3 text-left transition-opacity hover:opacity-60"
      >
        <KindIcon kind={node.kind} />
        <span className="min-w-0 flex-1">
          <span title={node.name} className={`block truncate text-sm font-semibold ${open ? 'text-accent-blue' : 'text-content-primary'}`}>
            {node.name}
          </span>
          <span className="block truncate text-xs text-content-dim">{node.kind}</span>
        </span>
        <span className="whitespace-nowrap font-mono text-2xs text-content-dim">{steps(target.steps.length)}</span>
        <IconChevron size={14} className={`shrink-0 text-content-dim transition-transform ${open ? 'rotate-90' : ''}`} />
      </button>
      {open && (
        <div className="animate-fadeSlideIn pb-4 pl-16 pr-6">
          <p className="text-xs text-content-dim">The shortest way there. Other, longer ways may exist.</p>
          <PathView
            chain={chain}
            scanId={scanId}
            showImpact={target.level === 'admin'}
            endNote={END_NOTE[target.level]}
            onReach={onReach}
          />
          <ActOnPath key={chain.id} chain={chain} related={result.related[target.node.id]} />
        </div>
      )}
    </li>
  )
}
