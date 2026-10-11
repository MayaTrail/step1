/**
 * A completed scan: its verdict, then two tabs. Ranked paths are the paths
 * Scout chose and scored; the reach tab answers what one identity, picked by
 * the reader, can become.
 *
 * `envelope.state` is the backend's verdict and is never re-derived here: a
 * partial scan is never framed as clean, whatever it found.
 */

import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

import { formatWhen } from '@/components/threatfeed/feedMeta'
import { IconChevron } from '@/components/ui/Icons'
import type { AttackChain, PathRelated, ScanEnvelope } from '@/types/attackGraph'

import { ActOnPath } from './ActOnPath'
import { PathView } from './PathView'
import { SEVERITY_TEXT, impactLabel, pathTitle, severityOf } from './pathModel'
import type { Severity } from './pathModel'
import { ReachView } from './ReachView'
import { CARD, FILTER_ROW, FilterChip, PANEL_HEIGHT } from './SplitPanels'
import { TwoWays } from './TwoWays'

const FULL_COMPROMISE = 'FULL_ACCOUNT_COMPROMISE'

type Tab = 'ranked' | 'reach'

export function ScanResult({
  envelope, scanId, related,
}: { envelope: ScanEnvelope; scanId: string; related: Record<string, PathRelated> }) {
  if (envelope.state === 'clean') return <Clean envelope={envelope} />
  if (envelope.state === 'partial') return <Partial envelope={envelope} />
  return <Findings envelope={envelope} scanId={scanId} related={related} />
}

function scopeText(envelope: ScanEnvelope): string {
  const regions = envelope.regions ?? []
  return regions.length > 0 ? regions.join(', ') : 'IAM only'
}

function Findings({
  envelope, scanId, related,
}: { envelope: ScanEnvelope; scanId: string; related: Record<string, PathRelated> }) {
  const [selected, setSelected] = useState(0)
  const [tab, setTab] = useState<Tab>('ranked')
  const [origin, setOrigin] = useState('')
  const [explained, setExplained] = useState(false)
  useEffect(() => {
    setSelected(0)
    setTab('ranked')
    setOrigin('')
  }, [scanId])

  const reachFrom = (nodeId: string) => {
    setOrigin(nodeId)
    setTab('reach')
  }
  const openRanked = (index: number) => {
    setSelected(index)
    setTab('ranked')
  }

  const chains = envelope.chains
  const compromise = chains.filter((c) => c.terminal_impact === FULL_COMPROMISE).length
  if (chains.length === 0) return null

  return (
    <div>
      <div className="flex flex-wrap items-center gap-x-8 gap-y-3 rounded-card border border-border bg-surface-card px-6 py-4 shadow-ring">
        <div>
          <div className="text-xl font-semibold text-danger">
            {chains.length}{envelope.truncated ? '+' : ''} escalation path{chains.length === 1 ? '' : 's'}
          </div>
          <div className="text-xs text-content-dim">
            {compromise > 0 ? `${compromise} reach full account compromise` : 'None reaches full account compromise'}
          </div>
        </div>
        <Stat value={formatWhen(envelope.scanned_at)} label="scanned" />
        <Stat value={scopeText(envelope)} label={(envelope.regions ?? []).length ? 'regions read' : 'no regions read'} />
        <div className="max-w-sm text-xs text-content-dim">
          Organization SCPs are not evaluated, so a path may already be blocked by one.{' '}
          <Link to="/guardrails" className="text-accent-blue no-underline transition-opacity hover:opacity-60">
            See guardrails
          </Link>
        </div>
      </div>

      <div className="mt-5 flex items-end justify-between gap-3 border-b border-border">
        <div className="flex gap-6" role="tablist">
          <TabButton on={tab === 'ranked'} onClick={() => setTab('ranked')}>Ranked paths ({chains.length})</TabButton>
          <TabButton on={tab === 'reach'} onClick={() => setTab('reach')}>What can an identity reach?</TabButton>
        </div>
        <button
          type="button"
          onClick={() => setExplained((open) => !open)}
          aria-expanded={explained}
          className="bg-transparent px-0 pb-2.5 text-xs text-accent-blue transition-opacity hover:opacity-60"
        >
          {explained ? 'Hide' : 'How these differ'}
        </button>
      </div>
      {explained && (
        <div className="mt-3 animate-fadeSlideIn rounded-card border border-border bg-surface-card px-6 pb-4 pt-1 shadow-ring">
          <TwoWays />
        </div>
      )}

      {tab === 'reach' && (
        <ReachView envelope={envelope} scanId={scanId} origin={origin} onOrigin={setOrigin} onOpenRanked={openRanked} />
      )}
      {tab === 'ranked' && (
        <RankedPaths
          chains={chains}
          selected={Math.min(selected, chains.length - 1)}
          onSelect={setSelected}
          scanId={scanId}
          related={related}
          onReach={reachFrom}
        />
      )}
    </div>
  )
}

type SeverityFilter = Severity | 'all'

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low']

function RankedPaths({
  chains, selected, onSelect, scanId, related, onReach,
}: {
  chains: AttackChain[]
  selected: number
  onSelect: (index: number) => void
  scanId: string
  related: Record<string, PathRelated>
  onReach: (nodeId: string) => void
}) {
  const [filter, setFilter] = useState<SeverityFilter>('all')

  const chain = chains[selected]
  if (!chain) return null
  const shown = chains.map((c, i) => ({ c, i })).filter(({ c }) => filter === 'all' || severityOf(c.score) === filter)

  // Filtering away the open path opens the first one left, so the card always matches a visible row.
  const pickFilter = (next: SeverityFilter) => {
    setFilter(next)
    const first = chains.findIndex((c) => next === 'all' || severityOf(c.score) === next)
    if (next !== 'all' && severityOf(chain.score) !== next && first >= 0) onSelect(first)
  }

  return (
    <div className="mt-4 grid grid-cols-1 items-start gap-4 xl:grid-cols-3">
      <div style={{ maxHeight: PANEL_HEIGHT }} className={`${CARD} overflow-y-auto`}>
        <div className={FILTER_ROW}>
          <FilterChip on={filter === 'all'} count={chains.length} onClick={() => pickFilter('all')}>All</FilterChip>
          {SEVERITIES.map((severity) => {
            const count = chains.filter((c) => severityOf(c.score) === severity).length
            return (
              <FilterChip key={severity} on={filter === severity} count={count} onClick={() => pickFilter(severity)}>
                {severity}
              </FilterChip>
            )
          })}
        </div>
        <ol className="divide-y divide-border">
          {shown.map(({ c, i }) => {
            const severity = severityOf(c.score)
            const on = c.id === chain.id
            return (
              <li key={c.id}>
                <button
                  type="button"
                  onClick={() => onSelect(i)}
                  aria-current={on}
                  className="flex w-full items-center gap-3 bg-transparent px-4 py-3 text-left transition-opacity hover:opacity-60"
                >
                  <span className="w-5 font-mono text-xs text-content-dim">{c.rank}</span>
                  <span className="min-w-0 flex-1">
                    <span className={`line-clamp-2 break-words text-sm font-semibold ${on ? 'text-accent-blue' : 'text-content-primary'}`}>
                      {pathTitle(c)}
                    </span>
                    <span className="block truncate text-xs text-content-dim">
                      {c.steps.length === 0 ? 'Already privileged, no steps' : impactLabel(c.terminal_impact)}
                    </span>
                  </span>
                  <span className={`text-xs font-semibold ${SEVERITY_TEXT[severity]}`}>{severity}</span>
                  <IconChevron size={14} className="text-content-dim" />
                </button>
              </li>
            )
          })}
        </ol>
      </div>

      <section
        key={chain.id}
        style={{ height: PANEL_HEIGHT }}
        className={`${CARD} min-w-0 overflow-y-auto px-6 py-5 xl:col-span-2`}
      >
        <div className="font-mono text-2xs uppercase tracking-label text-danger">
          Path {chain.rank} · score {chain.score ?? 'unknown'}
        </div>
        <div className="text-base font-semibold text-content-primary">{pathTitle(chain)}</div>
        {chain.narrative && <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">{chain.narrative}</p>}

        <PathView chain={chain} scanId={scanId} onReach={onReach} />

        <ActOnPath key={chain.id} chain={chain} related={related[chain.id]} />
      </section>
    </div>
  )
}

function TabButton({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={on}
      onClick={onClick}
      className={`-mb-px border-b-2 bg-transparent px-0 pb-2.5 text-sm font-medium transition-opacity hover:opacity-60
        ${on ? 'border-content-primary text-content-primary' : 'border-transparent text-content-dim'}`}
    >
      {children}
    </button>
  )
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="text-xs text-content-dim">
      <div className="text-sm font-semibold text-content-primary">{value}</div>
      {label}
    </div>
  )
}

function Clean({ envelope }: { envelope: ScanEnvelope }) {
  const regions = envelope.regions ?? []
  return (
    <div className="rounded-card border border-border bg-surface-card px-7 py-6 shadow-ring">
      <div className="mb-1.5 font-mono text-2xs uppercase tracking-label text-safe">Clean</div>
      <div className="text-lg font-semibold text-content-primary">No escalation paths found</div>
      <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">
        Every identity&apos;s permissions were read and none leads to more access than it already has. Organization
        SCPs were not evaluated.{' '}
        {regions.length > 0
          ? `Resources were read in ${regions.join(', ')}.`
          : 'Resources were not read (IAM only); add regions to look for paths through Lambda or EC2.'}
      </p>
      <div className="mt-2 text-xs text-content-dim">Scanned {formatWhen(envelope.scanned_at)}</div>
    </div>
  )
}

function Partial({ envelope }: { envelope: ScanEnvelope }) {
  const selfScoped = envelope.mode === 'self'
  return (
    <div className="rounded-card border border-border bg-surface-card px-7 py-6 shadow-ring">
      <div className="mb-1.5 font-mono text-2xs uppercase tracking-label text-warning">Partial</div>
      <div className="text-lg font-semibold text-content-primary">This scan does not cover your whole account</div>
      <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">
        {selfScoped
          ? 'The role could only read itself: its policy no longer grants iam:GetAccountAuthorizationDetails. Fix its policy, then manage the role on the Attack Graph overview and save it again.'
          : 'Scout did not report how much of the account it could read, so this result is not treated as complete.'}{' '}
        A partial scan that found nothing does not mean your account is clean.
      </p>
      <div className="mt-2 text-xs text-content-dim">Scanned {formatWhen(envelope.scanned_at)}</div>
    </div>
  )
}
