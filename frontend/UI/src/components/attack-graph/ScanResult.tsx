/**
 * A completed scan: its verdict, the ranked paths, and the selected path.
 *
 * `envelope.state` is the backend's verdict and is never re-derived here: a
 * partial scan is never framed as clean, whatever it found.
 */

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { formatWhen } from '@/components/threatfeed/feedMeta'
import { IconChevron } from '@/components/ui/Icons'
import type { PathRelated, ScanEnvelope } from '@/types/attackGraph'

import { ActOnPath } from './ActOnPath'

import { PathMap } from './PathMap'
import { PathView } from './PathView'
import { SEVERITY_TEXT, impactLabel, pathTitle, severityOf } from './pathModel'

const FULL_COMPROMISE = 'FULL_ACCOUNT_COMPROMISE'

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
  const [view, setView] = useState<'path' | 'map'>('path')
  useEffect(() => setSelected(0), [scanId])

  const chains = envelope.chains
  const chain = chains[Math.min(selected, chains.length - 1)]
  const compromise = chains.filter((c) => c.terminal_impact === FULL_COMPROMISE).length
  if (!chain) return null

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

      <div className="mt-4 grid grid-cols-1 items-start gap-4 xl:grid-cols-3">
        <ol className="divide-y divide-border rounded-card border border-border bg-surface-card shadow-ring">
          {chains.map((c, i) => {
            const severity = severityOf(c.score)
            const on = c.id === chain.id
            return (
              <li key={c.id}>
                <button
                  type="button"
                  onClick={() => setSelected(i)}
                  aria-current={on}
                  className="flex w-full items-center gap-3 bg-transparent px-4 py-3 text-left transition-opacity hover:opacity-60"
                >
                  <span className="w-5 font-mono text-xs text-content-dim">{c.rank}</span>
                  <span className="min-w-0 flex-1">
                    <span className={`block truncate text-sm font-semibold ${on ? 'text-accent-blue' : 'text-content-primary'}`}>
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

        <section className="rounded-card border border-border bg-surface-card px-6 py-5 shadow-ring xl:col-span-2">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="font-mono text-2xs uppercase tracking-label text-danger">
                Path {chain.rank} · score {chain.score ?? 'unknown'}
              </div>
              <div className="text-base font-semibold text-content-primary">{pathTitle(chain)}</div>
              {chain.narrative && <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">{chain.narrative}</p>}
            </div>
            <div className="inline-flex overflow-hidden rounded-btn border border-border" role="tablist">
              {(['path', 'map'] as const).map((v) => (
                <button
                  key={v}
                  type="button"
                  role="tab"
                  aria-selected={view === v}
                  onClick={() => setView(v)}
                  className={`px-3 py-1 text-xs transition-opacity hover:opacity-60
                    ${view === v ? 'bg-surface-elevated text-content-primary' : 'bg-transparent text-content-dim'}`}
                >
                  {v === 'path' ? 'Path' : 'Map'}
                </button>
              ))}
            </div>
          </div>

          {view === 'path'
            ? <PathView chain={chain} scanId={scanId} />
            : <PathMap chains={chains} selected={chains.indexOf(chain)} onSelect={setSelected} />}

          <ActOnPath key={chain.id} chain={chain} related={related[chain.id]} />
        </section>
      </div>
    </div>
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
