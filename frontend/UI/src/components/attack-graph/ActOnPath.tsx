/**
 * What to do about one attack path: rehearse it, spot it, check it, close it.
 *
 * The emulations come from the backend, matched through the path's escalation
 * calls (see apps/attack_graph/related.py). The best three show; the rest wait
 * behind "Show N more". Detection and guardrail links follow the best match,
 * since that is the emulation whose rules and attack calls they describe.
 */

import { useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

import { IconChevron, IconFlask, IconSearch, IconShield, IconWrench } from '@/components/ui/Icons'
import type { AttackChain, PathRelated, RelatedEmulation } from '@/types/attackGraph'

const SHOWN = 3

const ROW = 'flex items-center gap-3.5 px-1 py-3'
const LINK_ROW = `${ROW} no-underline transition-opacity hover:opacity-60`

/** "a", "a and b", "a, b and c". */
function listCalls(calls: string[]): string {
  if (calls.length <= 1) return calls.join('')
  return `${calls.slice(0, -1).join(', ')} and ${calls[calls.length - 1]}`
}

/** Why a path has no emulation, in the reader's terms. */
function noMatchReason(chain: AttackChain, wanted: string[]): string {
  if (chain.steps.length === 0) {
    return 'This identity already holds the access, so there is no step for an emulation to perform. Closing it means removing that access.'
  }
  if (wanted.length === 0) {
    return 'Its steps make no call that grants access on its own, such as only assuming a role, so there is nothing to match.'
  }
  return `No MayaTrail emulation performs ${listCalls(wanted)}.`
}

export function ActOnPath({ chain, related }: { chain: AttackChain; related: PathRelated | undefined }) {
  const [more, setMore] = useState(false)
  const emulations = related?.emulations ?? []
  const wanted = related?.escalationCalls ?? []
  const top = emulations[0]
  const shown = more ? emulations : emulations.slice(0, SHOWN)
  const hidden = emulations.length - SHOWN

  return (
    <div className="mt-6">
      <div className="mb-1 flex flex-wrap items-baseline gap-x-2 font-mono text-2xs uppercase tracking-label text-content-dim">
        Act on this path
        {chain.mitre_techniques.map((id) => (
          <span key={id} className="normal-case tracking-body text-accent-blue">{id}</span>
        ))}
      </div>

      <div className="divide-y divide-border">
        {shown.map((emulation) => (
          <EmulationRow key={emulation.id} emulation={emulation} total={wanted.length} />
        ))}
        {hidden > 0 && (
          <div className="flex items-center gap-3 px-1 py-2.5">
            <button
              type="button"
              onClick={() => setMore((open) => !open)}
              className="bg-transparent p-0 text-xs text-accent-blue transition-opacity hover:opacity-60"
            >
              {more ? 'Show fewer emulations' : `Show ${hidden} more emulation${hidden > 1 ? 's' : ''}`}
            </button>
            {!more && <span className="text-xs text-content-dim">that share fewer of this path&apos;s calls</span>}
          </div>
        )}
        {!top && (
          <div className={ROW}>
            <RowIcon><IconFlask size={16} /></RowIcon>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold text-content-primary">
                {chain.steps.length === 0 ? 'No escalation to rehearse' : 'No emulation rehearses this path yet'}
              </div>
              <div className="text-xs text-content-dim">{noMatchReason(chain, wanted)}</div>
            </div>
            <span className="text-xs font-semibold text-content-dim">None yet</span>
          </div>
        )}

        {chain.detection && (
          <div className={ROW}>
            <RowIcon><IconSearch size={16} /></RowIcon>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold text-content-primary">How to spot it</div>
              <div className="text-xs text-content-dim">{chain.detection}</div>
            </div>
            {top && top.detectionCount > 0 && (
              <Link
                to={`/${top.platform}/emulations/${top.id}/detections`}
                className="shrink-0 text-xs text-accent-blue no-underline transition-opacity hover:opacity-60"
              >
                {top.detectionCount} rule{top.detectionCount > 1 ? 's' : ''} in {top.name}
              </Link>
            )}
          </div>
        )}

        <Link to={top ? `/${top.platform}/emulations/${top.id}?tab=path` : '/guardrails'} className={LINK_ROW}>
          <RowIcon><IconShield size={16} /></RowIcon>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold text-content-primary">Check with your guardrails</div>
            <div className="text-xs text-content-dim">
              {top
                ? `Ask your account whether an SCP or boundary already stops ${top.name}'s calls.`
                : 'See which guardrail policies would refuse calls like these.'}
            </div>
          </div>
          <span className="text-xs font-semibold text-accent-blue">Prevent</span>
          <IconChevron size={14} className="text-content-dim" />
        </Link>

        {chain.remediation && (
          <div className={ROW}>
            <RowIcon><IconWrench size={16} /></RowIcon>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold text-content-primary">How to close it</div>
              <div className="text-xs text-content-dim">{chain.remediation}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function EmulationRow({ emulation, total }: { emulation: RelatedEmulation; total: number }) {
  const covered = emulation.sharedCalls.length
  const full = covered === total
  return (
    <Link to={`/${emulation.platform}/emulations/${emulation.id}`} className={LINK_ROW}>
      <RowIcon><IconFlask size={16} /></RowIcon>
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-semibold text-content-primary">{emulation.name}</div>
        <div className="truncate text-xs text-content-dim">Performs {listCalls(emulation.sharedCalls)}</div>
      </div>
      <span className="rounded-btn border border-border px-1.5 font-mono text-2xs text-content-dim">{emulation.tier}</span>
      <span
        className={`whitespace-nowrap rounded-btn border px-1.5 font-mono text-2xs
          ${full ? 'border-safe text-safe' : 'border-border text-content-dim'}`}
      >
        {covered} of {total} escalation call{total > 1 ? 's' : ''}
      </span>
      <span className="text-xs font-semibold text-accent-blue">Emulate</span>
      <IconChevron size={14} className="text-content-dim" />
    </Link>
  )
}

function RowIcon({ children }: { children: ReactNode }) {
  return (
    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-elevated text-content-secondary">
      {children}
    </span>
  )
}
