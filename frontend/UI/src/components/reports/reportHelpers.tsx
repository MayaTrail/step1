/**
 * Shared vocabulary for the report and comparison surfaces.
 *
 * Verdict wording follows the global UI mode, exactly as the run's coverage
 * page does: technical is what a detection engineer expects, plain is what the
 * verdict means in English. One place, so a report and the page it was built
 * from can never word the same fact differently.
 */

import type { ReactNode } from 'react'
import type { ReportVerdict, VerdictChangeKind } from '@/types'

const VERDICT_LABEL: Record<ReportVerdict, string> = {
  fired: 'Fired',
  silent: 'Silent',
  no_logs: 'No logs',
}

const VERDICT_LABEL_PLAIN: Record<ReportVerdict, string> = {
  fired: 'Caught',
  silent: 'Missed',
  no_logs: 'No data',
}

export const verdictLabel = (verdict: ReportVerdict, plain: boolean): string =>
  (plain ? VERDICT_LABEL_PLAIN : VERDICT_LABEL)[verdict] ?? verdict

/** Text colour per verdict. Silent is the one that needs acting on. */
export const verdictClass: Record<ReportVerdict, string> = {
  fired: 'text-safe',
  silent: 'text-danger',
  no_logs: 'text-content-dim',
}

const CHANGE_LABEL: Record<VerdictChangeKind, string> = {
  regressed: 'Regressed',
  improved: 'Improved',
  changed: 'Changed',
  unchanged: 'Unchanged',
  added: 'New rule',
  removed: 'Rule gone',
}

const CHANGE_CLASS: Record<VerdictChangeKind, string> = {
  regressed: 'text-danger',
  improved: 'text-safe',
  changed: 'text-warning',
  unchanged: 'text-content-dim',
  added: 'text-accent-blue',
  removed: 'text-content-dim',
}

export const changeLabel = (kind: VerdictChangeKind): string => CHANGE_LABEL[kind] ?? kind
export const changeClass = (kind: VerdictChangeKind): string => CHANGE_CLASS[kind] ?? ''

/** A verdict rendered as a word in its own colour — never a bare dot. */
export function VerdictText({
  verdict,
  plain,
}: {
  verdict: ReportVerdict | null
  plain: boolean
}) {
  if (!verdict) return <span className="text-content-muted">—</span>
  return (
    <span className={`font-mono text-2xs uppercase tracking-label ${verdictClass[verdict]}`}>
      {verdictLabel(verdict, plain)}
    </span>
  )
}

/** Percentage from a 0..1 share, or an em dash when nothing was judged. */
export const pct = (value: number | null | undefined): string =>
  value === null || value === undefined ? '—' : `${Math.round(value * 100)}%`

/** Signed point delta, e.g. "−9 pts" / "+4 pts". */
export const deltaPoints = (value: number | null | undefined): string => {
  if (value === null || value === undefined) return '—'
  const points = Math.round(value * 100)
  if (points === 0) return 'no change'
  return `${points > 0 ? '+' : '−'}${Math.abs(points)} pts`
}

export const stamp = (iso: string | null | undefined): string => {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

/** A labelled block in the report's spec column. */
export function Spec({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5 border-b border-border last:border-b-0">
      <span className="font-mono text-2xs uppercase tracking-label text-content-dim shrink-0">
        {label}
      </span>
      <span className="text-[0.82rem] text-content-primary text-right min-w-0 break-words">
        {children}
      </span>
    </div>
  )
}

/** Section heading with more air above than below, and an optional count. */
export function SectionHead({ title, note }: { title: string; note?: string }) {
  return (
    <div className="flex items-baseline gap-3 mt-9 mb-3 pb-1.5 border-b border-border first:mt-0">
      <h2 className="font-display text-[0.95rem] font-semibold text-content-primary">{title}</h2>
      {note && (
        <span className="font-mono text-2xs uppercase tracking-label text-content-dim ml-auto">
          {note}
        </span>
      )}
    </div>
  )
}
