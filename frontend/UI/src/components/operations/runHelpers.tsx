import type { ReactNode } from 'react'
import type { EmulationRunStatus } from '@/types'
import { IconSearch } from '@/components/ui/Icons'

/**
 * Shared presentation helpers for the Operations run tables (Active Runs and
 * Results). Keeping status colours, the progress bar, table shell, search box,
 * and filter chip here means both pages render identical, design-consistent
 * rows without duplicating markup.
 */

interface StatusMeta {
  label: string
  text: string
  bg: string
  dot: string
}

/** Status → label + colour. */
const RUN_STATUS_META: Record<EmulationRunStatus, StatusMeta> = {
  running:   { label: 'Running',   text: 'text-safe',    bg: 'bg-safe-dim',    dot: 'bg-safe' },
  pending:   { label: 'Pending',   text: 'text-warning', bg: 'bg-warning-dim', dot: 'bg-warning' },
  completed: { label: 'Completed', text: 'text-safe',    bg: 'bg-safe-dim',    dot: 'bg-safe' },
  failed:    { label: 'Failed',    text: 'text-danger',  bg: 'bg-danger-dim',  dot: 'bg-danger' },
}

/** Pill status badge; the running state pulses to read as "live". */
export function RunStatusBadge({ status }: { status: EmulationRunStatus }) {
  const meta = RUN_STATUS_META[status]
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[11px] font-medium ${meta.text} ${meta.bg}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${meta.dot} ${status === 'running' ? 'animate-pulse' : ''}`} />
      {meta.label}
    </span>
  )
}

/**
 * Phase progress bar. Failed runs show "-" (there's no meaningful progress to
 * report); everything else shows a percentage derived from phase_current/total.
 */
export function RunProgress({ current, total, status }: { current: number; total: number; status: EmulationRunStatus }) {
  if (status === 'failed') {
    return <span className="font-mono text-xs text-content-dim">-</span>
  }
  const pct = total > 0 ? Math.round((current / total) * 100) : 0
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-1.5 rounded-full bg-surface-elevated overflow-hidden">
        <div className="h-full bg-accent-blue rounded-full transition-all duration-300" style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-[11px] text-content-secondary tabular-nums">{pct}%</span>
    </div>
  )
}

/** Compact relative time, e.g. "3m ago". Returns an em dash for null. */
export function formatRelative(iso: string | null): string {
  if (!iso) return '—'
  const diffMs = Date.now() - new Date(iso).getTime()
  if (diffMs < 0) return 'just now'
  const s = Math.floor(diffMs / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

/**
 * Honest completion proxy for the Results "Completion" column — phases reached
 * out of total. This deliberately replaces a fabricated numeric "score": a real
 * security score (detections fired, attack-path coverage) needs computation the
 * backend does not yet do.
 */
export function formatCompletion(current: number, total: number): string {
  if (total <= 0) return '—'
  return `${current}/${total} phases`
}

/** Table shell with a mono uppercase header row matching the design system. */
export function RunsTable({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <div className="bg-surface-card border border-border rounded-card overflow-x-auto">
      <table className="w-full border-collapse min-w-[720px]">
        <thead>
          <tr className="border-b border-border">
            {headers.map((h) => (
              <th
                key={h}
                className="text-left font-mono text-[10px] uppercase tracking-[1px] text-content-dim font-semibold px-4 py-3 whitespace-nowrap"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

/** A single body row with the standard hover treatment. */
export function RunsRow({ children }: { children: ReactNode }) {
  return (
    <tr className="border-b border-border last:border-0 transition-colors hover:bg-white/[0.02]">
      {children}
    </tr>
  )
}

/** Standard body cell. */
export function RunsCell({ children, className = '', title }: { children: ReactNode; className?: string; title?: string }) {
  return <td title={title} className={`px-4 py-3.5 text-sm text-content-secondary align-middle ${className}`}>{children}</td>
}

/** Search input with a leading magnifier icon. */
export function RunsSearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative flex-1 min-w-[200px] max-w-sm">
      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-content-dim pointer-events-none">
        <IconSearch size={15} />
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-surface-base border border-border rounded-lg pl-9 pr-3 py-2 text-sm text-content-primary
          placeholder:text-content-dim outline-none transition-colors focus:border-border-active"
      />
    </div>
  )
}
