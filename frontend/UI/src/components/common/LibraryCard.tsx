import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { Severity } from '@/types'

export interface CardAction {
  label: string
  /** Icon shown before the label. */
  icon?: ReactNode
  /** Router destination (renders a Link). */
  to?: string
  /** Click handler (renders a button). Ignored when `to` is set. */
  onClick?: () => void
  /** Emphasis: primary = red accent (Run), secondary = bordered (View). */
  variant?: 'primary' | 'secondary'
}

interface LibraryCardProps {
  name: string
  /** Mono eyebrow text in the top band, e.g. "APT Emulation · AWS". */
  eyebrow?: string
  /** Severity — colors the band gradient, eyebrow, and status dot. */
  severity?: Severity
  description?: string
  /** MITRE tactic chips. */
  tactics?: string[]
  /** One or two footer buttons (e.g. View + Run). */
  actions: CardAction[]
}

/** Per-severity accent: gradient, text, dot, and dot glow. */
const SEV_ACCENT: Record<Severity, { band: string; text: string; dot: string; glow: string }> = {
  CRITICAL: { band: 'from-danger/[0.08]',      text: 'text-danger',      dot: 'bg-danger',      glow: 'shadow-[0_0_8px_rgba(255,99,99,0.55)]' },
  HIGH:     { band: 'from-warning/[0.08]',     text: 'text-warning',     dot: 'bg-warning',     glow: 'shadow-[0_0_8px_rgba(255,188,51,0.5)]' },
  MEDIUM:   { band: 'from-accent-blue/[0.08]', text: 'text-accent-blue', dot: 'bg-accent-blue', glow: 'shadow-[0_0_8px_rgba(85,179,255,0.45)]' },
  LOW:      { band: 'from-white/[0.04]',       text: 'text-content-dim', dot: 'bg-content-dim', glow: '' },
}

/** Max tactic chips before collapsing into "+N". */
const MAX_TACTICS = 4

/**
 * Threat-intel library card (Option C) used by the Emulations / Detections /
 * Playbooks hubs.
 *
 * A severity-tinted top band (eyebrow + status dot) sits over the name,
 * description, MITRE tactic chips, and one or two footer actions. The band and
 * dot are the only severity-colored elements, keeping Raycast Red as
 * punctuation per the design system.
 */
export function LibraryCard({ name, eyebrow, severity, description, tactics, actions }: LibraryCardProps) {
  const accent = severity ? SEV_ACCENT[severity] : null
  const shown = tactics?.slice(0, MAX_TACTICS) ?? []
  const extra = tactics && tactics.length > MAX_TACTICS ? tactics.length - MAX_TACTICS : 0

  return (
    <div className="flex flex-col min-h-[250px] bg-surface-card border border-border rounded-card shadow-ring
      overflow-hidden transition-colors hover:border-border-active">
      {/* Top band */}
      <div className={`flex items-center justify-between gap-3 px-[18px] py-2.5 border-b border-border
        bg-gradient-to-r ${accent?.band ?? 'from-white/[0.03]'} to-transparent`}>
        <span className={`font-mono text-[9px] tracking-[1.5px] uppercase font-medium truncate ${accent?.text ?? 'text-content-dim'}`}>
          {eyebrow}
        </span>
        {severity && accent && (
          <span className="flex items-center gap-2 shrink-0">
            <span className={`font-mono text-[9px] font-bold tracking-[1px] ${accent.text}`}>{severity}</span>
            <span className={`w-2 h-2 rounded-full ${accent.dot} ${accent.glow}`} />
          </span>
        )}
      </div>

      {/* Body */}
      <div className="flex flex-col flex-1 p-[18px]">
        <div className="font-display text-[1.05rem] font-bold text-content-primary leading-snug mb-2">{name}</div>

        {description && (
          <p className="text-sm text-content-secondary leading-relaxed line-clamp-3">{description}</p>
        )}

        {shown.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-3">
            {shown.map((t) => (
              <span key={t} className="font-mono text-[10px] text-accent-blue bg-accent-blue/[0.08] border border-accent-blue/20 rounded-md px-2 py-[3px]">
                {t}
              </span>
            ))}
            {extra > 0 && <span className="font-mono text-[10px] text-content-dim px-1 py-[3px]">+{extra}</span>}
          </div>
        )}

        {/* Footer actions */}
        <div className={`mt-auto pt-4 grid gap-2 ${actions.length === 2 ? 'grid-cols-2' : 'grid-cols-1'}`}>
          {actions.map((a) => (
            <CardActionButton key={a.label} action={a} />
          ))}
        </div>
      </div>
    </div>
  )
}

function CardActionButton({ action }: { action: CardAction }) {
  const base =
    'inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-lg text-[13px] font-semibold no-underline transition-all whitespace-nowrap'
  const variant =
    action.variant === 'primary'
      ? 'bg-danger/[0.12] border border-danger/30 text-danger hover:bg-danger/[0.18]'
      : 'border border-[rgba(255,255,255,0.12)] text-content-primary hover:opacity-60'
  const className = `${base} ${variant}`

  if (action.to) {
    return (
      <Link to={action.to} className={className}>
        {action.icon}
        {action.label}
      </Link>
    )
  }
  return (
    <button onClick={action.onClick} className={className}>
      {action.icon}
      {action.label}
    </button>
  )
}
