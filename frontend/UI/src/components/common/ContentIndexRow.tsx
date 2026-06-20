import { Link } from 'react-router-dom'
import { IconChevron } from '@/components/ui/Icons'

interface ContentIndexRowProps {
  /** Destination route — typically a per-emulation scoped page. */
  to: string
  /** Primary label, e.g. the emulation name. */
  title: string
  /** Optional secondary line, e.g. tags or origin. */
  subtitle?: string
  /** Optional right-aligned mono badge, e.g. "SIGMA + KQL". */
  badge?: string
}

/**
 * One row in an index-style content hub (Detections, Playbooks).
 *
 * Detections and playbooks remain authored per emulation; these hubs are a
 * discovery layer that links into the existing scoped pages rather than
 * duplicating the underlying content.
 */
export function ContentIndexRow({ to, title, subtitle, badge }: ContentIndexRowProps) {
  return (
    <Link
      to={to}
      className="group flex items-center gap-4 bg-surface-card border border-border rounded-card px-5 py-4
        no-underline transition-all duration-150
        hover:border-border-active hover:bg-white/[0.02]"
    >
      <div className="flex-1 min-w-0">
        <div className="font-display text-[0.95rem] font-semibold text-content-primary truncate">{title}</div>
        {subtitle && <div className="text-xs text-content-dim mt-0.5 truncate">{subtitle}</div>}
      </div>
      {badge && (
        <span className="shrink-0 font-mono text-[10px] tracking-[0.5px] text-content-secondary
          bg-surface-elevated border border-border rounded px-2 py-1">
          {badge}
        </span>
      )}
      <IconChevron size={16} className="shrink-0 text-content-dim transition-colors group-hover:text-content-secondary" />
    </Link>
  )
}
