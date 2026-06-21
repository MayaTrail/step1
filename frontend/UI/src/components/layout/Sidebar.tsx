import { Link, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { platformRegistry, platformShortLabel } from '@/data'
import { PlatformIcon } from '@/components/ui/PlatformIcons'
import {
  IconHome,
  IconLayers,
  IconActivity,
  IconClock,
  IconFlask,
  IconSearch,
  IconClipboard,
  IconShield,
  IconBarChart,
  IconGear,
  IconBook,
} from '@/components/ui/Icons'

interface SidebarProps {
  isOpen: boolean
  onClose: () => void
}

/**
 * Workflow-first navigation sidebar.
 *
 * Replaces the previous platform-first accordion (AWS > Emulations/Playbooks/…)
 * with content hubs grouped by user goal: Operations, Security Content,
 * Platforms, and Administration. Each content type now lives in exactly one
 * place; platforms become discovery entry points rather than containers.
 */
export function Sidebar({ isOpen }: SidebarProps) {
  return (
    <aside className={`
      w-[240px] bg-surface-base border-r border-border overflow-y-auto shrink-0 py-4
      fixed top-[58px] bottom-0 left-0 z-[150] transition-transform duration-200 ease-in-out
      lg:static lg:top-auto lg:bottom-auto lg:z-auto lg:translate-x-0
      ${isOpen ? 'translate-x-0' : '-translate-x-full'}
    `}>

      {/* ── Dashboard ── */}
      <SectionLabel>Dashboard</SectionLabel>
      <NavItem to="/" exact icon={<IconHome size={17} />} label="Dashboard" />
      <NavItem to="/stacks" icon={<IconLayers size={17} />} label="Stacks" />

      <Spacer />

      {/* ── Operations ── */}
      <SectionLabel>Operations</SectionLabel>
      <NavItem to="/runs" icon={<IconActivity size={17} />} label="Active Runs" />
      <NavItem to="/results" icon={<IconClock size={17} />} label="Results" />

      <Spacer />

      {/* ── Security Content ── */}
      <SectionLabel>Security Content</SectionLabel>
      <NavItem to="/emulations" icon={<IconFlask size={17} />} label="Emulations" />
      <NavItem to="/detections" icon={<IconSearch size={17} />} label="Detections" />
      <NavItem to="/playbooks" icon={<IconClipboard size={17} />} label="Playbooks" />
      <NavItem to="/guardrails" icon={<IconShield size={17} />} label="Guardrails" />

      <Spacer />

      {/* ── Platforms ── */}
      <SectionLabel>Platforms</SectionLabel>
      {platformRegistry.map((platform) => (
        <NavItem
          key={platform.id}
          to={`/platforms/${platform.route}`}
          icon={<PlatformIcon platformId={platform.id} size={17} className="shrink-0" />}
          label={platformShortLabel(platform.id)}
          badge={platform.badgeCount}
        />
      ))}

      <Spacer />

      {/* ── Administration ── */}
      <SectionLabel>Administration</SectionLabel>
      <NavItem to="/reports" icon={<IconBarChart size={17} />} label="Reports" />
      <NavItem to="/settings" icon={<IconGear size={17} />} label="Settings" />
      <NavItem to="/docs" icon={<IconBook size={17} />} label="Documentation" />
    </aside>
  )
}

function Spacer() {
  return <div className="h-3" />
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="font-mono text-[9px] font-bold tracking-[2px] text-content-dim px-5 pb-2 pt-1 uppercase">
      {children}
    </div>
  )
}

interface NavItemProps {
  to: string
  icon: ReactNode
  label: string
  /** Match only on exact pathname (used for the "/" dashboard route). */
  exact?: boolean
  /** Override the active-match prefix (e.g. a platform route covering nested pages). */
  matchPrefix?: string
  /** Optional right-aligned count badge. */
  badge?: number
}

/**
 * A single sidebar link with a consistent active treatment: a left accent rail
 * in Raycast Blue (the design system's "selected item" color) plus a faint
 * blue surface tint. Hover uses the standard card surface, never a color swap.
 */
function NavItem({ to, icon, label, exact, matchPrefix, badge }: NavItemProps) {
  const location = useLocation()
  const prefix = matchPrefix ?? to
  const active = exact
    ? location.pathname === to
    : location.pathname === prefix || location.pathname.startsWith(`${prefix}/`)

  return (
    <Link
      to={to}
      className={`flex items-center gap-2.5 px-4 py-2 cursor-pointer transition-all duration-150
        border-l-2 text-[13px] font-medium no-underline
        ${active
          ? 'text-content-primary border-l-accent-blue bg-accent-blue/[0.06]'
          : 'text-content-secondary border-l-transparent hover:bg-surface-card hover:text-content-primary'
        }`}
    >
      <span className={active ? 'text-accent-blue' : 'text-content-dim'}>{icon}</span>
      <span>{label}</span>
      {badge != null && (
        <span className="ml-auto bg-surface-elevated rounded-[3px] px-[5px] py-px font-mono text-[9px] text-content-dim">
          {badge}
        </span>
      )}
    </Link>
  )
}
