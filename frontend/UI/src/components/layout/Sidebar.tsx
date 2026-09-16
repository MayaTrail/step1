import { Link, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { platformRegistry, platformShortLabel } from '@/data'
import { PlatformIcon } from '@/components/ui/PlatformIcons'
import { useUiMode } from '@/context/UiModeContext'
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
 *
 * Two shapes, chosen by the global UI mode:
 *
 * - **Classic** — the flat list of ~13 links under five section labels. Every
 *   destination is visible at all times. Unchanged, byte-for-byte, so the
 *   Technical/Simple switch is a true rollback.
 * - **Simple** — the collapsed IA: five top-level groups (Overview · Run ·
 *   Coverage · Library · Settings), each of which expands its children only
 *   when you are inside it. Same destinations, a fifth of the resting choices,
 *   and plain-language labels throughout.
 *
 * The footer toggle flips the whole app (dashboard, nav, coverage report).
 */
export function Sidebar({ isOpen }: SidebarProps) {
  const { plain } = useUiMode()

  return (
    <aside className={`
      w-[240px] bg-surface-base border-r border-border overflow-y-auto shrink-0 py-4
      flex flex-col
      fixed top-[58px] bottom-0 left-0 z-[150] transition-transform duration-200 ease-in-out
      lg:static lg:top-auto lg:bottom-auto lg:z-auto lg:translate-x-0
      ${isOpen ? 'translate-x-0' : '-translate-x-full'}
    `}>

      <nav className="flex-1">{plain ? <SimpleNav /> : <ClassicNav />}</nav>

      <ModeToggle />
    </aside>
  )
}

/** The original flat navigation — every link visible, engineer-facing labels. */
function ClassicNav() {
  return (
    <>
      {/* ── Dashboard ── */}
      <SectionLabel>Dashboard</SectionLabel>
      <NavItem to="/" exact icon={<IconHome size={17} />} label="Dashboard" />
      <NavItem to="/stacks" icon={<IconLayers size={17} />} label="Stacks" />

      <Spacer />

      {/* ── Operations ── */}
      <SectionLabel>Operations</SectionLabel>
      <NavItem to="/runs" icon={<IconActivity size={17} />} label="Active Runs" />
      <NavItem to="/results" icon={<IconClock size={17} />} label="Results" />
      <NavItem to="/schedules" icon={<IconActivity size={17} />} label="Schedules" />

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
        />
      ))}

      <Spacer />

      {/* ── Administration ── */}
      <SectionLabel>Administration</SectionLabel>
      <NavItem to="/reports" icon={<IconBarChart size={17} />} label="Reports" />
      <NavItem to="/settings" icon={<IconGear size={17} />} label="Settings" />
      <NavItem to="/docs" icon={<IconBook size={17} />} label="Documentation" />
    </>
  )
}

interface NavGroup {
  label: string
  icon: ReactNode
  /** Where the group header itself navigates. */
  to: string
  children: { to: string; label: string; icon?: ReactNode; exact?: boolean }[]
  /**
   * Extra path prefixes that belong to this group but are not one of its
   * links — e.g. `/aws/emulations/...` detail pages belong under Library.
   */
  alsoMatches?: string[]
}

/**
 * The collapsed IA: five groups instead of thirteen links.
 *
 * A group's children appear only while you are inside that group, so the
 * resting sidebar is five rows. Nothing was dropped — every Classic
 * destination lives under exactly one group, including the per-platform pages
 * (under Coverage) and the deep emulation routes (under Library).
 */
function SimpleNav() {
  const location = useLocation()

  const groups: NavGroup[] = [
    {
      label: 'Overview',
      icon: <IconHome size={17} />,
      to: '/',
      children: [
        { to: '/', label: 'Home', exact: true },
        { to: '/stacks', label: 'Cloud stacks' },
      ],
    },
    {
      label: 'Run',
      icon: <IconActivity size={17} />,
      to: '/runs',
      children: [
        { to: '/runs', label: 'Running now' },
        { to: '/results', label: 'Test results' },
        { to: '/schedules', label: 'Scheduled tests' },
      ],
    },
    {
      label: 'Coverage',
      icon: <IconBarChart size={17} />,
      to: '/reports',
      children: [
        { to: '/reports', label: 'Coverage reports' },
        ...platformRegistry.map((platform) => ({
          to: `/platforms/${platform.route}`,
          label: platformShortLabel(platform.id),
          icon: <PlatformIcon platformId={platform.id} size={14} className="shrink-0" />,
        })),
      ],
    },
    {
      label: 'Library',
      icon: <IconFlask size={17} />,
      to: '/emulations',
      children: [
        { to: '/emulations', label: 'Attack simulations' },
        { to: '/detections', label: 'Detection rules' },
        { to: '/playbooks', label: 'Response playbooks' },
        { to: '/guardrails', label: 'Safety limits' },
      ],
      // Deep platform-scoped content routes: /aws/emulations/…, /aws/guardrails/…
      alsoMatches: platformRegistry.flatMap((platform) => [
        `/${platform.route}/emulations`,
        `/${platform.route}/guardrails`,
      ]),
    },
    {
      label: 'Settings',
      icon: <IconGear size={17} />,
      to: '/settings',
      children: [
        { to: '/settings', label: 'Settings' },
        { to: '/me', label: 'Your profile' },
        { to: '/docs', label: 'Help & docs' },
      ],
    },
  ]

  const matches = (prefix: string, exact = false) =>
    exact
      ? location.pathname === prefix
      : location.pathname === prefix || location.pathname.startsWith(`${prefix}/`)

  return (
    <div className="flex flex-col gap-0.5">
      {groups.map((group) => {
        // "/" would prefix-match everything, so Overview opens only on an exact
        // match of one of its own children.
        const open =
          group.children.some((child) => matches(child.to, child.exact || child.to === '/')) ||
          (group.alsoMatches ?? []).some((prefix) => matches(prefix))

        return (
          <div key={group.label}>
            <GroupHeader group={group} open={open} />
            {open && (
              <div className="pb-1">
                {group.children.map((child) => (
                  <SubItem
                    key={child.to}
                    to={child.to}
                    label={child.label}
                    icon={child.icon}
                    active={matches(child.to, child.exact)}
                  />
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

function GroupHeader({ group, open }: { group: NavGroup; open: boolean }) {
  return (
    <Link
      to={group.to}
      className={`flex items-center gap-2.5 px-4 py-2.5 cursor-pointer transition-all duration-150
        border-l-2 text-[13px] font-semibold no-underline
        ${open
          ? 'text-content-primary border-l-accent-blue bg-accent-blue/[0.06]'
          : 'text-content-secondary border-l-transparent hover:bg-surface-card hover:text-content-primary'
        }`}
    >
      <span className={open ? 'text-accent-blue' : 'text-content-dim'}>{group.icon}</span>
      <span>{group.label}</span>
    </Link>
  )
}

function SubItem({
  to,
  label,
  icon,
  active,
}: {
  to: string
  label: string
  icon?: ReactNode
  active: boolean
}) {
  return (
    <Link
      to={to}
      className={`flex items-center gap-2 py-1.5 pl-[42px] pr-4 cursor-pointer transition-colors duration-150
        text-[12.5px] no-underline
        ${active
          ? 'text-accent-blue font-medium'
          : 'text-content-dim hover:text-content-primary'
        }`}
    >
      {icon}
      <span>{label}</span>
    </Link>
  )
}

/**
 * The single global Classic / Simple switch, pinned to the sidebar footer.
 * Classic = original technical surface; Simple = plain-language experience.
 * Flips dashboard, nav labels, and the coverage report together, and is the
 * one control that rolls the whole thing back.
 */
function ModeToggle() {
  const { mode, setMode } = useUiMode()
  return (
    <div className="mt-3 px-3 pt-3 border-t border-border">
      <div className="font-mono text-[9px] font-bold tracking-[2px] text-content-dim px-2 pb-1.5 uppercase">
        Language
      </div>
      <div className="inline-flex w-full rounded-btn border border-border bg-surface-deep p-0.5">
        {(['classic', 'new'] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            className={`flex-1 px-2 py-1.5 rounded-btn text-[11px] font-medium transition-colors ${
              mode === m
                ? 'bg-surface-elevated text-content-primary'
                : 'text-content-dim hover:text-content-secondary'
            }`}
          >
            {m === 'classic' ? 'Technical' : 'Simple'}
          </button>
        ))}
      </div>
    </div>
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
}

/**
 * A single sidebar link with a consistent active treatment: a left accent rail
 * in Raycast Blue (the design system's "selected item" color) plus a faint
 * blue surface tint. Hover uses the standard card surface, never a color swap.
 */
function NavItem({ to, icon, label, exact, matchPrefix }: NavItemProps) {
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
    </Link>
  )
}
