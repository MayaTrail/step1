import { useCallback, useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { platformRegistry, platformShortLabel } from '@/data'
import { useThreatFeed } from '@/hooks/useThreatFeed'
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
  IconBroadcast,
  IconLaunch,
  IconChevron,
} from '@/components/ui/Icons'

interface SidebarProps {
  isOpen: boolean
  onClose: () => void
}

/** Width when collapsed to an icon rail, and when open. */
const RAIL_WIDTH = 'w-[60px]'
const FULL_WIDTH = 'w-[240px]'

const COLLAPSED_KEY = 'mayatrail.sidebar.collapsed'
const SECTIONS_KEY = 'mayatrail.sidebar.closedSections'

/**
 * Read a persisted preference, tolerating a browser that refuses storage.
 *
 * Private windows and "block site data" make localStorage throw on access
 * rather than return null, so every read is guarded and falls back to the
 * default rather than failing the render.
 *
 * @param key - Storage key.
 * @param fallback - Value to use when nothing is stored or storage is unusable.
 * @returns The parsed value, or the fallback.
 */
function readStored<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key)
    return raw === null ? fallback : (JSON.parse(raw) as T)
  } catch {
    return fallback
  }
}

/**
 * Persist a preference, ignoring a browser that refuses storage.
 *
 * @param key - Storage key.
 * @param value - Value to store.
 */
function writeStored(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // A remembered sidebar is a convenience, never a requirement.
  }
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
  /*
   * The feed's own count, not the activity bell's. Feed items are content the
   * platform fetched; the bell reports the reader's own runs finishing. Two
   * different questions, so they get two different places rather than one
   * badge meaning either.
   */
  const { data: feed } = useThreatFeed({ limit: 1 })
  const feedCount = feed?.newSinceLastRun ?? 0

  const [collapsed, setCollapsed] = useState(() => readStored(COLLAPSED_KEY, false))
  const [closedSections, setClosedSections] = useState<string[]>(
    () => readStored<string[]>(SECTIONS_KEY, []),
  )

  useEffect(() => { writeStored(COLLAPSED_KEY, collapsed) }, [collapsed])
  useEffect(() => { writeStored(SECTIONS_KEY, closedSections) }, [closedSections])

  const toggleSection = useCallback((name: string) => {
    setClosedSections((current) =>
      current.includes(name)
        ? current.filter((entry) => entry !== name)
        : [...current, name],
    )
  }, [])

  /*
   * A collapsed rail has no room for section headings, so its groups cannot be
   * collapsed either. Treating every section as open while collapsed keeps the
   * icons reachable rather than hiding them behind a heading that is not drawn.
   */
  const isClosed = (name: string) => !collapsed && closedSections.includes(name)

  return (
    <aside className={`
      ${collapsed ? RAIL_WIDTH : FULL_WIDTH}
      bg-surface-base border-r border-border overflow-y-auto overflow-x-hidden shrink-0 py-4
      flex flex-col
      fixed top-[58px] bottom-0 left-0 z-[150] transition-all duration-200 ease-in-out
      lg:static lg:top-auto lg:bottom-auto lg:z-auto lg:translate-x-0
      ${isOpen ? 'translate-x-0' : '-translate-x-full'}
    `}>

      {/* ── Dashboard ── */}
      <SectionLabel
        name="Dashboard"
        collapsed={collapsed}
        closed={isClosed('Dashboard')}
        onToggle={toggleSection}
      />
      {!isClosed('Dashboard') && (
        <>
        <NavItem to="/" exact icon={<IconHome size={17} />} label="Dashboard" collapsed={collapsed} />
        <NavItem
          to="/threat-feed"
          icon={<IconBroadcast size={17} />}
          label="Threat Feed"
          count={feedCount}
          collapsed={collapsed}
        />
        <NavItem to="/stacks" icon={<IconLayers size={17} />} label="Stacks" collapsed={collapsed} />
        </>
      )}

      <Spacer />

      {/* ── Operations ── */}
      <SectionLabel
        name="Operations"
        collapsed={collapsed}
        closed={isClosed('Operations')}
        onToggle={toggleSection}
      />
      {!isClosed('Operations') && (
        <>
        <NavItem to="/workflows" icon={<IconLaunch size={17} />} label="Workflows" collapsed={collapsed} />
        <NavItem to="/runs" icon={<IconActivity size={17} />} label="Active Runs" collapsed={collapsed} />
        <NavItem to="/results" icon={<IconClock size={17} />} label="Results" collapsed={collapsed} />
        </>
      )}

      <Spacer />

      {/* ── Security Content ── */}
      <SectionLabel
        name="Security Content"
        collapsed={collapsed}
        closed={isClosed('Security Content')}
        onToggle={toggleSection}
      />
      {!isClosed('Security Content') && (
        <>
        <NavItem to="/emulations" icon={<IconFlask size={17} />} label="Emulations" collapsed={collapsed} />
        <NavItem to="/detections" icon={<IconSearch size={17} />} label="Detections" collapsed={collapsed} />
        <NavItem to="/playbooks" icon={<IconClipboard size={17} />} label="Playbooks" collapsed={collapsed} />
        <NavItem to="/guardrails" icon={<IconShield size={17} />} label="Guardrails" collapsed={collapsed} />
        </>
      )}

      <Spacer />

      {/* ── Platforms ── */}
      <SectionLabel
        name="Platforms"
        collapsed={collapsed}
        closed={isClosed('Platforms')}
        onToggle={toggleSection}
      />
      {!isClosed('Platforms') && platformRegistry.map((platform) => (
        <NavItem
          key={platform.id}
          to={`/platforms/${platform.route}`}
          icon={<PlatformIcon platformId={platform.id} size={17} className="shrink-0" />}
          label={platformShortLabel(platform.id)}
          collapsed={collapsed}
        />
      ))}

      <Spacer />

      {/* ── Administration ── */}
      <SectionLabel
        name="Administration"
        collapsed={collapsed}
        closed={isClosed('Administration')}
        onToggle={toggleSection}
      />
      {!isClosed('Administration') && (
        <>
        <NavItem to="/reports" icon={<IconBarChart size={17} />} label="Reports" collapsed={collapsed} />
        <NavItem to="/settings" icon={<IconGear size={17} />} label="Settings" collapsed={collapsed} />
        <NavItem to="/docs" icon={<IconBook size={17} />} label="Documentation" collapsed={collapsed} />
        </>
      )}

      <CollapseToggle collapsed={collapsed} onToggle={() => setCollapsed((v) => !v)} />
    </aside>
  )
}

function Spacer() {
  return <div className="h-3" />
}

interface SectionLabelProps {
  name: string
  collapsed: boolean
  closed: boolean
  onToggle: (name: string) => void
}

/**
 * A group heading that folds its own section away.
 *
 * On a collapsed rail it renders a hairline instead of a word, because a
 * two-pixel-per-letter heading is noise and the section cannot be folded there
 * anyway.
 */
function SectionLabel({ name, collapsed, closed, onToggle }: SectionLabelProps) {
  if (collapsed) {
    return <div className="mx-4 my-2 h-px bg-border" aria-hidden="true" />
  }

  return (
    <button
      type="button"
      onClick={() => onToggle(name)}
      aria-expanded={!closed}
      className="w-full flex items-center gap-1.5 px-5 pb-2 pt-1 bg-transparent border-none
        cursor-pointer font-mono text-[9px] font-bold tracking-[2px] uppercase text-content-dim
        transition-opacity hover:opacity-60"
    >
      <span>{name}</span>
      <span
        aria-hidden="true"
        className={`ml-auto transition-transform duration-150 ${closed ? '' : 'rotate-90'}`}
      >
        <IconChevron size={11} />
      </span>
    </button>
  )
}

/**
 * Fold the whole sidebar down to an icon rail.
 *
 * Pinned to the bottom so it never sits between a heading and its links, and
 * kept out of the scrolling group list so it is reachable however long the
 * navigation grows.
 */
function CollapseToggle({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      className="mt-auto mx-3 mb-1 flex items-center gap-2.5 px-2 py-2 rounded-btn
        bg-transparent border-none cursor-pointer text-content-dim
        transition-opacity hover:opacity-60"
    >
      <span className={`shrink-0 transition-transform duration-200 ${collapsed ? '' : 'rotate-180'}`}>
        <IconChevron size={15} />
      </span>
      {!collapsed && <span className="text-[12px] font-medium">Collapse</span>}
    </button>
  )
}

interface NavItemProps {
  to: string
  icon: ReactNode
  label: string
  /** Rendered after the label when above zero, for example "Threat Feed 12". */
  count?: number
  /** On the icon rail the label is dropped and becomes the tooltip. */
  collapsed?: boolean
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
function NavItem({ to, icon, label, count = 0, exact, matchPrefix, collapsed = false }: NavItemProps) {
  const location = useLocation()
  const prefix = matchPrefix ?? to
  const active = exact
    ? location.pathname === to
    : location.pathname === prefix || location.pathname.startsWith(`${prefix}/`)

  return (
    <Link
      to={to}
      title={collapsed ? label : undefined}
      className={`relative flex items-center gap-2.5 py-2 cursor-pointer transition-all duration-150
        border-l-2 text-[13px] font-medium no-underline
        ${collapsed ? 'px-0 justify-center' : 'px-4'}
        ${active
          ? 'text-content-primary border-l-accent-blue bg-accent-blue/[0.06]'
          : 'text-content-secondary border-l-transparent hover:bg-surface-card hover:text-content-primary'
        }`}
    >
      <span className={`shrink-0 ${active ? 'text-accent-blue' : 'text-content-dim'}`}>{icon}</span>
      {!collapsed && <span className="truncate">{label}</span>}

      {/* On the rail there is no label to sit beside, so the count becomes a
          dot: the exact number is unreadable at that width anyway. */}
      {count > 0 && (collapsed ? (
        <span
          aria-hidden="true"
          className="absolute top-1.5 right-2.5 w-1.5 h-1.5 rounded-full bg-accent-blue"
        />
      ) : (
        <span className="ml-auto shrink-0 font-mono text-[10px] text-accent-blue">
          {count > 99 ? '99+' : count}
        </span>
      ))}
    </Link>
  )
}
