import { useState, useRef, useEffect, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import mayatrailLogo from '@/assets/mayatrail-logo.svg'
import { NotificationBell } from './NotificationBell'

interface TopNavProps {
  onOpenSearch: () => void
  onToggleSidebar: () => void
}

export function TopNav({ onOpenSearch, onToggleSidebar }: TopNavProps) {
  const { user, logout } = useAuth()
  // The single fact the avatar reports. is_verified is set only when an STS
  // AssumeRole against the user's role ARN succeeds, and cleared on disconnect,
  // so it means exactly "a cloud account is connected".
  const connected = Boolean(user?.isVerified)
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false)
      }
    }
    if (dropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [dropdownOpen])

  return (
    <nav className="h-[58px] backdrop-blur-[20px] bg-[rgba(7,8,12,0.8)] border-b border-border flex items-center px-5 gap-3 shrink-0 relative z-[100]">

      {/* Left group. Shares free space equally with the right group, which is
          what actually centres the search between them: the two have different
          content widths (a logo against a bell plus an account chip), so
          centring the search inside the gap left it noticeably off-centre. */}
      <div className="flex items-center gap-3 flex-1">

        {/* Logo — danger gradient matching frontend */}
        <Link to="/" className="flex items-center gap-2.5 no-underline group shrink-0">
          <img
            src={mayatrailLogo}
            alt="MayaTrail"
            className="w-9 h-9 rounded-lg object-cover transition-all group-hover:shadow-[0_0_20px_rgba(255,34,68,0.3)]"
          />
          <span className="font-display text-[1.3rem] font-extrabold text-content-primary tracking-[-0.5px]">
            MayaTrail
          </span>
        </Link>

        {/* Hamburger — mobile only, toggles the sidebar overlay */}
        <button
          onClick={onToggleSidebar}
          className="lg:hidden flex items-center justify-center w-8 h-8 shrink-0 text-content-dim hover:text-content-primary rounded-btn hover:bg-surface-elevated transition-colors"
          aria-label="Toggle navigation"
        >
          <svg width="16" height="12" viewBox="0 0 16 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
            <line x1="0" y1="1" x2="16" y2="1" />
            <line x1="0" y1="6" x2="16" y2="6" />
            <line x1="0" y1="11" x2="16" y2="11" />
          </svg>
        </button>
      </div>

      {/* Search trigger, hidden on small screens to preserve space. Styled as
          the DESIGN.md input (page colour, hairline border) and names what it
          searches, since a bare "Search..." gave no hint of its scope.
          min-w-0 lets it give way first on a narrow window, so the logo and the
          account chip keep their full width instead of being clipped. */}
      <button
        type="button"
        onClick={onOpenSearch}
        className="hidden md:flex w-full max-w-md min-w-0 items-center gap-2.5 h-9 pl-3 pr-2 rounded-btn
          bg-surface-deep border border-border-active text-left cursor-pointer transition-opacity hover:opacity-60"
      >
        <svg
          className="w-4 h-4 shrink-0 text-content-dim"
          viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"
        >
          <circle cx="11" cy="11" r="7" />
          <path d="m21 21-4.3-4.3" />
        </svg>
        <span className="flex-1 truncate text-sm text-content-muted">Search emulations, detections, playbooks</span>
        <span className="flex shrink-0 gap-1">
          <Key>&#8984;</Key>
          <Key>K</Key>
        </span>
      </button>

      {/* Right group. flex-1 with justify-end rather than ml-auto: an auto
          margin would eat the free space and push the search off centre again. */}
      <div className="flex items-center gap-2.5 flex-1 justify-end">

        {/* Threat Feed notifications */}
        <NotificationBell />

        {/* Account dropdown */}
        <div className="relative" ref={dropdownRef}>
          {/* No box: the avatar, first name and chevron are the control. The
              dot on the avatar is the one place connection status shows here;
              the menu spells it out. */}
          <button
            type="button"
            onClick={() => setDropdownOpen((v) => !v)}
            aria-expanded={dropdownOpen}
            className="flex items-center gap-2 rounded-pill bg-transparent border-none py-1 pl-1 pr-2
              text-sm text-content-secondary cursor-pointer transition-opacity hover:opacity-60"
          >
            <Avatar initials={user?.initials ?? 'U'} connected={connected} />
            <span className="hidden sm:inline">{user?.name?.split(' ')[0] ?? 'User'}</span>
            <svg className="w-2.5 h-2.5 text-content-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M6 9l6 6 6-6" />
            </svg>
          </button>

          {/* Dropdown menu */}
          {dropdownOpen && (
            <div className="absolute top-full right-0 mt-2 w-64 bg-surface-card border border-border rounded-card shadow-float z-[300] overflow-hidden animate-fadeIn">
              <div className="flex items-center gap-3 px-4 py-3.5 border-b border-border">
                <Avatar initials={user?.initials ?? 'U'} connected={connected} large />
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-content-primary">{user?.name ?? 'User'}</div>
                  <div className="truncate font-mono text-2xs text-content-muted">{user?.username ?? ''}</div>
                </div>
              </div>
              {/* Which status the avatar's dot reports, so it is never read as
                  whether the login itself is enabled. */}
              <div className={`mx-4 flex items-center gap-2 whitespace-nowrap border-b border-border py-2.5 text-xs
                ${connected ? 'text-safe' : 'text-content-dim'}`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-safe' : 'bg-content-muted'}`} />
                {connected ? 'AWS account connected' : 'No cloud account yet'}
                {!connected && (
                  <button
                    type="button"
                    onClick={() => { setDropdownOpen(false); navigate('/me') }}
                    className="ml-auto bg-transparent border-none p-0 text-xs text-accent-blue cursor-pointer transition-opacity hover:opacity-60"
                  >
                    Connect AWS
                  </button>
                )}
              </div>
              <div className="py-1">
                <DropdownItem icon={<IconUser />} label="Profile" onClick={() => { setDropdownOpen(false); navigate('/me') }} />
                <DropdownItem icon={<IconGear />} label="Settings" onClick={() => { setDropdownOpen(false); navigate('/settings') }} />
                <DropdownItem icon={<IconKey />} label="API keys" onClick={() => setDropdownOpen(false)} />
                <DropdownItem icon={<IconUsers />} label="Team" onClick={() => setDropdownOpen(false)} />
              </div>
              <div className="h-px bg-border" />
              <div className="py-1">
                <DropdownItem
                  icon={<IconSignOut />}
                  label="Sign out"
                  className="text-danger"
                  onClick={() => {
                    setDropdownOpen(false)
                    logout()
                  }}
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </nav>
  )
}

/**
 * The user's initials in a raised circle, with a dot for cloud connection:
 * green when an AWS account is connected, grey when not. Not connected is a
 * normal starting state, so it is neutral rather than red.
 */
function Avatar({ initials, connected, large = false }: { initials: string; connected: boolean; large?: boolean }) {
  return (
    <span
      className={`relative flex shrink-0 items-center justify-center rounded-full bg-surface-elevated border border-border-active
        font-semibold text-content-primary ${large ? 'w-9 h-9 text-xs' : 'w-7 h-7 text-2xs'}`}
    >
      {initials}
      <span
        aria-hidden="true"
        className={`absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full ring-2 ring-surface-deep
          ${connected ? 'bg-safe' : 'bg-content-muted'}`}
      />
    </span>
  )
}

/** One keyboard key cap, in the DESIGN.md key gradient. */
function Key({ children }: { children: ReactNode }) {
  return (
    <kbd
      className="min-w-5 px-1.5 py-0.5 rounded text-center font-mono text-2xs text-content-secondary"
      style={KEY_STYLE}
    >
      {children}
    </kbd>
  )
}

const KEY_STYLE = {
  background: 'linear-gradient(180deg, #121212 0%, #0d0d0d 100%)',
  boxShadow: 'inset 0 1px 0 0 rgba(255,255,255,0.08), 0 1px 1px 0 rgba(0,0,0,0.4)',
}

function DropdownItem({
  icon,
  label,
  className = '',
  onClick,
}: {
  icon: ReactNode
  label: string
  className?: string
  onClick?: () => void
}) {
  return (
    <div
      onClick={onClick}
      className={`px-4 py-2.5 cursor-pointer text-sm flex items-center gap-2.5 transition-opacity hover:opacity-60
        ${className || 'text-content-secondary'}`}
    >
      <span className="shrink-0">{icon}</span>
      {label}
    </div>
  )
}

/* ── Inline SVG icons (no emoji, per the design system; all inherit currentColor) ── */

const MENU_ICON = 'w-4 h-4'

function IconUser() {
  return (
    <svg className={MENU_ICON} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21a8 8 0 0116 0" />
    </svg>
  )
}

function IconGear() {
  return (
    <svg className={MENU_ICON} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z" />
    </svg>
  )
}

function IconKey() {
  return (
    <svg className={MENU_ICON} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="7.5" cy="15.5" r="3.5" />
      <path d="M10 13l9-9M16 3l3 3-3 3" />
    </svg>
  )
}

function IconUsers() {
  return (
    <svg className={MENU_ICON} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2 21a7 7 0 0114 0M16 5a3.5 3.5 0 010 6.5M22 21a6 6 0 00-4-5.5" />
    </svg>
  )
}

function IconSignOut() {
  return (
    <svg className={MENU_ICON} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9" />
    </svg>
  )
}
