import { useState, useRef, useEffect, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { useTheme } from '@/context/ThemeContext'
import { useDemoCountdown, formatCountdown } from '@/hooks/useDemoCountdown'
import mayatrailLogo from '@/assets/mayatrail-logo.png'

interface TopNavProps {
  onOpenSearch: () => void
  onToggleSidebar: () => void
}

export function TopNav({ onOpenSearch, onToggleSidebar }: TopNavProps) {
  const { user, logout } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const { remaining, isExpired, isActive } = useDemoCountdown(
    user?.isDemo ? user.demoExpiresAt : null,
  )
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

      {/* Search trigger — hidden on small screens to preserve space */}
      <div
        className="hidden md:flex flex-1 max-w-[400px] mx-auto relative items-center cursor-pointer group"
        onClick={onOpenSearch}
      >
        <svg
          className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-content-dim pointer-events-none"
          viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
        >
          <circle cx="11" cy="11" r="7" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          readOnly
          placeholder="Search..."
          className="w-full bg-surface-elevated border border-border rounded-full py-2 pl-10 pr-14 text-content-primary font-mono text-xs outline-none cursor-pointer
            transition-colors group-hover:border-border-active
            placeholder:text-content-dim"
        />
        <kbd
          className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded text-[10px] font-mono text-content-secondary pointer-events-none"
          style={{
            background: 'linear-gradient(180deg, #121212 0%, #0d0d0d 100%)',
            boxShadow: 'inset 0 1px 0 0 rgba(255,255,255,0.08), 0 1px 1px 0 rgba(0,0,0,0.4)',
          }}
        >
          &#8984;K
        </kbd>
      </div>

      {/* Right section */}
      <div className="flex items-center gap-2.5 ml-auto">

        {/* Demo countdown — only rendered for demo users with an active timer; hidden on small screens */}
        {isActive && (
          <div
            className={`hidden sm:flex items-center gap-2 border rounded-full px-3.5 py-1.5 font-mono text-xs transition-all ${
              isExpired
                ? 'bg-danger/[0.08] border-danger/30 text-danger'
                : 'bg-[#ff8c00]/[0.08] border-[#ff8c00]/30 text-[#ff8c00]'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                isExpired ? 'bg-danger' : 'bg-[#ff8c00] animate-pulse'
              }`}
            />
            {isExpired
              ? 'Demo expired'
              : `${formatCountdown(remaining!)} left`}
          </div>
        )}

        {/* Theme toggle — icon-only, cycles light / dark / system */}
        <button
          onClick={toggleTheme}
          aria-label={`Theme: ${theme}`}
          title={`Theme: ${theme}`}
          className="hidden sm:flex w-9 h-9 items-center justify-center bg-surface-elevated border border-border rounded-full text-content-secondary
            cursor-pointer transition-all hover:border-border-active hover:text-content-primary"
        >
          {theme === 'light' ? <IconSun /> : theme === 'dark' ? <IconMoon /> : <IconMonitor />}
        </button>

        {/* Account dropdown */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setDropdownOpen((v) => !v)}
            className="bg-surface-elevated border border-border rounded-full pl-1 pr-3 py-1 text-content-primary font-display text-sm font-medium
              flex items-center gap-2 cursor-pointer transition-all hover:border-border-active"
          >
            {/* Avatar — a green ring marks an AWS-verified (IAM) identity, amber for demo. */}
            <div
              className={`w-[26px] h-[26px] rounded-full bg-surface-card flex items-center justify-center text-[11px] font-bold text-content-primary
                ${user?.isVerified ? 'ring-2 ring-safe/70' : user?.isDemo ? 'ring-2 ring-warning/70' : ''}`}
            >
              {user?.initials ?? 'U'}
            </div>
            <span className="hidden sm:inline">{user?.name?.split(' ')[0] ?? 'User'}</span>
            {user?.isVerified && (
              <span className="hidden md:inline font-mono text-[9px] font-semibold tracking-wider text-safe border border-safe/30 rounded px-1.5 py-0.5">
                IAM
              </span>
            )}
            {user?.isDemo && (
              <span className="hidden md:inline font-mono text-[9px] font-semibold tracking-wider text-warning border border-warning/30 rounded px-1.5 py-0.5">
                DEMO
              </span>
            )}
            <svg className="w-2.5 h-2.5 text-content-dim" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M6 9l6 6 6-6" />
            </svg>
          </button>

          {/* Dropdown menu */}
          {dropdownOpen && (
            <div className="absolute top-[calc(100%+8px)] right-0 bg-surface-card border border-border rounded-card w-[200px] shadow-[0_12px_40px_rgba(0,0,0,0.6)] z-[300] overflow-hidden animate-fadeIn">
              <div className="px-4 py-3.5 border-b border-border">
                <div className="text-sm font-bold text-content-primary">{user?.name ?? 'User'}</div>
                <div className="font-mono text-[10px] text-content-dim mt-0.5">{user?.username ?? ''}</div>
              </div>
              <div className="py-1">
                <DropdownItem icon={<IconUser />} label="Profile" onClick={() => { setDropdownOpen(false); navigate('/me') }} />
                <DropdownItem icon={<IconGear />} label="Settings" onClick={() => { setDropdownOpen(false); navigate('/settings') }} />
                <DropdownItem icon={<IconKey />} label="API Keys" onClick={() => setDropdownOpen(false)} />
                <DropdownItem icon={<IconUsers />} label="Team" onClick={() => setDropdownOpen(false)} />
              </div>
              <div className="h-px bg-border" />
              <div className="py-1">
                <DropdownItem
                  icon={<IconSignOut />}
                  label="Sign Out"
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
      className={`px-4 py-2.5 cursor-pointer text-sm text-content-secondary flex items-center gap-2.5
        transition-colors hover:bg-surface-elevated hover:text-content-primary ${className}`}
    >
      <span className="shrink-0">{icon}</span>
      {label}
    </div>
  )
}

/* ── Inline SVG icons (no emoji, per the design system; all inherit currentColor) ── */

const THEME_ICON = 'w-[18px] h-[18px]'
const MENU_ICON = 'w-4 h-4'

function IconSun() {
  return (
    <svg className={THEME_ICON} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
    </svg>
  )
}

function IconMoon() {
  return (
    <svg className={THEME_ICON} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" />
    </svg>
  )
}

function IconMonitor() {
  return (
    <svg className={THEME_ICON} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
    </svg>
  )
}

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
