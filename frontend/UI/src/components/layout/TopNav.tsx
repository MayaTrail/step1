import { useState, useRef, useEffect } from 'react'
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
        className="hidden md:flex flex-1 max-w-[400px] mx-auto relative cursor-pointer"
        onClick={onOpenSearch}
      >
        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-content-dim text-sm">
          &#128269;
        </span>
        <input
          type="text"
          readOnly
          placeholder="Search emulations, techniques, actors...  ( / )"
          className="w-full bg-surface-elevated border border-border rounded-lg py-2 pl-10 pr-4 text-content-primary font-mono text-xs outline-none cursor-pointer
            transition-colors hover:border-border-active
            placeholder:text-content-dim"
        />
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

        {/* Theme toggle — hidden on small screens */}
        <button
          onClick={toggleTheme}
          className="hidden sm:flex bg-surface-elevated border border-border rounded-full px-3.5 py-1.5 text-content-secondary text-sm
            items-center gap-1.5 cursor-pointer transition-all hover:border-border-active hover:text-content-primary"
        >
          {theme === 'dark' ? '☽' : theme === 'light' ? '☀️' : '⚙️'} Theme
        </button>

        {/* Account dropdown */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setDropdownOpen((v) => !v)}
            className="bg-danger/[0.08] border border-danger/30 rounded-lg px-3.5 py-[7px] text-content-primary font-display text-sm font-semibold
              flex items-center gap-2 cursor-pointer transition-all hover:bg-danger/[0.12] hover:border-danger/50"
          >
            <div className="w-[26px] h-[26px] rounded-full bg-gradient-to-br from-danger to-[#ff6644] flex items-center justify-center text-[11px] font-extrabold text-white">
              {user?.initials ?? 'U'}
            </div>
            {user?.isDemo && (
              <span className="font-mono text-[9px] font-bold tracking-wider bg-orange/20 text-orange border border-orange/30 rounded px-1.5 py-0.5">
                DEMO
              </span>
            )}
            {user?.isVerified && (
              <span className="font-mono text-[9px] font-bold tracking-wider bg-green/20 text-green border border-green/30 rounded px-1.5 py-0.5">
                IAM
              </span>
            )}
            <span className="hidden sm:inline">{user?.name?.split(' ').map((n) => n[0] + '.').join(' ') ?? 'User'}</span>
            <span className="text-[10px]">&#9662;</span>
          </button>

          {/* Dropdown menu */}
          {dropdownOpen && (
            <div className="absolute top-[calc(100%+8px)] right-0 bg-surface-card border border-border rounded-card w-[200px] shadow-[0_12px_40px_rgba(0,0,0,0.6)] z-[300] overflow-hidden animate-fadeIn">
              <div className="px-4 py-3.5 border-b border-border">
                <div className="text-sm font-bold text-content-primary">{user?.name ?? 'User'}</div>
                <div className="font-mono text-[10px] text-content-dim mt-0.5">{user?.username ?? ''}</div>
              </div>
              <div className="py-1">
                <DropdownItem icon="👤" label="Profile" onClick={() => { setDropdownOpen(false); navigate('/me') }} />
                <DropdownItem icon="⚙️" label="Settings" onClick={() => { setDropdownOpen(false); navigate('/settings') }} />
                <DropdownItem icon="🔑" label="API Keys" onClick={() => setDropdownOpen(false)} />
                <DropdownItem icon="👥" label="Team" onClick={() => setDropdownOpen(false)} />
              </div>
              <div className="h-px bg-border" />
              <div className="py-1">
                <DropdownItem
                  icon="🚪"
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
  icon: string
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
      <span>{icon}</span>
      {label}
    </div>
  )
}
