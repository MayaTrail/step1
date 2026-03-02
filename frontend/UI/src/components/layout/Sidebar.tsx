import { useState, useCallback } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { platformRegistry } from '@/data'
import type { PlatformId } from '@/types'
import { PlatformIcon } from '@/components/ui/PlatformIcons'

/** Sub-nav items for each platform */
const subNavItems = [
  { key: 'emulations', label: 'APT Emulations', icon: '\uD83C\uDFAF' },
  { key: 'playbooks', label: 'Playbooks', icon: '\uD83D\uDCCB' },
  { key: 'detections', label: 'Detections', icon: '\uD83D\uDD0D' },
  { key: 'guardrails', label: 'Guardrails', icon: '\uD83D\uDEE1' },
] as const

export function Sidebar() {
  const location = useLocation()
  const [expanded, setExpanded] = useState<Set<PlatformId>>(() => {
    // Auto-expand the platform that matches the current URL
    const match = location.pathname.match(/^\/(aws|azure|gcp|ai|k8s)/)
    return match ? new Set([match[1] as PlatformId]) : new Set()
  })

  const togglePlatform = useCallback((id: PlatformId) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const isActivePlatform = (route: string) => location.pathname.startsWith(`/${route}`)

  return (
    <aside className="w-[240px] bg-surface-base border-r border-border overflow-y-auto shrink-0 py-4">

      {/* ── Dashboard Section ── */}
      <SectionLabel>Dashboard</SectionLabel>
      <Link
        to="/"
        className={`flex items-center gap-2.5 px-4 py-2.5 cursor-pointer transition-all duration-150
          border-l-2 text-sm font-semibold no-underline
          ${location.pathname === '/'
            ? 'text-danger border-l-danger bg-danger/[0.06]'
            : 'text-content-secondary border-l-transparent hover:bg-surface-card hover:text-content-primary'
          }`}
      >
        &#127968; Home
      </Link>
      <Link
        to="/stacks"
        className={`flex items-center gap-2.5 px-4 py-2.5 cursor-pointer transition-all duration-150
          border-l-2 text-sm font-semibold no-underline
          ${location.pathname === '/stacks'
            ? 'text-accent-cyan border-l-accent-cyan bg-accent-cyan/[0.06]'
            : 'text-content-secondary border-l-transparent hover:bg-surface-card hover:text-content-primary'
          }`}
      >
        &#9881;&#65039; Stacks
      </Link>

      <div className="h-3" />

      {/* ── Platforms Section ── */}
      <SectionLabel>Platforms</SectionLabel>

      {platformRegistry.map((platform) => {
        const isActive = isActivePlatform(platform.route)
        const isOpen = expanded.has(platform.id)

        return (
          <div key={platform.id}>
            {/* Platform toggle */}
            <button
              onClick={() => togglePlatform(platform.id)}
              className={`w-full flex items-center gap-2.5 px-4 py-2.5 cursor-pointer transition-all duration-150
                border-l-2 text-[13px] font-semibold text-left
                ${isActive
                  ? 'text-danger border-l-danger bg-danger/[0.06]'
                  : 'text-content-secondary border-l-transparent hover:bg-surface-card hover:text-content-primary'
                }`}
            >
              <PlatformIcon platformId={platform.id} size={18} className="shrink-0" />
              <span>{platform.label.split(' ')[0] === 'Amazon' ? 'AWS'
                : platform.label.split(' ')[0] === 'Google' ? 'GCP'
                  : platform.label.split(' ')[0] === 'Microsoft' ? 'Azure'
                    : platform.label.includes('AI') ? 'AI'
                      : platform.label}</span>
              <span className="ml-auto bg-surface-elevated rounded-[3px] px-[5px] py-px font-mono text-[9px] text-content-dim">
                {platform.badgeCount}
              </span>
              <span
                className={`text-[10px] transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`}
              >
                &#9654;
              </span>
            </button>

            {/* Sub-items */}
            {isOpen && (
              <div className="bg-black/20 border-l border-border ml-6">
                {subNavItems.map((item) => {
                  // Build the sub-item path
                  const path = item.key === 'playbooks'
                    ? `/${platform.route}/playbooks/0`
                    : `/${platform.route}/${item.key}`
                  const isSubActive = location.pathname.startsWith(`/${platform.route}/${item.key}`)

                  return (
                    <Link
                      key={item.key}
                      to={path}
                      className={`flex items-center gap-2 px-4 py-2 cursor-pointer text-xs font-medium no-underline
                        transition-all duration-150
                        ${isSubActive
                          ? 'text-accent-blue bg-accent-blue/[0.06]'
                          : 'text-content-dim hover:text-content-secondary hover:bg-white/[0.02]'
                        }`}
                    >
                      <span>{item.icon}</span>
                      {item.label}
                    </Link>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}

      <div className="h-4" />

      {/* ── System Section ── */}
      <SectionLabel>System</SectionLabel>
      <SystemItem icon="&#128202;" label="Reports" />
      <SystemItem icon="&#9881;&#65039;" label="Settings" />
      <SystemItem icon="&#128214;" label="Documentation" />
    </aside>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-mono text-[9px] font-bold tracking-[2px] text-content-dim px-5 pb-2 uppercase">
      {children}
    </div>
  )
}

function SystemItem({ icon, label }: { icon: string; label: string }) {
  return (
    <div className="flex items-center gap-2.5 px-4 py-2.5 cursor-pointer text-content-dim text-xs
      transition-colors hover:text-content-secondary hover:bg-surface-card">
      <span>{icon}</span>
      {label}
    </div>
  )
}
