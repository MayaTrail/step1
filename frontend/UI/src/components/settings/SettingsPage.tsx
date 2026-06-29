import { useEffect, useState } from 'react'
import { useTheme } from '@/context/ThemeContext'
import { useAuth } from '@/context/AuthContext'
import { AIAssistantTab } from './AIAssistantTab'
import { SectionHeader } from './SectionHeader'

/**
 * SettingsPage — full-width, top-tab settings with three sections: Appearance,
 * AI Assistant, and Account. Each tab shows one section in the full content
 * width. There are no placeholder tabs and no controls that do not do anything.
 */

const TABS = [
    { id: 'appearance', label: 'Appearance' },
    { id: 'ai', label: 'AI Assistant' },
    { id: 'account', label: 'Account' },
] as const

type TabId = (typeof TABS)[number]['id']

export function SettingsPage() {
    const [active, setActive] = useState<TabId>('appearance')

    return (
        <div className="w-full">
            <div className="mb-6">
                <h1 className="font-display text-[28px] md:text-[32px] font-bold text-content-primary tracking-[-0.5px]">
                    Settings
                </h1>
                <p className="text-content-secondary text-sm mt-1 tracking-[0.2px]">
                    Manage your preferences for this workspace.
                </p>
            </div>

            {/* Top tabs — Raycast-red underline marks the active section. */}
            <div className="flex gap-1 border-b border-white/[0.05] mb-8 overflow-x-auto">
                {TABS.map((t) => (
                    <button
                        key={t.id}
                        type="button"
                        onClick={() => setActive(t.id)}
                        className={`px-4 py-3 -mb-px text-sm font-medium whitespace-nowrap border-b-2 transition-colors cursor-pointer bg-transparent
                            ${active === t.id
                                ? 'text-content-primary border-danger'
                                : 'text-content-dim border-transparent hover:text-content-secondary'}`}
                    >
                        {t.label}
                    </button>
                ))}
            </div>

            <div className="pb-12">
                {active === 'appearance' && <AppearanceSection />}
                {active === 'ai' && <AIAssistantTab />}
                {active === 'account' && <AccountSection />}
            </div>
        </div>
    )
}

/* ── Appearance ── */

const THEMES = [
    { id: 'light', label: 'Light' },
    { id: 'dark', label: 'Dark' },
    { id: 'system', label: 'System' },
] as const

function AppearanceSection() {
    const { theme, setTheme } = useTheme()
    const [reduceMotion, setReduceMotion] = useState(false)

    useEffect(() => {
        document.documentElement.classList.toggle('reduce-motion', reduceMotion)
    }, [reduceMotion])

    return (
        <>
            <SectionHeader title="Appearance" description="Customize the interface. Changes apply immediately." />

            <div className="bg-surface-card rounded-[12px] border border-border p-6 md:p-8 shadow-ring divide-y divide-white/[0.05]">
                {/* Theme */}
                <div className="flex items-center justify-between pb-5">
                    <div>
                        <p className="text-content-primary text-sm font-medium">Theme</p>
                        <p className="text-content-dim text-xs mt-0.5">Light, dark, or match your system.</p>
                    </div>
                    <div className="inline-flex rounded-btn border border-border bg-surface-base p-0.5">
                        {THEMES.map((t) => (
                            <button
                                key={t.id}
                                type="button"
                                onClick={() => setTheme(t.id)}
                                className={`px-3 py-1.5 rounded-[6px] text-xs font-medium transition-colors cursor-pointer border-none
                                    ${theme === t.id ? 'bg-white/10 text-content-primary' : 'text-content-dim hover:text-content-secondary'}`}
                            >
                                {t.label}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Reduce motion */}
                <div className="py-5">
                    <ToggleRow
                        label="Reduce Motion"
                        description="Disable non-essential animations."
                        checked={reduceMotion}
                        onToggle={() => setReduceMotion(!reduceMotion)}
                    />
                </div>

                {/* Fonts (read-only) */}
                <div className="flex items-center justify-between pt-5">
                    <div>
                        <p className="text-content-primary text-sm font-medium">Fonts</p>
                        <p className="text-content-dim text-xs mt-0.5">Set by the design system.</p>
                    </div>
                    <span className="font-mono text-xs text-content-secondary">Inter · Geist Mono</span>
                </div>
            </div>
        </>
    )
}

/* ── Account ── */

function AccountSection() {
    const { user, logout } = useAuth()
    if (!user) return null

    const rows: [string, string][] = [
        ['Sign-in method', user.method === 'google_sso' ? 'Google SSO' : 'Email & password'],
        ['Account status', user.isDemo ? 'Demo' : user.isVerified ? 'Verified' : 'Unverified'],
        ['AWS connection', user.isVerified ? 'Connected' : 'Not connected'],
    ]
    if (user.isDemo && user.demoExpiresAt) {
        rows.push(['Demo expires', new Date(user.demoExpiresAt).toLocaleString()])
    }

    return (
        <>
            <SectionHeader title="Account" description="Your identity and session for this workspace." />

            <div className="bg-surface-card rounded-[12px] border border-border p-6 md:p-8 shadow-ring">
                <div className="flex items-center gap-3 mb-6">
                    <div className="w-11 h-11 rounded-full bg-surface-elevated border border-border flex items-center justify-center font-mono text-sm text-content-primary">
                        {user.initials}
                    </div>
                    <div>
                        <p className="text-content-primary text-sm font-semibold">{user.name}</p>
                        <p className="text-content-dim text-xs font-mono">{user.username}</p>
                    </div>
                </div>

                <dl className="divide-y divide-white/[0.05] border-t border-white/[0.05]">
                    {rows.map(([label, value]) => (
                        <div key={label} className="flex items-center justify-between py-3">
                            <dt className="text-content-dim text-sm">{label}</dt>
                            <dd className="text-content-primary text-sm">{value}</dd>
                        </div>
                    ))}
                </dl>

                <div className="mt-6 flex justify-end">
                    <button
                        onClick={() => logout()}
                        className="px-4 py-2 rounded-btn text-sm font-medium text-danger hover:opacity-70 transition-opacity bg-transparent border border-border cursor-pointer"
                    >
                        Sign out
                    </button>
                </div>
            </div>
        </>
    )
}

/* ── Toggle row ── */

function ToggleRow({ label, description, checked, onToggle }: {
    label: string
    description: string
    checked: boolean
    onToggle: () => void
}) {
    return (
        <div className="flex items-center justify-between">
            <div>
                <p className="text-content-primary text-sm font-medium">{label}</p>
                <p className="text-content-dim text-xs mt-0.5">{description}</p>
            </div>
            <button
                type="button"
                role="switch"
                aria-checked={checked}
                onClick={onToggle}
                className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                style={{ backgroundColor: checked ? '#FF6363' : 'rgba(255,255,255,0.1)' }}
            >
                <span
                    className={`pointer-events-none inline-block h-4 w-4 transform rounded-full shadow ring-0 transition duration-200 ease-in-out
                        ${checked ? 'translate-x-4 bg-white' : 'translate-x-0 bg-content-secondary'}`}
                />
            </button>
        </div>
    )
}
