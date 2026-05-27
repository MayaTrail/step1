import { useState, useEffect, useCallback } from 'react'
import { useTheme } from '@/context/ThemeContext'

type SettingsTab = 'general' | 'appearance' | 'account'

const NAV_ITEMS: { id: SettingsTab; label: string; icon: JSX.Element }[] = [
    {
        id: 'general',
        label: 'General',
        icon: (
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.573-1.066z" />
                <circle cx="12" cy="12" r="3" />
            </svg>
        ),
    },
    {
        id: 'appearance',
        label: 'Appearance',
        icon: (
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01" />
            </svg>
        ),
    },
    {
        id: 'account',
        label: 'Account',
        icon: (
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
        ),
    },
]

export function SettingsPage() {
    const [activeTab, setActiveTab] = useState<SettingsTab>('appearance')

    // ⌘S keyboard shortcut
    useEffect(() => {
        function handleKeyDown(e: KeyboardEvent) {
            if ((e.metaKey || e.ctrlKey) && e.key === 's') {
                e.preventDefault()
                // Save action — placeholder for future persistence
            }
        }
        document.addEventListener('keydown', handleKeyDown)
        return () => document.removeEventListener('keydown', handleKeyDown)
    }, [])

    return (
        <div className="flex flex-col md:flex-row gap-0 -mx-6 lg:-mx-8 -my-7 min-h-full animate-fadeIn">
            {/* ── Settings Sidebar (Desktop) ── */}
            <aside className="hidden md:flex flex-col w-60 border-r border-white/[0.05] bg-surface-card p-4 gap-2 shrink-0 min-h-full">
                <div className="mb-6 px-2 mt-2">
                    <h1 className="text-lg font-bold text-content-primary tracking-[0.2px]">Settings</h1>
                    <p className="text-sm text-content-dim tracking-[0.2px]">Manage your preferences</p>
                </div>
                <nav className="flex-1 flex flex-col gap-1">
                    {NAV_ITEMS.map((item) => (
                        <button
                            key={item.id}
                            type="button"
                            onClick={() => setActiveTab(item.id)}
                            className={`flex items-center gap-3 px-3 py-2 rounded-[6px] text-sm font-medium tracking-[0.2px]
                                transition-all duration-150 ease-in-out w-full text-left cursor-pointer border-none
                                ${activeTab === item.id
                                    ? 'bg-white/10 text-content-primary shadow-[0_0_0_1px_rgba(255,255,255,0.1)_inset]'
                                    : 'bg-transparent text-content-dim hover:text-content-secondary hover:bg-white/[0.04]'
                                }`}
                        >
                            {item.icon}
                            {item.label}
                        </button>
                    ))}
                </nav>
            </aside>

            {/* ── Mobile Tab Bar ── */}
            <div className="md:hidden flex border-b border-white/[0.05] bg-surface-card px-2">
                {NAV_ITEMS.map((item) => (
                    <button
                        key={item.id}
                        type="button"
                        onClick={() => setActiveTab(item.id)}
                        className={`flex items-center gap-2 px-4 py-3 text-xs font-semibold tracking-[0.5px] uppercase
                            border-b-2 transition-colors cursor-pointer bg-transparent border-x-0 border-t-0
                            ${activeTab === item.id
                                ? 'text-content-primary border-danger'
                                : 'text-content-dim border-transparent hover:text-content-secondary'
                            }`}
                    >
                        {item.label}
                    </button>
                ))}
            </div>

            {/* ── Main Content ── */}
            <main className="flex-1 overflow-y-auto w-full max-w-4xl mx-auto px-6 md:px-10 py-8 md:py-12">
                {activeTab === 'appearance' && <AppearanceTab />}
                {activeTab === 'general' && <PlaceholderTab title="General" />}
                {activeTab === 'account' && <PlaceholderTab title="Account" />}
            </main>
        </div>
    )
}

/* ══════════════════════════════════════════════
   Appearance Tab
   ══════════════════════════════════════════════ */

function AppearanceTab() {
    const { theme, setTheme } = useTheme()
    const [highContrast, setHighContrast] = useState(true)
    const [reduceMotion, setReduceMotion] = useState(false)

    // Apply reduce-motion preference
    useEffect(() => {
        document.documentElement.classList.toggle('reduce-motion', reduceMotion)
    }, [reduceMotion])

    const handleApply = useCallback(() => {
        // Settings are already applied reactively — this is a UX affordance.
        // Could persist to backend in the future.
    }, [])

    return (
        <>
            {/* Header */}
            <header className="mb-10">
                <div
                    className="h-1 w-16 mb-5 rounded-full opacity-80"
                    style={{
                        background: 'repeating-linear-gradient(-45deg, #FF6363, #FF6363 4px, transparent 4px, transparent 8px)',
                    }}
                />
                <h2 className="font-display text-[28px] md:text-[36px] font-bold text-content-primary leading-tight mb-2 tracking-[-0.5px]">
                    Appearance
                </h2>
                <p className="text-content-secondary text-sm max-w-2xl leading-relaxed">
                    Customize the visual interface. Changes apply immediately across all application windows.
                </p>
            </header>

            <div className="space-y-8">
                {/* ── Theme Preference ── */}
                <section className="bg-surface-card rounded-[12px] border border-border p-6 md:p-8 shadow-ring">
                    <h3 className="font-display text-lg font-semibold text-content-primary mb-6">Theme Preference</h3>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                        <ThemeCard
                            label="Light"
                            selected={theme === 'light'}
                            onClick={() => setTheme('light')}
                            preview={<LightPreview />}
                        />
                        <ThemeCard
                            label="Dark"
                            selected={theme === 'dark'}
                            onClick={() => setTheme('dark')}
                            preview={<DarkPreview />}
                        />
                        <ThemeCard
                            label="System Match"
                            selected={theme === 'system'}
                            onClick={() => setTheme('system')}
                            preview={<SystemPreview />}
                        />
                    </div>
                </section>

                {/* ── Typography & Interface Details ── */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                    {/* Typography */}
                    <section className="bg-surface-card rounded-[12px] border border-border p-6 shadow-ring">
                        <h3 className="font-display text-lg font-semibold text-content-primary mb-6">Typography</h3>
                        <div className="space-y-3">
                            <FontRow family="Inter" role="Body & Interface" active />
                            <FontRow family="Geist Mono" role="Code blocks" mono />
                        </div>
                    </section>

                    {/* Interface Details */}
                    <section className="bg-surface-card rounded-[12px] border border-border p-6 shadow-ring">
                        <h3 className="font-display text-lg font-semibold text-content-primary mb-6">Interface Details</h3>
                        <div className="space-y-5">
                            <ToggleRow
                                label="High Contrast Shadows"
                                description="Enhance physical depth simulation"
                                checked={highContrast}
                                onToggle={() => setHighContrast(!highContrast)}
                                accentColor="#FF6363"
                            />
                            <div className="h-px w-full bg-white/[0.05]" />
                            <ToggleRow
                                label="Reduce Motion"
                                description="Disable non-essential animations"
                                checked={reduceMotion}
                                onToggle={() => setReduceMotion(!reduceMotion)}
                                accentColor="#FF6363"
                            />
                            <div className="h-px w-full bg-white/[0.05]" />
                            {/* Tracking Base — display-only */}
                            <div className="flex flex-col gap-2">
                                <div className="flex justify-between items-end">
                                    <p className="text-content-primary text-sm font-medium">Tracking Base</p>
                                    <p className="text-accent-blue text-xs font-mono">+0.2px</p>
                                </div>
                                <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden relative">
                                    <div className="absolute top-0 left-0 h-full w-[40%] bg-accent-blue rounded-full" />
                                    <div className="absolute top-1/2 -translate-y-1/2 left-[40%] w-3 h-3 bg-white rounded-full shadow-md -ml-1.5 border border-black/20" />
                                </div>
                            </div>
                        </div>
                    </section>
                </div>

                {/* ── Action Bar ── */}
                <div className="mt-10 flex items-center justify-end gap-4 border-t border-white/[0.05] pt-7">
                    <button className="flex items-center gap-2 px-4 py-2 rounded-btn text-content-secondary hover:text-content-primary transition-colors text-sm font-medium bg-transparent border-none cursor-pointer">
                        Cancel
                        <kbd className="px-1.5 py-0.5 rounded text-[10px] font-mono text-content-dim border border-border ml-1"
                            style={{
                                background: 'linear-gradient(180deg, #121212 0%, #0d0d0d 100%)',
                                boxShadow: 'inset 0 1px 0 0 rgba(255,255,255,0.1), 0 2px 0 0 #000, 0 3px 2px 0 rgba(0,0,0,0.5)',
                            }}
                        >
                            Esc
                        </kbd>
                    </button>
                    <button
                        onClick={handleApply}
                        className="flex items-center gap-2 px-5 py-2 rounded-pill bg-white/10 hover:bg-white/[0.15] text-content-primary
                            shadow-ring transition-all text-sm font-semibold border border-border active:scale-[0.98] cursor-pointer"
                    >
                        Apply Changes
                        <div className="flex items-center gap-1 ml-1 opacity-60">
                            <kbd className="w-5 h-5 flex items-center justify-center rounded text-[10px] font-mono text-white border border-border"
                                style={{
                                    background: 'linear-gradient(180deg, #121212 0%, #0d0d0d 100%)',
                                    boxShadow: 'inset 0 1px 0 0 rgba(255,255,255,0.1), 0 2px 0 0 #000, 0 3px 2px 0 rgba(0,0,0,0.5)',
                                }}
                            >⌘</kbd>
                            <kbd className="w-5 h-5 flex items-center justify-center rounded text-[10px] font-mono text-white border border-border"
                                style={{
                                    background: 'linear-gradient(180deg, #121212 0%, #0d0d0d 100%)',
                                    boxShadow: 'inset 0 1px 0 0 rgba(255,255,255,0.1), 0 2px 0 0 #000, 0 3px 2px 0 rgba(0,0,0,0.5)',
                                }}
                            >S</kbd>
                        </div>
                    </button>
                </div>
            </div>
        </>
    )
}

/* ── Theme Card ── */
function ThemeCard({ label, selected, onClick, preview }: {
    label: string
    selected: boolean
    onClick: () => void
    preview: React.ReactNode
}) {
    return (
        <button
            type="button"
            onClick={onClick}
            className="group flex flex-col items-start text-left focus:outline-none bg-transparent border-none cursor-pointer p-0"
        >
            <div
                className={`w-full aspect-[4/3] rounded-lg mb-3 overflow-hidden relative
                    transition-transform group-hover:scale-[1.02] group-active:scale-[0.98]
                    ${selected
                        ? 'border-2 border-accent-blue shadow-[0_0_0_1px_#55b3ff,inset_0_1px_0_0_rgba(255,255,255,0.1)]'
                        : 'border border-border shadow-ring'
                    }`}
            >
                {preview}
            </div>
            <span className={`text-sm font-medium flex items-center gap-2 transition-colors
                ${selected ? 'text-content-primary' : 'text-content-secondary group-hover:text-content-primary'}`}>
                {label}
                {selected && (
                    <svg className="w-4 h-4 text-accent-blue" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                )}
            </span>
        </button>
    )
}

/* ── macOS Window Previews ── */
function WindowDots({ dark }: { dark?: boolean }) {
    return (
        <div className={`absolute top-0 w-full h-7 flex items-center px-3 gap-1.5 border-b
            ${dark
                ? 'bg-surface-elevated border-white/10'
                : 'bg-white border-black/10'
            }`}>
            <div className="w-2 h-2 rounded-full bg-red-500" />
            <div className="w-2 h-2 rounded-full bg-yellow-500" />
            <div className="w-2 h-2 rounded-full bg-green-500" />
        </div>
    )
}

function LightPreview() {
    return (
        <div className="w-full h-full bg-[#f9f9f9]">
            <WindowDots />
            <div className="mt-10 mx-4 h-2 bg-black/[0.06] rounded w-1/3 mb-2" />
            <div className="mx-4 h-2 bg-black/[0.06] rounded w-1/2" />
        </div>
    )
}

function DarkPreview() {
    return (
        <div className="w-full h-full bg-[#07080a]">
            <WindowDots dark />
            <div className="mt-10 mx-4 h-2 bg-white/10 rounded w-1/3 mb-2" />
            <div className="mx-4 h-2 bg-white/10 rounded w-1/2" />
        </div>
    )
}

function SystemPreview() {
    return (
        <div className="w-full h-full bg-gradient-to-br from-[#f9f9f9] from-50% to-[#07080a] to-50%">
            <div className="absolute top-0 w-full h-7 flex items-center px-3 gap-1.5 border-b border-white/10"
                style={{ background: 'linear-gradient(to right, white 50%, #101111 50%)' }}>
                <div className="w-2 h-2 rounded-full bg-red-500" />
                <div className="w-2 h-2 rounded-full bg-yellow-500" />
                <div className="w-2 h-2 rounded-full bg-green-500" />
            </div>
        </div>
    )
}

/* ── Font Row ── */
function FontRow({ family, role, active, mono }: {
    family: string
    role: string
    active?: boolean
    mono?: boolean
}) {
    return (
        <div className={`flex items-center justify-between p-3 bg-surface-elevated rounded-lg border border-white/[0.05]
            ${active ? 'shadow-[0_0_0_1px_rgba(255,255,255,0.1)]' : ''}`}>
            <div>
                <p className={`text-content-primary text-sm font-medium ${mono ? 'font-mono' : ''}`}>{family}</p>
                <p className="text-content-dim text-xs">{role}</p>
            </div>
            {active ? (
                <svg className="w-[18px] h-[18px] text-accent-blue" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="20 6 9 17 4 12" />
                </svg>
            ) : (
                <span className="text-xs px-2.5 py-1 rounded bg-white/[0.04] text-content-secondary hover:text-content-primary hover:bg-white/[0.08] transition-colors border border-border cursor-pointer">
                    Change
                </span>
            )}
        </div>
    )
}

/* ── Toggle Row ── */
function ToggleRow({ label, description, checked, onToggle, accentColor }: {
    label: string
    description: string
    checked: boolean
    onToggle: () => void
    accentColor: string
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
                style={{ backgroundColor: checked ? accentColor : 'rgba(255,255,255,0.1)' }}
            >
                <span
                    className={`pointer-events-none inline-block h-4 w-4 transform rounded-full shadow ring-0 transition duration-200 ease-in-out
                        ${checked ? 'translate-x-4 bg-white' : 'translate-x-0 bg-content-secondary'}`}
                />
            </button>
        </div>
    )
}

/* ── Placeholder Tab ── */
function PlaceholderTab({ title }: { title: string }) {
    return (
        <>
            <header className="mb-10">
                <div
                    className="h-1 w-16 mb-5 rounded-full opacity-80"
                    style={{
                        background: 'repeating-linear-gradient(-45deg, #FF6363, #FF6363 4px, transparent 4px, transparent 8px)',
                    }}
                />
                <h2 className="font-display text-[28px] md:text-[36px] font-bold text-content-primary leading-tight mb-2 tracking-[-0.5px]">
                    {title}
                </h2>
                <p className="text-content-secondary text-sm max-w-2xl leading-relaxed">
                    This section is under development.
                </p>
            </header>
            <div className="bg-surface-card rounded-[12px] border border-border p-12 shadow-ring flex flex-col items-center justify-center text-center">
                <div className="w-16 h-16 rounded-2xl bg-surface-elevated border border-border flex items-center justify-center text-2xl mb-5">
                    🚧
                </div>
                <h3 className="font-display text-lg font-semibold text-content-primary mb-2">Coming Soon</h3>
                <p className="text-content-dim text-sm max-w-sm leading-relaxed">
                    {title} settings will be available in a future update. Stay tuned!
                </p>
            </div>
        </>
    )
}
