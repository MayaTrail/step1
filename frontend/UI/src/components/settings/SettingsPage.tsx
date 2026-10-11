import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { fetchProfile, type UserProfile } from '@/services/auth.service'
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

function AppearanceSection() {
    const [reduceMotion, setReduceMotion] = useState(false)

    useEffect(() => {
        document.documentElement.classList.toggle('reduce-motion', reduceMotion)
    }, [reduceMotion])

    return (
        <>
            <SectionHeader title="Appearance" description="Customize the interface. Changes apply immediately." />

            <div className="bg-surface-card rounded-[12px] border border-border p-6 md:p-8 shadow-ring divide-y divide-white/[0.05]">
                {/* Reduce motion */}
                <div className="pb-5">
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
        ['Account status', user.isVerified ? 'Verified' : 'Unverified'],
    ]

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

            <ConnectedRoles />
        </>
    )
}

/**
 * "role/deploy-role" in arn:aws:iam::111122223333:role/deploy-role, with the
 * account shortened to its last four digits so the row identifies the account
 * without printing its full number.
 */
function describeRole(arn: string): { name: string; account: string } {
    const parts = arn.split(':')
    const account = parts[4] ?? ''
    const resource = parts.slice(5).join(':')
    return {
        name: resource.replace(/^role\//, '') || arn,
        account: account.length >= 4 ? `…${account.slice(-4)}` : '',
    }
}

/**
 * Read-only list of the AWS roles this workspace uses. Each role is managed
 * where it is used: the emulation role on Profile, the Scout audit role on
 * Attack Graph. The ARNs come from the profile endpoint, as the session token
 * only says whether a role is connected.
 */
function ConnectedRoles() {
    const [profile, setProfile] = useState<UserProfile | null>(null)
    const [failed, setFailed] = useState(false)

    useEffect(() => {
        fetchProfile().then(setProfile).catch(() => setFailed(true))
    }, [])

    const regions = profile?.aws_audit_regions ?? []
    const roles = [
        {
            label: 'Emulation role',
            purpose: 'Deploys labs and runs emulations in your account.',
            arn: profile?.aws_role_arn ?? '',
            detail: '',
            to: '/me',
            manage: 'Manage in Profile',
        },
        {
            label: 'Scout audit role',
            purpose: 'Reads IAM configuration for Attack Graph. Read-only.',
            arn: profile?.aws_audit_role_arn ?? '',
            detail: regions.length ? `${regions.length} region${regions.length > 1 ? 's' : ''}` : 'IAM only',
            to: '/attack-graph',
            manage: 'Manage on Attack Graph',
        },
    ]

    return (
        <div className="mt-8">
            <SectionHeader title="Connected roles" description="The AWS roles MayaTrail assumes in your account, and where to change each one." />

            <div className="rounded-card border border-border bg-surface-card px-6 shadow-ring md:px-8">
                {failed && <p className="py-4 text-sm text-content-dim">Could not load your roles. Reload the page to try again.</p>}
                {!failed && (
                    <ul className="divide-y divide-border">
                        {roles.map((role) => {
                            const { name, account } = describeRole(role.arn)
                            return (
                                <li key={role.label} className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 py-4">
                                    <div className="min-w-0">
                                        <p className="text-sm font-semibold text-content-primary">{role.label}</p>
                                        <p className="mt-0.5 text-xs text-content-dim">{role.purpose}</p>
                                    </div>
                                    <div className="flex items-center gap-6">
                                        <div className="text-right">
                                            {!profile && <p className="text-xs text-content-dim">Loading…</p>}
                                            {profile && role.arn && (
                                                <>
                                                    <p className="font-mono text-xs text-content-primary">{name}</p>
                                                    <p className="text-xs text-content-dim">
                                                        {[account && `account ${account}`, role.detail].filter(Boolean).join(' · ')}
                                                    </p>
                                                </>
                                            )}
                                            {profile && !role.arn && <p className="text-xs text-content-dim">Not connected</p>}
                                        </div>
                                        <Link to={role.to} className="text-xs text-accent-blue no-underline transition-opacity hover:opacity-60">
                                            {role.arn ? role.manage : 'Connect'}
                                        </Link>
                                    </div>
                                </li>
                            )
                        })}
                    </ul>
                )}
            </div>
        </div>
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
