import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { useDemoCountdown } from '@/hooks/useDemoCountdown'
import { fetchProfile, type UserProfile } from '@/services/auth.service'

export function ProfilePage() {
    const { user, logout } = useAuth()
    const navigate = useNavigate()
    const [profile, setProfile] = useState<UserProfile | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    const loadProfile = useCallback(async () => {
        setLoading(true)
        setError(null)
        try {
            const data = await fetchProfile()
            setProfile(data)
        } catch {
            setError('Failed to load profile. Please try again.')
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => {
        loadProfile()
    }, [loadProfile])

    if (loading) {
        return (
            <div className="flex items-center justify-center h-full">
                <div className="flex flex-col items-center gap-4 animate-fadeIn">
                    <div className="w-10 h-10 border-[3px] border-danger/30 border-t-danger rounded-full animate-spin" />
                    <span className="font-mono text-xs text-content-dim tracking-[1px] uppercase">
                        Loading profile…
                    </span>
                </div>
            </div>
        )
    }

    if (error) {
        return (
            <div className="flex items-center justify-center h-full">
                <div className="bg-surface-card border border-danger/30 rounded-card p-8 max-w-md text-center animate-fadeIn">
                    <div className="w-14 h-14 rounded-full bg-danger/[0.12] flex items-center justify-center text-2xl mx-auto mb-4">
                        ⚠️
                    </div>
                    <h2 className="font-display text-lg font-bold text-content-primary mb-2">
                        Something went wrong
                    </h2>
                    <p className="text-sm text-content-secondary mb-5">{error}</p>
                    <button
                        onClick={loadProfile}
                        className="bg-danger border-none rounded-btn px-6 py-2.5 text-white font-display text-sm font-bold cursor-pointer
              transition-all hover:-translate-y-[1px] hover:shadow-[0_6px_24px_rgba(255,34,68,0.35)]"
                    >
                        Retry
                    </button>
                </div>
            </div>
        )
    }

    const displayName = profile
        ? [profile.first_name, profile.last_name].filter(Boolean).join(' ') || profile.username
        : user?.name ?? 'User'
    const memberSince = profile?.date_joined
        ? new Date(profile.date_joined).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
        })
        : '—'
    const initials =
        user?.initials ??
        displayName
            .split(' ')
            .map((w) => w[0])
            .join('')
            .toUpperCase()
            .slice(0, 2)

    return (
        <div className="max-w-[800px] mx-auto animate-fadeIn py-4">
            {/* ── Profile Header ── */}
            <section className="flex flex-col items-center justify-center pt-4 pb-10">
                <div className="relative group cursor-pointer mb-5">
                    {/* Avatar */}
                    <div
                        className="w-[120px] h-[120px] rounded-full flex items-center justify-center
                            text-[2.8rem] font-extrabold text-white
                            shadow-[0_8px_32px_rgba(255,99,99,0.25)] ring-[3px] ring-surface-card
                            transition-all group-hover:shadow-[0_12px_44px_rgba(255,99,99,0.35)] group-hover:scale-[1.03]"
                        style={{
                            background: 'linear-gradient(135deg, #FF6363, #ff8f8f)',
                        }}
                    >
                        {initials}
                    </div>
                    {/* Edit icon overlay */}
                    <div
                        className="absolute bottom-0 right-0 w-8 h-8 rounded-full flex items-center justify-center
                            bg-surface-elevated border border-border shadow-ring
                            transition-colors hover:bg-[#252829]"
                    >
                        <svg className="w-3.5 h-3.5 text-content-secondary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" />
                            <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" />
                        </svg>
                    </div>
                </div>
                <h1 className="font-display text-[1.8rem] font-bold text-content-primary tracking-[-0.3px] leading-tight mb-1">
                    {displayName}
                </h1>
                <p className="text-content-dim text-sm font-medium">
                    {profile?.email ?? user?.username ?? ''}
                </p>
            </section>

            {/* ── Personal Information ── */}
            <section className="flex flex-col gap-3 mb-8">
                <h2 className="text-content-dim text-xs font-semibold tracking-[1.5px] uppercase px-2">
                    Personal Information
                </h2>
                <div className="bg-surface-card rounded-[12px] shadow-ring overflow-hidden flex flex-col">
                    <InfoRow label="Full Name" value={displayName} />
                    <InfoRow label="Email Address" value={profile?.email ?? '—'} />
                    <InfoRow label="Username" value={profile?.username ?? user?.username ?? '—'} />
                    <InfoRow label="Member Since" value={memberSince} last />
                </div>
            </section>

            {/* ── Connection Mode ── */}
            <ConnectionModeCard
                user={user}
                profile={profile}
                onUpgrade={() => navigate('/connector?upgrade=1')}
            />

            {/* ── Preferences ── */}
            <section className="flex flex-col gap-3 mb-8">
                <h2 className="text-content-dim text-xs font-semibold tracking-[1.5px] uppercase px-2">
                    Preferences
                </h2>
                <div className="bg-surface-card rounded-[12px] shadow-ring overflow-hidden flex flex-col">
                    <PrefRow
                        icon={
                            <svg className="w-[18px] h-[18px] text-content-secondary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                                <path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.573-1.066z" />
                                <circle cx="12" cy="12" r="3" />
                            </svg>
                        }
                        label="Account Settings"
                        onClick={() => navigate('/settings')}
                    />
                    <PrefRow
                        icon={
                            <svg className="w-[18px] h-[18px] text-content-secondary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                                <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                        }
                        label="Privacy & Security"
                        onClick={() => navigate('/settings')}
                        last
                    />
                </div>
            </section>

            {/* ── Account ID ── */}
            {profile?.id && (
                <div className="bg-surface-card border border-border rounded-[12px] px-5 py-4 mb-6
                    flex items-center justify-between shadow-ring">
                    <div>
                        <div className="font-mono text-[10px] text-content-dim tracking-[1px] uppercase mb-1">Account ID</div>
                        <div className="font-mono text-sm text-content-secondary">{profile.id}</div>
                    </div>
                    <button
                        onClick={() => navigator.clipboard.writeText(String(profile.id))}
                        className="bg-surface-elevated border border-border rounded-btn px-3.5 py-2 text-content-secondary
                            font-mono text-[11px] cursor-pointer transition-all hover:border-border-active hover:text-content-primary
                            active:scale-95"
                    >
                        Copy ID
                    </button>
                </div>
            )}

            {/* ── Sign Out ── */}
            <div className="flex justify-center pt-2">
                <button
                    onClick={logout}
                    className="bg-transparent border border-danger/20 hover:bg-danger/[0.08] rounded-btn px-6 py-2.5
                        text-danger font-display text-sm font-semibold cursor-pointer
                        transition-all flex items-center gap-2 tracking-[0.3px]"
                >
                    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                    </svg>
                    Sign Out
                </button>
            </div>
        </div>
    )
}

/* ── Info Row ── */
function InfoRow({ label, value, last }: { label: string; value: string; last?: boolean }) {
    return (
        <div
            className={`flex items-center justify-between px-5 py-4 hover:bg-white/[0.02] transition-colors cursor-pointer
                ${last ? '' : 'border-b border-white/[0.05]'}`}
        >
            <div className="flex flex-col gap-0.5">
                <span className="text-content-dim text-xs font-medium">{label}</span>
                <span className="text-content-primary text-sm font-medium">{value}</span>
            </div>
            <svg className="w-[18px] h-[18px] text-content-dim" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M9 5l7 7-7 7" />
            </svg>
        </div>
    )
}

/* ── Preference Row ── */
function PrefRow({ icon, label, onClick, last }: {
    icon: React.ReactNode
    label: string
    onClick: () => void
    last?: boolean
}) {
    return (
        <button
            type="button"
            onClick={onClick}
            className={`flex items-center justify-between px-5 py-4 hover:bg-white/[0.02] transition-colors cursor-pointer w-full text-left group
                ${last ? '' : 'border-b border-white/[0.05]'}`}
        >
            <div className="flex items-center gap-3">
                <div className="p-2 bg-surface-elevated rounded-lg border border-border group-hover:bg-[#252829] transition-colors">
                    {icon}
                </div>
                <span className="text-content-primary text-sm font-medium">{label}</span>
            </div>
            <svg className="w-[18px] h-[18px] text-content-dim" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M9 5l7 7-7 7" />
            </svg>
        </button>
    )
}

/* ── Connection Mode Card ── */
function ConnectionModeCard({
    user,
    profile,
    onUpgrade,
}: {
    user: ReturnType<typeof import('@/context/AuthContext').useAuth>['user']
    profile: UserProfile | null
    onUpgrade: () => void
}) {
    if (!user) return null

    const isDemo = user.isDemo
    const isVerified = user.isVerified

    if (isDemo) {
        return <DemoModeCard user={user} onUpgrade={onUpgrade} />
    }

    if (isVerified) {
        return (
            <div className="bg-surface-card border border-border rounded-[12px] shadow-ring relative overflow-hidden mb-8">
                <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-accent-blue via-[#55d4ff] to-green" />
                <div className="px-6 py-5">
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-lg bg-accent-blue/[0.12] border border-accent-blue/20 flex items-center justify-center text-lg">
                                ☁️
                            </div>
                            <div>
                                <div className="font-mono text-[10px] text-content-dim tracking-[1px] uppercase mb-0.5">Connection Mode</div>
                                <div className="font-display text-sm font-bold text-content-primary">AWS Connector</div>
                            </div>
                        </div>
                        <span className="inline-flex items-center gap-1.5 bg-safe/[0.12] border border-safe/30 rounded-full px-3 py-1
              font-mono text-[10px] text-safe tracking-[0.5px] font-medium uppercase">
                            <span className="w-1.5 h-1.5 rounded-full bg-safe" />
                            Verified
                        </span>
                    </div>
                    {profile?.aws_role_arn && (
                        <div className="bg-surface-elevated rounded-lg px-4 py-3 border border-border">
                            <div className="font-mono text-[10px] text-content-dim tracking-[1px] uppercase mb-1">Role ARN</div>
                            <div className="font-mono text-xs text-accent-blue break-all">
                                {profile.aws_role_arn.replace(/^(arn:aws:iam::\d{4})\d+(:role\/.{4}).*$/, '$1****$2****')}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        )
    }

    return null
}

/* ── Demo Mode Card with Countdown ── */
function DemoModeCard({
    user,
    onUpgrade,
}: {
    user: NonNullable<ReturnType<typeof import('@/context/AuthContext').useAuth>['user']>
    onUpgrade: () => void
}) {
    const { isExpired } = useDemoCountdown(user.demoExpiresAt)

    return (
        <div className={`bg-surface-card border rounded-[12px] shadow-ring relative overflow-hidden mb-8 transition-all duration-300
            ${isExpired ? 'border-[#ff8c00]/40' : 'border-border'}`}>
            <div className={`absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r
                ${isExpired ? 'from-[#ff8c00] via-danger to-[#ff8c00]' : 'from-[#ff8c00] via-amber-400 to-[#ff8c00]'}`} />
            <div className="px-6 py-5">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg
                            ${isExpired
                                ? 'bg-danger/[0.12] border border-danger/20'
                                : 'bg-[#ff8c00]/[0.12] border border-[#ff8c00]/20'
                            }`}>
                            {isExpired ? '⏱️' : '🧪'}
                        </div>
                        <div>
                            <div className="font-mono text-[10px] text-content-dim tracking-[1px] uppercase mb-0.5">Connection Mode</div>
                            <div className="font-display text-sm font-bold text-content-primary">Demo Sandbox</div>
                        </div>
                    </div>
                    <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1
              font-mono text-[10px] tracking-[0.5px] font-medium uppercase
              ${isExpired
                            ? 'bg-danger/[0.12] border border-danger/30 text-danger'
                            : 'bg-[#ff8c00]/[0.12] border border-[#ff8c00]/30 text-[#ff8c00]'
                        }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${isExpired ? 'bg-danger' : 'bg-[#ff8c00] animate-pulse'}`} />
                        {isExpired ? 'Expired' : 'Active'}
                    </span>
                </div>

                {/* Expired notice */}
                {isExpired && (
                    <div className="mb-4">
                        <div className="bg-danger/[0.06] border border-danger/20 rounded-lg px-4 py-3">
                            <p className="font-mono text-[11px] text-danger leading-relaxed">
                                Your 5-minute demo session has ended. Connect your AWS account to continue using MayaTrail.
                            </p>
                        </div>
                    </div>
                )}

                {/* Info notice */}
                <div className="flex items-start gap-2 mb-4 bg-surface-elevated/50 rounded-lg px-3.5 py-2.5 border border-border">
                    <span className="text-xs mt-0.5">ℹ️</span>
                    <p className="font-mono text-[10px] text-content-dim leading-relaxed">
                        Demo mode can only be activated once. Connect your AWS account for full, unlimited access to all emulations and detections.
                    </p>
                </div>

                {/* Upgrade CTA */}
                <button
                    type="button"
                    onClick={onUpgrade}
                    className="w-full bg-accent-blue border-none rounded-btn py-3
            text-white font-display text-sm font-bold cursor-pointer
            transition-all hover:-translate-y-[1px] hover:shadow-[0_8px_32px_rgba(0,180,216,0.35)]
            active:translate-y-0 flex items-center justify-center gap-2"
                >
                    <span>☁️</span>
                    Connect AWS Account
                    <span className="text-xs opacity-70">→</span>
                </button>
            </div>
        </div>
    )
}
