import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/context/AuthContext'
import { fetchProfile, type UserProfile } from '@/services/auth.service'

export function ProfilePage() {
    const { user, logout } = useAuth()
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
        <div className="max-w-3xl mx-auto animate-fadeIn">
            {/* Page heading */}
            <div className="mb-7">
                <h1 className="font-display text-[1.8rem] font-[900] text-content-primary tracking-[-0.5px] leading-tight">
                    My Profile
                </h1>
                <p className="text-sm text-content-secondary mt-1.5">
                    View and manage your account information.
                </p>
            </div>

            {/* Profile hero card */}
            <div className="bg-surface-card border border-border rounded-card relative overflow-hidden mb-6">
                {/* Top gradient accent */}
                <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-danger via-[#ff6644] to-accent-blue" />

                {/* Banner area — subtle radial glow */}
                <div
                    className="h-32 relative"
                    style={{
                        background:
                            'radial-gradient(circle at 30% 60%, rgba(255,34,68,0.08), transparent 55%), radial-gradient(circle at 70% 40%, rgba(0,180,216,0.08), transparent 55%)',
                    }}
                />

                {/* Avatar + name block — overlapping banner */}
                <div className="px-8 pb-8 -mt-14 relative z-[1]">
                    <div className="flex items-end gap-6">
                        {/* Avatar */}
                        <div className="w-[100px] h-[100px] rounded-2xl bg-gradient-to-br from-danger to-[#ff6644] flex items-center justify-center
              text-[2.2rem] font-extrabold text-white shadow-[0_8px_32px_rgba(255,34,68,0.3)] ring-4 ring-surface-card
              transition-all hover:shadow-[0_12px_44px_rgba(255,34,68,0.45)] hover:scale-[1.03]">
                            {initials}
                        </div>

                        {/* Identity */}
                        <div className="pb-1.5 flex-1 min-w-0">
                            <h2 className="font-display text-[1.5rem] font-[800] text-content-primary tracking-[-0.5px] truncate">
                                {displayName}
                            </h2>
                            <div className="flex items-center gap-3 mt-1">
                                <span className="font-mono text-xs text-content-dim">@{profile?.username ?? user?.username}</span>
                                <span className="w-1 h-1 rounded-full bg-content-dim" />
                                <span className="inline-flex items-center gap-1.5 bg-safe/[0.12] border border-safe/30 rounded-full px-2.5 py-0.5
                  font-mono text-[10px] text-safe tracking-[0.5px] font-medium uppercase">
                                    <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
                                    Active
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Info grid */}
            <div className="grid grid-cols-2 gap-5 mb-6">
                <InfoField
                    icon="✉️"
                    label="Email Address"
                    value={profile?.email ?? '—'}
                />
                <InfoField
                    icon="👤"
                    label="Username"
                    value={profile?.username ?? user?.username ?? '—'}
                />
                <InfoField
                    icon="🏷️"
                    label="First Name"
                    value={profile?.first_name || '—'}
                />
                <InfoField
                    icon="🏷️"
                    label="Last Name"
                    value={profile?.last_name || '—'}
                />
                <InfoField
                    icon="📅"
                    label="Member Since"
                    value={memberSince}
                />
                <InfoField
                    icon="🔐"
                    label="Auth Method"
                    value={user?.method === 'google_sso' ? 'Google SSO' : 'Email & Password'}
                />
            </div>

            {/* Account ID */}
            {profile?.id && (
                <div className="bg-surface-card border border-border rounded-card px-6 py-4 mb-6
          flex items-center justify-between">
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

            {/* Actions */}
            <div className="flex gap-4">
                <button
                    onClick={loadProfile}
                    className="bg-surface-elevated border border-border rounded-btn px-6 py-3
            text-content-secondary font-display text-sm font-semibold cursor-pointer
            transition-all hover:border-border-active hover:text-content-primary hover:-translate-y-[1px]
            flex items-center gap-2"
                >
                    <span>↻</span> Refresh
                </button>
                <button
                    onClick={logout}
                    className="bg-danger/[0.08] border border-danger/30 rounded-btn px-6 py-3
            text-danger font-display text-sm font-semibold cursor-pointer
            transition-all hover:bg-danger/[0.15] hover:border-danger/50 hover:-translate-y-[1px]
            flex items-center gap-2"
                >
                    <span>🚪</span> Sign Out
                </button>
            </div>
        </div>
    )
}

/* ── Info Field Card ── */
function InfoField({ icon, label, value }: { icon: string; label: string; value: string }) {
    return (
        <div className="bg-surface-card border border-border rounded-card px-5 py-4
      transition-all duration-[300ms] hover:border-border-active group">
            <div className="flex items-center gap-2 mb-2">
                <span className="text-base">{icon}</span>
                <span className="font-mono text-[10px] text-content-dim tracking-[1px] uppercase">{label}</span>
            </div>
            <div className="font-body text-[0.95rem] text-content-primary font-medium truncate group-hover:text-white transition-colors">
                {value}
            </div>
        </div>
    )
}
