import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { useDemoCountdown, formatCountdown } from '@/hooks/useDemoCountdown'
import { fetchProfile, type UserProfile } from '@/services/auth.service'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import {
    IconChevron,
    IconGear,
    IconShield,
    IconCloud,
    IconCopy,
    IconLogout,
    IconFlask,
    IconClock,
    IconInfo,
    IconAlert,
} from '@/components/ui/Icons'

/**
 * ProfilePage — single-column centered layout.
 *
 * A prominent identity header (avatar, name, status badges) sits above
 * a vertical stack of information cards: Account Overview, AWS Connection,
 * Security & Access, and a sign-out danger zone. Presentation only:
 * data comes from fetchProfile + useAuth, demo expiry from useDemoCountdown.
 */
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
                    <div className="w-10 h-10 border-2 border-danger/30 border-t-danger rounded-full animate-spin" />
                    <span className="font-mono text-2xs text-content-dim tracking-label uppercase">
                        Loading profile
                    </span>
                </div>
            </div>
        )
    }

    if (error) {
        return (
            <div className="flex items-center justify-center h-full">
                <Card className="p-8 max-w-md text-center animate-fadeIn">
                    <div className="w-14 h-14 rounded-full bg-danger-dim text-danger flex items-center justify-center mx-auto mb-4">
                        <IconAlert size={26} />
                    </div>
                    <h2 className="font-display text-lg font-semibold text-content-primary mb-2">
                        Something went wrong
                    </h2>
                    <p className="text-sm text-content-secondary mb-5">{error}</p>
                    <Button variant="primary" onClick={loadProfile}>
                        Retry
                    </Button>
                </Card>
            </div>
        )
    }

    const displayName = profile
        ? [profile.first_name, profile.last_name].filter(Boolean).join(' ') || profile.username
        : user?.name ?? 'User'
    const username = profile?.username ?? user?.username ?? '—'
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
    const authMethod = profile?.auth_method === 'google_sso' ? 'Google SSO' : 'Credentials'

    return (
        <div className="max-w-3xl mx-auto py-8 px-4 animate-fadeIn">
            <div className="flex flex-col gap-6">
                {/* ── Profile header hero ── */}
                <ProfileHeader
                    initials={initials}
                    displayName={displayName}
                    username={username}
                    memberSince={memberSince}
                    authMethod={authMethod}
                    user={user}
                />

                {/* ── Account overview ── */}
                <Card className="p-6">
                    <CardEyebrow>Account overview</CardEyebrow>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-5">
                        {profile?.id && (
                            <div className="sm:col-span-2">
                                <AccountId id={String(profile.id)} />
                            </div>
                        )}
                        <Field label="Email address" value={profile?.email ?? '—'} />
                        <Field label="Username" value={username} />
                        <Field label="Auth method" value={authMethod} />
                        <Field label="Member since" value={memberSince} />
                    </div>
                </Card>

                {/* ── Connection mode ── */}
                <ConnectionModeCard
                    user={user}
                    profile={profile}
                    onUpgrade={() => navigate('/connector?upgrade=1')}
                />

                {/* ── Security & access ── */}
                <Card className="p-2">
                    <div className="px-4 pt-3 pb-1">
                        <CardEyebrow>Security & access</CardEyebrow>
                    </div>
                    <AccessRow
                        icon={<IconGear size={18} />}
                        label="Account settings"
                        onClick={() => navigate('/settings')}
                    />
                    <AccessRow
                        icon={<IconShield size={18} />}
                        label="Privacy & security"
                        onClick={() => navigate('/settings')}
                    />
                </Card>

                {/* ── Danger zone ── */}
                <Card accent="red" className="p-6">
                    <CardEyebrow>Danger zone</CardEyebrow>
                    <p className="text-sm text-content-secondary mb-4">
                        Sign out of your current session. You will need to log in again to access MayaTrail.
                    </p>
                    <Button
                        variant="danger"
                        size="md"
                        onClick={logout}
                        icon={<IconLogout size={16} />}
                    >
                        Sign out
                    </Button>
                </Card>
            </div>
        </div>
    )
}

/* ── Profile header hero ── */
function ProfileHeader({
    initials,
    displayName,
    username,
    memberSince,
    authMethod,
    user,
}: {
    initials: string
    displayName: string
    username: string
    memberSince: string
    authMethod: string
    user: ReturnType<typeof useAuth>['user']
}) {
    /** Derive connection badge from user state. */
    const connectionBadge = (() => {
        if (!user) return null
        if (user.isVerified) {
            return { label: 'AWS Connected', tone: 'green' as const }
        }
        if (user.isDemo) {
            return { label: 'Demo Active', tone: 'yellow' as const }
        }
        return { label: 'Not Connected', tone: 'neutral' as const }
    })()

    return (
        <Card className="p-8">
            <div className="flex flex-col items-center text-center">
                {/* Avatar with warm glow */}
                <div className="relative mb-5">
                    <div
                        className="absolute inset-0 rounded-full opacity-40 blur-2xl"
                        style={{ background: 'rgba(215, 201, 175, 0.05)', transform: 'scale(1.6)' }}
                        aria-hidden="true"
                    />
                    <div className="relative w-[120px] h-[120px] rounded-full bg-key shadow-button flex items-center justify-center font-display text-4xl font-semibold text-content-primary">
                        {initials}
                    </div>
                </div>

                {/* Name + handle */}
                <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
                    {displayName}
                </h1>
                <p className="font-mono text-xs text-content-dim mt-1">
                    @{username}
                </p>
                <p className="font-mono text-2xs text-content-muted mt-1 tracking-body">
                    Member since {memberSince}
                </p>

                {/* Status badges */}
                <div className="flex items-center gap-2 mt-4">
                    {connectionBadge && (
                        <Badge tone={connectionBadge.tone} mono dot>
                            {connectionBadge.label}
                        </Badge>
                    )}
                    <Badge tone="neutral" mono>
                        {authMethod}
                    </Badge>
                </div>
            </div>
        </Card>
    )
}

/* ── Account ID block with copy feedback ── */
function AccountId({ id }: { id: string }) {
    const [copied, setCopied] = useState(false)

    const copy = () => {
        navigator.clipboard.writeText(id)
        setCopied(true)
        setTimeout(() => setCopied(false), 1600)
    }

    return (
        <div className="flex flex-col gap-1.5">
            <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
                Account ID
            </span>
            <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-content-secondary truncate">{id}</span>
                <button
                    type="button"
                    onClick={copy}
                    aria-label="Copy account ID"
                    className="shrink-0 flex items-center justify-center w-7 h-7 rounded-btn text-content-dim transition-opacity hover:opacity-70"
                >
                    {copied ? (
                        <span className="font-mono text-2xs text-safe">OK</span>
                    ) : (
                        <IconCopy size={15} />
                    )}
                </button>
            </div>
        </div>
    )
}

/* ── Card eyebrow label ── */
function CardEyebrow({ children }: { children: React.ReactNode }) {
    return (
        <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-4">
            {children}
        </div>
    )
}

/* ── Definition-grid field ── */
function Field({ label, value }: { label: string; value: string }) {
    return (
        <div className="flex flex-col gap-1 min-w-0">
            <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
                {label}
            </span>
            <span className="text-sm text-content-primary font-medium break-words">{value}</span>
        </div>
    )
}

/* ── Access row (navigable) ── */
function AccessRow({
    icon,
    label,
    onClick,
}: {
    icon: React.ReactNode
    label: string
    onClick: () => void
}) {
    return (
        <button
            type="button"
            onClick={onClick}
            className="w-full flex items-center justify-between px-4 py-3 rounded-btn text-left transition-opacity hover:opacity-70"
        >
            <span className="flex items-center gap-3">
                <span className="text-content-secondary">{icon}</span>
                <span className="text-sm text-content-primary font-medium">{label}</span>
            </span>
            <span className="text-content-dim">
                <IconChevron size={16} />
            </span>
        </button>
    )
}

/* ── Connection Mode hero ── */
function ConnectionModeCard({
    user,
    profile,
    onUpgrade,
}: {
    user: ReturnType<typeof useAuth>['user']
    profile: UserProfile | null
    onUpgrade: () => void
}) {
    if (!user) return null

    if (user.isDemo) {
        return <DemoModeCard user={user} onUpgrade={onUpgrade} />
    }

    if (user.isVerified) {
        const maskedArn = profile?.aws_role_arn?.replace(
            /^(arn:aws:iam::\d{4})\d+(:role\/.{4}).*$/,
            '$1****$2****',
        )
        return (
            <Card accent="blue" className="p-6">
                <div className="flex items-center justify-between gap-4 mb-4">
                    <div className="flex items-center gap-3">
                        <span className="w-10 h-10 rounded-btn flex items-center justify-center bg-accent-blue/10 border border-accent-blue/20 text-accent-blue">
                            <IconCloud size={20} />
                        </span>
                        <div>
                            <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-0.5">
                                Connection mode
                            </div>
                            <div className="font-display text-sm font-semibold text-content-primary">
                                AWS Connector
                            </div>
                        </div>
                    </div>
                    <Badge tone="green" mono dot>
                        Verified
                    </Badge>
                </div>
                {maskedArn && (
                    <div className="bg-surface-elevated rounded-btn px-4 py-3 border border-border">
                        <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-1">
                            Role ARN
                        </div>
                        <div className="font-mono text-xs text-accent-blue break-all">{maskedArn}</div>
                    </div>
                )}
            </Card>
        )
    }

    return null
}

/* ── Demo Mode hero with live countdown ── */
function DemoModeCard({
    user,
    onUpgrade,
}: {
    user: NonNullable<ReturnType<typeof useAuth>['user']>
    onUpgrade: () => void
}) {
    const { remaining, isExpired } = useDemoCountdown(user.demoExpiresAt)

    return (
        <Card accent={isExpired ? 'red' : 'amber'} className="p-6">
            <div className="flex items-center justify-between gap-4 mb-4">
                <div className="flex items-center gap-3">
                    <span
                        className={`w-10 h-10 rounded-btn flex items-center justify-center border ${
                            isExpired
                                ? 'bg-danger-dim border-danger/20 text-danger'
                                : 'bg-warning-dim border-warning/20 text-warning'
                        }`}
                    >
                        {isExpired ? <IconClock size={20} /> : <IconFlask size={20} />}
                    </span>
                    <div>
                        <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-0.5">
                            Connection mode
                        </div>
                        <div className="font-display text-sm font-semibold text-content-primary">
                            Demo Sandbox
                        </div>
                    </div>
                </div>
                <Badge tone={isExpired ? 'red' : 'yellow'} mono dot pulse={!isExpired}>
                    {isExpired ? 'Expired' : remaining !== null ? formatCountdown(remaining) : 'Active'}
                </Badge>
            </div>

            {isExpired && (
                <div className="bg-danger-dim border border-danger/20 rounded-btn px-4 py-3 mb-4">
                    <p className="font-mono text-xs text-danger leading-relaxed">
                        Your demo session has ended. Connect your AWS account to continue using MayaTrail.
                    </p>
                </div>
            )}

            <div className="flex items-start gap-2 mb-4 bg-surface-elevated rounded-btn px-3.5 py-2.5 border border-border">
                <span className="text-content-dim mt-0.5 shrink-0">
                    <IconInfo size={14} />
                </span>
                <p className="font-mono text-2xs text-content-dim leading-relaxed">
                    Demo mode can only be activated once. Connect your AWS account for full, unlimited
                    access to all emulations and detections.
                </p>
            </div>

            <Button
                variant="cta"
                size="lg"
                onClick={onUpgrade}
                icon={<IconCloud size={16} />}
                className="w-full"
            >
                Connect AWS Account
            </Button>
        </Card>
    )
}
